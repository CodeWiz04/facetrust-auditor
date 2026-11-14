import io
from datetime import date
from pathlib import Path
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.api.v1.dataset import router as dataset_router
from app.core.config import get_settings
from app.core.crypto import generate_biometric_key, set_active_key
from app.core.errors import register_exception_handlers
from app.db.base import Base


@pytest.fixture(scope="module")
def valid_png_bytes() -> bytes:
    img = Image.new("RGB", (120, 120), color=(50, 100, 150))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Test client with isolated database and storage."""
    test_key = generate_biometric_key()
    set_active_key(test_key)

    storage_root = tmp_path / "storage"
    storage_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(get_settings(), "storage_dir", str(storage_root))

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(dataset_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    Base.metadata.drop_all(bind=engine)
    set_active_key(None)


def test_api_create_and_get_subject(client: TestClient):
    payload = {
        "subject_code": "sub_api_01",
        "consent_given": True,
        "consent_date": str(date.today()),
        "purpose": "evaluation",
        "group": "male_20s_medium",
    }
    resp = client.post("/api/v1/dataset/subjects", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["subject_code"] == "sub_api_01"
    assert data["consent_status"] == "granted"
    assert data["group"] == "male_20s_medium"
    assert data["image_count"] == 0

    # Fetch by ID
    subject_id = data["id"]
    get_resp = client.get(f"/api/v1/dataset/subjects/{subject_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == subject_id


def test_api_create_duplicate_rejected(client: TestClient):
    payload = {
        "subject_code": "sub_api_dup",
        "consent_given": True,
        "consent_date": str(date.today()),
        "purpose": "evaluation",
        "group": "female_30s",
    }
    resp1 = client.post("/api/v1/dataset/subjects", json=payload)
    assert resp1.status_code == 201

    resp2 = client.post("/api/v1/dataset/subjects", json=payload)
    assert resp2.status_code == 400
    assert resp2.json()["error_code"] == "CON-INVALID"


def test_api_create_subject_validation_error(client: TestClient):
    # Future consent date must fail Pydantic validation
    payload = {
        "subject_code": "sub_future",
        "consent_given": True,
        "consent_date": "2099-01-01",
        "purpose": "evaluation",
    }
    resp = client.post("/api/v1/dataset/subjects", json=payload)
    assert resp.status_code == 422
    assert resp.json()["error_code"] == "VALIDATION-FAILED"


def test_api_image_upload_and_listing(client: TestClient, valid_png_bytes: bytes):
    # 1. Create subject
    subj_payload = {
        "subject_code": "sub_img_01",
        "consent_given": True,
        "consent_date": str(date.today()),
        "purpose": "threshold_tuning",
        "group": "group_x",
    }
    subj_resp = client.post("/api/v1/dataset/subjects", json=subj_payload)
    subject_id = subj_resp.json()["id"]

    # 2. Upload valid PNG image
    upload_resp = client.post(
        f"/api/v1/dataset/subjects/{subject_id}/images",
        files={"file": ("face1.png", valid_png_bytes, "image/png")},
    )
    assert upload_resp.status_code == 201
    img_data = upload_resp.json()
    assert img_data["subject_id"] == subject_id
    assert img_data["width"] == 120
    assert img_data["height"] == 120
    assert img_data["detected_type"] == "png"
    assert img_data["clean_hash"].startswith("sha256:")

    # 3. List images
    list_resp = client.get(f"/api/v1/dataset/subjects/{subject_id}/images")
    assert list_resp.status_code == 200
    images_list = list_resp.json()
    assert images_list["total"] == 1
    assert images_list["items"][0]["id"] == img_data["id"]


def test_api_upload_corrupted_file_rejected(client: TestClient):
    subj_payload = {
        "subject_code": "sub_bad_upload",
        "consent_given": True,
        "consent_date": str(date.today()),
        "purpose": "evaluation",
    }
    subj_resp = client.post("/api/v1/dataset/subjects", json=subj_payload)
    subject_id = subj_resp.json()["id"]

    upload_resp = client.post(
        f"/api/v1/dataset/subjects/{subject_id}/images",
        files={"file": ("malicious.png", b"Not a real PNG file at all!", "image/png")},
    )
    assert upload_resp.status_code == 400
    assert upload_resp.json()["error_code"] == "FILE-TYPE-INVALID"


def test_api_withdraw_consent_blocks_future_uploads(
    client: TestClient, valid_png_bytes: bytes
):
    subj_payload = {
        "subject_code": "sub_revoker",
        "consent_given": True,
        "consent_date": str(date.today()),
        "purpose": "bias_audit",
    }
    subj_resp = client.post("/api/v1/dataset/subjects", json=subj_payload)
    subject_id = subj_resp.json()["id"]

    # Withdraw consent
    withdraw_resp = client.post(
        f"/api/v1/dataset/subjects/{subject_id}/withdraw-consent",
        json={"reason": "User revoked authorization"},
    )
    assert withdraw_resp.status_code == 200
    assert withdraw_resp.json()["consent_status"] == "withdrawn"

    # Attempt to upload image must be rejected
    upload_resp = client.post(
        f"/api/v1/dataset/subjects/{subject_id}/images",
        files={"file": ("face.png", valid_png_bytes, "image/png")},
    )
    assert upload_resp.status_code == 400
    assert upload_resp.json()["error_code"] == "CON-WITHDRAWN"
