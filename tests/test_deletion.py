import io
import json
from datetime import date
from pathlib import Path
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.api.v1.dataset import router as dataset_router
from app.core.config import get_settings
from app.core.crypto import generate_biometric_key, set_active_key
from app.core.errors import AppError, register_exception_handlers
from app.db.base import Base
from app.models.audit import AuditLog
from app.models.dataset import BiometricEmbedding, Subject, SubjectImage
from app.schemas.dataset import SubjectCreate
from app.schemas.deletion import SubjectDeletionRequest
from app.services.dataset_service import (
    create_subject,
    get_subject,
    ingest_subject_image,
)
from app.services.deletion_service import execute_privacy_deletion


@pytest.fixture(scope="module")
def sample_png_bytes() -> bytes:
    img = Image.new("RGB", (100, 100), color=(80, 120, 160))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
def env_setup(tmp_path, monkeypatch):
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

    yield TestingSession, storage_root

    Base.metadata.drop_all(bind=engine)
    set_active_key(None)


def test_privacy_deletion_service_end_to_end(env_setup, sample_png_bytes: bytes):
    TestingSession, storage_root = env_setup
    db: Session = TestingSession()

    # 1. Onboard subject
    subject = create_subject(
        db,
        SubjectCreate(
            subject_code="sub_volunteer_delete_01",
            consent_given=True,
            consent_date=str(date.today()),
            purpose="evaluation",
            group="female_20s_medium",
        ),
        actor_id="operator_sam",
    )

    # 2. Ingest two images
    img1 = ingest_subject_image(db, subject.id, sample_png_bytes, "img1.png")
    img2 = ingest_subject_image(db, subject.id, sample_png_bytes, "img2.png")

    file1_path = (storage_root / img1.storage_path).resolve()
    file2_path = (storage_root / img2.storage_path).resolve()
    assert file1_path.exists()
    assert file2_path.exists()

    # Verify embeddings exist
    embeddings_before = db.scalars(
        select(BiometricEmbedding).where(BiometricEmbedding.subject_id == subject.id)
    ).all()
    assert len(embeddings_before) == 2

    # 3. Execute Privacy Deletion (FR-6, T6)
    receipt = execute_privacy_deletion(
        db=db,
        subject_id=subject.id,
        request_data=SubjectDeletionRequest(
            confirm=True, reason="Subject revoked GDPR consent"
        ),
        actor_id="admin_chief",
    )

    # 4. Verify physical files are forensically shredded from disk
    assert not file1_path.exists()
    assert not file2_path.exists()

    # 5. Verify database records are purged
    with pytest.raises(AppError) as exc_info:
        get_subject(db, subject.id)
    assert exc_info.value.code == "NOT-FOUND"

    images_after = db.scalars(
        select(SubjectImage).where(SubjectImage.subject_id == subject.id)
    ).all()
    assert len(images_after) == 0

    embeddings_after = db.scalars(
        select(BiometricEmbedding).where(BiometricEmbedding.subject_id == subject.id)
    ).all()
    assert len(embeddings_after) == 0

    # 6. Verify Deletion Receipt
    assert receipt.status == "verified_deleted"
    assert receipt.images_shredded == 2
    assert receipt.embeddings_destroyed == 2
    assert len(receipt.tombstone_hash) == 64

    # 7. Audit log verification (Zero personal data stored!)
    audit_entry = db.scalar(
        select(AuditLog).where(AuditLog.event == "SUBJECT_PERMANENTLY_DELETED")
    )
    assert audit_entry is not None
    payload = json.loads(audit_entry.payload_json)

    # Plaintext subject code and image paths must NOT be present in audit payload
    assert "sub_volunteer_delete_01" not in audit_entry.payload_json
    assert "img1.png" not in audit_entry.payload_json
    assert payload["subject_hash"] == receipt.subject_hash
    assert payload["tombstone_hash"] == receipt.tombstone_hash
    assert payload["images_shredded"] == 2
    assert payload["embeddings_destroyed"] == 2

    db.close()


def test_api_privacy_deletion(env_setup, sample_png_bytes: bytes):
    TestingSession, _ = env_setup

    def override_get_db():
        session = TestingSession()
        try:
            yield session
        finally:
            session.close()

    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(dataset_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as client:
        # Create subject and upload image
        subj_resp = client.post(
            "/api/v1/dataset/subjects",
            json={
                "subject_code": "sub_api_delete_test",
                "consent_given": True,
                "consent_date": str(date.today()),
                "purpose": "evaluation",
            },
        )
        assert subj_resp.status_code == 201
        subject_id = subj_resp.json()["id"]

        img_resp = client.post(
            f"/api/v1/dataset/subjects/{subject_id}/images",
            files={"file": ("face.png", sample_png_bytes, "image/png")},
        )
        assert img_resp.status_code == 201

        # Delete subject
        del_resp = client.delete(f"/api/v1/dataset/subjects/{subject_id}")
        assert del_resp.status_code == 200
        receipt = del_resp.json()
        assert receipt["status"] == "verified_deleted"
        assert receipt["images_shredded"] == 1
        assert receipt["embeddings_destroyed"] == 1

        # Subject must no longer exist
        get_resp = client.get(f"/api/v1/dataset/subjects/{subject_id}")
        assert get_resp.status_code == 404


def test_api_shred_requires_confirmation(env_setup):
    TestingSession, _ = env_setup

    def override_get_db():
        session = TestingSession()
        try:
            yield session
        finally:
            session.close()

    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(dataset_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as client:
        # Create subject
        subj_resp = client.post(
            "/api/v1/dataset/subjects",
            json={
                "subject_code": "sub_confirm_test",
                "consent_given": True,
                "consent_date": str(date.today()),
                "purpose": "evaluation",
            },
        )
        subject_id = subj_resp.json()["id"]

        # Attempt shred with confirm=False must be rejected (HTTP 422)
        bad_shred = client.post(
            f"/api/v1/dataset/subjects/{subject_id}/shred",
            json={"confirm": False},
        )
        assert bad_shred.status_code == 422

        # Valid shred with confirm=True succeeds
        good_shred = client.post(
            f"/api/v1/dataset/subjects/{subject_id}/shred",
            json={"confirm": True, "reason": "Confirmed consent withdrawal"},
        )
        assert good_shred.status_code == 200
        assert good_shred.json()["status"] == "verified_deleted"
