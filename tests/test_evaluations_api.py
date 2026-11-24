"""Integration tests for threshold tuning, subgroup bias auditing, and liveness endpoints."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Generator

import numpy as np
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw, ImageFilter
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.api.v1.evaluations import router as evaluations_router
from app.core.config import get_settings
from app.core.crypto import encrypt_embedding, generate_biometric_key, set_active_key
from app.core.errors import register_exception_handlers
from app.db.base import Base
from app.models.audit import AuditLog
from app.models.dataset import BiometricEmbedding, ConsentStatus, Subject, SubjectImage


def _create_synthetic_image(is_attack: bool = False) -> bytes:
    """Create a synthetic PNG image for liveness and dataset testing."""
    if is_attack:
        # Uniform dark image triggers both LIV-BLURRY (variance=0) and LIV-TOO-DARK (mean=25 < 60)
        img = Image.new("RGB", (120, 120), color=(25, 25, 25))
    else:
        img = Image.new("RGB", (150, 150), color=(120, 140, 160))
        draw = ImageDraw.Draw(img)
        draw.rectangle([20, 20, 130, 130], fill=(200, 180, 150), outline=(0, 0, 0))
        draw.ellipse([40, 40, 60, 60], fill=(40, 40, 40))
        draw.ellipse([90, 40, 110, 60], fill=(40, 40, 40))
        draw.line([75, 65, 75, 85], fill=(80, 50, 50), width=2)
        draw.arc([50, 85, 100, 110], start=0, end=180, fill=(150, 50, 50), width=3)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
def test_setup(tmp_path, monkeypatch) -> Generator[tuple[TestClient, sessionmaker], None, None]:
    """Test client with isolated SQLite in-memory database."""
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
    app.include_router(evaluations_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as client:
        yield client, TestingSession


def _enroll_sample_subject(
    session: Session,
    subject_code: str,
    group: str,
    vectors: list[list[float]],
    model_name: str = "dlib-resnet-128d",
) -> Subject:
    """Helper to enroll a consented subject with synthetic embeddings."""
    sub = Subject(
        subject_code=subject_code,
        consent_status=ConsentStatus.GRANTED.value,
        consent_date="2026-11-20",
        purpose="evaluation",
        group=group,
    )
    session.add(sub)
    session.flush()

    for idx, vec in enumerate(vectors):
        img = SubjectImage(
            subject_id=sub.id,
            original_filename=f"{subject_code}_{idx}.png",
            input_hash=f"sha256:{subject_code}_{idx}",
            clean_hash=f"sha256:clean_{subject_code}_{idx}",
            storage_path=f"{sub.id}_{idx}.enc",
            width=150,
            height=150,
            detected_type="png",
        )
        session.add(img)
        session.flush()

        enc_token = encrypt_embedding(vec)
        emb = BiometricEmbedding(
            image_id=img.id,
            subject_id=sub.id,
            model_name=model_name,
            model_version="1.0.0",
            encrypted_embedding=enc_token,
            vector_dim=len(vec),
        )
        session.add(emb)

    session.commit()
    return sub


def test_threshold_evaluation_insufficient_data(test_setup):
    client, _ = test_setup
    res = client.post("/api/v1/evaluations/threshold", json={"model_name": "dlib-resnet-128d"})
    assert res.status_code == 400
    assert res.json()["error_code"] == "EVAL-INSUFFICIENT-DATA"


def test_threshold_evaluation_success(test_setup):
    client, SessionMaker = test_setup
    db = SessionMaker()

    # Generate distinct synthetic embeddings (128-d vectors)
    np.random.seed(42)
    # Subject 1 has 2 similar embeddings
    base_v1 = np.random.randn(128)
    v1_a = (base_v1 + np.random.randn(128) * 0.05).tolist()
    v1_b = (base_v1 + np.random.randn(128) * 0.05).tolist()

    # Subject 2 has 2 similar embeddings
    base_v2 = np.random.randn(128)
    v2_a = (base_v2 + np.random.randn(128) * 0.05).tolist()
    v2_b = (base_v2 + np.random.randn(128) * 0.05).tolist()

    _enroll_sample_subject(db, "SUB-001", "group_a", [v1_a, v1_b], model_name="dlib-resnet-128d")
    _enroll_sample_subject(db, "SUB-002", "group_b", [v2_a, v2_b], model_name="dlib-resnet-128d")
    db.close()

    res = client.post(
        "/api/v1/evaluations/threshold",
        json={"model_name": "dlib-resnet-128d", "threshold_steps": 25},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["model_name"] == "dlib-resnet-128d"
    assert data["total_genuine_pairs"] == 2  # 1 pair for sub 1 + 1 pair for sub 2
    assert data["total_impostor_pairs"] == 4  # 2x2 cross pairs
    assert len(data["roc_curve"]) == 25
    assert 0.0 <= data["eer"] <= 1.0
    assert data["decision"]["stage"] == "threshold"
    assert data["decision"]["status"] == "completed"

    # Verify audit record
    db = SessionMaker()
    audit_entry = db.query(AuditLog).filter(AuditLog.event == "EVALUATION_THRESHOLD_COMPLETED").first()
    assert audit_entry is not None
    assert audit_entry.event == "EVALUATION_THRESHOLD_COMPLETED"
    db.close()


def test_subgroup_bias_audit_success(test_setup):
    client, SessionMaker = test_setup
    db = SessionMaker()

    np.random.seed(123)
    # Group A: 2 subjects
    s1_a = np.random.randn(128).tolist()
    s1_b = (np.array(s1_a) + 0.05).tolist()
    s2_a = np.random.randn(128).tolist()
    s2_b = (np.array(s2_a) + 0.05).tolist()

    # Group B: 1 subject
    s3_a = np.random.randn(128).tolist()
    s3_b = (np.array(s3_a) + 0.05).tolist()

    _enroll_sample_subject(db, "SUB-GA-1", "male_20s", [s1_a, s1_b])
    _enroll_sample_subject(db, "SUB-GA-2", "male_20s", [s2_a, s2_b])
    _enroll_sample_subject(db, "SUB-GB-1", "female_20s", [s3_a, s3_b])
    db.close()

    res = client.post(
        "/api/v1/evaluations/bias",
        json={"model_name": "dlib-resnet-128d", "operating_threshold": 0.5},
    )
    assert res.status_code == 200
    data = res.json()

    assert len(data["subgroups"]) == 2
    groups = {s["group"] for s in data["subgroups"]}
    assert "male_20s" in groups
    assert "female_20s" in groups

    for s in data["subgroups"]:
        # Verify small sample warning triggers because N < 30
        assert s["warning"] is not None
        assert "low statistical confidence" in s["warning"]

    assert data["decision"]["stage"] == "subgroup"

    # Verify audit record
    db = SessionMaker()
    audit_entry = db.query(AuditLog).filter(AuditLog.event == "EVALUATION_BIAS_COMPLETED").first()
    assert audit_entry is not None
    db.close()


def test_liveness_endpoint_live_and_attack(test_setup):
    client, SessionMaker = test_setup

    # 1. Genuine clear face sample
    live_png = _create_synthetic_image(is_attack=False)
    res_live = client.post(
        "/api/v1/evaluations/liveness",
        files={"file": ("live.png", live_png, "image/png")},
    )
    assert res_live.status_code == 200
    data_live = res_live.json()
    assert data_live["status"] == "completed"
    assert data_live["score"] >= 0.7

    # 2. Presentation attack (blurry print replay)
    spoof_png = _create_synthetic_image(is_attack=True)
    res_spoof = client.post(
        "/api/v1/evaluations/liveness",
        files={"file": ("spoof.png", spoof_png, "image/png")},
    )
    assert res_spoof.status_code == 200
    data_spoof = res_spoof.json()
    assert "LIV-BLURRY" in data_spoof["rules_fired"]
    assert data_spoof["status"] in ("flagged", "rejected")

    # Verify audit record
    db = SessionMaker()
    audit_entries = db.query(AuditLog).filter(AuditLog.event == "EVALUATION_LIVENESS_COMPLETED").all()
    assert len(audit_entries) == 2
    db.close()


def test_list_evaluations_and_get_details(test_setup):
    client, _ = test_setup

    # Run liveness evaluation
    png = _create_synthetic_image()
    res = client.post("/api/v1/evaluations/liveness", files={"file": ("test.png", png, "image/png")})
    assert res.status_code == 200

    # List evaluations
    list_res = client.get("/api/v1/evaluations")
    assert list_res.status_code == 200
    runs = list_res.json()["items"]
    assert len(runs) >= 1

    run_id = runs[0]["id"]

    # Get specific evaluation run details
    detail_res = client.get(f"/api/v1/evaluations/{run_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == run_id
    assert len(detail["results"]) >= 1

    # Non-existent run
    not_found = client.get("/api/v1/evaluations/non-existent-id")
    assert not_found.status_code == 404
    assert not_found.json()["error_code"] == "NOT-FOUND"
