"""FR-6 API tests: authorization, CSRF, validation, forensic deletion evidence, privacy, verification.

Uses the full app (conftest `client` / `api` fixtures).

Evaluation-case mapping:
  T6      Consent controls & permanent deletion -> test_admin_executes_confirmed_deletion,
                                                   test_withdrawn_consent_permanently_shredded
  T-final Malformed / unauthorized / safe failure -> test_unauthenticated_deletion_rejected,
                                                   test_missing_csrf_rejected,
                                                   test_auditor_cannot_delete_and_denial_audited,
                                                   test_unconfirmed_deletion_rejected,
                                                   test_rate_limit_on_deletion
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import get_settings
from app.core.crypto import encrypt_embedding
from app.db.session import SessionLocal
from app.models.audit import AuditLog
from app.models.dataset import BiometricEmbedding, ConsentStatus, Subject, SubjectImage
from tests.conftest import ApiHelper

ADMIN = "admin@example.com"
AUDITOR = "auditor@example.com"
ANALYST = "analyst@example.com"
MODEL = "synthetic-test-64d"


def seed_subject_with_biometrics(code: str = "SUB-DEL-001", num_images: int = 2) -> tuple[str, list[Path]]:
    """Helper: Seeds a subject with real encrypted image files on disk and embeddings in DB."""
    settings = get_settings()
    storage_root = Path(settings.storage_dir).resolve()
    storage_root.mkdir(parents=True, exist_ok=True)

    rng = np.random.default_rng(42)
    dim = 64
    created_paths = []

    with SessionLocal() as db:
        sub = Subject(
            subject_code=code,
            consent_status=ConsentStatus.GRANTED.value,
            consent_date="2026-11-01",
            purpose="evaluation",
            group="female_20s",
        )
        db.add(sub)
        db.flush()

        base_vec = rng.normal(size=dim).tolist()

        for k in range(num_images):
            # Create encrypted dummy file in storage_dir
            rel_path = f"{sub.id}_{k}.enc"
            disk_file = storage_root / rel_path
            disk_file.write_bytes(b"CIPHERTEXT_SIMULATED_ENCRYPTED_FACE_" * 100)
            created_paths.append(disk_file)

            img = SubjectImage(
                subject_id=sub.id,
                original_filename=f"face_{k}.png",
                input_hash=f"sha256:input_{code}_{k}",
                clean_hash=f"sha256:clean_{code}_{k}",
                storage_path=rel_path,
                width=160,
                height=160,
                detected_type="png",
            )
            db.add(img)
            db.flush()

            db.add(BiometricEmbedding(
                image_id=img.id,
                subject_id=sub.id,
                model_name=MODEL,
                model_version="1.0.0",
                encrypted_embedding=encrypt_embedding(base_vec),
                vector_dim=dim,
            ))

        db.commit()
        return sub.id, created_paths


def audit_events(event: str) -> list[dict]:
    with SessionLocal() as db:
        rows = db.scalars(
            select(AuditLog).where(AuditLog.event == event).order_by(AuditLog.seq)
        ).all()
        return [json.loads(r.payload_json) | {"_role": r.actor_role} for r in rows]


@pytest.fixture()
def admin(api: ApiHelper) -> ApiHelper:
    api.register_and_login(ADMIN)
    return api


# --------------------------------------------------------------------------- Authz & CSRF
def test_unauthenticated_deletion_rejected(client: TestClient):
    # Deletion execution
    r = client.post("/api/v1/deletion/subjects/sub-123", json={"confirm": True})
    assert r.status_code == 401
    assert r.json()["error_code"] == "AUTH-SESSION-INVALID"

    # History & receipts
    assert client.get("/api/v1/deletion/history").status_code == 401
    assert client.get(f"/api/v1/deletion/receipts/{'a'*64}").status_code == 401
    assert client.get(f"/api/v1/deletion/verify/{'a'*64}").status_code == 401


def test_missing_csrf_rejected(admin: ApiHelper):
    sub_id, _ = seed_subject_with_biometrics("SUB-CSRF-01")
    r = admin.client.post(f"/api/v1/deletion/subjects/{sub_id}", json={"confirm": True})
    assert r.status_code == 403
    assert r.json()["error_code"] == "AUTH-CSRF-INVALID"


def test_auditor_cannot_delete_and_denial_audited(admin: ApiHelper):
    sub_id, paths = seed_subject_with_biometrics("SUB-AUDITOR-DENY")

    created = admin.register(AUDITOR).json()
    r = admin.client.patch(
        f"/api/v1/users/{created['id']}/role",
        json={"role": "auditor"},
        headers=admin.csrf_headers(),
    )
    assert r.status_code == 200

    with TestClient(admin.client.app) as c:
        auditor = ApiHelper(c)
        assert auditor.login(AUDITOR).status_code == 200

        # Auditor cannot delete
        denied = auditor.client.post(
            f"/api/v1/deletion/subjects/{sub_id}",
            json={"confirm": True},
            headers=auditor.csrf_headers(),
        )
        assert denied.status_code == 403
        assert denied.json()["error_code"] == "AUTH-FORBIDDEN"

        # Auditor CAN view history
        hist = auditor.client.get("/api/v1/deletion/history")
        assert hist.status_code == 200

    # Verify physical files were untouched
    for p in paths:
        assert p.exists()

    # Check denial was audited
    denials = [e for e in audit_events("ACCESS_DENIED") if e.get("action") == "deletion.execute"]
    assert len(denials) >= 1


# --------------------------------------------------------------------------- Validation
def test_unconfirmed_deletion_rejected(admin: ApiHelper):
    sub_id, _ = seed_subject_with_biometrics("SUB-UNCONFIRMED")
    r = admin.client.post(
        f"/api/v1/deletion/subjects/{sub_id}",
        json={"confirm": False},
        headers=admin.csrf_headers(),
    )
    assert r.status_code == 422
    assert r.json()["error_code"] == "VALIDATION-FAILED"


def test_extra_fields_in_deletion_rejected(admin: ApiHelper):
    sub_id, _ = seed_subject_with_biometrics("SUB-EXTRA-FIELDS")
    r = admin.client.post(
        f"/api/v1/deletion/subjects/{sub_id}",
        json={"confirm": True, "unrecognized_field": "exploit"},
        headers=admin.csrf_headers(),
    )
    assert r.status_code == 422
    assert r.json()["error_code"] == "VALIDATION-FAILED"


def test_invalid_tombstone_hash_pattern_rejected(admin: ApiHelper):
    # Invalid hash format fails schema pattern validation (422)
    r = admin.client.get("/api/v1/deletion/receipts/not-a-valid-sha256-hash")
    assert r.status_code == 422
    assert r.json()["error_code"] == "VALIDATION-FAILED"

    # Path traversal attempt is safely handled without stack trace
    r2 = admin.client.get("/api/v1/deletion/receipts/..%2F..%2Fetc%2Fpasswd")
    assert r2.status_code in (404, 422)
    assert "Traceback" not in r2.text


def test_nonexistent_subject_deletion_returns_404_and_audits(admin: ApiHelper):
    r = admin.client.post(
        "/api/v1/deletion/subjects/phantom-nonexistent-id",
        json={"confirm": True},
        headers=admin.csrf_headers(),
    )
    assert r.status_code == 404
    assert r.json()["error_code"] == "NOT-FOUND"

    failures = audit_events("DELETION_FAILED")
    assert len(failures) >= 1
    assert failures[-1]["error_code"] == "NOT-FOUND"


# --------------------------------------------------------------------------- Execution & Forensic Erasure (FR-6, T6)
def test_admin_executes_confirmed_deletion(admin: ApiHelper):
    code = "SUB-VOLUNTEER-FORENSIC-01"
    sub_id, paths = seed_subject_with_biometrics(code, num_images=2)

    for p in paths:
        assert p.exists()

    # Admin executes privacy-preserving deletion
    r = admin.client.post(
        f"/api/v1/deletion/subjects/{sub_id}",
        json={"confirm": True, "reason": "Subject revoked biometric consent (FR-6, T6)"},
        headers=admin.csrf_headers(),
    )
    assert r.status_code == 200, r.text
    receipt = r.json()

    # 1. Receipt validation
    assert receipt["status"] == "verified_deleted"
    assert receipt["images_shredded"] == 2
    assert receipt["embeddings_destroyed"] == 2
    assert len(receipt["tombstone_hash"]) == 64
    assert len(receipt["subject_hash"]) == 64

    # 2. Decision and explainability validation
    assert receipt["decision"]["stage"] == "deletion"
    assert receipt["decision"]["status"] == "completed"
    assert receipt["decision"]["confidence"] == 1.0
    rules = receipt["rules_fired"]
    assert "DEL-CONFIRMED-SHRED" in rules
    assert "DEL-IMAGES-PURGED" in rules
    assert "DEL-EMBEDDINGS-PURGED" in rules
    assert "DEL-TOMBSTONE-VERIFIED" in rules
    assert any("forensically overwritten" in reason for reason in receipt["reasons"])

    # 3. Forensic physical destruction verified
    for p in paths:
        assert not p.exists()

    # 4. Database hard-deletion verified
    with SessionLocal() as db:
        assert db.scalar(select(Subject).where(Subject.id == sub_id)) is None
        assert db.scalar(select(SubjectImage).where(SubjectImage.subject_id == sub_id)) is None
        assert db.scalar(select(BiometricEmbedding).where(BiometricEmbedding.subject_id == sub_id)) is None

    # 5. Zero-PII audit record verified
    deletion_logs = audit_events("SUBJECT_PERMANENTLY_DELETED")
    assert len(deletion_logs) >= 1
    latest = deletion_logs[-1]
    assert latest["tombstone_hash"] == receipt["tombstone_hash"]
    assert latest["subject_hash"] == receipt["subject_hash"]
    assert latest["images_shredded"] == 2
    assert latest["embeddings_destroyed"] == 2

    # Verify no raw PII in audit log payload
    raw_payload_str = json.dumps(latest)
    assert code not in raw_payload_str
    assert "face_0.png" not in raw_payload_str


# --------------------------------------------------------------------------- Receipt Retrieval & Verification
def test_get_receipt_and_verify_tombstone(admin: ApiHelper):
    sub_id, _ = seed_subject_with_biometrics("SUB-RECEIPT-VERIFY", num_images=1)

    r = admin.client.post(
        f"/api/v1/deletion/subjects/{sub_id}",
        json={"confirm": True, "reason": "Audit verification test"},
        headers=admin.csrf_headers(),
    )
    assert r.status_code == 200
    tombstone = r.json()["tombstone_hash"]

    # 1. Retrieve receipt by tombstone hash
    rec_resp = admin.client.get(f"/api/v1/deletion/receipts/{tombstone}")
    assert rec_resp.status_code == 200
    fetched = rec_resp.json()
    assert fetched["tombstone_hash"] == tombstone
    assert fetched["status"] == "verified_deleted"
    assert fetched["images_shredded"] == 1

    # 2. Verify receipt against audit log
    verify_resp = admin.client.get(f"/api/v1/deletion/verify/{tombstone}")
    assert verify_resp.status_code == 200
    verification = verify_resp.json()
    assert verification["verified"] is True
    assert verification["tombstone_hash"] == tombstone
    assert verification["audit_seq"] is not None

    # 3. Nonexistent tombstone returns 404
    non_existent = "f" * 64
    missing_resp = admin.client.get(f"/api/v1/deletion/verify/{non_existent}")
    assert missing_resp.status_code == 404
    assert missing_resp.json()["error_code"] == "DEL-RECEIPT-NOT-FOUND"


def test_deletion_history_lists_events(admin: ApiHelper):
    seed_subject_with_biometrics("SUB-HIST-1", num_images=1)
    seed_subject_with_biometrics("SUB-HIST-2", num_images=1)

    admin.client.post(
        "/api/v1/deletion/subjects/SUB-HIST-1",
        json={"confirm": True},
        headers=admin.csrf_headers(),
    )
    admin.client.post(
        "/api/v1/deletion/subjects/SUB-HIST-2",
        json={"confirm": True},
        headers=admin.csrf_headers(),
    )

    hist_resp = admin.client.get("/api/v1/deletion/history")
    assert hist_resp.status_code == 200
    data = hist_resp.json()
    assert data["total"] >= 2
    assert len(data["items"]) >= 2
    assert all("tombstone_hash" in item for item in data["items"])
    assert all("subject_hash" in item for item in data["items"])


def test_rate_limit_on_deletion(admin: ApiHelper):
    # Attempting more than 10 deletions in rapid succession triggers 429
    codes = [
        admin.client.post(
            "/api/v1/deletion/subjects/phantom-rate-limit",
            json={"confirm": True},
            headers=admin.csrf_headers(),
        ).status_code
        for _ in range(12)
    ]
    # First 10 are 404 (subject not found), 11th and 12th are 429
    assert codes[:10] == [404] * 10
    assert codes[10] == 429
