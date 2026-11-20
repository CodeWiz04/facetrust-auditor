"""Privacy-preserving deletion and right-to-be-forgotten service (FR-6, T6).

Enforces:
1. Complete physical and forensic destruction of stored encrypted face images.
2. Complete hard-deletion of biometric embeddings and relational links.
3. Creation of an immutable, PII-free cryptographic tombstone audit record.
4. Issuance of a verifiable deletion receipt.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, selectinload

from app.core import audit
from app.core.config import get_settings
from app.core.errors import AppError
from app.core.shredder import secure_shred_file, verify_file_deleted
from app.core.time import utc_iso, utcnow
from app.models.dataset import BiometricEmbedding, Subject, SubjectImage
from app.schemas.deletion import DeletionReceipt, SubjectDeletionRequest
from engine.errors import EngineError
from engine.hashing import canonical_json, sha256_hex


def execute_privacy_deletion(
    db: Session,
    subject_id: str,
    request_data: SubjectDeletionRequest | None = None,
    actor_id: str | None = None,
    actor_role: str | None = None,
    ip: str | None = None,
) -> DeletionReceipt:
    """Permanently shred all biometrics and purge records for a subject (FR-6)."""
    # 1. Fetch subject with all images and embeddings eager loaded
    subject = db.scalar(
        select(Subject)
        .options(
            selectinload(Subject.images).selectinload(SubjectImage.embeddings),
            selectinload(Subject.embeddings),
        )
        .where((Subject.id == subject_id) | (Subject.subject_code == subject_id))
    )
    if not subject:
        raise AppError("NOT-FOUND", detail=f"Subject '{subject_id}' not found")

    settings = get_settings()
    storage_root = Path(settings.storage_dir).resolve()

    images_to_shred = list(subject.images)
    shredded_count = 0
    embeddings_count = len(subject.embeddings)

    # 2. Forensically shred all physical encrypted image files from storage
    for img in images_to_shred:
        file_path = (storage_root / img.storage_path).resolve()
        if file_path.exists():
            shred_ok = secure_shred_file(file_path, passes=2)
            if not shred_ok or not verify_file_deleted(file_path):
                raise EngineError(
                    "DEL-VERIFY-FAILED",
                    f"Physical shredding could not be verified for image {img.id}",
                )
            shredded_count += 1
        else:
            # If already removed from disk, record as sanitized
            shredded_count += 1

    # 3. Create non-reversible cryptographic pseudonym hash of the subject code
    # This prevents any PII from remaining in logs while allowing proof of deletion
    subject_hash = sha256_hex(subject.subject_code)
    deleted_timestamp = utcnow()
    reason = request_data.reason if request_data else "Consent revoked / Right to be forgotten"

    tombstone_material = {
        "subject_hash": subject_hash,
        "images_shredded": shredded_count,
        "embeddings_destroyed": embeddings_count,
        "deleted_at": utc_iso(deleted_timestamp),
        "reason": reason[:100] if reason else None,
    }
    tombstone_hash = sha256_hex(canonical_json(tombstone_material))

    # 4. Hard-delete all DB entities associated with the subject
    db.execute(delete(BiometricEmbedding).where(BiometricEmbedding.subject_id == subject.id))
    db.execute(delete(SubjectImage).where(SubjectImage.subject_id == subject.id))
    db.execute(delete(Subject).where(Subject.id == subject.id))

    # 5. Record tamper-evident audit event (zero PII retained)
    audit.record(
        db,
        event="SUBJECT_PERMANENTLY_DELETED",
        actor_id=actor_id,
        actor_role=actor_role,
        ip=ip,
        payload={
            "subject_hash": subject_hash,
            "tombstone_hash": tombstone_hash,
            "images_shredded": shredded_count,
            "embeddings_destroyed": embeddings_count,
            "status": "verified_deleted",
        },
    )

    db.commit()

    # 6. Return verifiable deletion receipt
    return DeletionReceipt(
        subject_hash=subject_hash,
        status="verified_deleted",
        images_shredded=shredded_count,
        embeddings_destroyed=embeddings_count,
        tombstone_hash=tombstone_hash,
        deleted_at=deleted_timestamp,
    )
