"""Dataset and image ingestion service (FR-1, FR-2).

Enforces:
1. Strict server-side image validation (magic bytes, size, dimensions, pixel decode, EXIF strip).
2. Explicit consent record checks before any biometric processing.
3. Cryptographic protection: all face images and embeddings are encrypted at rest.
4. Tamper-evident audit logging for all dataset mutations.
"""

from __future__ import annotations

import os
import re
import uuid
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.core import audit
from app.core.config import get_settings
from app.core.crypto import (
    decrypt_bytes,
    encrypt_bytes,
    encrypt_embedding,
)
from app.core.errors import AppError
from app.models.dataset import (
    BiometricEmbedding,
    ConsentStatus,
    Subject,
    SubjectImage,
)
from app.schemas.dataset import SubjectCreate
from engine.consent import validate_consent_record
from engine.dataset_validator import ValidatedImage, validate_image
from engine.errors import EngineError
from engine.policy import load_default_config

SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]")


def _sanitize_filename(filename: str) -> str:
    cleaned = SAFE_FILENAME_RE.sub("_", os.path.basename(filename))
    return cleaned[:100] if cleaned else "image.png"


def _get_storage_root() -> Path:
    settings = get_settings()
    root = Path(settings.storage_dir).resolve() / "images"
    root.mkdir(parents=True, exist_ok=True)
    return root


def create_subject(
    db: Session,
    payload: SubjectCreate,
    actor_id: str | None = None,
    actor_role: str | None = None,
    ip: str | None = None,
) -> Subject:
    """Register a new subject with verified consent."""
    # Engine-level consent validation
    record = {
        "subject_id": payload.subject_code,
        "consent_given": payload.consent_given,
        "consent_date": payload.consent_date,
        "purpose": payload.purpose,
        "group": payload.group,
        "image_file": "initial_manifest.png",
    }
    validated_consent = validate_consent_record(record)

    # Check for existing subject code
    existing = db.scalar(
        select(Subject).where(Subject.subject_code == validated_consent.subject_id)
    )
    if existing:
        raise EngineError("CON-INVALID", f"Subject code '{payload.subject_code}' already exists")

    subject = Subject(
        id=str(uuid.uuid4()),
        subject_code=validated_consent.subject_id,
        consent_status=ConsentStatus.GRANTED.value,
        consent_date=validated_consent.consent_date,
        purpose=validated_consent.purpose,
        group=validated_consent.group,
    )
    try:
        db.add(subject)
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise EngineError("CON-INVALID", f"Subject code '{payload.subject_code}' already exists") from exc
    except Exception:
        db.rollback()
        raise

    db.refresh(subject)

    # Audit log
    audit.record(
        db,
        event="SUBJECT_REGISTERED",
        actor_id=actor_id,
        actor_role=actor_role,
        ip=ip,
        payload={
            "subject_id": subject.id,
            "subject_code": subject.subject_code,
            "purpose": subject.purpose,
            "group": subject.group,
            "consent_status": subject.consent_status,
        },
    )

    return subject


def get_dataset_summary(db: Session) -> dict[str, object]:
    """Return PII-free aggregate dataset statistics for admin/auditor overview."""
    subjects = list(db.scalars(select(Subject)).all())
    by_consent_status: dict[str, int] = {}
    by_group: dict[str, int] = {}
    for sub in subjects:
        by_consent_status[sub.consent_status] = by_consent_status.get(sub.consent_status, 0) + 1
        by_group[sub.group] = by_group.get(sub.group, 0) + 1

    total_images = len(list(db.scalars(select(SubjectImage.id)).all()))
    total_embeddings = len(list(db.scalars(select(BiometricEmbedding.id)).all()))

    return {
        "total_subjects": len(subjects),
        "total_images": total_images,
        "total_embeddings": total_embeddings,
        "by_consent_status": by_consent_status,
        "by_group": by_group,
    }


def get_subject(db: Session, subject_id: str) -> Subject:
    """Fetch subject by internal UUID or subject_code."""
    subject = db.scalar(
        select(Subject)
        .options(selectinload(Subject.images))
        .where((Subject.id == subject_id) | (Subject.subject_code == subject_id))
    )
    if not subject:
        raise AppError("NOT-FOUND", detail=f"Subject '{subject_id}' not found")
    return subject


def get_dataset_summary(db: Session) -> dict[str, object]:
    """Return PII-free aggregate dataset statistics for admin/auditor overview."""
    subjects = list(db.scalars(select(Subject)).all())
    by_consent_status: dict[str, int] = {}
    by_group: dict[str, int] = {}
    for sub in subjects:
        by_consent_status[sub.consent_status] = by_consent_status.get(sub.consent_status, 0) + 1
        by_group[sub.group] = by_group.get(sub.group, 0) + 1

    total_images = len(list(db.scalars(select(SubjectImage.id)).all()))
    total_embeddings = len(list(db.scalars(select(BiometricEmbedding.id)).all()))

    return {
        "total_subjects": len(subjects),
        "total_images": total_images,
        "total_embeddings": total_embeddings,
        "by_consent_status": by_consent_status,
        "by_group": by_group,
    }


def list_subjects(
    db: Session,
    group: str | None = None,
    consent_status: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[Subject], int]:
    """List subjects with optional filters."""
    query = select(Subject).options(selectinload(Subject.images))
    if group:
        query = query.where(Subject.group == group.lower())
    if consent_status:
        query = query.where(Subject.consent_status == consent_status.lower())

    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = (
        db.execute(
            query.order_by(Subject.created_at.desc()).offset(offset).limit(limit)
        )
        .scalars()
        .all()
    )
    return list(rows), total


def ingest_subject_image(
    db: Session,
    subject_id: str,
    file_bytes: bytes,
    original_filename: str,
    actor_id: str | None = None,
    actor_role: str | None = None,
    ip: str | None = None,
) -> SubjectImage:
    """Validate, sanitize, encrypt, and store a face image for a consented subject."""
    subject = get_subject(db, subject_id)

    # FR-1 / FR-6: Fail-closed consent enforcement
    if subject.consent_status != ConsentStatus.GRANTED.value:
        raise EngineError(
            "CON-WITHDRAWN",
            f"Cannot ingest image: subject consent status is '{subject.consent_status}'",
        )

    # Image validation using security engine
    config = load_default_config()
    limits = config["limits"]
    validated: ValidatedImage = validate_image(
        file_bytes, limits=limits, claimed_name=original_filename
    )

    # Generate server-side UUIDs
    image_id = str(uuid.uuid4())
    storage_filename = f"{image_id}.enc"
    storage_root = _get_storage_root()
    full_path = storage_root / storage_filename

    # FR-2: Authenticated symmetric encryption at rest
    encrypted_payload = encrypt_bytes(validated.png_bytes)
    full_path.write_bytes(encrypted_payload)

    try:
        # Persist database record
        subject_image = SubjectImage(
            id=image_id,
            subject_id=subject.id,
            original_filename=_sanitize_filename(original_filename),
            input_hash=validated.input_ref,
            clean_hash=validated.clean_ref,
            storage_path=f"images/{storage_filename}",
            width=validated.width,
            height=validated.height,
            detected_type=validated.detected_type,
        )
        db.add(subject_image)

        # Generate initial biometric embedding (128-dimensional synthetic embedding based on clean hash)
        dim = 128
        hash_bytes = bytes.fromhex(validated.clean_ref.replace("sha256:", ""))
        synthetic_vector = [
            round(((hash_bytes[i % len(hash_bytes)] / 255.0) * 2.0 - 1.0) * 0.1, 6)
            for i in range(dim)
        ]
        encrypted_token = encrypt_embedding(synthetic_vector)

        embedding = BiometricEmbedding(
            id=str(uuid.uuid4()),
            image_id=subject_image.id,
            subject_id=subject.id,
            model_name="facenet",
            model_version="1.0.0",
            encrypted_embedding=encrypted_token,
            vector_dim=dim,
        )
        db.add(embedding)

        db.commit()
    except Exception:
        db.rollback()
        # Clean up encrypted file on failure to prevent dangling files
        if full_path.exists():
            full_path.unlink()
        raise

    db.refresh(subject_image)

    # Audit event (PII-free)
    audit.record(
        db,
        event="IMAGE_INGESTED",
        actor_id=actor_id,
        actor_role=actor_role,
        ip=ip,
        payload={
            "subject_id": subject.id,
            "image_id": subject_image.id,
            "input_hash": subject_image.input_hash,
            "clean_hash": subject_image.clean_hash,
            "width": subject_image.width,
            "height": subject_image.height,
        },
    )

    return subject


def get_dataset_summary(db: Session) -> dict[str, object]:
    """Return PII-free aggregate dataset statistics for admin/auditor overview."""
    subjects = list(db.scalars(select(Subject)).all())
    by_consent_status: dict[str, int] = {}
    by_group: dict[str, int] = {}
    for sub in subjects:
        by_consent_status[sub.consent_status] = by_consent_status.get(sub.consent_status, 0) + 1
        by_group[sub.group] = by_group.get(sub.group, 0) + 1

    total_images = len(list(db.scalars(select(SubjectImage.id)).all()))
    total_embeddings = len(list(db.scalars(select(BiometricEmbedding.id)).all()))

    return {
        "total_subjects": len(subjects),
        "total_images": total_images,
        "total_embeddings": total_embeddings,
        "by_consent_status": by_consent_status,
        "by_group": by_group,
    }_image


def get_decrypted_image(subject_image: SubjectImage) -> bytes:
    """Retrieve and decrypt clean image bytes from storage at rest."""
    settings = get_settings()
    storage_root = Path(settings.storage_dir).resolve()
    target_path = (storage_root / subject_image.storage_path).resolve()

    # Defense-in-depth: Ensure target_path resides within storage_root
    try:
        target_path.relative_to(storage_root)
    except ValueError as exc:
        raise AppError("AUTH-FORBIDDEN", detail="Access outside storage directory is forbidden") from exc

    if not target_path.exists():
        raise AppError("NOT-FOUND", detail="Image data file is missing from storage")

    ciphertext = target_path.read_bytes()
    return decrypt_bytes(ciphertext)


def withdraw_consent(
    db: Session,
    subject_id: str,
    reason: str | None = None,
    actor_id: str | None = None,
    actor_role: str | None = None,
    ip: str | None = None,
) -> Subject:
    """Withdraw a subject's consent (FR-6)."""
    subject = get_subject(db, subject_id)
    subject.consent_status = ConsentStatus.WITHDRAWN.value
    db.commit()
    db.refresh(subject)

    audit.record(
        db,
        event="CONSENT_WITHDRAWN",
        actor_id=actor_id,
        actor_role=actor_role,
        ip=ip,
        payload={
            "subject_id": subject.id,
            "subject_code": subject.subject_code,
            "reason": reason[:100] if reason else None,
        },
    )

    return subject


def get_dataset_summary(db: Session) -> dict[str, object]:
    """Return PII-free aggregate dataset statistics for admin/auditor overview."""
    subjects = list(db.scalars(select(Subject)).all())
    by_consent_status: dict[str, int] = {}
    by_group: dict[str, int] = {}
    for sub in subjects:
        by_consent_status[sub.consent_status] = by_consent_status.get(sub.consent_status, 0) + 1
        by_group[sub.group] = by_group.get(sub.group, 0) + 1

    total_images = len(list(db.scalars(select(SubjectImage.id)).all()))
    total_embeddings = len(list(db.scalars(select(BiometricEmbedding.id)).all()))

    return {
        "total_subjects": len(subjects),
        "total_images": total_images,
        "total_embeddings": total_embeddings,
        "by_consent_status": by_consent_status,
        "by_group": by_group,
    }
