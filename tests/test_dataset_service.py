import io
from datetime import date
from pathlib import Path
import pytest
from PIL import Image
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.crypto import generate_biometric_key, set_active_key
from app.core.errors import AppError
from app.db.base import Base
from app.models.audit import AuditLog
from app.models.dataset import ConsentStatus, Subject, SubjectImage
from app.schemas.dataset import SubjectCreate
from app.services.dataset_service import (
    create_subject,
    get_decrypted_image,
    get_subject,
    ingest_subject_image,
    list_subjects,
    withdraw_consent,
)
from engine.dataset_validator import PNG_MAGIC
from engine.errors import EngineError


@pytest.fixture(scope="module")
def sample_png_bytes() -> bytes:
    """Generate a valid, deterministic 150x150 RGB PNG image in memory."""
    img = Image.new("RGB", (150, 150), color=(100, 150, 200))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
def db_session(tmp_path, monkeypatch):
    """Isolated in-memory database and temporary storage root."""
    test_key = generate_biometric_key()
    set_active_key(test_key)

    storage_root = tmp_path / "storage"
    storage_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(get_settings(), "storage_dir", str(storage_root))

    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = TestingSession()

    yield session

    session.close()
    Base.metadata.drop_all(bind=engine)
    set_active_key(None)


def test_create_subject_with_valid_consent(db_session: Session):
    payload = SubjectCreate(
        subject_code="sub_alice_01",
        consent_given=True,
        consent_date=str(date.today()),
        purpose="evaluation",
        group="female_20s_fair",
    )
    subject = create_subject(db_session, payload, actor_id="admin_1")

    assert subject.id is not None
    assert subject.subject_code == "sub_alice_01"
    assert subject.consent_status == ConsentStatus.GRANTED.value
    assert subject.purpose == "evaluation"
    assert subject.group == "female_20s_fair"

    # Verify audit log entry was created
    audit_entry = db_session.scalar(
        select(AuditLog).where(AuditLog.event == "SUBJECT_REGISTERED")
    )
    assert audit_entry is not None
    assert audit_entry.actor_id == "admin_1"


def test_create_subject_duplicate_code_rejected(db_session: Session):
    payload = SubjectCreate(
        subject_code="sub_duplicate",
        consent_given=True,
        consent_date=str(date.today()),
        purpose="evaluation",
        group="male_30s",
    )
    create_subject(db_session, payload)

    with pytest.raises(EngineError) as exc_info:
        create_subject(db_session, payload)
    assert exc_info.value.code == "CON-INVALID"


def test_ingest_image_stores_encrypted_at_rest(
    db_session: Session, sample_png_bytes: bytes, tmp_path
):
    payload = SubjectCreate(
        subject_code="sub_bob_02",
        consent_given=True,
        consent_date=str(date.today()),
        purpose="threshold_tuning",
        group="male_20s",
    )
    subject = create_subject(db_session, payload)

    image_record = ingest_subject_image(
        db=db_session,
        subject_id=subject.id,
        file_bytes=sample_png_bytes,
        original_filename="portrait.png",
        actor_id="operator_bob",
    )

    assert image_record.id is not None
    assert image_record.subject_id == subject.id
    assert image_record.width == 150
    assert image_record.height == 150
    assert image_record.clean_hash.startswith("sha256:")

    # Verify storage file is encrypted: must NOT start with PNG magic bytes!
    storage_file = Path(get_settings().storage_dir) / image_record.storage_path
    assert storage_file.exists()
    raw_stored_bytes = storage_file.read_bytes()
    assert not raw_stored_bytes.startswith(PNG_MAGIC)

    # Verify decryption restores original clean image bytes
    decrypted_bytes = get_decrypted_image(image_record)
    assert decrypted_bytes.startswith(PNG_MAGIC)

    # Verify biometric embedding row was generated and encrypted
    assert len(image_record.embeddings) == 1
    assert image_record.embeddings[0].vector_dim == 128
    assert len(image_record.embeddings[0].encrypted_embedding) > 0


def test_ingest_image_fails_if_consent_withdrawn(
    db_session: Session, sample_png_bytes: bytes
):
    payload = SubjectCreate(
        subject_code="sub_withdrawn",
        consent_given=True,
        consent_date=str(date.today()),
        purpose="evaluation",
        group="female_40s",
    )
    subject = create_subject(db_session, payload)

    # Withdraw consent
    withdraw_consent(db_session, subject.id, reason="Volunteer opted out")

    # Ingestion attempt must fail closed
    with pytest.raises(EngineError) as exc_info:
        ingest_subject_image(
            db=db_session,
            subject_id=subject.id,
            file_bytes=sample_png_bytes,
            original_filename="blocked.png",
        )
    assert exc_info.value.code == "CON-WITHDRAWN"


def test_ingest_image_rejects_corrupted_bytes(db_session: Session):
    payload = SubjectCreate(
        subject_code="sub_corrupt",
        consent_given=True,
        consent_date=str(date.today()),
        purpose="evaluation",
    )
    subject = create_subject(db_session, payload)

    with pytest.raises(EngineError) as exc_info:
        ingest_subject_image(
            db=db_session,
            subject_id=subject.id,
            file_bytes=b"This is not a real image at all",
            original_filename="bad.png",
        )
    assert exc_info.value.code == "FILE-TYPE-INVALID"


def test_list_and_get_subjects(db_session: Session):
    for i in range(3):
        create_subject(
            db_session,
            SubjectCreate(
                subject_code=f"sub_multi_{i}",
                consent_given=True,
                consent_date=str(date.today()),
                purpose="evaluation",
                group="group_a" if i < 2 else "group_b",
            ),
        )

    all_subjects, count = list_subjects(db_session)
    assert count == 3
    assert len(all_subjects) == 3

    group_a_subjects, a_count = list_subjects(db_session, group="group_a")
    assert a_count == 2
    assert len(group_a_subjects) == 2

    # Get by code and by id
    s0 = get_subject(db_session, "sub_multi_0")
    assert s0.subject_code == "sub_multi_0"
    s0_by_id = get_subject(db_session, s0.id)
    assert s0_by_id.id == s0.id


def test_get_subject_not_found_raises_app_error(db_session: Session):
    with pytest.raises(AppError) as exc_info:
        get_subject(db_session, "non_existent_id")
    assert exc_info.value.code == "NOT-FOUND"
    assert exc_info.value.status_code == 404


def test_get_decrypted_image_file_missing(db_session: Session, sample_png_bytes: bytes):
    payload = SubjectCreate(
        subject_code="sub_missing_file",
        consent_given=True,
        consent_date=str(date.today()),
        purpose="evaluation",
    )
    subject = create_subject(db_session, payload)
    img_rec = ingest_subject_image(
        db_session, subject.id, sample_png_bytes, "photo.png"
    )

    # Delete underlying file
    storage_file = Path(get_settings().storage_dir) / img_rec.storage_path
    if storage_file.exists():
        storage_file.unlink()

    with pytest.raises(AppError) as exc_info:
        get_decrypted_image(img_rec)
    assert exc_info.value.code == "NOT-FOUND"
    assert exc_info.value.status_code == 404


def test_get_dataset_summary_counts(db_session: Session, sample_png_bytes: bytes):
    from app.services.dataset_service import get_dataset_summary

    payload = SubjectCreate(
        subject_code="sub_summary_01",
        consent_given=True,
        consent_date=str(date.today()),
        purpose="evaluation",
        group="group_a",
    )
    subject = create_subject(db_session, payload)
    ingest_subject_image(db_session, subject.id, sample_png_bytes, "photo.png")

    summary = get_dataset_summary(db_session)
    assert summary["total_subjects"] >= 1
    assert summary["total_images"] >= 1
    assert summary["by_group"]["group_a"] >= 1
    assert summary["by_consent_status"]["granted"] >= 1
