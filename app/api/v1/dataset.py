"""Dataset and consent management API endpoints (FR-1)."""

from __future__ import annotations

from fastapi import (
    APIRouter,
    Depends,
    File,
    Query,
    Request,
    UploadFile,
    status,
)
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_csrf, require_roles_audited
from app.core.rate_limit import client_ip, enforce
from app.models.user import User, UserRole
from app.schemas.dataset import (
    ConsentWithdrawRequest,
    ImageListResponse,
    ImageUploadResponse,
    SubjectCreate,
    SubjectListResponse,
    SubjectResponse,
)
from app.services import dataset_service, policy_service
from engine.errors import EngineError

router = APIRouter(prefix="/dataset", tags=["dataset"])

ADMIN = UserRole.ADMIN.value
ANALYST = UserRole.ANALYST.value
AUDITOR = UserRole.AUDITOR.value

_can_create = require_roles_audited("dataset.create", ADMIN, ANALYST)
_can_upload = require_roles_audited("dataset.upload", ADMIN, ANALYST)
_can_withdraw = require_roles_audited("dataset.withdraw_consent", ADMIN, ANALYST)
_can_read = require_roles_audited("dataset.read", ADMIN, ANALYST, AUDITOR)


def _subject_to_response(subject) -> SubjectResponse:
    return SubjectResponse(
        id=subject.id,
        subject_code=subject.subject_code,
        consent_status=subject.consent_status,
        consent_date=subject.consent_date,
        purpose=subject.purpose,
        group=subject.group,
        created_at=subject.created_at,
        updated_at=subject.updated_at,
        image_count=len(subject.images) if subject.images else 0,
    )


@router.post(
    "/subjects",
    response_model=SubjectResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new consented subject",
)
def create_subject(
    payload: SubjectCreate,
    request: Request,
    user: User = Depends(_can_create),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> SubjectResponse:
    """Register a new volunteer subject with validated consent statement and subgroup labels."""
    enforce(request, "dataset.create", 30, 60, identity=user.id)
    ip = client_ip(request)
    subject = dataset_service.create_subject(
        db,
        payload=payload,
        actor_id=user.id,
        actor_role=user.role,
        ip=ip,
    )
    return _subject_to_response(subject)


@router.get(
    "/subjects",
    response_model=SubjectListResponse,
    summary="List registered subjects",
)
def list_subjects(
    group: str | None = Query(default=None, description="Filter by demographic group"),
    consent_status: str | None = Query(
        default=None, description="Filter by consent status (granted, withdrawn, revoked)"
    ),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    _: User = Depends(_can_read),
    db: Session = Depends(get_db),
) -> SubjectListResponse:
    """List consented subjects with demographic labels and consent status."""
    subjects, total = dataset_service.list_subjects(
        db, group=group, consent_status=consent_status, offset=offset, limit=limit
    )
    return SubjectListResponse(
        items=[_subject_to_response(s) for s in subjects],
        total=total,
    )


@router.get(
    "/subjects/{subject_id}",
    response_model=SubjectResponse,
    summary="Get subject by ID or subject code",
)
def get_subject(
    subject_id: str,
    _: User = Depends(_can_read),
    db: Session = Depends(get_db),
) -> SubjectResponse:
    """Retrieve details for a single consented subject."""
    subject = dataset_service.get_subject(db, subject_id)
    return _subject_to_response(subject)


@router.post(
    "/subjects/{subject_id}/images",
    response_model=ImageUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload face image for a consented subject",
)
async def upload_subject_image(
    subject_id: str,
    request: Request,
    file: UploadFile = File(..., description="JPEG or PNG face image"),
    user: User = Depends(_can_upload),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> ImageUploadResponse:
    """Ingest a face image: validates magic bytes, size, dimensions, pixel decode, EXIF strip, and encrypts at rest."""
    enforce(request, "dataset.upload", 30, 60, identity=user.id)
    
    cfg = policy_service.get_active_config(db)
    limits = cfg.get("limits", {})
    max_bytes = limits.get("max_image_bytes", 10_000_000)

    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > max_bytes:
                raise EngineError("FILE-TOO-LARGE", f"content-length {cl} exceeds max {max_bytes}")
        except ValueError:
            pass

    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise EngineError("FILE-TOO-LARGE", f"file bytes exceed max {max_bytes}")

    ip = client_ip(request)
    filename = file.filename or "uploaded_face.png"

    subject_image = dataset_service.ingest_subject_image(
        db=db,
        subject_id=subject_id,
        file_bytes=content,
        original_filename=filename,
        actor_id=user.id,
        actor_role=user.role,
        ip=ip,
    )
    return ImageUploadResponse.model_validate(subject_image)


@router.get(
    "/subjects/{subject_id}/images",
    response_model=ImageListResponse,
    summary="List images for a subject",
)
def list_subject_images(
    subject_id: str,
    _: User = Depends(_can_read),
    db: Session = Depends(get_db),
) -> ImageListResponse:
    """List all encrypted face images enrolled for the specified subject."""
    subject = dataset_service.get_subject(db, subject_id)
    images = subject.images
    return ImageListResponse(
        items=[ImageUploadResponse.model_validate(img) for img in images],
        total=len(images),
    )


@router.post(
    "/subjects/{subject_id}/withdraw-consent",
    response_model=SubjectResponse,
    summary="Withdraw subject consent",
)
def withdraw_consent(
    subject_id: str,
    payload: ConsentWithdrawRequest,
    request: Request,
    user: User = Depends(_can_withdraw),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> SubjectResponse:
    """Withdraw a subject's consent to prevent further processing or image collection."""
    enforce(request, "dataset.withdraw_consent", 10, 60, identity=user.id)
    ip = client_ip(request)
    subject = dataset_service.withdraw_consent(
        db,
        subject_id=subject_id,
        reason=payload.reason,
        actor_id=user.id,
        actor_role=user.role,
        ip=ip,
    )
    return _subject_to_response(subject)
