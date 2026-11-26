"""FR-6 Privacy-Preserving Deletion API.

Roles (enforced on the server):

  action                                    admin  analyst  auditor
  ----------------------------------------  -----  -------  -------
  execute forensic deletion (high impact)     x
  read / verify deletion receipts             x       x        x
  view deletion history (zero PII)            x       x        x

Executing privacy deletion requires:
- Active administrator session
- Valid X-CSRF-Token header
- Explicit confirmation (`confirm: true`)
- Subject code / ID parameter

Denied attempts are recorded in the append-only audit log (ACCESS_DENIED)
and answered with a generic 403.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Path, Query, Request
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_csrf, require_roles_audited
from app.core.rate_limit import client_ip, enforce
from app.models.user import User, UserRole
from app.schemas.deletion import (
    DeletionHistoryItem,
    DeletionHistoryResponse,
    DeletionReceipt,
    DeletionVerifyResponse,
    SubjectDeletionRequest,
)
from app.services import deletion_service

router = APIRouter(prefix="/deletion", tags=["privacy deletion (FR-6)"])

ADMIN = UserRole.ADMIN.value
ANALYST = UserRole.ANALYST.value
AUDITOR = UserRole.AUDITOR.value

_can_execute = require_roles_audited("deletion.execute", ADMIN)
_can_read = require_roles_audited("deletion.read", ADMIN, ANALYST, AUDITOR)

DELETION_LIMIT, DELETION_WINDOW = 10, 60
TOMBSTONE_PATTERN = r"^[0-9a-f]{64}$"


@router.post(
    "/subjects/{subject_id}",
    response_model=DeletionReceipt,
    summary="Execute privacy-preserving forensic deletion of subject biometrics (FR-6, T6)",
)
def execute_deletion(
    subject_id: str,
    payload: SubjectDeletionRequest,
    request: Request,
    user: User = Depends(_can_execute),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> DeletionReceipt:
    """Forensically shred all images, destroy embeddings, purge database rows, and issue receipt."""
    enforce(request, "deletion.execute", DELETION_LIMIT, DELETION_WINDOW, identity=user.id)
    return deletion_service.execute_privacy_deletion(
        db=db,
        subject_id=subject_id,
        request_data=payload,
        actor_id=user.id,
        actor_role=user.role,
        ip=client_ip(request),
    )


@router.get(
    "/receipts/{tombstone_hash}",
    response_model=DeletionReceipt,
    summary="Retrieve verifiable cryptographic deletion receipt by tombstone hash",
)
def get_receipt(
    tombstone_hash: str = Path(..., pattern=TOMBSTONE_PATTERN),
    _: User = Depends(_can_read),
    db: Session = Depends(get_db),
) -> DeletionReceipt:
    """Retrieve immutable proof of data erasure from the audit log (zero PII)."""
    return deletion_service.get_deletion_receipt(db, tombstone_hash=tombstone_hash)


@router.get(
    "/verify/{tombstone_hash}",
    response_model=DeletionVerifyResponse,
    summary="Cryptographically verify a deletion receipt against the append-only audit trail",
)
def verify_receipt(
    tombstone_hash: str = Path(..., pattern=TOMBSTONE_PATTERN),
    _: User = Depends(_can_read),
    db: Session = Depends(get_db),
) -> DeletionVerifyResponse:
    """Verify that a deletion tombstone is intact and recorded in the cryptographic audit log."""
    res = deletion_service.verify_deletion_tombstone(db, tombstone_hash=tombstone_hash)
    return DeletionVerifyResponse(**res)


@router.get(
    "/history",
    response_model=DeletionHistoryResponse,
    summary="List privacy deletion audit history (zero PII)",
)
def list_history(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(_can_read),
    db: Session = Depends(get_db),
) -> DeletionHistoryResponse:
    """List historical privacy-preserving deletion records."""
    items, total = deletion_service.list_deletion_tombstones(db, limit=limit, offset=offset)
    return DeletionHistoryResponse(
        items=[DeletionHistoryItem(**i) for i in items],
        total=total,
    )
