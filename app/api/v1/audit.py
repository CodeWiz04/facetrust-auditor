"""Audit-log read and chain-verification endpoints (admin / auditor only)."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_roles
from app.core import audit
from app.models.audit import AuditLog
from app.models.user import User, UserRole
from app.schemas.audit import (
    AuditEventResponse,
    AuditListResponse,
    AuditVerifyResponse,
)

router = APIRouter(prefix="/audit", tags=["audit"])

_audit_readers = require_roles(UserRole.ADMIN.value, UserRole.AUDITOR.value)


def _payload(raw: str) -> dict:
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {"corrupt": True}


@router.get("/events", response_model=AuditListResponse)
def list_events(
    limit: int = Query(default=50, ge=1, le=500),
    after_seq: int = Query(default=0, ge=0),
    _: User = Depends(_audit_readers),
    db: Session = Depends(get_db),
) -> AuditListResponse:
    """List audit entries in chain order."""
    rows = (
        db.execute(
            select(AuditLog)
            .where(AuditLog.seq > after_seq)
            .order_by(AuditLog.seq)
            .limit(limit)
        )
        .scalars()
        .all()
    )
    items = [
        AuditEventResponse(
            seq=row.seq,
            event=row.event,
            actor_id=row.actor_id,
            actor_role=row.actor_role,
            ip=row.ip,
            payload=_payload(row.payload_json),
            prev_hash=row.prev_hash,
            entry_hash=row.entry_hash,
            created_at=row.created_at,
        )
        for row in rows
    ]
    return AuditListResponse(items=items)


@router.get("/verify", response_model=AuditVerifyResponse)
def verify(
    _: User = Depends(_audit_readers),
    db: Session = Depends(get_db),
) -> AuditVerifyResponse:
    """Recompute the hash chain and report the first broken entry."""
    return AuditVerifyResponse(**audit.verify_chain(db))
