"""Policy administration and configuration tuning endpoints (admin only)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_roles
from app.core.rate_limit import client_ip
from app.models.user import User, UserRole
from app.schemas.policy import (
    PolicyHistoryResponse,
    PolicyResponse,
    PolicyUpdateRequest,
    PolicyUpdateResponse,
)
from app.services import policy_service

router = APIRouter(prefix="/policy", tags=["policy"])

_admins_only = require_roles(UserRole.ADMIN.value)
_readers = require_roles(UserRole.ADMIN.value, UserRole.AUDITOR.value)


@router.get(
    "",
    response_model=PolicyResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current active system policy configuration",
)
def get_policy(
    _: User = Depends(_admins_only),
    db: Session = Depends(get_db),
) -> PolicyResponse:
    """Return the current active policy config, its cryptographic hash, and permitted tunables."""
    return policy_service.get_policy_response(db)


@router.patch(
    "",
    response_model=PolicyUpdateResponse,
    status_code=status.HTTP_200_OK,
    summary="Update permitted evaluation policy parameters (admin only)",
)
def update_policy(
    payload: PolicyUpdateRequest,
    request: Request,
    actor: User = Depends(_admins_only),
    db: Session = Depends(get_db),
) -> PolicyUpdateResponse:
    """Apply validated policy configuration changes. Only allow-listed keys can be modified."""
    ip = client_ip(request)
    return policy_service.update_system_policy(
        db=db,
        changes=payload.changes,
        actor_id=actor.id,
        actor_role=actor.role,
        ip=ip,
    )


@router.get(
    "/history",
    response_model=PolicyHistoryResponse,
    status_code=status.HTTP_200_OK,
    summary="List system policy version history (admin/auditor)",
)
def get_policy_history(
    limit: int = Query(default=50, ge=1, le=200, description="Maximum number of policy versions to return"),
    _: User = Depends(_readers),
    db: Session = Depends(get_db),
) -> PolicyHistoryResponse:
    """Return ordered system policy version history for audit review."""
    return policy_service.get_policy_history(db=db, limit=limit)
