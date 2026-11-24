"""Policy administration and configuration tuning endpoints (admin only)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_roles
from app.core.rate_limit import client_ip
from app.models.user import User, UserRole
from app.schemas.policy import PolicyResponse, PolicyUpdateRequest, PolicyUpdateResponse
from app.services import policy_service

router = APIRouter(prefix="/policy", tags=["policy"])

_admins_only = require_roles(UserRole.ADMIN.value)


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
