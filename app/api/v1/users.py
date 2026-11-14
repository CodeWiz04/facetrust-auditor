"""Administrator user management (role-based authorization demo)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_csrf, require_roles
from app.core import audit
from app.core.errors import AppError
from app.core.rate_limit import client_ip
from app.core.time import utcnow
from app.models.session import UserSession
from app.models.user import User, UserRole
from app.schemas.user import RoleUpdateRequest, UserListResponse, UserResponse

router = APIRouter(prefix="/users", tags=["users"])

_admin_only = require_roles(UserRole.ADMIN.value)


def _active_admin_count(db: Session, excluding_user_id: str | None = None) -> int:
    query = select(func.count()).select_from(User).where(
        User.role == UserRole.ADMIN.value,
        User.is_active.is_(True),
    )
    if excluding_user_id is not None:
        query = query.where(User.id != excluding_user_id)
    return db.scalar(query) or 0


@router.get("", response_model=UserListResponse)
def list_users(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(_admin_only),
    db: Session = Depends(get_db),
) -> UserListResponse:
    """List accounts (administrators only)."""
    total = db.scalar(select(func.count()).select_from(User)) or 0
    rows = (
        db.execute(
            select(User).order_by(User.created_at.desc()).limit(limit).offset(offset)
        )
        .scalars()
        .all()
    )
    return UserListResponse(
        items=[UserResponse.model_validate(row) for row in rows], total=total
    )


@router.get("/{user_id}", response_model=UserResponse)
def get_user(
    user_id: str,
    _: User = Depends(_admin_only),
    db: Session = Depends(get_db),
) -> User:
    """Fetch one account (administrators only)."""
    user = db.get(User, user_id)
    if user is None:
        raise AppError("USER-NOT-FOUND", detail=f"user_id={user_id}")
    return user


@router.patch("/{user_id}/role", response_model=UserResponse)
def update_role(
    user_id: str,
    body: RoleUpdateRequest,
    request: Request,
    admin: User = Depends(_admin_only),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> User:
    """Change a user's role, refusing to remove the last administrator."""
    target = db.get(User, user_id)
    if target is None:
        raise AppError("USER-NOT-FOUND", detail=f"user_id={user_id}")

    new_role = body.role.value
    old_role = target.role
    if new_role == old_role:
        return target

    if old_role == UserRole.ADMIN.value and _active_admin_count(
        db, excluding_user_id=target.id
    ) == 0:
        raise AppError("USER-LAST-ADMIN", detail=f"user_id={target.id}")

    target.role = new_role
    target.updated_at = utcnow()
    audit.record(
        db,
        event="user.role_changed",
        actor_id=admin.id,
        actor_role=admin.role,
        ip=client_ip(request),
        payload={
            "target_user_id": target.id,
            "old_role": old_role,
            "new_role": new_role,
        },
    )
    return target


@router.post("/{user_id}/deactivate", response_model=UserResponse)
def deactivate_user(
    user_id: str,
    request: Request,
    admin: User = Depends(_admin_only),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> User:
    """Disable an account and revoke its sessions."""
    target = db.get(User, user_id)
    if target is None:
        raise AppError("USER-NOT-FOUND", detail=f"user_id={user_id}")
    if target.id == admin.id:
        raise AppError("USER-SELF-ACTION", detail="cannot deactivate self")

    if (
        target.role == UserRole.ADMIN.value
        and target.is_active
        and _active_admin_count(db, excluding_user_id=target.id) == 0
    ):
        raise AppError("USER-LAST-ADMIN", detail=f"user_id={target.id}")

    if target.is_active:
        target.is_active = False
        target.updated_at = utcnow()
        db.execute(
            update(UserSession)
            .where(
                UserSession.user_id == target.id,
                UserSession.revoked_at.is_(None),
            )
            .values(revoked_at=utcnow())
        )
        audit.record(
            db,
            event="user.deactivated",
            actor_id=admin.id,
            actor_role=admin.role,
            ip=client_ip(request),
            payload={"target_user_id": target.id},
        )
    return target
