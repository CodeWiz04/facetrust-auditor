"""FastAPI request dependencies (database session, current user, RBAC, CSRF)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError
from app.core.security import hash_token, tokens_equal
from app.core.time import utcnow
from app.db.session import get_db
from app.models.session import UserSession
from app.models.user import User, UserRole


def get_current_session(
    request: Request,
    db: Session = Depends(get_db),
) -> UserSession:
    """Resolve active server-side session from HttpOnly session cookie."""
    settings = get_settings()
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        # Check Authorization header bearer token fallback for CLI/testing
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]

    if not token:
        raise AppError("AUTH-SESSION-INVALID", detail="Missing session token")

    thash = hash_token(token)
    session = db.scalar(
        select(UserSession).where(
            UserSession.token_hash == thash,
            UserSession.revoked_at.is_(None),
        )
    )
    if not session or session.expires_at <= utcnow():
        raise AppError("AUTH-SESSION-INVALID", detail="Session is expired or revoked")

    # Update last seen timestamp
    session.last_seen_at = utcnow()
    db.commit()
    return session


def get_current_user(
    session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> User:
    """Return user owning the active session."""
    user = session.user
    if not user or not user.is_active:
        raise AppError("AUTH-ACCOUNT-DISABLED", detail="Account is disabled")
    return user


def require_roles(*allowed_roles: str) -> Callable[..., User]:
    """Dependency factory checking that current user possesses an allowed role."""

    def _role_checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise AppError("AUTH-FORBIDDEN", detail=f"Role '{user.role}' not permitted for this action")
        return user

    return _role_checker


def require_csrf(
    request: Request,
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    session: UserSession = Depends(get_current_session),
) -> None:
    """Enforce CSRF verification for state-modifying requests."""
    # Safe methods do not require CSRF token
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return

    if not x_csrf_token:
        raise AppError("AUTH-CSRF-INVALID", detail="Missing CSRF token header")

    if not tokens_equal(hash_token(x_csrf_token), session.csrf_hash):
        raise AppError("AUTH-CSRF-INVALID", detail="Invalid CSRF token")
