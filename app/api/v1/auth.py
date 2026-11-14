"""Authentication: registration, login, sessions, logout and password change."""

from __future__ import annotations

import hashlib
from datetime import timedelta

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import (
    get_current_session,
    get_current_user,
    get_db,
    require_csrf,
)
from app.core import audit
from app.core.config import Settings, get_settings
from app.core.errors import AppError
from app.core.rate_limit import client_ip, login_rate_limit, register_rate_limit
from app.core.security import (
    burn_password_check,
    generate_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.core.time import utcnow
from app.models.session import UserSession
from app.models.user import User, UserRole
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    SessionListResponse,
    SessionResponse,
)
from app.schemas.user import UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])


def _email_fingerprint(email: str) -> str:
    """Non-reversible identifier for audit logs (no raw PII in the chain)."""
    return hashlib.sha256(email.encode("utf-8")).hexdigest()[:16]


def _set_auth_cookies(
    response: Response, token: str, csrf_token: str, max_age: int
) -> None:
    settings = get_settings()
    common = {
        "max_age": max_age,
        "secure": settings.cookie_secure,
        "samesite": settings.cookie_samesite,
        "path": "/",
    }
    response.set_cookie(
        settings.session_cookie_name, token, httponly=True, **common
    )
    # Readable by the frontend so it can echo it in the X-CSRF-Token header.
    response.set_cookie(
        settings.csrf_cookie_name, csrf_token, httponly=False, **common
    )


def _clear_auth_cookies(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        settings.session_cookie_name,
        path="/",
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
    )
    response.delete_cookie(
        settings.csrf_cookie_name,
        path="/",
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
    )


def _session_ttl_seconds(settings: Settings) -> int:
    return settings.session_ttl_minutes * 60


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=201,
    dependencies=[Depends(register_rate_limit)],
)
def register(
    body: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """Create an account.

    The very first account becomes an administrator when
    BOOTSTRAP_FIRST_USER_ADMIN is enabled; everyone else starts as analyst.
    """
    settings = get_settings()

    existing = db.execute(
        select(User).where(User.email == body.email)
    ).scalar_one_or_none()
    if existing is not None:
        raise AppError("USER-EXISTS")

    user_count = db.scalar(select(func.count()).select_from(User)) or 0
    is_bootstrap = user_count == 0 and settings.bootstrap_first_user_admin
    role = UserRole.ADMIN.value if is_bootstrap else UserRole.ANALYST.value

    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        role=role,
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise AppError("USER-EXISTS", detail="unique email race") from exc

    audit.record(
        db,
        event="user.registered",
        actor_id=user.id,
        actor_role=role,
        ip=client_ip(request),
        payload={"role": role, "bootstrap_admin": is_bootstrap},
    )
    return user


@router.post(
    "/login",
    response_model=LoginResponse,
    dependencies=[Depends(login_rate_limit)],
)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginResponse:
    """Verify credentials and start a server-side session."""
    settings = get_settings()
    now = utcnow()
    ip = client_ip(request)
    user = db.execute(
        select(User).where(User.email == body.email)
    ).scalar_one_or_none()

    if user is None:
        burn_password_check(body.password)
        audit.record(
            db,
            event="auth.login_failed",
            ip=ip,
            payload={
                "email_sha256": _email_fingerprint(body.email),
                "reason": "unknown_user",
            },
        )
        raise AppError("AUTH-INVALID-CREDENTIALS")

    if not user.is_active:
        audit.record(
            db,
            event="auth.login_failed",
            actor_id=user.id,
            actor_role=user.role,
            ip=ip,
            payload={"reason": "account_disabled"},
        )
        raise AppError("AUTH-ACCOUNT-DISABLED")

    if user.locked_until is not None and user.locked_until > now:
        audit.record(
            db,
            event="auth.login_failed",
            actor_id=user.id,
            actor_role=user.role,
            ip=ip,
            payload={"reason": "account_locked"},
        )
        raise AppError("AUTH-ACCOUNT-LOCKED")

    if not verify_password(body.password, user.password_hash):
        user.failed_login_count += 1
        locked = user.failed_login_count >= settings.login_max_failed_attempts
        if locked:
            user.locked_until = now + timedelta(
                minutes=settings.login_lockout_minutes
            )
        audit.record(
            db,
            event="auth.login_failed",
            actor_id=user.id,
            actor_role=user.role,
            ip=ip,
            payload={
                "reason": "bad_password",
                "failed_count": user.failed_login_count,
                "locked": locked,
            },
        )
        raise AppError("AUTH-INVALID-CREDENTIALS")

    # Successful login: reset lockout state and drop stale sessions.
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now

    db.execute(
        delete(UserSession).where(
            UserSession.user_id == user.id,
            or_(
                UserSession.expires_at <= now,
                UserSession.revoked_at.is_not(None),
            ),
        )
    )

    raw_token = generate_token()
    csrf_token = generate_token()
    expires_at = now + timedelta(minutes=settings.session_ttl_minutes)

    session = UserSession(
        user_id=user.id,
        token_hash=hash_token(raw_token),
        csrf_hash=hash_token(csrf_token),
        ip=ip,
        user_agent=(request.headers.get("user-agent") or "")[:500] or None,
        created_at=now,
        last_seen_at=now,
        expires_at=expires_at,
    )
    db.add(session)

    audit.record(
        db,
        event="auth.login_succeeded",
        actor_id=user.id,
        actor_role=user.role,
        ip=ip,
        payload={"session_id": session.id},
    )

    _set_auth_cookies(
        response,
        raw_token,
        csrf_token,
        max_age=_session_ttl_seconds(settings),
    )
    return LoginResponse(user=user, csrf_token=csrf_token, expires_at=expires_at)


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    session: UserSession = Depends(get_current_session),
    user: User = Depends(get_current_user),
    _: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Revoke the current session and clear cookies."""
    session.revoked_at = utcnow()
    audit.record(
        db,
        event="auth.logout",
        actor_id=user.id,
        actor_role=user.role,
        ip=client_ip(request),
        payload={"session_id": session.id},
    )
    _clear_auth_cookies(response)
    return {"status": "ok"}


@router.get("/me", response_model=UserResponse)
def me(user: User = Depends(get_current_user)) -> User:
    """Return the authenticated user."""
    return user


@router.get("/sessions", response_model=SessionListResponse)
def list_sessions(
    current: UserSession = Depends(get_current_session),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SessionListResponse:
    """List this user's live sessions."""
    rows = (
        db.execute(
            select(UserSession)
            .where(
                UserSession.user_id == user.id,
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > utcnow(),
            )
            .order_by(UserSession.created_at.desc())
        )
        .scalars()
        .all()
    )
    items = [
        SessionResponse.model_validate(row).model_copy(
            update={"current": row.id == current.id}
        )
        for row in rows
    ]
    return SessionListResponse(items=items)


@router.delete("/sessions/{session_id}")
def revoke_session(
    session_id: str,
    response: Response,
    session: UserSession = Depends(get_current_session),
    user: User = Depends(get_current_user),
    _: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Revoke one of the current user's sessions."""
    target = db.get(UserSession, session_id)
    if target is None or target.user_id != user.id:
        raise AppError("NOT-FOUND", detail=f"session_id={session_id}")

    if target.revoked_at is None:
        target.revoked_at = utcnow()
        audit.record(
            db,
            event="auth.session_revoked",
            actor_id=user.id,
            actor_role=user.role,
            payload={"session_id": target.id, "self": target.id == session.id},
        )

    if target.id == session.id:
        _clear_auth_cookies(response)
    return {"status": "ok"}


@router.post("/password")
def change_password(
    body: ChangePasswordRequest,
    request: Request,
    session: UserSession = Depends(get_current_session),
    user: User = Depends(get_current_user),
    _: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Change the password and revoke every other session."""
    if not verify_password(body.current_password, user.password_hash):
        raise AppError("AUTH-INVALID-CREDENTIALS", detail="wrong current password")
    if verify_password(body.new_password, user.password_hash):
        raise AppError("AUTH-PASSWORD-WEAK", detail="new password equals old password")

    user.password_hash = hash_password(body.new_password)
    db.execute(
        update(UserSession)
        .where(
            UserSession.user_id == user.id,
            UserSession.id != session.id,
            UserSession.revoked_at.is_(None),
        )
        .values(revoked_at=utcnow())
    )
    audit.record(
        db,
        event="auth.password_changed",
        actor_id=user.id,
        actor_role=user.role,
        ip=client_ip(request),
        payload={"other_sessions_revoked": True},
    )
    return {"status": "ok"}
