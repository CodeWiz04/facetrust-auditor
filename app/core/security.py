"""Password hashing, opaque session tokens and CSRF tokens.

- Passwords are hashed with bcrypt (adaptive cost). Only the hash is stored.
- Session and CSRF tokens are random 256-bit values. The database stores only
  their SHA-256 hash, so a database leak does not expose usable tokens.
- All comparisons use constant-time helpers.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

import bcrypt

from app.core.config import get_settings
from app.core.errors import AppError

# bcrypt only uses the first 72 bytes of a password. Reject longer input
# instead of silently truncating it.
MAX_PASSWORD_BYTES = 72

# Verified against when the email is unknown, so login latency does not
# reveal whether an account exists.
_DUMMY_HASH = bcrypt.hashpw(b"facetrust-dummy-password", bcrypt.gensalt(rounds=10))

_WEAK_PASSWORDS = {
    "password",
    "password1",
    "password123",
    "123456789012",
    "qwertyuiop12",
    "letmein12345",
}


def validate_password(password: str) -> str:
    """Enforce the configured password policy; return the password unchanged."""
    if not isinstance(password, str):
        raise AppError("AUTH-PASSWORD-WEAK", detail="password is not a string")

    min_len = get_settings().password_min_length
    if len(password) < min_len:
        raise AppError(
            "AUTH-PASSWORD-WEAK",
            detail=f"password shorter than {min_len} characters",
        )
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise AppError(
            "AUTH-PASSWORD-TOO-LONG",
            detail=f"password exceeds {MAX_PASSWORD_BYTES} bytes",
        )
    if password.lower() in _WEAK_PASSWORDS:
        raise AppError("AUTH-PASSWORD-WEAK", detail="password is too common")
    if not any(ch.isalpha() for ch in password) or not any(
        ch.isdigit() for ch in password
    ):
        raise AppError(
            "AUTH-PASSWORD-WEAK",
            detail="password needs at least one letter and one digit",
        )
    return password


def hash_password(password: str) -> str:
    """Return a bcrypt hash (cost from settings)."""
    validate_password(password)
    rounds = get_settings().bcrypt_rounds
    return bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(rounds=rounds)
    ).decode("ascii")


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time password check; malformed hashes simply fail."""
    if not isinstance(password, str) or not isinstance(stored_hash, str):
        return False
    raw = password.encode("utf-8")
    if len(raw) > MAX_PASSWORD_BYTES:
        return False
    try:
        return bcrypt.checkpw(raw, stored_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


def burn_password_check(password: str) -> None:
    """Spend the same bcrypt cost for unknown accounts (anti-enumeration)."""
    raw = password.encode("utf-8")[:MAX_PASSWORD_BYTES] or b"x"
    bcrypt.checkpw(raw, _DUMMY_HASH)


def generate_token(nbytes: int = 32) -> str:
    """Opaque, URL-safe random token (default 256 bits)."""
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """SHA-256 hex digest used as the database lookup value for a token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_equal(left: str, right: str) -> bool:
    """Constant-time token comparison."""
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
