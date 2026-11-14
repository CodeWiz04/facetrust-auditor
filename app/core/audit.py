"""Hash-chained, append-only audit log.

Each entry commits to the previous entry's hash:

    entry_hash = SHA256(canonical_json({...entry fields..., "prev_hash": prev}))

Any modification, deletion, or reordering of stored entries breaks the chain
and is detected by `verify_chain()`.

The write lock serialises appends *and their commit* so the chain is
consistent within one process. For multi-worker deployments this table should
be written through a single worker (or a database advisory lock).
"""

from __future__ import annotations

import hmac
import json
import logging
import math
import threading
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.core.time import utc_iso, utcnow
from engine.hashing import canonical_json, sha256_hex

logger = logging.getLogger("facetrust.audit")

GENESIS_HASH = "0" * 64
_AUDIT_LOCK = threading.Lock()

# Never persist these keys, even if a caller passes them by mistake.
_REDACT_KEYS = {
    "password",
    "current_password",
    "new_password",
    "token",
    "session_token",
    "csrf_token",
    "authorization",
    "cookie",
    "secret",
    "secret_key",
    "biometric_encryption_key",
}


def sanitize(value: Any) -> Any:
    """Recursively redact secret-looking keys and non-finite numbers."""
    if isinstance(value, dict):
        return {
            str(key): (
                "[REDACTED]" if str(key).lower() in _REDACT_KEYS else sanitize(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _canonical_payload(payload: dict[str, Any] | None) -> str:
    return canonical_json(sanitize(payload or {}))


def compute_entry_hash(
    *,
    prev_hash: str,
    seq: int,
    event: str,
    actor_id: str | None,
    actor_role: str | None,
    ip: str | None,
    payload_json: str,
    created_at: datetime,
) -> str:
    material = {
        "prev_hash": prev_hash,
        "seq": seq,
        "event": event,
        "actor_id": actor_id,
        "actor_role": actor_role,
        "ip": ip,
        "payload": json.loads(payload_json),
        "created_at": utc_iso(created_at),
    }
    return sha256_hex(canonical_json(material))


def record(
    db: Session,
    *,
    event: str,
    actor_id: str | None = None,
    actor_role: str | None = None,
    ip: str | None = None,
    payload: dict[str, Any] | None = None,
    commit: bool = True,
) -> Any:
    """Append one audit entry.

    `commit=True` (default) commits the caller's pending changes together with
    the audit entry, making security events and business changes atomic.
    """
    from app.models.audit import AuditLog  # local import avoids a cycle

    payload_json = _canonical_payload(payload)

    # Imported here as well so `init_db` has the model registered.
    with _AUDIT_LOCK:
        last = db.execute(
            select(AuditLog).order_by(AuditLog.seq.desc()).limit(1)
        ).scalar_one_or_none()

        seq = (last.seq + 1) if last is not None else 1
        prev_hash = last.entry_hash if last is not None else GENESIS_HASH
        created_at = utcnow()

        entry = AuditLog(
            seq=seq,
            event=event,
            actor_id=actor_id,
            actor_role=actor_role,
            ip=ip,
            payload_json=payload_json,
            prev_hash=prev_hash,
            entry_hash="",
            created_at=created_at,
        )
        entry.entry_hash = compute_entry_hash(
            prev_hash=prev_hash,
            seq=seq,
            event=event,
            actor_id=actor_id,
            actor_role=actor_role,
            ip=ip,
            payload_json=payload_json,
            created_at=created_at,
        )
        db.add(entry)

        try:
            if commit:
                db.commit()
            else:
                db.flush()
        except Exception as exc:  # noqa: BLE001 - converted to a safe error
            db.rollback()
            logger.exception("audit_write_failed event=%s", event)
            raise AppError(
                "ENG-INTERNAL", detail="audit chain write failed"
            ) from exc

        return entry


def verify_chain(db: Session) -> dict[str, Any]:
    """Recompute the whole chain and report the first broken entry."""
    from app.models.audit import AuditLog

    rows = db.execute(select(AuditLog).order_by(AuditLog.seq)).scalars().all()

    prev_hash = GENESIS_HASH
    broken_at: int | None = None
    reason: str | None = None

    for index, row in enumerate(rows, start=1):
        if row.seq != index:
            broken_at, reason = row.seq, "sequence gap or reordering"
            break
        if not hmac.compare_digest(row.prev_hash, prev_hash):
            broken_at, reason = row.seq, "previous hash mismatch"
            break
        expected = compute_entry_hash(
            prev_hash=row.prev_hash,
            seq=row.seq,
            event=row.event,
            actor_id=row.actor_id,
            actor_role=row.actor_role,
            ip=row.ip,
            payload_json=row.payload_json,
            created_at=row.created_at,
        )
        if not hmac.compare_digest(expected, row.entry_hash):
            broken_at, reason = row.seq, "entry hash mismatch"
            break
        prev_hash = row.entry_hash

    return {
        "chain_ok": broken_at is None,
        "entries": len(rows),
        "broken_at": broken_at,
        "reason": reason,
        "head_hash": prev_hash,
    }
