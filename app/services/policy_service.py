"""Active security policy: load, verify, and change it with a full audit trail (FR-3).

- The policy lives in the append-only `policy_versions` table. On first use
  it is seeded from `engine/config/defaults.json` (CONFIG_INITIALIZED event).
- Every load re-hashes the stored JSON and compares it with the stored hash,
  so a hand-edited row is detected (CFG-INTEGRITY) instead of silently used.
- Changes go through `engine.policy.update_config()` (allow-list, type and
  range checks, consistency checks) and are written as a NEW version plus a
  CONFIG_CHANGED audit event in the same commit.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from sqlalchemy import desc, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core import audit
from app.core.errors import AppError
from app.core.time import utcnow
from app.models.policy import PolicyVersion
from engine.errors import EngineError
from engine.hashing import canonical_json, config_hash
from engine.policy import load_default_config, update_config, validate_config

# FR-3 endpoints may only change these keys. Liveness / subgroup settings
# belong to other modules and keep their own admin flow.
THRESHOLD_KEYS = frozenset({"match_threshold", "target_far"})


def _latest(db: Session) -> PolicyVersion | None:
    return db.scalar(select(PolicyVersion).order_by(desc(PolicyVersion.version)).limit(1))


def _seed(db: Session) -> PolicyVersion:
    config = load_default_config()
    row = PolicyVersion(
        version=int(config["config_version"]),
        config_json=canonical_json(config),
        config_hash=config_hash(config),
        changes_json="[]",
        reason="Initial policy loaded from engine/config/defaults.json",
        created_by=None,
        created_at=utcnow(),
    )
    db.add(row)
    try:
        audit.record(
            db,
            event="CONFIG_INITIALIZED",
            actor_id=None,
            actor_role="system",
            payload={"version": row.version, "config_hash": row.config_hash},
        )
    except AppError:
        # Another request seeded at the same moment (unique version) - use theirs.
        existing = _latest(db)
        if existing is None:
            raise
        return existing
    return row


def get_active_policy(db: Session) -> tuple[dict[str, Any], PolicyVersion]:
    """Return (validated config dict, its PolicyVersion row)."""
    row = _latest(db) or _seed(db)
    try:
        config = json.loads(row.config_json)
    except (TypeError, ValueError):
        raise AppError("CFG-INTEGRITY", detail=f"policy v{row.version} is not valid JSON")
    if config_hash(config) != row.config_hash:
        raise AppError("CFG-INTEGRITY", detail=f"policy v{row.version} hash mismatch")
    try:
        validate_config(config)
    except EngineError as exc:
        raise AppError("CFG-INTEGRITY", detail=f"policy v{row.version} invalid: {exc.code}")
    return config, row


def get_active_config(db: Session) -> dict[str, Any]:
    """Convenience for other modules (FR-4 / FR-5) that only need the dict."""
    return get_active_policy(db)[0]


def list_policy_versions(db: Session, limit: int = 50, offset: int = 0) -> tuple[list[PolicyVersion], int]:
    get_active_policy(db)  # make sure v1 exists
    rows = list(
        db.scalars(
            select(PolicyVersion).order_by(desc(PolicyVersion.version)).limit(limit).offset(offset)
        ).all()
    )
    total = len(list(db.scalars(select(PolicyVersion.id)).all()))
    return rows, total


def apply_changes(
    db: Session,
    *,
    changes: dict[str, Any],
    reason: str,
    actor_id: str,
    actor_role: str,
    ip: str | None,
    expected_version: int | None = None,
    source_run_id: str | None = None,
    allowed_keys: Iterable[str] = THRESHOLD_KEYS,
) -> tuple[PolicyVersion, list[dict[str, Any]]]:
    """Validate and apply changes. Returns (active row, change records).

    No-op changes (same values) return the current row and an empty list,
    so a repeated submission does not create duplicate versions.
    """
    config, current = get_active_policy(db)

    def _reject(code: str, detail: str) -> None:
        audit.record(
            db,
            event="CONFIG_CHANGE_REJECTED",
            actor_id=actor_id,
            actor_role=actor_role,
            ip=ip,
            payload={
                "error_code": code,
                "keys": sorted(str(k) for k in changes)[:10] if isinstance(changes, dict) else [],
                "version": current.version,
                "source_run_id": source_run_id,
            },
        )

    if expected_version is not None and expected_version != current.version:
        _reject("CFG-VERSION-CONFLICT", "stale expected_version")
        raise AppError(
            "CFG-VERSION-CONFLICT",
            detail=f"expected v{expected_version}, active v{current.version}",
        )

    allowed = frozenset(allowed_keys)
    unknown = [k for k in changes if k not in allowed]
    if unknown:
        _reject("CFG-UNKNOWN-KEY", "key outside FR-3 allow-list")
        raise EngineError("CFG-UNKNOWN-KEY", f"not changeable here: {unknown[:5]}")

    try:
        new_config, records = update_config(config, changes)
    except EngineError as exc:
        _reject(exc.code, exc.detail or "")
        raise

    if not records:
        return current, []

    row = PolicyVersion(
        version=int(new_config["config_version"]),
        config_json=canonical_json(new_config),
        config_hash=config_hash(new_config),
        changes_json=canonical_json(records),
        reason=reason,
        source_run_id=source_run_id,
        created_by=actor_id,
        created_at=utcnow(),
    )
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise AppError("CFG-VERSION-CONFLICT", detail="concurrent policy update")

    audit.record(
        db,
        event="CONFIG_CHANGED",
        actor_id=actor_id,
        actor_role=actor_role,
        ip=ip,
        payload={
            "module": "threshold_tuning",
            "version_from": current.version,
            "version_to": row.version,
            "config_hash_before": current.config_hash,
            "config_hash_after": row.config_hash,
            "changes": records,
            "reason": reason,
            "source_run_id": source_run_id,
        },
    )
    return row, records


def policy_to_dict(row: PolicyVersion, config: dict[str, Any] | None = None) -> dict[str, Any]:
    if config is None:
        config = json.loads(row.config_json)
    try:
        changes = json.loads(row.changes_json or "[]")
    except (TypeError, ValueError):
        changes = []
    return {
        "version": row.version,
        "config_hash": row.config_hash,
        "match_threshold": float(config["match_threshold"]),
        "target_far": float(config["target_far"]),
        "changes": changes,
        "reason": row.reason,
        "source_run_id": row.source_run_id,
        "created_by": row.created_by,
        "created_at": row.created_at,
    }