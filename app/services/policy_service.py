"""Policy administration and configuration management service."""

from __future__ import annotations

import json
from typing import Any, Iterable

from sqlalchemy import desc, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core import audit
from app.core.errors import AppError
from app.core.time import utcnow
from app.models.policy import PolicyVersion, SystemPolicy
from app.schemas.policy import (
    ChangeRecord,
    PolicyResponse,
    PolicyUpdateResponse,
)
from engine.errors import EngineError
from engine.hashing import canonical_json, config_hash
from engine.policy import TUNABLES, load_default_config, update_config, validate_config

# FR-3 endpoints may only change these keys. Liveness / subgroup settings
# belong to other modules and keep their own admin flow.
THRESHOLD_KEYS = frozenset({"match_threshold", "target_far"})


def get_active_system_policy(
    db: Session,
) -> tuple[dict[str, Any], str, int, SystemPolicy | None]:
    """Retrieve active system policy configuration, cryptographic hash, and version.

    If no policy has been stored yet, initializes the genesis policy from defaults.
    """
    row = db.scalar(
        select(SystemPolicy)
        .where(SystemPolicy.is_active == True)  # noqa: E712
        .order_by(desc(SystemPolicy.config_version))
    )

    if row:
        cfg = json.loads(row.config_json)
        return cfg, row.config_hash, row.config_version, row

    # Initialize genesis default policy in the database
    default_cfg = load_default_config()
    default_hash = config_hash(default_cfg)
    genesis_policy = SystemPolicy(
        config_version=default_cfg.get("config_version", 1),
        config_hash=default_hash,
        config_json=canonical_json(default_cfg),
        changes_json="[]",
        is_active=True,
        applied_by="system-genesis",
        applied_at=utcnow(),
    )
    db.add(genesis_policy)
    db.flush()

    return default_cfg, default_hash, genesis_policy.config_version, genesis_policy


def get_policy_response(db: Session) -> PolicyResponse:
    """Return the current active policy configuration and permitted tunables list."""
    config, cfg_hash, version, row = get_active_system_policy(db)
    return PolicyResponse(
        config_version=version,
        config_hash=cfg_hash,
        config=config,
        tunables=sorted(list(TUNABLES.keys())),
        applied_by=row.applied_by if row else None,
        applied_at=row.applied_at if row else None,
    )


def update_system_policy(
    db: Session,
    changes: dict[str, Any],
    actor_id: str | None = None,
    actor_role: str | None = None,
    ip: str | None = None,
) -> PolicyUpdateResponse:
    """Validate, persist, and audit-log configuration modifications (admin only)."""
    current_config, current_hash, current_version, _ = get_active_system_policy(db)

    # 1. Security engine pure functional validation
    new_config, records = update_config(current_config, changes)

    # If nothing changed, return current state without version bump
    if not records:
        return PolicyUpdateResponse(
            config_version=current_version,
            config_hash=current_hash,
            changes=[],
            config=current_config,
            applied_by=actor_id,
            applied_at=utcnow(),
        )

    new_hash = config_hash(new_config)
    new_version = new_config.get("config_version", current_version + 1)
    applied_time = utcnow()

    # 2. Deactivate previous active policies
    db.execute(
        update(SystemPolicy)
        .where(SystemPolicy.is_active == True)  # noqa: E712
        .values(is_active=False)
    )

    # 3. Store new active policy version
    new_policy = SystemPolicy(
        config_version=new_version,
        config_hash=new_hash,
        config_json=canonical_json(new_config),
        changes_json=canonical_json(records),
        is_active=True,
        applied_by=actor_id,
        applied_at=applied_time,
    )
    db.add(new_policy)
    db.flush()

    # 4. Hash-chained audit event commitment
    audit.record(
        db,
        event="CONFIG_CHANGED",
        actor_id=actor_id,
        actor_role=actor_role,
        ip=ip,
        payload={
            "config_version": new_version,
            "config_hash": new_hash,
            "prev_hash": current_hash,
            "changes": records,
        },
    )

    change_items = [
        ChangeRecord(key=r["key"], old=r["old"], new=r["new"]) for r in records
    ]

    return PolicyUpdateResponse(
        config_version=new_version,
        config_hash=new_hash,
        changes=change_items,
        config=new_config,
        applied_by=actor_id,
        applied_at=applied_time,
    )


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
