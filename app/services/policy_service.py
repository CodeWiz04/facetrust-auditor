"""Policy administration and configuration management service.

Provides:
- Least-privilege tunable validation via security engine
- Persistent versioned configuration storage
- Hash-chained audit logging of all parameter changes (CONFIG_CHANGED)
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import desc, select, update
from sqlalchemy.orm import Session

from app.core import audit
from app.core.time import utcnow
from app.models.policy import SystemPolicy
from app.schemas.policy import (
    ChangeRecord,
    PolicyResponse,
    PolicyUpdateResponse,
)
from engine.hashing import canonical_json, config_hash
from engine.policy import TUNABLES, load_default_config, update_config


def get_active_policy(
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
    config, cfg_hash, version, row = get_active_policy(db)
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
    current_config, current_hash, current_version, _ = get_active_policy(db)

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
