"""Versioned, append-only security policy (FR-3 threshold configuration).

Every change to the matching threshold / target FAR creates a NEW row; rows
are never updated or deleted. The active policy is the row with the highest
`version`. Together with the CONFIG_CHANGED audit event this makes every
threshold change traceable: who, when, why, old -> new, and (optionally)
which evaluation run provided the evidence.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.time import utcnow
from app.db.base import Base


class PolicyVersion(Base):
    __tablename__ = "policy_versions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    version: Mapped[int] = mapped_column(
        Integer, unique=True, index=True, nullable=False
    )
    config_json: Mapped[str] = mapped_column(Text, nullable=False)
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    changes_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    source_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False, index=True
    )