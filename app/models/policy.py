"""SQLAlchemy ORM model for versioned system policies and audit-traceable configurations."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.time import utcnow
from app.db.base import Base


class SystemPolicy(Base):
    """A versioned system policy snapshot with cryptographic hash commitment."""

    __tablename__ = "system_policies"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    config_version: Mapped[int] = mapped_column(Integer, unique=True, index=True, nullable=False)
    config_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    config_json: Mapped[str] = mapped_column(Text, nullable=False)
    changes_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    applied_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    applied_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False, index=True
    )
