"""Audit log response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class AuditEventResponse(BaseModel):
    seq: int
    event: str
    actor_id: str | None = None
    actor_role: str | None = None
    ip: str | None = None
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str
    created_at: datetime


class AuditListResponse(BaseModel):
    items: list[AuditEventResponse]


class AuditVerifyResponse(BaseModel):
    chain_ok: bool
    entries: int
    broken_at: int | None = None
    reason: str | None = None
    head_hash: str
