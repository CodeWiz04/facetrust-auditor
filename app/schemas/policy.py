"""Pydantic schemas for system policy administration and configuration tuning."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class PolicyUpdateRequest(BaseModel):
    """Admin request to tune permitted evaluation parameters (least privilege allow-list)."""

    changes: dict[str, Any] = Field(
        ...,
        description="Key-value pairs of permitted tunables to update (e.g. {'match_threshold': 0.55, 'target_far': 0.005})",
    )


class ChangeRecord(BaseModel):
    """Audit record of a single modified configuration key."""

    key: str
    old: Any
    new: Any


class PolicyResponse(BaseModel):
    """Current active policy configuration and cryptographic commitment."""

    config_version: int
    config_hash: str
    config: dict[str, Any]
    tunables: list[str]
    applied_by: str | None = None
    applied_at: datetime


class PolicyVersionSummary(BaseModel):
    """Summary of a single historical system policy version."""

    config_version: int
    config_hash: str
    changes: list[ChangeRecord]
    is_active: bool
    applied_by: str | None = None
    applied_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PolicyHistoryResponse(BaseModel):
    """Ordered list of system policy versions for audit review."""

    items: list[PolicyVersionSummary]
    total: int | None = None

    model_config = ConfigDict(from_attributes=True)


class PolicyUpdateResponse(BaseModel):
    """Result of policy update with audit change records."""

    config_version: int
    config_hash: str
    changes: list[ChangeRecord]
    config: dict[str, Any]
    applied_by: str | None = None
    applied_at: datetime


class PolicyVersionSummary(BaseModel):
    """Summary of a single historical system policy version."""

    config_version: int
    config_hash: str
    changes: list[ChangeRecord]
    is_active: bool
    applied_by: str | None = None
    applied_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PolicyHistoryResponse(BaseModel):
    """Ordered list of system policy versions for audit review."""

    items: list[PolicyVersionSummary]
    total: int
