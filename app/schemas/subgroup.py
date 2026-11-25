"""Schemas for the FR-4 subgroup metrics endpoints (history, groups overview)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class GroupOverviewItem(BaseModel):
    group: str
    subjects: int | None = None   # null when suppressed (< 3 subjects)
    suppressed: bool = False


class GroupOverviewResponse(BaseModel):
    items: list[GroupOverviewItem]


class SubgroupRunItem(BaseModel):
    """Row for the FR-4 history table / dashboard."""

    model_config = ConfigDict(protected_namespaces=())

    run_id: str
    model_name: str
    model_version: str
    created_at: datetime
    created_by: str | None = None
    status: str | None = None
    severity: str | None = None
    policy_version: int | None = None
    operating_threshold: float | None = None
    threshold_source: str | None = None
    max_frr_gap: float | None = None
    max_far_gap: float | None = None
    subgroups_count: int | None = None
    rules_fired: list[str] = Field(default_factory=list)


class SubgroupRunListResponse(BaseModel):
    items: list[SubgroupRunItem]
    total: int