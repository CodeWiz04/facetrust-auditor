"""Schemas for the FR-3 threshold policy endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Printable text only (no control characters) - the reason is stored in the
# audit log and shown on the dashboard.
REASON_PATTERN = r"^[^\x00-\x1f\x7f]{5,500}$"


class PolicyChangeOut(BaseModel):
    key: str
    old: float | int
    new: float | int


class PolicyResponse(BaseModel):
    version: int
    config_hash: str
    match_threshold: float
    target_far: float
    changes: list[PolicyChangeOut] = Field(default_factory=list)
    reason: str | None = None
    source_run_id: str | None = None
    created_by: str | None = None
    created_at: datetime


class PolicyHistoryResponse(BaseModel):
    items: list[PolicyResponse]
    total: int


class PolicyUpdateRequest(BaseModel):
    """Administrator sets the threshold (and/or target FAR) directly."""

    model_config = ConfigDict(extra="forbid")

    match_threshold: float | None = Field(default=None, ge=-1.0, le=1.0, allow_inf_nan=False)
    target_far: float | None = Field(default=None, ge=0.0001, le=0.5, allow_inf_nan=False)
    reason: str = Field(pattern=REASON_PATTERN, description="Why the change is made (audited)")
    confirm: bool = Field(default=False, description="Must be true: high-impact action")
    expected_version: int | None = Field(
        default=None, ge=1, description="Optimistic lock: the version you are changing"
    )

    @model_validator(mode="after")
    def _at_least_one(self) -> "PolicyUpdateRequest":
        if self.match_threshold is None and self.target_far is None:
            raise ValueError("provide match_threshold and/or target_far")
        return self

    def changes(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.match_threshold is not None:
            out["match_threshold"] = self.match_threshold
        if self.target_far is not None:
            out["target_far"] = self.target_far
        return out


class ApplyRecommendationRequest(BaseModel):
    """Administrator applies the recommended threshold from an evaluation run."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(pattern=REASON_PATTERN)
    confirm: bool = False
    acknowledge_low_confidence: bool = False
    expected_version: int | None = Field(default=None, ge=1)


class PolicyUpdateResponse(BaseModel):
    changed: bool
    policy: PolicyResponse
    changes: list[PolicyChangeOut] = Field(default_factory=list)


class ThresholdRunItem(BaseModel):
    """Row for the FR-3 history table / dashboard."""

    model_config = ConfigDict(protected_namespaces=())

    run_id: str
    model_name: str
    model_version: str
    created_at: datetime
    created_by: str | None = None
    status: str | None = None
    severity: str | None = None
    policy_version: int | None = None
    active_threshold: float | None = None
    recommended_threshold: float | None = None
    target_far: float | None = None
    target_met: bool | None = None
    far_at_active: float | None = None
    frr_at_active: float | None = None
    eer: float | None = None
    rules_fired: list[str] = Field(default_factory=list)


class ThresholdRunListResponse(BaseModel):
    items: list[ThresholdRunItem]
    total: int