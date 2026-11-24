"""Pydantic schemas for threshold tuning, subgroup bias metrics, and liveness evaluations."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ThresholdEvalRequest(BaseModel):
    """Parameters for running genuine/impostor threshold evaluation (FR-3, T1, T2)."""

    model_name: str = Field(
        default="dlib-resnet-128d",
        description="Biometric model to evaluate",
    )
    threshold_steps: int = Field(
        default=50,
        ge=10,
        le=500,
        description="Number of discrete threshold steps to compute for ROC curve",
    )
    target_far: float | None = Field(
        default=None,
        ge=0.0001,
        le=0.5,
        description="Override target FAR (e.g. 0.01 for 1% FAR); defaults to policy setting",
    )


class RocPoint(BaseModel):
    """Single discrete threshold step in ROC and DET evaluation."""

    threshold: float
    far: float
    frr: float
    tpr: float
    genuine_matches: int
    impostor_matches: int


class ThresholdEvalResponse(BaseModel):
    """Result of genuine vs. impostor threshold tuning and error rate analysis."""

    run_id: str
    model_name: str
    model_version: str
    config_hash: str
    operating_threshold: float
    far_at_threshold: float
    frr_at_threshold: float
    eer: float
    eer_threshold: float
    total_genuine_pairs: int
    total_impostor_pairs: int
    roc_curve: list[RocPoint]
    decision: dict[str, Any] | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SubgroupBiasRequest(BaseModel):
    """Parameters for running demographic subgroup bias evaluation (FR-4, T5)."""

    model_name: str = Field(
        default="dlib-resnet-128d",
        description="Biometric model to audit for bias",
    )
    operating_threshold: float | None = Field(
        default=None,
        description="Threshold at which to compute demographic error rates (defaults to policy)",
    )


class SubgroupMetricItem(BaseModel):
    """Performance metrics for a specific demographic subgroup."""

    group: str
    sample_count: int
    genuine_pairs: int
    impostor_pairs: int
    far: float
    frr: float
    warning: str | None = None


class SubgroupBiasResponse(BaseModel):
    """Comprehensive demographic bias audit report with disparity measures."""

    run_id: str
    model_name: str
    operating_threshold: float
    subgroups: list[SubgroupMetricItem]
    max_far_gap: float
    max_frr_gap: float
    disparity_ratio: float | None = None
    summary: str
    decision: dict[str, Any] | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class LivenessCheckResponse(BaseModel):
    """Detailed result of presentation-attack / spoofing detection (FR-5, T4)."""

    decision_id: str
    status: Literal["completed", "rejected", "flagged"]
    outcome: str
    score: float
    threshold: float
    severity: str
    rules_fired: list[str]
    reasons: list[str]
    metrics: dict[str, float]
    latency_ms: float
    created_at: str


class EvaluationRunSummary(BaseModel):
    """High-level summary of a historical evaluation run."""

    id: str
    run_type: str
    model_name: str
    operating_threshold: float | None = None
    created_at: datetime
    created_by: str | None = None
    summary: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class EvaluationListResponse(BaseModel):
    """Paginated list of historical evaluation runs."""

    items: list[EvaluationRunSummary]
    total: int
