"""Pydantic schemas for threshold tuning, subgroup bias metrics, and liveness evaluations."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


MODEL_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
MODEL_VERSION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,31}$"


class ThresholdEvalRequest(BaseModel):
    """Parameters for running genuine/impostor threshold evaluation (FR-3, T1, T2).

    The ACTIVE threshold always comes from the stored policy (server side);
    the client cannot inject a threshold into the evidence.
    """

    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    model_name: str = Field(
        default="dlib-resnet-128d",
        pattern=MODEL_NAME_PATTERN,
        description="Biometric model whose stored embeddings are evaluated",
    )
    model_version: str | None = Field(
        default=None,
        pattern=MODEL_VERSION_PATTERN,
        description="Required only when embeddings from several versions exist",
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
        allow_inf_nan=False,
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


class OperatingPointOut(BaseModel):
    """Exact error rates at one threshold, with 95% Wilson confidence intervals."""

    threshold: float
    far: float
    frr: float
    far_ci95: list[float]
    frr_ci95: list[float]
    false_accepts: int
    false_rejects: int
    genuine_pairs: int
    impostor_pairs: int


class FiredRuleOut(BaseModel):
    rule: str
    severity: str
    reason: str


class ThresholdEvalResponse(BaseModel):
    """Result of genuine vs. impostor threshold tuning and error rate analysis.

    The first block of fields is unchanged from the original endpoint, so
    existing clients keep working. FR-3 adds the explainability fields below.
    """

    run_id: str
    model_name: str
    model_version: str
    config_hash: str
    operating_threshold: float          # = recommended threshold
    far_at_threshold: float
    frr_at_threshold: float
    eer: float
    eer_threshold: float
    total_genuine_pairs: int
    total_impostor_pairs: int
    roc_curve: list[RocPoint]
    decision: dict[str, Any] | None = None
    created_at: datetime

    # ---- FR-3 explainability / evidence ----
    status: Literal["completed", "rejected", "flagged"] = "completed"
    severity: str = "info"
    confidence: float | None = None
    rules_fired: list[str] = Field(default_factory=list)
    rules: list[FiredRuleOut] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    recommended_action: str = ""
    policy_version: int | None = None
    target_far: float | None = None
    target_met: bool | None = None
    target_band: list[float] = Field(default_factory=list)
    active: OperatingPointOut | None = None
    recommended: OperatingPointOut | None = None
    genuine_summary: dict[str, float | int] = Field(default_factory=dict)
    impostor_summary: dict[str, float | int] = Field(default_factory=dict)
    d_prime: float | None = None
    subjects: int | None = None
    embeddings: int | None = None
    impostor_pairs_total: int | None = None
    impostor_sampled: bool = False
    engine_version: str | None = None

    model_config = ConfigDict(from_attributes=True, protected_namespaces=())


class SubgroupBiasRequest(BaseModel):
    """Parameters for running demographic subgroup bias evaluation (FR-4, T5)."""

    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    model_name: str = Field(
        default="dlib-resnet-128d",
        pattern=MODEL_NAME_PATTERN,
        description="Biometric model to audit for bias",
    )
    model_version: str | None = Field(
        default=None,
        pattern=MODEL_VERSION_PATTERN,
        description="Required only when embeddings from several versions exist",
    )
    operating_threshold: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        allow_inf_nan=False,
        description="Threshold at which to compute demographic error rates (defaults to policy)",
    )


class SubgroupMetricItem(BaseModel):
    """Performance metrics for a specific demographic subgroup."""

    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    group: str
    sample_count: int | None = None
    subjects: int | None = None
    embeddings: int | None = None
    status: str = "ok"
    eligible: bool = True
    genuine_pairs: int = 0
    impostor_pairs: int = 0
    cross_pairs: int = 0
    impostor_sampled: bool = False
    cross_sampled: bool = False
    far: float | None = None
    frr: float | None = None
    far_ci95: list[float] | None = None
    frr_ci95: list[float] | None = None
    false_accepts: int | None = None
    false_rejects: int | None = None
    far_cross: float | None = None
    far_cross_ci95: list[float] | None = None
    group_threshold_for_target: float | None = None
    d_prime: float | None = None
    genuine_summary: dict[str, Any] = Field(default_factory=dict)
    impostor_summary: dict[str, Any] = Field(default_factory=dict)
    warning: str | None = None


class SubgroupBiasResponse(BaseModel):
    """Comprehensive demographic bias audit report with disparity measures."""

    run_id: str
    model_name: str
    model_version: str | None = None
    config_hash: str | None = None
    policy_version: int | None = None
    operating_threshold: float
    threshold_source: str | None = None
    target_far: float | None = None
    min_group_n: int | None = None

    status: Literal["completed", "rejected", "flagged"] = "completed"
    severity: str = "info"
    confidence: float | None = None
    rules_fired: list[str] = Field(default_factory=list)
    rules: list[dict[str, Any]] | list[FiredRuleOut] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    recommended_action: str = ""

    subgroups: list[SubgroupMetricItem]
    max_far_gap: float
    max_frr_gap: float
    disparity_ratio: float | None = None
    far_disparity_ratio: float | None = None
    frr_comparison: dict[str, Any] | None = None
    far_comparison: dict[str, Any] | None = None
    eligible_groups: list[str] = Field(default_factory=list)
    suppressed_groups: int = 0
    engine_version: str | None = None

    summary: str
    decision: dict[str, Any] | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True, protected_namespaces=())


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