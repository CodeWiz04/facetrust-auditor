"""Pydantic schemas for FR-5 basic liveness cue checks.

The response is intentionally evidence-only: hashes, cue metrics, rule IDs,
reasons, and the engine decision. Uploaded bytes and filenames are never
returned or stored.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class LivenessCueMetrics(BaseModel):
    """Numeric liveness cues produced by engine.liveness."""

    blur_variance: float
    hf_ratio: float
    glare_ratio: float
    mean_brightness: float
    attack_votes: float
    liveness_score: float


class LivenessCheckResponse(BaseModel):
    """Explainable result of a basic liveness / presentation-attack check."""

    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    decision_id: str
    status: Literal["completed", "rejected", "flagged"]
    result: Literal["genuine", "suspicious", "invalid"]
    outcome: str
    score: float
    threshold: float
    severity: str
    confidence: float | None = None

    rules_fired: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    recommended_action: str

    metrics: LivenessCueMetrics

    # Privacy-safe references only. Never include filename, bytes, EXIF, or path.
    input_ref: str
    clean_ref: str
    detected_type: str
    width: int
    height: int

    config_hash: str
    model: str
    model_version: str
    engine_version: str
    latency_ms: float
    created_at: str
