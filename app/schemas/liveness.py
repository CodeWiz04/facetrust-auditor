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

