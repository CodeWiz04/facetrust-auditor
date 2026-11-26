"""FR-5 service: validate, analyse, explain, persist, and audit liveness checks.

Security properties:
- Input is validated and sanitized by engine.dataset_validator.validate_image.
- Only the existing engine.liveness rules are used; no duplicate cue logic.
- Only hashes and cue metrics are persisted; raw image bytes, filenames,
  EXIF/GPS metadata, and paths are discarded after decoding.
- Every successful check and every rejected input writes a hash-chained audit
  entry.
"""

from __future__ import annotations

from io import BytesIO

import numpy as np
from PIL import Image
from sqlalchemy.orm import Session

from app.core import audit
from app.core.time import utcnow
from app.models.evaluation import EvaluationResult, EvaluationRun, EvaluationType
from app.schemas.liveness import LivenessCheckResponse, LivenessCueMetrics
from app.services import policy_service
from engine.dataset_validator import validate_image
from engine.decision import Decision
from engine.errors import EngineError
from engine.hashing import canonical_json, config_hash, hash_input
from engine.liveness import analyze_liveness_cues


def _interpret(status: str) -> tuple[str, str]:
    """Map the engine status to a clear client-facing result and action."""
    if status == "completed":
        return "genuine", "accept_as_live_candidate"
    if status == "flagged":
        return "suspicious", "manual_review_or_retry"
    return "invalid", "reject_upload"


def _to_response(
    decision: Decision,
    metrics: dict[str, float],
    input_ref: str,
    clean_ref: str,
    detected_type: str,
    width: int,
    height: int,
    cfg_hash: str,
) -> LivenessCheckResponse:
    result, recommended_action = _interpret(decision.status)
    score = float(decision.score if decision.score is not None else 0.0)
    threshold = float(decision.threshold if decision.threshold is not None else 0.0)

    return LivenessCheckResponse(
        decision_id=decision.decision_id,
        status=decision.status,
        result=result,
        outcome=decision.outcome,
        score=score,
        threshold=threshold,
        severity=decision.severity,
        confidence=decision.confidence,
        rules_fired=list(decision.rules_fired),
        reasons=list(decision.reasons),
        recommended_action=recommended_action,
        metrics=LivenessCueMetrics(**metrics),
        input_ref=input_ref,
        clean_ref=clean_ref,
        detected_type=detected_type,
        width=width,
        height=height,
        config_hash=cfg_hash,
        model=decision.model,
        model_version=decision.model_version,
        engine_version=decision.engine_version,
        latency_ms=decision.latency_ms,
        created_at=decision.created_at,
    )
