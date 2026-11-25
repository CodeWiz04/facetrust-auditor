"""Biometric evaluation service for threshold tuning, bias auditing, and liveness testing.

Implements:
- FR-3: delegated to app/services/threshold_service.py (engine/threshold.py).
- FR-4: delegated to app/services/subgroup_service.py (engine/subgroup.py).
- FR-5: Presentation-attack liveness cue orchestration.
"""

from __future__ import annotations

import json
from datetime import datetime
from io import BytesIO
from typing import Any, Sequence

import numpy as np
from PIL import Image
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.errors import AppError
from app.core.time import utcnow
from app.models.evaluation import EvaluationResult, EvaluationRun, EvaluationType
from app.services import policy_service
from app.schemas.evaluation import (
    EvaluationListResponse,
    EvaluationRunSummary,
    LivenessCheckResponse,
    SubgroupBiasRequest,
    SubgroupBiasResponse,
    ThresholdEvalRequest,
    ThresholdEvalResponse,
)
from engine.dataset_validator import ValidatedImage, validate_image
from engine.decision import Decision, Timer
from engine.hashing import canonical_json, config_hash
from engine.liveness import analyze_liveness_cues


def run_threshold_evaluation(
    db: Session,
    request: ThresholdEvalRequest,
    actor_id: str | None = None,
    actor_role: str | None = None,
    ip: str | None = None,
) -> ThresholdEvalResponse:
    """FR-3 threshold tuning.

    Kept for backward compatibility; the implementation lives in
    `app/services/threshold_service.py` and the maths in `engine/threshold.py`.
    """
    from app.services import threshold_service

    return threshold_service.run_threshold_tuning(
        db, request, actor_id=actor_id, actor_role=actor_role, ip=ip
    )


def run_subgroup_bias_audit(
    db: Session,
    request: SubgroupBiasRequest,
    actor_id: str | None = None,
    actor_role: str | None = None,
    ip: str | None = None,
) -> SubgroupBiasResponse:
    """FR-4 subgroup metrics.

    Kept for backward compatibility; the implementation lives in
    `app/services/subgroup_service.py` and the maths in `engine/subgroup.py`.
    """
    from app.services import subgroup_service

    return subgroup_service.run_subgroup_audit(
        db, request, actor_id=actor_id, actor_role=actor_role, ip=ip
    )


def evaluate_liveness_sample(
    db: Session,
    file_bytes: bytes,
    claimed_name: str = "liveness_sample.png",
    actor_id: str | None = None,
    actor_role: str | None = None,
    ip: str | None = None,
) -> LivenessCheckResponse:
    """Validate an uploaded face sample, analyze liveness cues, and record tamper-evident audit decision (FR-5, T4)."""
    config = policy_service.get_active_config(db)
    cfg_hash = config_hash(config)
    limits = config["limits"]

    # 1. Validate real image decode, bounds, type, and size
    validated: ValidatedImage = validate_image(
        file_bytes, limits=limits, claimed_name=claimed_name
    )

    # 2. Decode to RGB array
    with Image.open(BytesIO(validated.png_bytes)) as img:
        rgb = np.ascontiguousarray(np.asarray(img.convert("RGB"), dtype=np.uint8))

    # 3. Security engine liveness analysis
    decision, metrics = analyze_liveness_cues(
        rgb, config=config, input_ref=validated.input_ref, config_hash=cfg_hash
    )

    is_attack = decision.status in ("rejected", "flagged")
    liveness_score = float(decision.score if decision.score is not None else 0.0)
    rules_fired = list(decision.rules_fired)
    reasons = list(decision.reasons)

    # 4. Record EvaluationRun and EvaluationResult
    run = EvaluationRun(
        run_type=EvaluationType.LIVENESS.value,
        model_name="liveness-engine",
        model_version="1.0.0",
        config_hash=cfg_hash,
        operating_threshold=None,
        summary_metrics_json=canonical_json({
            "input_hash": validated.input_ref,
            "liveness_score": liveness_score,
            "is_attack": is_attack,
            "rules_fired": rules_fired,
            **metrics,
        }),
        created_by=actor_id,
        created_at=utcnow(),
    )
    db.add(run)
    db.flush()

    db.add(
        EvaluationResult(
            run_id=run.id,
            category="liveness_sample",
            item_key=validated.input_ref,
            metrics_json=canonical_json(metrics),
            decision_json=canonical_json(decision.to_dict()),
            created_at=utcnow(),
        )
    )

    # 5. Tamper-evident audit log
    audit.record(
        db,
        event="EVALUATION_LIVENESS_COMPLETED",
        actor_id=actor_id,
        actor_role=actor_role,
        ip=ip,
        payload={
            "run_id": run.id,
            "input_hash": validated.input_ref,
            "liveness_score": liveness_score,
            "is_attack": is_attack,
            "rules_fired": rules_fired,
        },
    )

    return LivenessCheckResponse(
        decision_id=decision.decision_id,
        status=decision.status,
        outcome=decision.outcome,
        score=liveness_score,
        threshold=float(decision.threshold if decision.threshold is not None else 0.0),
        severity=decision.severity,
        rules_fired=rules_fired,
        reasons=reasons,
        metrics=metrics,
        latency_ms=decision.latency_ms,
        created_at=decision.created_at,
    )


def list_evaluation_runs(
    db: Session,
    run_type: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> EvaluationListResponse:
    """Retrieve historical evaluation runs ordered by newest first."""
    query = select(EvaluationRun).order_by(desc(EvaluationRun.created_at))
    if run_type:
        query = query.where(EvaluationRun.run_type == run_type)

    total = len(list(db.scalars(query).all()))
    runs = list(db.scalars(query.limit(limit).offset(offset)).all())

    summaries = [
        EvaluationRunSummary(
            id=r.id,
            run_type=r.run_type,
            model_name=r.model_name,
            operating_threshold=r.operating_threshold,
            created_by=r.created_by,
            created_at=r.created_at,
            summary=json.loads(r.summary_metrics_json) if r.summary_metrics_json else {},
        )
        for r in runs
    ]

    return EvaluationListResponse(items=summaries, total=total)


def get_evaluation_run(db: Session, run_id: str) -> EvaluationRun:
    """Retrieve an evaluation run by ID with all its results."""
    run = db.scalar(select(EvaluationRun).where(EvaluationRun.id == run_id))
    if not run:
        raise AppError("NOT-FOUND", detail=f"Evaluation run '{run_id}' not found")
    return run