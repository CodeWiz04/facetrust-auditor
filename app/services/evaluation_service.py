"""Biometric evaluation service for threshold tuning, bias auditing, and liveness testing.

Implements:
- FR-3: delegated to app/services/threshold_service.py (engine/threshold.py).
- FR-4: Demographic subgroup disparity analysis and sample size auditing.
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
from app.core.crypto import decrypt_embedding
from app.core.errors import AppError
from app.core.time import utcnow
from app.models.dataset import BiometricEmbedding, ConsentStatus, Subject
from app.models.evaluation import EvaluationResult, EvaluationRun, EvaluationType
from app.services import policy_service
from app.schemas.evaluation import (
    EvaluationListResponse,
    EvaluationRunSummary,
    LivenessCheckResponse,
    SubgroupBiasRequest,
    SubgroupBiasResponse,
    SubgroupMetricItem,
    ThresholdEvalRequest,
    ThresholdEvalResponse,
)
from engine.dataset_validator import ValidatedImage, validate_image
from engine.decision import Decision, Timer
from engine.embeddings import cosine_score
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
    """Execute demographic subgroup bias auditing and disparity analysis (FR-4, T5)."""
    timer = Timer()
    config = policy_service.get_active_config(db)
    cfg_hash = config_hash(config)
    min_group_n = int(config.get("min_group_n", 30))
    operating_th = (
        request.operating_threshold
        if request.operating_threshold is not None
        else float(config.get("match_threshold", 0.5))
    )

    # 1. Query active consented subjects
    subjects = list(
        db.scalars(
            select(Subject).where(Subject.consent_status == ConsentStatus.GRANTED.value)
        ).all()
    )
    if not subjects:
        raise AppError(
            "EVAL-INSUFFICIENT-DATA",
            detail="No subjects with granted consent exist for bias auditing.",
        )

    # Group subjects by demographic group label
    subjects_by_group: dict[str, list[Subject]] = {}
    for sub in subjects:
        group_key = sub.group.strip() if sub.group else "undisclosed"
        subjects_by_group.setdefault(group_key, []).append(sub)

    # Decrypt embeddings by subject
    embeddings_by_sub: dict[str, list[list[float]]] = {}
    model_version = "1.0.0"

    for sub in subjects:
        sub_embs = list(
            db.scalars(
                select(BiometricEmbedding).where(
                    BiometricEmbedding.subject_id == sub.id,
                    BiometricEmbedding.model_name == request.model_name,
                )
            ).all()
        )
        if sub_embs:
            model_version = sub_embs[0].model_version
            vectors = [decrypt_embedding(e.encrypted_embedding) for e in sub_embs]
            if vectors:
                embeddings_by_sub[sub.id] = vectors

    if not embeddings_by_sub:
        raise AppError(
            "EVAL-INSUFFICIENT-DATA",
            detail=f"No enrolled embeddings found for model '{request.model_name}'.",
        )

    # 2. Compute metrics per subgroup
    subgroup_metrics: list[SubgroupMetricItem] = []

    for group_name, group_subs in subjects_by_group.items():
        sample_count = len(group_subs)
        warning_msg = None
        if sample_count < min_group_n:
            warning_msg = (
                f"Sample size N={sample_count} < {min_group_n} provides low statistical "
                "confidence (wide 95% confidence interval)."
            )

        # Genuine pairs within this group
        group_genuine_scores: list[float] = []
        for s in group_subs:
            vecs = embeddings_by_sub.get(s.id, [])
            n_vecs = len(vecs)
            if n_vecs >= 2:
                for i in range(n_vecs):
                    for j in range(i + 1, n_vecs):
                        group_genuine_scores.append(cosine_score(vecs[i], vecs[j]))

        # Impostor pairs involving subjects in this group
        group_impostor_scores: list[float] = []
        for s in group_subs:
            vecs_s = embeddings_by_sub.get(s.id, [])
            for other_sub_id, other_vecs in embeddings_by_sub.items():
                if other_sub_id != s.id:
                    for vs in vecs_s:
                        for vo in other_vecs:
                            group_impostor_scores.append(cosine_score(vs, vo))
                            if len(group_impostor_scores) >= 10000:
                                break
                        if len(group_impostor_scores) >= 10000:
                            break
                if len(group_impostor_scores) >= 10000:
                    break

        n_gen = len(group_genuine_scores)
        n_imp = len(group_impostor_scores)

        if n_gen > 0:
            gen_matches = sum(1 for sc in group_genuine_scores if sc >= operating_th)
            frr = round(float((n_gen - gen_matches) / n_gen), 6)
        else:
            frr = 0.0

        if n_imp > 0:
            imp_matches = sum(1 for sc in group_impostor_scores if sc >= operating_th)
            far = round(float(imp_matches / n_imp), 6)
        else:
            far = 0.0

        subgroup_metrics.append(
            SubgroupMetricItem(
                group=group_name,
                sample_count=sample_count,
                genuine_pairs=n_gen,
                impostor_pairs=n_imp,
                far=far,
                frr=frr,
                warning=warning_msg,
            )
        )

    # 3. Disparity calculations
    fars = [m.far for m in subgroup_metrics]
    frrs = [m.frr for m in subgroup_metrics]

    max_far_gap = round(float(max(fars) - min(fars)), 6) if fars else 0.0
    max_frr_gap = round(float(max(frrs) - min(frrs)), 6) if frrs else 0.0

    valid_frrs = [m.frr for m in subgroup_metrics if m.frr > 0]
    disparity_ratio = (
        round(float(max(frrs) / min(valid_frrs)), 3)
        if valid_frrs and len(valid_frrs) > 0 and min(valid_frrs) > 0
        else None
    )

    is_disparity_high = max_frr_gap > 0.05 or max_far_gap > 0.02
    summary = (
        f"Audited {len(subgroup_metrics)} demographic subgroups at operating threshold {operating_th:.4f}. "
        f"Maximum FRR gap: {max_frr_gap * 100:.2f}%, Maximum FAR gap: {max_far_gap * 100:.2f}%."
    )
    if is_disparity_high:
        summary += " Noticeable demographic disparity detected between subgroups."
    else:
        summary += " Demographic performance is relatively balanced across evaluated groups."

    # 4. Explainable Decision
    rules_fired = ("BIAS-DISPARITY-FLAG",) if is_disparity_high else ()
    status = "flagged" if is_disparity_high else "completed"
    severity = "medium" if is_disparity_high else "info"

    decision = Decision.create(
        stage="subgroup",
        status=status,
        outcome="SUBGROUP_BIAS_AUDIT_COMPLETED",
        score=max_frr_gap,
        threshold=operating_th,
        severity=severity,
        confidence=1.0,
        rules_fired=rules_fired,
        reasons=(
            f"Evaluated {len(subgroup_metrics)} demographic subgroups.",
            f"Max FRR gap between groups is {max_frr_gap * 100:.2f}%.",
            f"Max FAR gap between groups is {max_far_gap * 100:.2f}%.",
            summary,
        ),
        config_hash=cfg_hash,
        input_ref=f"eval:bias:{request.model_name}",
        latency_ms=timer.ms(),
        model=request.model_name,
        model_version=model_version,
    )

    # 5. Persist run and results
    run = EvaluationRun(
        run_type=EvaluationType.BIAS_AUDIT.value,
        model_name=request.model_name,
        model_version=model_version,
        config_hash=cfg_hash,
        operating_threshold=operating_th,
        summary_metrics_json=canonical_json({
            "operating_threshold": operating_th,
            "max_far_gap": max_far_gap,
            "max_frr_gap": max_frr_gap,
            "disparity_ratio": disparity_ratio,
            "subgroups_count": len(subgroup_metrics),
        }),
        created_by=actor_id,
        created_at=utcnow(),
    )
    db.add(run)
    db.flush()

    for item in subgroup_metrics:
        db.add(
            EvaluationResult(
                run_id=run.id,
                category="subgroup",
                item_key=item.group,
                metrics_json=canonical_json(item.model_dump()),
                decision_json=canonical_json(decision.to_dict()),
                created_at=utcnow(),
            )
        )

    # 6. Append-only tamper-evident audit log
    audit.record(
        db,
        event="EVALUATION_BIAS_COMPLETED",
        actor_id=actor_id,
        actor_role=actor_role,
        ip=ip,
        payload={
            "run_id": run.id,
            "model_name": request.model_name,
            "operating_threshold": operating_th,
            "max_far_gap": max_far_gap,
            "max_frr_gap": max_frr_gap,
            "disparity_ratio": disparity_ratio,
            "subgroups_evaluated": len(subgroup_metrics),
        },
    )

    return SubgroupBiasResponse(
        run_id=run.id,
        model_name=request.model_name,
        operating_threshold=operating_th,
        subgroups=subgroup_metrics,
        max_far_gap=max_far_gap,
        max_frr_gap=max_frr_gap,
        disparity_ratio=disparity_ratio,
        summary=summary,
        decision=decision.to_dict(),
        created_at=run.created_at,
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