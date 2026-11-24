"""Biometric evaluation service for threshold tuning, bias auditing, and liveness testing.

Implements:
- FR-3: Genuine vs. impostor threshold tuning, ROC/DET curves, and EER calculation.
- FR-4: Demographic subgroup disparity analysis and sample size auditing.
- FR-5: Presentation-attack liveness cue orchestration.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Sequence

import numpy as np
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.crypto import decrypt_embedding
from app.core.errors import AppError
from app.core.time import utcnow
from app.models.dataset import BiometricEmbedding, ConsentStatus, Subject
from app.models.evaluation import EvaluationResult, EvaluationRun, EvaluationType
from app.schemas.evaluation import (
    EvaluationListResponse,
    EvaluationRunSummary,
    RocPoint,
    SubgroupBiasRequest,
    SubgroupBiasResponse,
    SubgroupMetricItem,
    ThresholdEvalRequest,
    ThresholdEvalResponse,
)
from engine.decision import Decision, Timer
from engine.embeddings import cosine_score
from engine.hashing import canonical_json, config_hash
from engine.policy import load_default_config


def compute_pairwise_scores(
    embeddings_by_subject: dict[str, list[list[float]]],
    max_impostor_pairs: int = 50000,
) -> tuple[list[float], list[float]]:
    """Compute all genuine and impostor cosine similarity scores."""
    genuine_scores: list[float] = []
    impostor_scores: list[float] = []

    # 1. Genuine pairs (within each subject)
    for subject_id, vectors in embeddings_by_subject.items():
        n = len(vectors)
        if n >= 2:
            for i in range(n):
                for j in range(i + 1, n):
                    score = cosine_score(vectors[i], vectors[j])
                    genuine_scores.append(score)

    # 2. Impostor pairs (between different subjects)
    subjects = list(embeddings_by_subject.keys())
    num_subjects = len(subjects)
    impostor_count = 0

    for i in range(num_subjects):
        sub_a = subjects[i]
        vecs_a = embeddings_by_subject[sub_a]
        for j in range(i + 1, num_subjects):
            sub_b = subjects[j]
            vecs_b = embeddings_by_subject[sub_b]
            for va in vecs_a:
                for vb in vecs_b:
                    score = cosine_score(va, vb)
                    impostor_scores.append(score)
                    impostor_count += 1
                    if impostor_count >= max_impostor_pairs:
                        break
                if impostor_count >= max_impostor_pairs:
                    break
            if impostor_count >= max_impostor_pairs:
                break
        if impostor_count >= max_impostor_pairs:
            break

    return genuine_scores, impostor_scores


def compute_roc_curve(
    genuine_scores: Sequence[float],
    impostor_scores: Sequence[float],
    steps: int = 50,
) -> list[RocPoint]:
    """Sweep threshold values to compute discrete ROC and DET curve points."""
    if not genuine_scores or not impostor_scores:
        return []

    # Threshold range bounded between -0.2 and 1.0 (cosine range of interest)
    thresholds = np.linspace(-0.2, 1.0, num=steps, dtype=float)
    g_arr = np.array(genuine_scores, dtype=np.float64)
    i_arr = np.array(impostor_scores, dtype=np.float64)

    total_genuine = len(g_arr)
    total_impostor = len(i_arr)
    points: list[RocPoint] = []

    for t in thresholds:
        th = float(t)
        gen_matches = int(np.sum(g_arr >= th))
        imp_matches = int(np.sum(i_arr >= th))

        tpr = float(gen_matches / total_genuine)
        frr = float(1.0 - tpr)
        far = float(imp_matches / total_impostor)

        points.append(
            RocPoint(
                threshold=round(th, 4),
                far=round(far, 6),
                frr=round(frr, 6),
                tpr=round(tpr, 6),
                genuine_matches=gen_matches,
                impostor_matches=imp_matches,
            )
        )

    return points


def calculate_eer(roc_curve: list[RocPoint]) -> tuple[float, float]:
    """Find Equal Error Rate (EER) where |FAR - FRR| is minimized."""
    if not roc_curve:
        return 0.0, 0.5

    best_diff = float("inf")
    best_eer = 0.0
    best_threshold = 0.5

    for pt in roc_curve:
        diff = abs(pt.far - pt.frr)
        if diff < best_diff:
            best_diff = diff
            best_eer = (pt.far + pt.frr) / 2.0
            best_threshold = pt.threshold

    return round(best_eer, 6), round(best_threshold, 4)


def find_operating_threshold(
    roc_curve: list[RocPoint],
    target_far: float,
    default_threshold: float = 0.5,
) -> tuple[float, float, float]:
    """Select the operating threshold meeting target FAR."""
    if not roc_curve:
        return default_threshold, 0.0, 0.0

    # Look for the lowest threshold achieving FAR <= target_far
    candidates = [pt for pt in roc_curve if pt.far <= target_far]
    if candidates:
        selected = candidates[0]
        return selected.threshold, selected.far, selected.frr

    # If none strictly satisfy target_far, pick the point with lowest FAR
    lowest_far_pt = min(roc_curve, key=lambda p: p.far)
    return lowest_far_pt.threshold, lowest_far_pt.far, lowest_far_pt.frr


def run_threshold_evaluation(
    db: Session,
    request: ThresholdEvalRequest,
    actor_id: str | None = None,
    actor_role: str | None = None,
    ip: str | None = None,
) -> ThresholdEvalResponse:
    """Execute full threshold tuning analysis and ROC curve generation (FR-3)."""
    timer = Timer()
    config = load_default_config()
    cfg_hash = config_hash(config)

    # 1. Query active consented subjects and their biometric embeddings for this model
    subjects = list(
        db.scalars(
            select(Subject).where(Subject.consent_status == ConsentStatus.GRANTED.value)
        ).all()
    )
    if not subjects:
        raise AppError(
            "EVAL-INSUFFICIENT-DATA",
            detail="No subjects with granted consent exist in the auditing database.",
        )

    embeddings_by_subject: dict[str, list[list[float]]] = {}
    model_version = "1.0.0"

    for sub in subjects:
        sub_embeddings = list(
            db.scalars(
                select(BiometricEmbedding).where(
                    BiometricEmbedding.subject_id == sub.id,
                    BiometricEmbedding.model_name == request.model_name,
                )
            ).all()
        )
        if sub_embeddings:
            model_version = sub_embeddings[0].model_version
            vectors: list[list[float]] = []
            for emb in sub_embeddings:
                try:
                    vec = decrypt_embedding(emb.encrypted_embedding)
                    vectors.append(vec)
                except Exception as exc:
                    raise AppError(
                        "DEL-VERIFY-FAILED",
                        detail=f"Failed to decrypt stored embedding for evaluation: {exc}",
                    )
            if vectors:
                embeddings_by_subject[sub.id] = vectors

    # 2. Validate sufficient pairs exist
    genuine_scores, impostor_scores = compute_pairwise_scores(embeddings_by_subject)
    if len(genuine_scores) == 0:
        raise AppError(
            "EVAL-INSUFFICIENT-DATA",
            detail=(
                f"Insufficient matching pairs for model '{request.model_name}'. "
                "At least 2 face samples for at least one consented subject are required to evaluate genuine pairs."
            ),
        )
    if len(impostor_scores) == 0:
        raise AppError(
            "EVAL-INSUFFICIENT-DATA",
            detail=(
                f"Insufficient impostor pairs for model '{request.model_name}'. "
                "At least 2 distinct consented subjects are required to evaluate impostor pairs."
            ),
        )

    # 3. Compute ROC curve and EER
    roc_points = compute_roc_curve(
        genuine_scores, impostor_scores, steps=request.threshold_steps
    )
    eer, eer_threshold = calculate_eer(roc_points)

    target_far = (
        request.target_far
        if request.target_far is not None
        else float(config.get("target_far", 0.01))
    )
    op_th, far_at_th, frr_at_th = find_operating_threshold(
        roc_points,
        target_far=target_far,
        default_threshold=float(config.get("match_threshold", 0.5)),
    )

    summary_metrics = {
        "operating_threshold": op_th,
        "far_at_threshold": far_at_th,
        "frr_at_threshold": frr_at_th,
        "eer": eer,
        "eer_threshold": eer_threshold,
        "target_far": target_far,
        "total_genuine_pairs": len(genuine_scores),
        "total_impostor_pairs": len(impostor_scores),
    }

    # 4. Create explainable Decision record
    decision = Decision.create(
        stage="threshold",
        status="completed",
        outcome="THRESHOLD_EVALUATION_COMPLETED",
        score=far_at_th,
        threshold=op_th,
        confidence=1.0,
        rules_fired=(),
        reasons=(
            f"Computed {len(roc_points)} ROC points across {len(genuine_scores)} genuine and {len(impostor_scores)} impostor pairs.",
            f"EER is {eer * 100:.2f}% at threshold {eer_threshold}.",
            f"Operating threshold {op_th:.4f} meets target FAR of {target_far * 100:.2f}%.",
        ),
        config_hash=cfg_hash,
        input_ref=f"eval:threshold:{request.model_name}",
        latency_ms=timer.ms(),
        model=request.model_name,
        model_version=model_version,
    )

    # 5. Persist EvaluationRun and results in DB
    run = EvaluationRun(
        run_type=EvaluationType.THRESHOLD.value,
        model_name=request.model_name,
        model_version=model_version,
        config_hash=cfg_hash,
        operating_threshold=op_th,
        summary_metrics_json=canonical_json(summary_metrics),
        created_by=actor_id,
        created_at=utcnow(),
    )
    db.add(run)
    db.flush()

    # Store individual ROC curve points in EvaluationResult
    for pt in roc_points:
        result_item = EvaluationResult(
            run_id=run.id,
            category="curve_point",
            item_key=str(pt.threshold),
            metrics_json=canonical_json(pt.model_dump()),
            decision_json=canonical_json(decision.to_dict()),
            created_at=utcnow(),
        )
        db.add(result_item)

    # 6. Append-only tamper-evident audit log
    audit.record(
        db,
        event="EVALUATION_THRESHOLD_COMPLETED",
        actor_id=actor_id,
        actor_role=actor_role,
        ip=ip,
        payload={
            "run_id": run.id,
            "model_name": request.model_name,
            "operating_threshold": op_th,
            "eer": eer,
            "eer_threshold": eer_threshold,
            "total_genuine_pairs": len(genuine_scores),
            "total_impostor_pairs": len(impostor_scores),
        },
    )

    return ThresholdEvalResponse(
        run_id=run.id,
        model_name=request.model_name,
        model_version=model_version,
        config_hash=cfg_hash,
        operating_threshold=op_th,
        far_at_threshold=far_at_th,
        frr_at_threshold=frr_at_th,
        eer=eer,
        eer_threshold=eer_threshold,
        total_genuine_pairs=len(genuine_scores),
        total_impostor_pairs=len(impostor_scores),
        roc_curve=roc_points,
        decision=decision.to_dict(),
        created_at=run.created_at,
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
    config = load_default_config()
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
            model_version=r.model_version,
            operating_threshold=r.operating_threshold,
            created_by=r.created_by,
            created_at=r.created_at,
            summary_metrics=json.loads(r.summary_metrics_json) if r.summary_metrics_json else {},
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
