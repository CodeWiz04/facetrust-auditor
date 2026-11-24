"""FR-3 threshold tuning service (API/service layer, Layer 2).

Flow for one evaluation:

  1. Load the ACTIVE policy (threshold + target FAR) from the policy store.
  2. Load embeddings of subjects whose consent is GRANTED and whose consent
     purpose covers threshold tuning ("evaluation" or "threshold_tuning").
     Embeddings are decrypted in memory only.
  3. Call the security engine (`engine.threshold.evaluate_threshold`).
  4. Persist ONLY aggregate evidence (curve, operating points, score
     distribution summaries, decision) - no subject IDs, no vectors.
  5. Append EVALUATION_THRESHOLD_COMPLETED to the hash-chained audit log.

Admins can then apply the recommendation (`apply_run_recommendation`),
which goes through `policy_service.apply_changes` (CONFIG_CHANGED event).
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.crypto import decrypt_embedding
from app.core.errors import AppError
from app.core.time import utc_iso, utcnow
from app.models.dataset import BiometricEmbedding, ConsentStatus, Subject
from app.models.evaluation import EvaluationResult, EvaluationRun, EvaluationType
from app.schemas.evaluation import ThresholdEvalRequest, ThresholdEvalResponse
from app.services import policy_service
from engine.errors import EngineError
from engine.hashing import canonical_json
from engine.threshold import MAX_EMBEDDINGS, evaluate_threshold

# Consent purposes that cover threshold tuning (purpose limitation).
THRESHOLD_PURPOSES = ("evaluation", "threshold_tuning")


# ---------------------------------------------------------------------------
# Loading consented data
# ---------------------------------------------------------------------------
def _resolve_model_version(db: Session, model_name: str, requested: str | None) -> str:
    versions = sorted(
        set(
            db.scalars(
                select(BiometricEmbedding.model_version)
                .join(Subject, Subject.id == BiometricEmbedding.subject_id)
                .where(
                    BiometricEmbedding.model_name == model_name,
                    Subject.consent_status == ConsentStatus.GRANTED.value,
                    Subject.purpose.in_(THRESHOLD_PURPOSES),
                )
            ).all()
        )
    )
    if not versions:
        raise AppError(
            "EVAL-INSUFFICIENT-DATA",
            detail=f"no consented embeddings for model '{model_name}'",
        )
    if requested is not None:
        if requested not in versions:
            raise AppError(
                "EVAL-INSUFFICIENT-DATA",
                detail=f"no consented embeddings for {model_name} {requested}",
            )
        return requested
    if len(versions) > 1:
        # Scores from different model versions are not comparable.
        raise AppError("EVAL-MODEL-VERSION-AMBIGUOUS", detail=f"versions={versions[:10]}")
    return versions[0]


def _load_embeddings(
    db: Session, model_name: str, model_version: str
) -> dict[str, list[list[float]]]:
    rows = db.execute(
        select(BiometricEmbedding.id, BiometricEmbedding.subject_id,
               BiometricEmbedding.encrypted_embedding)
        .join(Subject, Subject.id == BiometricEmbedding.subject_id)
        .where(
            BiometricEmbedding.model_name == model_name,
            BiometricEmbedding.model_version == model_version,
            Subject.consent_status == ConsentStatus.GRANTED.value,
            Subject.purpose.in_(THRESHOLD_PURPOSES),
        )
        .order_by(BiometricEmbedding.subject_id, BiometricEmbedding.id)
        .limit(MAX_EMBEDDINGS + 1)
    ).all()

    if len(rows) > MAX_EMBEDDINGS:
        raise AppError("EVAL-INSUFFICIENT-DATA", detail=f"more than {MAX_EMBEDDINGS} embeddings")

    by_subject: dict[str, list[list[float]]] = {}
    for emb_id, subject_id, token in rows:
        try:
            vector = decrypt_embedding(token)
        except Exception as exc:  # noqa: BLE001 - tampered / wrong key
            raise AppError(
                "EVAL-DATA-INTEGRITY",
                detail=f"embedding_id={emb_id} decrypt failed ({type(exc).__name__})",
            )
        by_subject.setdefault(subject_id, []).append(vector)
    return by_subject


# ---------------------------------------------------------------------------
# Run an evaluation
# ---------------------------------------------------------------------------
def _audit_failure(db: Session, *, code: str, request: ThresholdEvalRequest,
                   actor_id: str | None, actor_role: str | None, ip: str | None) -> None:
    db.rollback()
    audit.record(
        db,
        event="EVALUATION_THRESHOLD_FAILED",
        actor_id=actor_id,
        actor_role=actor_role,
        ip=ip,
        payload={
            "error_code": code,
            "model_name": request.model_name,
            "model_version": request.model_version,
        },
    )


def run_threshold_tuning(
    db: Session,
    request: ThresholdEvalRequest,
    actor_id: str | None = None,
    actor_role: str | None = None,
    ip: str | None = None,
) -> ThresholdEvalResponse:
    config, policy = policy_service.get_active_policy(db)
    cfg_hash = policy.config_hash
    target_far = request.target_far if request.target_far is not None else float(config["target_far"])
    active_threshold = float(config["match_threshold"])

    try:
        model_version = _resolve_model_version(db, request.model_name, request.model_version)
        embeddings = _load_embeddings(db, request.model_name, model_version)
        decision, report = evaluate_threshold(
            embeddings,
            active_threshold=active_threshold,
            target_far=target_far,
            config_hash=cfg_hash,
            model=request.model_name,
            model_version=model_version,
            input_ref=f"eval:threshold:{request.model_name}:{model_version}:policy-v{policy.version}",
            curve_steps=request.threshold_steps,
        )
    except AppError as exc:
        _audit_failure(db, code=exc.code, request=request,
                       actor_id=actor_id, actor_role=actor_role, ip=ip)
        raise
    except EngineError as exc:
        _audit_failure(db, code=exc.code, request=request,
                       actor_id=actor_id, actor_role=actor_role, ip=ip)
        if exc.code == "DATA-INSUFFICIENT":
            raise AppError("EVAL-INSUFFICIENT-DATA", detail=exc.detail)
        raise
    finally:
        embeddings = None  # noqa: F841 - drop decrypted vectors as soon as possible

    rep = report.to_dict()
    rules_fired = list(decision.rules_fired)
    summary = {
        # original keys (kept for existing clients)
        "operating_threshold": report.recommended.threshold,
        "far_at_threshold": report.recommended.far,
        "frr_at_threshold": report.recommended.frr,
        "eer": report.eer,
        "eer_threshold": report.eer_threshold,
        "target_far": report.target_far,
        "total_genuine_pairs": report.genuine_pairs,
        "total_impostor_pairs": report.impostor_pairs,
        # FR-3 evidence
        "status": decision.status,
        "severity": decision.severity,
        "confidence": decision.confidence,
        "rules_fired": rules_fired,
        "policy_version": policy.version,
        "active_threshold": report.active.threshold,
        "far_at_active": report.active.far,
        "frr_at_active": report.active.frr,
        "target_met": report.target_met,
        "target_band": list(report.target_band),
        "recommended_action": report.recommended_action,
        "decision_id": decision.decision_id,
        "engine_version": report.engine_version,
        "impostor_sampled": report.impostor_sampled,
        "sample_seed": report.sample_seed,
        "subjects": report.subjects,
        "embeddings": report.embeddings,
        "d_prime": report.d_prime,
    }

    now = utcnow()
    run = EvaluationRun(
        run_type=EvaluationType.THRESHOLD.value,
        model_name=request.model_name,
        model_version=model_version,
        config_hash=cfg_hash,
        operating_threshold=report.recommended.threshold,
        summary_metrics_json=canonical_json(summary),
        created_by=actor_id,
        created_at=now,
    )
    db.add(run)
    db.flush()

    decision_json = canonical_json(decision.to_dict())
    db.add(EvaluationResult(
        run_id=run.id, category="decision", item_key=decision.decision_id,
        metrics_json=canonical_json(rep), decision_json=decision_json,
        created_at=now,
    ))
    for name in ("active", "recommended"):
        db.add(EvaluationResult(
            run_id=run.id, category="operating_point", item_key=name,
            metrics_json=canonical_json(rep[name]), decision_json=None, created_at=now,
        ))
    for name in ("genuine", "impostor"):
        db.add(EvaluationResult(
            run_id=run.id, category="score_distribution", item_key=name,
            metrics_json=canonical_json(rep[f"{name}_summary"]), decision_json=None,
            created_at=now,
        ))
    for pt in report.curve:
        db.add(EvaluationResult(
            run_id=run.id, category="curve_point", item_key=str(pt["threshold"]),
            metrics_json=canonical_json(pt), decision_json=None, created_at=now,
        ))

    audit.record(
        db,
        event="EVALUATION_THRESHOLD_COMPLETED",
        actor_id=actor_id,
        actor_role=actor_role,
        ip=ip,
        payload={
            "run_id": run.id,
            "decision_id": decision.decision_id,
            "model_name": request.model_name,
            "model_version": model_version,
            "policy_version": policy.version,
            "config_hash": cfg_hash,
            "status": decision.status,
            "rules_fired": rules_fired,
            "active_threshold": report.active.threshold,
            "far_at_active": report.active.far,
            "operating_threshold": report.recommended.threshold,
            "eer": report.eer,
            "eer_threshold": report.eer_threshold,
            "target_far": target_far,
            "total_genuine_pairs": report.genuine_pairs,
            "total_impostor_pairs": report.impostor_pairs,
        },
    )

    return ThresholdEvalResponse(
        run_id=run.id,
        model_name=request.model_name,
        model_version=model_version,
        config_hash=cfg_hash,
        operating_threshold=report.recommended.threshold,
        far_at_threshold=report.recommended.far,
        frr_at_threshold=report.recommended.frr,
        eer=report.eer,
        eer_threshold=report.eer_threshold,
        total_genuine_pairs=report.genuine_pairs,
        total_impostor_pairs=report.impostor_pairs,
        roc_curve=report.curve,
        decision=decision.to_dict(),
        created_at=run.created_at,
        status=decision.status,
        severity=decision.severity,
        confidence=decision.confidence,
        rules_fired=rules_fired,
        rules=rep["rules"],
        reasons=list(decision.reasons),
        recommended_action=report.recommended_action,
        policy_version=policy.version,
        target_far=report.target_far,
        target_met=report.target_met,
        target_band=list(report.target_band),
        active=rep["active"],
        recommended=rep["recommended"],
        genuine_summary=report.genuine_summary,
        impostor_summary=report.impostor_summary,
        d_prime=report.d_prime,
        subjects=report.subjects,
        embeddings=report.embeddings,
        impostor_pairs_total=report.impostor_pairs_total,
        impostor_sampled=report.impostor_sampled,
        engine_version=report.engine_version,
    )


# ---------------------------------------------------------------------------
# History / detail / export
# ---------------------------------------------------------------------------
def get_threshold_run(db: Session, run_id: str) -> EvaluationRun:
    run = db.scalar(select(EvaluationRun).where(EvaluationRun.id == run_id))
    if run is None:
        raise AppError("NOT-FOUND", detail=f"evaluation run {run_id!r} not found")
    if run.run_type != EvaluationType.THRESHOLD.value:
        raise AppError("EVAL-RUN-TYPE-MISMATCH", detail=f"run_type={run.run_type}")
    return run


def _summary(run: EvaluationRun) -> dict[str, Any]:
    try:
        value = json.loads(run.summary_metrics_json or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def run_list_item(run: EvaluationRun) -> dict[str, Any]:
    s = _summary(run)
    return {
        "run_id": run.id,
        "model_name": run.model_name,
        "model_version": run.model_version,
        "created_at": run.created_at,
        "created_by": run.created_by,
        "status": s.get("status"),
        "severity": s.get("severity"),
        "policy_version": s.get("policy_version"),
        "active_threshold": s.get("active_threshold"),
        "recommended_threshold": run.operating_threshold,
        "target_far": s.get("target_far"),
        "target_met": s.get("target_met"),
        "far_at_active": s.get("far_at_active"),
        "frr_at_active": s.get("frr_at_active"),
        "eer": s.get("eer"),
        "rules_fired": list(s.get("rules_fired") or []),
    }


def list_threshold_runs(
    db: Session,
    *,
    status: str | None = None,
    model_name: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    query = (
        select(EvaluationRun)
        .where(EvaluationRun.run_type == EvaluationType.THRESHOLD.value)
        .order_by(desc(EvaluationRun.created_at))
    )
    if model_name:
        query = query.where(EvaluationRun.model_name == model_name)
    items = [run_list_item(r) for r in db.scalars(query).all()]
    if status:
        items = [i for i in items if i["status"] == status]
    return items[offset: offset + limit], len(items)


def run_detail(run: EvaluationRun) -> dict[str, Any]:
    detail: dict[str, Any] = {
        "run_id": run.id,
        "model_name": run.model_name,
        "model_version": run.model_version,
        "config_hash": run.config_hash,
        "created_by": run.created_by,
        "created_at": utc_iso(run.created_at),
        "summary": _summary(run),
        "decision": None,
        "operating_points": {},
        "score_distribution": {},
        "curve": [],
    }
    for res in run.results:
        try:
            metrics = json.loads(res.metrics_json or "{}")
        except (TypeError, ValueError):
            metrics = {}
        if res.category == "decision" and res.decision_json:
            detail["decision"] = json.loads(res.decision_json)
            detail["rules"] = metrics.get("rules", [])
        elif res.category == "operating_point":
            detail["operating_points"][res.item_key] = metrics
        elif res.category == "score_distribution":
            detail["score_distribution"][res.item_key] = metrics
        elif res.category == "curve_point":
            detail["curve"].append(metrics)
    detail["curve"].sort(key=lambda p: p.get("threshold", 0.0))
    return detail


CSV_COLUMNS = ("threshold", "far", "frr", "tpr", "genuine_matches", "impostor_matches")


def export_run(
    db: Session,
    run_id: str,
    fmt: str,
    *,
    actor_id: str,
    actor_role: str,
    ip: str | None,
) -> tuple[bytes, str, str]:
    """Sanitized export: aggregates only. Returns (body, media_type, filename)."""
    run = get_threshold_run(db, run_id)
    detail = run_detail(run)

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(CSV_COLUMNS)
        for p in detail["curve"]:
            # numeric values only -> no CSV/formula injection possible
            writer.writerow([float(p[c]) if c in ("threshold", "far", "frr", "tpr")
                             else int(p[c]) for c in CSV_COLUMNS])
        body, media = buf.getvalue().encode("utf-8"), "text/csv; charset=utf-8"
    else:
        report = {
            "report_type": "facetrust.fr3.threshold_tuning",
            "exported_at": utc_iso(utcnow()),
            "privacy_note": "Aggregate metrics only; no subject identifiers, images or embeddings.",
            **detail,
        }
        body, media = json.dumps(report, indent=2, sort_keys=True).encode("utf-8"), "application/json"

    audit.record(
        db,
        event="REPORT_EXPORTED",
        actor_id=actor_id,
        actor_role=actor_role,
        ip=ip,
        payload={"module": "threshold_tuning", "run_id": run.id, "format": fmt,
                 "bytes": len(body)},
    )
    return body, media, f"threshold-run-{run.id}.{fmt}"


# ---------------------------------------------------------------------------
# Apply a recommendation (admin)
# ---------------------------------------------------------------------------
def apply_run_recommendation(
    db: Session,
    run_id: str,
    *,
    reason: str,
    acknowledge_low_confidence: bool,
    expected_version: int | None,
    actor_id: str,
    actor_role: str,
    ip: str | None,
):
    run = get_threshold_run(db, run_id)
    s = _summary(run)
    config, _policy = policy_service.get_active_policy(db)

    def block(code: str, detail: str):
        audit.record(
            db, event="CONFIG_CHANGE_REJECTED", actor_id=actor_id, actor_role=actor_role,
            ip=ip, payload={"error_code": code, "source_run_id": run.id, "why": detail},
        )
        raise AppError(code, detail=detail)

    if "target_met" not in s or run.operating_threshold is None:
        block("THR-APPLY-BLOCKED", "run predates FR-3 evidence format; re-run evaluation")
    if s.get("target_met") is not True:
        block("THR-APPLY-BLOCKED", "recommendation does not meet the target FAR")
    if float(s.get("target_far", -1)) != float(config["target_far"]):
        block("THR-APPLY-BLOCKED", "run target FAR differs from the active policy; re-run")
    if "THR-LOW-CONFIDENCE" in (s.get("rules_fired") or []) and not acknowledge_low_confidence:
        block("THR-LOW-CONFIDENCE-UNACKNOWLEDGED", "low-confidence run not acknowledged")

    return policy_service.apply_changes(
        db,
        changes={"match_threshold": float(run.operating_threshold)},
        reason=reason,
        actor_id=actor_id,
        actor_role=actor_role,
        ip=ip,
        expected_version=expected_version,
        source_run_id=run.id,
    )