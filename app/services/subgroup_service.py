"""FR-4 subgroup metrics service (API/service layer, Layer 2).

Flow for one audit:

  1. Load the ACTIVE policy (threshold, target FAR, min_group_n). The FR-3
     threshold an admin applied is what gets audited, unless the caller asks
     for a what-if override (recorded as threshold_source="override").
  2. Load embeddings + self-reported group labels of subjects whose consent
     is GRANTED and whose purpose covers bias auditing ("evaluation" or
     "bias_audit"). Vectors are decrypted in memory only.
  3. Call the security engine (`engine.subgroup.audit_subgroups`).
  4. Persist aggregate evidence only (per-group rates, comparisons, decision)
     - no subject IDs, no vectors; groups < 3 subjects are suppressed.
  5. Append EVALUATION_BIAS_COMPLETED to the hash-chained audit log.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.errors import AppError
from app.core.time import utc_iso, utcnow
from app.models.dataset import BiometricEmbedding, ConsentStatus, Subject
from app.models.evaluation import EvaluationResult, EvaluationRun, EvaluationType
from app.schemas.evaluation import SubgroupBiasRequest, SubgroupBiasResponse
from app.services import policy_service
from app.services.threshold_service import load_consented_embeddings, resolve_model_version
from engine.errors import EngineError
from engine.hashing import canonical_json
from engine.subgroup import MIN_REPORTABLE_SUBJECTS, UNDISCLOSED, audit_subgroups

# Consent purposes that cover bias auditing (purpose limitation).
BIAS_PURPOSES = ("evaluation", "bias_audit")


def _load_groups(db: Session, subject_ids: list[str]) -> dict[str, str]:
    groups: dict[str, str] = {}
    for start in range(0, len(subject_ids), 500):  # stay under SQLite's variable limit
        chunk = subject_ids[start:start + 500]
        for sid, label in db.execute(
            select(Subject.id, Subject.group).where(Subject.id.in_(chunk))
        ).all():
            groups[sid] = label or UNDISCLOSED
    return groups


def _audit_failure(db: Session, *, code: str, request: SubgroupBiasRequest,
                   actor_id: str | None, actor_role: str | None, ip: str | None) -> None:
    db.rollback()
    audit.record(
        db,
        event="EVALUATION_BIAS_FAILED",
        actor_id=actor_id,
        actor_role=actor_role,
        ip=ip,
        payload={"error_code": code, "model_name": request.model_name,
                 "model_version": request.model_version},
    )


def _summary_text(report, decision) -> str:
    frr, far = report.frr_comparison, report.far_comparison
    text = (f"Audited {len(report.groups)} demographic subgroups at operating threshold "
            f"{report.threshold:.4f} ({report.threshold_source}). "
            f"Maximum FRR gap: {frr.gap * 100:.2f}%, Maximum FAR gap: {far.gap * 100:.2f}%.")
    if decision.status == "completed":
        text += " Demographic performance is within tolerance across evaluated groups."
    else:
        text += f" Flagged: {', '.join(decision.rules_fired)}."
    return text


def run_subgroup_audit(
    db: Session,
    request: SubgroupBiasRequest,
    actor_id: str | None = None,
    actor_role: str | None = None,
    ip: str | None = None,
) -> SubgroupBiasResponse:
    config, policy = policy_service.get_active_policy(db)
    cfg_hash = policy.config_hash
    if request.operating_threshold is not None:
        threshold, source = float(request.operating_threshold), "override"
    else:
        threshold, source = float(config["match_threshold"]), "policy"
    target_far = float(config["target_far"])
    min_group_n = int(config["min_group_n"])

    try:
        model_version = resolve_model_version(
            db, request.model_name, request.model_version, purposes=BIAS_PURPOSES
        )
        embeddings = load_consented_embeddings(
            db, request.model_name, model_version, purposes=BIAS_PURPOSES
        )
        groups = _load_groups(db, list(embeddings))
        decision, report = audit_subgroups(
            embeddings,
            groups,
            threshold=threshold,
            target_far=target_far,
            min_group_n=min_group_n,
            config_hash=cfg_hash,
            model=request.model_name,
            model_version=model_version,
            input_ref=f"eval:bias:{request.model_name}:{model_version}:policy-v{policy.version}",
            threshold_source=source,
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
    frr_cmp, far_cmp = rep["frr_comparison"], rep["far_comparison"]
    rules_fired = list(decision.rules_fired)
    summary_text = _summary_text(report, decision)
    summary = {
        # original keys (kept for existing clients)
        "operating_threshold": report.threshold,
        "max_far_gap": far_cmp["gap"],
        "max_frr_gap": frr_cmp["gap"],
        "disparity_ratio": frr_cmp["ratio"],
        "subgroups_count": len(report.groups),
        # FR-4 evidence
        "status": decision.status,
        "severity": decision.severity,
        "confidence": decision.confidence,
        "rules_fired": rules_fired,
        "policy_version": policy.version,
        "threshold_source": source,
        "target_far": target_far,
        "min_group_n": min_group_n,
        "eligible_groups": rep["eligible_groups"],
        "suppressed_groups": rep["suppressed_groups"],
        "frr_comparison": frr_cmp,
        "far_comparison": far_cmp,
        "recommended_action": report.recommended_action,
        "decision_id": decision.decision_id,
        "engine_version": report.engine_version,
        "summary": summary_text,
    }

    now = utcnow()
    run = EvaluationRun(
        run_type=EvaluationType.BIAS_AUDIT.value,
        model_name=request.model_name,
        model_version=model_version,
        config_hash=cfg_hash,
        operating_threshold=report.threshold,
        summary_metrics_json=canonical_json(summary),
        created_by=actor_id,
        created_at=now,
    )
    db.add(run)
    db.flush()

    db.add(EvaluationResult(
        run_id=run.id, category="decision", item_key=decision.decision_id,
        metrics_json=canonical_json({k: v for k, v in rep.items() if k != "groups"}),
        decision_json=canonical_json(decision.to_dict()), created_at=now,
    ))
    for g in rep["groups"]:
        db.add(EvaluationResult(
            run_id=run.id, category="subgroup", item_key=g["group"][:128],
            metrics_json=canonical_json(g), decision_json=None, created_at=now,
        ))

    audit.record(
        db,
        event="EVALUATION_BIAS_COMPLETED",
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
            "operating_threshold": report.threshold,
            "threshold_source": source,
            "status": decision.status,
            "rules_fired": rules_fired,
            "max_far_gap": far_cmp["gap"],
            "max_frr_gap": frr_cmp["gap"],
            "disparity_ratio": frr_cmp["ratio"],
            "subgroups_evaluated": len(report.groups),
            "eligible_groups": len(rep["eligible_groups"]),
            "suppressed_groups": rep["suppressed_groups"],
        },
    )

    items = [
        {**g, "sample_count": g["subjects"]}
        for g in rep["groups"]
    ]
    return SubgroupBiasResponse(
        run_id=run.id,
        model_name=request.model_name,
        operating_threshold=report.threshold,
        subgroups=items,
        max_far_gap=far_cmp["gap"],
        max_frr_gap=frr_cmp["gap"],
        disparity_ratio=frr_cmp["ratio"],
        summary=summary_text,
        decision=decision.to_dict(),
        created_at=run.created_at,
        model_version=model_version,
        config_hash=cfg_hash,
        policy_version=policy.version,
        threshold_source=source,
        target_far=target_far,
        min_group_n=min_group_n,
        status=decision.status,
        severity=decision.severity,
        confidence=decision.confidence,
        rules_fired=rules_fired,
        rules=rep["rules"],
        reasons=list(decision.reasons),
        recommended_action=report.recommended_action,
        frr_comparison=frr_cmp,
        far_comparison=far_cmp,
        eligible_groups=rep["eligible_groups"],
        suppressed_groups=rep["suppressed_groups"],
        far_disparity_ratio=far_cmp["ratio"],
        engine_version=report.engine_version,
    )


# ---------------------------------------------------------------------------
# Group overview (for the dashboard filter) - counts only, small cells hidden
# ---------------------------------------------------------------------------
def group_overview(db: Session) -> list[dict[str, Any]]:
    rows = db.execute(
        select(Subject.group, func.count(func.distinct(Subject.id)))
        .join(BiometricEmbedding, BiometricEmbedding.subject_id == Subject.id)
        .where(
            Subject.consent_status == ConsentStatus.GRANTED.value,
            Subject.purpose.in_(BIAS_PURPOSES),
        )
        .group_by(Subject.group)
        .order_by(Subject.group)
    ).all()
    out = []
    for label, count in rows:
        small = int(count) < MIN_REPORTABLE_SUBJECTS
        out.append({
            "group": label or UNDISCLOSED,
            "subjects": None if small else int(count),
            "suppressed": small,
        })
    return out


# ---------------------------------------------------------------------------
# History / detail / export
# ---------------------------------------------------------------------------
def get_bias_run(db: Session, run_id: str) -> EvaluationRun:
    run = db.scalar(select(EvaluationRun).where(EvaluationRun.id == run_id))
    if run is None:
        raise AppError("NOT-FOUND", detail=f"evaluation run {run_id!r} not found")
    if run.run_type != EvaluationType.BIAS_AUDIT.value:
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
        "operating_threshold": run.operating_threshold,
        "threshold_source": s.get("threshold_source"),
        "max_frr_gap": s.get("max_frr_gap"),
        "max_far_gap": s.get("max_far_gap"),
        "subgroups_count": s.get("subgroups_count"),
        "rules_fired": list(s.get("rules_fired") or []),
    }


def list_bias_runs(
    db: Session,
    *,
    status: str | None = None,
    model_name: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    query = (
        select(EvaluationRun)
        .where(EvaluationRun.run_type == EvaluationType.BIAS_AUDIT.value)
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
        "operating_threshold": run.operating_threshold,
        "created_by": run.created_by,
        "created_at": utc_iso(run.created_at),
        "summary": _summary(run),
        "decision": None,
        "rules": [],
        "subgroups": [],
    }
    for res in run.results:
        try:
            metrics = json.loads(res.metrics_json or "{}")
        except (TypeError, ValueError):
            metrics = {}
        if res.category == "decision" and res.decision_json:
            detail["decision"] = json.loads(res.decision_json)
            detail["rules"] = metrics.get("rules", [])
        elif res.category == "subgroup":
            detail["subgroups"].append(metrics)
    detail["subgroups"].sort(key=lambda g: str(g.get("group", "")))
    return detail


CSV_COLUMNS = (
    "group", "status", "eligible", "subjects", "embeddings", "genuine_pairs",
    "impostor_pairs", "frr", "frr_ci_low", "frr_ci_high", "far", "far_ci_low",
    "far_ci_high", "far_cross", "group_threshold_for_target",
)


def _csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection in text cells."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


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
    run = get_bias_run(db, run_id)
    detail = run_detail(run)

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(CSV_COLUMNS)
        for g in detail["subgroups"]:
            frr_ci = g.get("frr_ci95") or [None, None]
            far_ci = g.get("far_ci95") or [None, None]
            writer.writerow([
                _csv_safe(g.get("group")), g.get("status"), g.get("eligible"),
                g.get("subjects"), g.get("embeddings"), g.get("genuine_pairs"),
                g.get("impostor_pairs"), g.get("frr"), frr_ci[0], frr_ci[1],
                g.get("far"), far_ci[0], far_ci[1], g.get("far_cross"),
                g.get("group_threshold_for_target"),
            ])
        body, media = buf.getvalue().encode("utf-8"), "text/csv; charset=utf-8"
    else:
        report = {
            "report_type": "facetrust.fr4.subgroup_metrics",
            "exported_at": utc_iso(utcnow()),
            "privacy_note": ("Aggregate metrics only; no subject identifiers, images or "
                             f"embeddings. Groups with fewer than {MIN_REPORTABLE_SUBJECTS} "
                             "subjects are suppressed."),
            **detail,
        }
        body = json.dumps(report, indent=2, sort_keys=True).encode("utf-8")
        media = "application/json"

    audit.record(
        db,
        event="REPORT_EXPORTED",
        actor_id=actor_id,
        actor_role=actor_role,
        ip=ip,
        payload={"module": "subgroup_metrics", "run_id": run.id, "format": fmt,
                 "bytes": len(body)},
    )
    return body, media, f"subgroup-run-{run.id}.{fmt}"