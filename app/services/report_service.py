"""Sanitized report export service — produces PDF/JSON/CSV evidence packages.

Implements FR-6 privacy constraints:
- No PII in exports (no raw names, emails, or face images)
- Subject identity represented only as opaque SHA-256 pseudonyms
- Evaluation results, ROC curve data, and subgroup metrics included verbatim
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.time import utcnow
from app.models.audit import AuditLog
from app.models.dataset import Subject
from app.models.evaluation import EvaluationResult, EvaluationRun
from engine.hashing import canonical_json, sha256_hex


def _safe_metrics(metrics_json: str | None) -> dict[str, Any]:
    if not metrics_json:
        return {}
    try:
        return json.loads(metrics_json)
    except (ValueError, TypeError):
        return {"parse_error": True}


def build_json_report(
    db: Session,
    run_id: str | None = None,
    include_audit_tail: int = 20,
) -> dict[str, Any]:
    """Build a sanitized JSON evidence report for one or all evaluation runs."""
    now_iso = utcnow().isoformat()

    # Evaluation runs
    if run_id:
        rows = list(db.scalars(select(EvaluationRun).where(EvaluationRun.id == run_id)).all())
    else:
        rows = list(db.scalars(select(EvaluationRun).order_by(EvaluationRun.created_at.desc())).all())

    runs_out = []
    for run in rows:
        results = list(
            db.scalars(
                select(EvaluationResult).where(EvaluationResult.run_id == run.id)
            ).all()
        )
        results_out = [
            {
                "category": r.category,
                "item_key": r.item_key,
                "metrics": _safe_metrics(r.metrics_json),
            }
            for r in results
        ]
        runs_out.append({
            "id": run.id,
            "run_type": run.run_type,
            "model_name": run.model_name,
            "model_version": run.model_version,
            "config_hash": run.config_hash,
            "operating_threshold": run.operating_threshold,
            "summary_metrics": _safe_metrics(run.summary_metrics_json),
            "created_at": run.created_at.isoformat(),
            "results": results_out,
        })

    # Subject summary (pseudonymised only)
    subjects = list(db.scalars(select(Subject)).all())
    subject_summary = {
        "total": len(subjects),
        "by_consent_status": {},
        "by_group": {},
    }
    raw_by_group: dict[str, int] = {}
    for sub in subjects:
        subject_summary["by_consent_status"][sub.consent_status] = (
            subject_summary["by_consent_status"].get(sub.consent_status, 0) + 1
        )
        grp = sub.group or "undisclosed"
        raw_by_group[grp] = raw_by_group.get(grp, 0) + 1

    for grp, count in raw_by_group.items():
        if count < 3:
            subject_summary["by_group"][grp] = {"count": None, "suppressed": True}
        else:
            subject_summary["by_group"][grp] = {"count": count, "suppressed": False}

    # Audit tail (last N events, no PII)
    audit_rows = list(
        db.scalars(
            select(AuditLog).order_by(AuditLog.seq.desc()).limit(include_audit_tail)
        ).all()
    )
    audit_out = [
        {
            "seq": a.seq,
            "event": a.event,
            "actor_role": a.actor_role,
            "hash": a.entry_hash,
            "created_at": a.created_at.isoformat(),
        }
        for a in reversed(audit_rows)
    ]

    report = {
        "report_type": "facetrust_auditor_evidence_report",
        "generated_at": now_iso,
        "schema_version": "1.0",
        "disclaimer": "This report contains no personal identifiable information. Subject identities are opaque pseudonyms only.",
        "subject_summary": subject_summary,
        "evaluation_runs": runs_out,
        "audit_trail_tail": audit_out,
    }

    # Exclude volatile fields (generated_at, report_integrity_hash) so the hash is
    # deterministic across back-to-back calls on identical data.
    hashable = {k: v for k, v in report.items() if k not in ("generated_at", "report_integrity_hash")}
    report_hash = sha256_hex(canonical_json(hashable))
    report["report_integrity_hash"] = report_hash
    return report


def build_csv_report(db: Session, run_id: str | None = None) -> bytes:
    """Build a CSV report of all or a specific evaluation run summary with subgroup metrics."""
    buf = io.StringIO()
    writer = csv.writer(buf)

    writer.writerow([
        "run_id", "run_type", "model_name", "model_version",
        "config_hash", "operating_threshold", "created_at",
        "category", "item_key",
        "far", "frr", "tpr", "threshold",
        "sample_count", "warning",
    ])

    query = select(EvaluationRun)
    if run_id:
        query = query.where(EvaluationRun.id == run_id)
    runs = list(db.scalars(query.order_by(EvaluationRun.created_at)).all())
    for run in runs:
        results = list(
            db.scalars(select(EvaluationResult).where(EvaluationResult.run_id == run.id)).all()
        )
        if not results:
            writer.writerow([
                run.id, run.run_type, run.model_name, run.model_version,
                run.config_hash, run.operating_threshold, run.created_at.isoformat(),
                "", "", "", "", "", "", "", "",
            ])
        for res in results:
            m = _safe_metrics(res.metrics_json)
            writer.writerow([
                run.id, run.run_type, run.model_name, run.model_version,
                run.config_hash, run.operating_threshold, run.created_at.isoformat(),
                res.category, res.item_key,
                m.get("far", ""), m.get("frr", ""), m.get("tpr", ""), m.get("threshold", ""),
                m.get("sample_count", ""), m.get("warning", ""),
            ])

    return buf.getvalue().encode("utf-8")
