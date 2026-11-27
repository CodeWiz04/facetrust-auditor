"""API endpoints for threshold tuning, demographic bias auditing, and presentation-attack detection."""

from __future__ import annotations

import json
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    File,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_csrf, require_roles_audited
from app.api.v1 import subgroups, thresholds
from app.core.config import get_settings
from app.core.errors import AppError
from app.core.rate_limit import client_ip
from app.core.security import hash_token
from app.core.time import utcnow
from app.models.session import UserSession
from app.models.user import User, UserRole
from app.schemas.evaluation import (
    EvaluationListResponse,
    LivenessCheckResponse,
    SubgroupBiasRequest,
    SubgroupBiasResponse,
    ThresholdEvalRequest,
    ThresholdEvalResponse,
)
from app.services import evaluation_service, report_service

router = APIRouter(prefix="/evaluations", tags=["evaluations"])


def _resolve_actor(request: Request, db: Session) -> tuple[str, str]:
    """Best-effort caller identity for audit entries of the FR-5 endpoint.

    (The previous version called a non-existent `Session.select`, so it
    never found the session.) FR-3 / FR-4 endpoints do not use this: they require
    an authenticated, authorized user via dependencies.
    """
    settings = get_settings()
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]

    if token:
        session = db.scalar(
            select(UserSession).where(
                UserSession.token_hash == hash_token(token),
                UserSession.revoked_at.is_(None),
            )
        )
        if session and session.expires_at > utcnow() and session.user:
            return session.user.id, session.user.role

    return "auditor-operator", "operator"


@router.post(
    "/threshold",
    response_model=ThresholdEvalResponse,
    status_code=status.HTTP_200_OK,
    summary="Run genuine vs. impostor threshold evaluation (FR-3)",
)
def evaluate_threshold(
    payload: ThresholdEvalRequest,
    request: Request,
    user: User = Depends(require_roles_audited(
        "threshold.evaluate", UserRole.ADMIN.value, UserRole.ANALYST.value
    )),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> ThresholdEvalResponse:
    """Same as POST /api/v1/threshold/evaluate (kept for existing clients).

    Requires an authenticated admin/analyst session and the X-CSRF-Token header.
    """
    return thresholds.run_evaluation(payload, request, user, db)


@router.post(
    "/bias",
    response_model=SubgroupBiasResponse,
    status_code=status.HTTP_200_OK,
    summary="Run demographic subgroup bias audit (FR-4)",
)
def evaluate_bias(
    payload: SubgroupBiasRequest,
    request: Request,
    user: User = Depends(require_roles_audited(
        "subgroup.audit", UserRole.ADMIN.value, UserRole.ANALYST.value
    )),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> SubgroupBiasResponse:
    """Same as POST /api/v1/subgroups/audit (kept for existing clients).

    Requires an authenticated admin/analyst session and the X-CSRF-Token header.
    """
    return subgroups.run_audit(payload, request, user, db)


@router.post(
    "/liveness",
    response_model=LivenessCheckResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze image for presentation attacks / liveness cues (FR-5)",
)
def evaluate_liveness(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> LivenessCheckResponse:
    """Check uploaded image against blur, frequency moiré, specular glare, and luminance rules."""
    actor_id, actor_role = _resolve_actor(request, db)
    ip = client_ip(request)

    file_bytes = file.file.read()
    if not file_bytes:
        raise AppError("FILE-CORRUPT", detail="Uploaded sample file is empty")

    return evaluation_service.evaluate_liveness_sample(
        db=db,
        file_bytes=file_bytes,
        claimed_name=file.filename or "sample.png",
        actor_id=actor_id,
        actor_role=actor_role,
        ip=ip,
    )


@router.get(
    "",
    response_model=EvaluationListResponse,
    status_code=status.HTTP_200_OK,
    summary="List historical evaluation runs",
)
def list_evaluations(
    run_type: str | None = Query(
        default=None, description="Filter by evaluation type (threshold, bias_audit, liveness)"
    ),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> EvaluationListResponse:
    """Retrieve historical evaluation runs in reverse chronological order."""
    return evaluation_service.list_evaluation_runs(
        db=db,
        run_type=run_type,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{run_id}",
    response_model=dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Get details of a specific evaluation run",
)
def get_evaluation(
    run_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Retrieve full evaluation run metadata and granular item results."""
    run = evaluation_service.get_evaluation_run(db=db, run_id=run_id)

    results_data = []
    for res in run.results:
        results_data.append({
            "id": res.id,
            "category": res.category,
            "item_key": res.item_key,
            "metrics": json.loads(res.metrics_json) if res.metrics_json else {},
            "decision": json.loads(res.decision_json) if res.decision_json else None,
            "created_at": res.created_at.isoformat(),
        })

    return {
        "id": run.id,
        "run_type": run.run_type,
        "model_name": run.model_name,
        "model_version": run.model_version,
        "config_hash": run.config_hash,
        "operating_threshold": run.operating_threshold,
        "summary_metrics": json.loads(run.summary_metrics_json) if run.summary_metrics_json else {},
        "created_by": run.created_by,
        "created_at": run.created_at.isoformat(),
        "results": results_data,
    }


@router.get(
    "/{run_id}/export",
    status_code=status.HTTP_200_OK,
    summary="Export sanitized evidence report for a specific evaluation run",
)
def export_evaluation_run(
    run_id: str,
    format: str = Query(default="json", pattern="^(json|csv)$", description="Export format: json or csv"),
    db: Session = Depends(get_db),
) -> Response:
    """Export a PII-free JSON or CSV evidence report for a specific evaluation run."""
    # Ensure the run exists (raises NOT-FOUND if missing)
    evaluation_service.get_evaluation_run(db=db, run_id=run_id)

    if format == "csv":
        csv_bytes = report_service.build_csv_report(db=db)
        return Response(
            content=csv_bytes,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=evaluation_{run_id}.csv"},
        )

    report = report_service.build_json_report(db=db, run_id=run_id)
    return Response(
        content=json.dumps(report, indent=2, ensure_ascii=True),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=evaluation_{run_id}.json"},
    )