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
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.config import get_settings
from app.core.errors import AppError
from app.core.rate_limit import client_ip
from app.core.security import hash_token
from app.core.time import utcnow
from app.models.session import UserSession
from app.schemas.evaluation import (
    EvaluationListResponse,
    LivenessCheckResponse,
    SubgroupBiasRequest,
    SubgroupBiasResponse,
    ThresholdEvalRequest,
    ThresholdEvalResponse,
)
from app.services import evaluation_service

router = APIRouter(prefix="/evaluations", tags=["evaluations"])


def _resolve_actor(request: Request, db: Session) -> tuple[str, str]:
    """Resolve caller's actor ID and role from active session or defaults."""
    settings = get_settings()
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]

    if token:
        thash = hash_token(token)
        session = db.scalar(
            Session.select(UserSession).where(
                UserSession.token_hash == thash,
                UserSession.revoked_at.is_(None),
            )
        ) if hasattr(Session, "select") else None
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
    db: Session = Depends(get_db),
) -> ThresholdEvalResponse:
    """Tune biometric match threshold, compute ROC/DET curve, EER, and FAR/FRR metrics."""
    actor_id, actor_role = _resolve_actor(request, db)
    ip = client_ip(request)
    return evaluation_service.run_threshold_evaluation(
        db=db,
        request=payload,
        actor_id=actor_id,
        actor_role=actor_role,
        ip=ip,
    )


@router.post(
    "/bias",
    response_model=SubgroupBiasResponse,
    status_code=status.HTTP_200_OK,
    summary="Run demographic subgroup bias audit (FR-4)",
)
def evaluate_bias(
    payload: SubgroupBiasRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> SubgroupBiasResponse:
    """Audit biometric accuracy across demographic subgroups and compute disparity metrics."""
    actor_id, actor_role = _resolve_actor(request, db)
    ip = client_ip(request)
    return evaluation_service.run_subgroup_bias_audit(
        db=db,
        request=payload,
        actor_id=actor_id,
        actor_role=actor_role,
        ip=ip,
    )


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
