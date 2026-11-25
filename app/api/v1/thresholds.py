"""FR-3 threshold tuning API.

Roles (enforced on the server):

  action                               admin  analyst  auditor
  -----------------------------------  -----  -------  -------
  run an evaluation                      x       x
  read active policy                     x       x        x
  list / read / export runs              x       x        x
  read policy history                    x                x
  change threshold / apply a run         x

Every state-changing call needs the X-CSRF-Token header. High-impact calls
(changing the threshold) also need `"confirm": true` and a reason.
Denied attempts are audited (ACCESS_DENIED) and answered with a generic 403.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_csrf, require_roles_audited
from app.core import audit
from app.core.errors import AppError
from app.core.rate_limit import client_ip, enforce
from app.models.user import User, UserRole
from app.schemas.evaluation import ThresholdEvalRequest, ThresholdEvalResponse
from app.schemas.threshold import (
    ApplyRecommendationRequest,
    PolicyHistoryResponse,
    PolicyResponse,
    PolicyUpdateRequest,
    PolicyUpdateResponse,
    ThresholdRunItem,
    ThresholdRunListResponse,
)
from app.services import policy_service, threshold_service

router = APIRouter(prefix="/threshold", tags=["threshold (FR-3)"])

ADMIN = UserRole.ADMIN.value
ANALYST = UserRole.ANALYST.value
AUDITOR = UserRole.AUDITOR.value

_can_run = require_roles_audited("threshold.evaluate", ADMIN, ANALYST)
_can_read = require_roles_audited("threshold.read", ADMIN, ANALYST, AUDITOR)
_can_read_history = require_roles_audited("threshold.policy_history", ADMIN, AUDITOR)
_can_change = require_roles_audited("threshold.policy_change", ADMIN)

# Sensitive / expensive actions are rate limited per user.
EVALUATE_LIMIT, EVALUATE_WINDOW = 10, 60
CHANGE_LIMIT, CHANGE_WINDOW = 10, 60


def run_evaluation(
    payload: ThresholdEvalRequest, request: Request, user: User, db: Session
) -> ThresholdEvalResponse:
    """Shared by POST /threshold/evaluate and POST /evaluations/threshold."""
    enforce(request, "threshold.evaluate", EVALUATE_LIMIT, EVALUATE_WINDOW, identity=user.id)
    return threshold_service.run_threshold_tuning(
        db, payload, actor_id=user.id, actor_role=user.role, ip=client_ip(request)
    )


@router.post("/evaluate", response_model=ThresholdEvalResponse,
             summary="Run threshold tuning on consented embeddings (FR-3, T1/T2)")
def evaluate(
    payload: ThresholdEvalRequest,
    request: Request,
    user: User = Depends(_can_run),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> ThresholdEvalResponse:
    return run_evaluation(payload, request, user, db)


# ---------------------------------------------------------------- policy
@router.get("/policy", response_model=PolicyResponse, summary="Active threshold policy")
def get_policy(
    _: User = Depends(_can_read),
    db: Session = Depends(get_db),
) -> PolicyResponse:
    config, row = policy_service.get_active_policy(db)
    return PolicyResponse(**policy_service.policy_to_dict(row, config))


@router.get("/policy/history", response_model=PolicyHistoryResponse,
            summary="All policy versions, newest first")
def policy_history(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(_can_read_history),
    db: Session = Depends(get_db),
) -> PolicyHistoryResponse:
    rows, total = policy_service.list_policy_versions(db, limit=limit, offset=offset)
    return PolicyHistoryResponse(
        items=[PolicyResponse(**policy_service.policy_to_dict(r)) for r in rows], total=total
    )


def _require_confirmation(db: Session, user: User, request: Request, confirm: bool,
                          action: str) -> None:
    if confirm is not True:
        audit.record(
            db, event="CONFIG_CHANGE_REJECTED", actor_id=user.id, actor_role=user.role,
            ip=client_ip(request),
            payload={"error_code": "CFG-CONFIRMATION-REQUIRED", "action": action},
        )
        raise AppError("CFG-CONFIRMATION-REQUIRED", detail=action)


@router.patch("/policy", response_model=PolicyUpdateResponse,
              summary="Change match threshold / target FAR (admin, confirmed)")
def update_policy(
    body: PolicyUpdateRequest,
    request: Request,
    admin: User = Depends(_can_change),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> PolicyUpdateResponse:
    enforce(request, "threshold.policy_change", CHANGE_LIMIT, CHANGE_WINDOW, identity=admin.id)
    _require_confirmation(db, admin, request, body.confirm, "policy_update")
    row, records = policy_service.apply_changes(
        db,
        changes=body.changes(),
        reason=body.reason,
        actor_id=admin.id,
        actor_role=admin.role,
        ip=client_ip(request),
        expected_version=body.expected_version,
    )
    return PolicyUpdateResponse(
        changed=bool(records),
        policy=PolicyResponse(**policy_service.policy_to_dict(row)),
        changes=records,
    )


# ---------------------------------------------------------------- runs
@router.get("/runs", response_model=ThresholdRunListResponse,
            summary="Threshold tuning history (filterable)")
def list_runs(
    status: str | None = Query(default=None, pattern=r"^(completed|flagged|rejected)$"),
    model_name: str | None = Query(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(_can_read),
    db: Session = Depends(get_db),
) -> ThresholdRunListResponse:
    items, total = threshold_service.list_threshold_runs(
        db, status=status, model_name=model_name, limit=limit, offset=offset
    )
    return ThresholdRunListResponse(items=[ThresholdRunItem(**i) for i in items], total=total)


@router.get("/runs/{run_id}", summary="Full evidence for one run (curve, decision, rules)")
def get_run(
    run_id: str,
    _: User = Depends(_can_read),
    db: Session = Depends(get_db),
) -> dict:
    return threshold_service.run_detail(threshold_service.get_threshold_run(db, run_id))


@router.get("/runs/{run_id}/export", summary="Sanitized report export (json or csv)")
def export_run(
    run_id: str,
    request: Request,
    format: str = Query(default="json", pattern=r"^(json|csv)$"),
    user: User = Depends(_can_read),
    db: Session = Depends(get_db),
) -> Response:
    body, media_type, filename = threshold_service.export_run(
        db, run_id, format, actor_id=user.id, actor_role=user.role, ip=client_ip(request)
    )
    return Response(
        content=body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/runs/{run_id}/apply", response_model=PolicyUpdateResponse,
             summary="Apply a run's recommended threshold (admin, confirmed)")
def apply_run(
    run_id: str,
    body: ApplyRecommendationRequest,
    request: Request,
    admin: User = Depends(_can_change),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> PolicyUpdateResponse:
    enforce(request, "threshold.policy_change", CHANGE_LIMIT, CHANGE_WINDOW, identity=admin.id)
    _require_confirmation(db, admin, request, body.confirm, "apply_run")
    row, records = threshold_service.apply_run_recommendation(
        db,
        run_id,
        reason=body.reason,
        acknowledge_low_confidence=body.acknowledge_low_confidence,
        expected_version=body.expected_version,
        actor_id=admin.id,
        actor_role=admin.role,
        ip=client_ip(request),
    )
    return PolicyUpdateResponse(
        changed=bool(records),
        policy=PolicyResponse(**policy_service.policy_to_dict(row)),
        changes=records,
    )