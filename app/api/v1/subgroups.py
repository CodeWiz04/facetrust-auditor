"""FR-4 subgroup metrics (demographic bias audit) API.

Roles (enforced on the server):

  action                               admin  analyst  auditor
  -----------------------------------  -----  -------  -------
  run an audit                           x       x
  group overview (counts only)           x       x        x
  list / read / export runs              x       x        x

Running an audit needs the X-CSRF-Token header and is rate limited per user.
Denied attempts are audited (ACCESS_DENIED) and answered with a generic 403.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_csrf, require_roles_audited
from app.core.rate_limit import client_ip, enforce
from app.models.user import User, UserRole
from app.schemas.evaluation import SubgroupBiasRequest, SubgroupBiasResponse
from app.schemas.subgroup import (
    GroupOverviewResponse,
    SubgroupRunItem,
    SubgroupRunListResponse,
)
from app.services import subgroup_service

router = APIRouter(prefix="/subgroups", tags=["subgroup metrics (FR-4)"])

ADMIN = UserRole.ADMIN.value
ANALYST = UserRole.ANALYST.value
AUDITOR = UserRole.AUDITOR.value

_can_run = require_roles_audited("subgroup.audit", ADMIN, ANALYST)
_can_read = require_roles_audited("subgroup.read", ADMIN, ANALYST, AUDITOR)

AUDIT_LIMIT, AUDIT_WINDOW = 10, 60


def run_audit(
    payload: SubgroupBiasRequest, request: Request, user: User, db: Session
) -> SubgroupBiasResponse:
    """Shared by POST /subgroups/audit and POST /evaluations/bias."""
    enforce(request, "subgroup.audit", AUDIT_LIMIT, AUDIT_WINDOW, identity=user.id)
    return subgroup_service.run_subgroup_audit(
        db, payload, actor_id=user.id, actor_role=user.role, ip=client_ip(request)
    )


@router.post("/audit", response_model=SubgroupBiasResponse,
             summary="Run a demographic subgroup audit (FR-4, T5)")
def audit(
    payload: SubgroupBiasRequest,
    request: Request,
    user: User = Depends(_can_run),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> SubgroupBiasResponse:
    return run_audit(payload, request, user, db)


@router.get("/groups", response_model=GroupOverviewResponse,
            summary="Consented subjects per group (small groups suppressed)")
def groups(
    _: User = Depends(_can_read),
    db: Session = Depends(get_db),
) -> GroupOverviewResponse:
    return GroupOverviewResponse(items=subgroup_service.group_overview(db))


@router.get("/runs", response_model=SubgroupRunListResponse,
            summary="Subgroup audit history (filterable)")
def list_runs(
    status: str | None = Query(default=None, pattern=r"^(completed|flagged|rejected)$"),
    model_name: str | None = Query(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(_can_read),
    db: Session = Depends(get_db),
) -> SubgroupRunListResponse:
    items, total = subgroup_service.list_bias_runs(
        db, status=status, model_name=model_name, limit=limit, offset=offset
    )
    return SubgroupRunListResponse(items=[SubgroupRunItem(**i) for i in items], total=total)


@router.get("/runs/{run_id}", summary="Full evidence for one audit (per-group rates, rules)")
def get_run(
    run_id: str,
    _: User = Depends(_can_read),
    db: Session = Depends(get_db),
) -> dict:
    return subgroup_service.run_detail(subgroup_service.get_bias_run(db, run_id))


@router.get("/runs/{run_id}/export", summary="Sanitized bias report export (json or csv)")
def export_run(
    run_id: str,
    request: Request,
    format: str = Query(default="json", pattern=r"^(json|csv)$"),
    user: User = Depends(_can_read),
    db: Session = Depends(get_db),
) -> Response:
    body, media_type, filename = subgroup_service.export_run(
        db, run_id, format, actor_id=user.id, actor_role=user.role, ip=client_ip(request)
    )
    return Response(
        content=body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )