"""Sanitized evidence report export API endpoints (FR-6 privacy constraints)."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_roles
from app.models.user import User, UserRole
from app.services import report_service

router = APIRouter(prefix="/reports", tags=["reports"])

_readers = require_roles(UserRole.ADMIN.value, UserRole.AUDITOR.value)


@router.get(
    "/json",
    status_code=status.HTTP_200_OK,
    summary="Export sanitized JSON evidence report",
)
def export_json_report(
    run_id: str | None = Query(default=None, description="Restrict report to a specific evaluation run ID"),
    audit_tail: int = Query(default=20, ge=1, le=200, description="Number of audit events to include"),
    _: User = Depends(_readers),
    db: Session = Depends(get_db),
) -> Response:
    """Return a PII-free JSON report with evaluation metrics, subgroup summaries, and audit chain tail."""
    report = report_service.build_json_report(
        db=db, run_id=run_id, include_audit_tail=audit_tail
    )
    return Response(
        content=json.dumps(report, indent=2, ensure_ascii=True),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=facetrust_report.json"},
    )


@router.get(
    "/csv",
    status_code=status.HTTP_200_OK,
    summary="Export sanitized CSV evaluation metrics report",
)
def export_csv_report(
    _: User = Depends(_readers),
    db: Session = Depends(get_db),
) -> Response:
    """Return a CSV file of all evaluation runs and per-item metrics with no PII."""
    csv_bytes = report_service.build_csv_report(db=db)
    return Response(
        content=csv_bytes,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=facetrust_report.csv"},
    )
