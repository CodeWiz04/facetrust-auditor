"""FR-5 basic liveness cues API.

Roles (enforced on the server):

  action                         admin  analyst  auditor
  -----------------------------  -----  -------  -------
  run a liveness check             x       x

Checks require an authenticated session, the X-CSRF-Token header, and are
rate limited per user. Denied role attempts are audited (ACCESS_DENIED) and
answered with a generic 403. Uploads are read with a hard byte cap before the
service performs full validation.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Request, UploadFile, status
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_csrf, require_roles_audited
from app.core.rate_limit import client_ip, enforce
from app.models.user import User, UserRole
from app.schemas.liveness import LivenessCheckResponse
from app.services import liveness_service, policy_service

router = APIRouter(prefix="/liveness", tags=["liveness (FR-5)"])

ADMIN = UserRole.ADMIN.value
ANALYST = UserRole.ANALYST.value

_can_check = require_roles_audited("liveness.check", ADMIN, ANALYST)

CHECK_LIMIT, CHECK_WINDOW = 10, 60


@router.post(
    "/check",
    response_model=LivenessCheckResponse,
    status_code=status.HTTP_200_OK,
    summary="Run basic liveness cue analysis (FR-5)",
)
def check_liveness(
    request: Request,
    file: UploadFile = File(..., description="JPEG or PNG face image"),
    user: User = Depends(_can_check),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> LivenessCheckResponse:
    """Validate the image, report explainable cues, and record the action."""
    enforce(request, "liveness.check", CHECK_LIMIT, CHECK_WINDOW, identity=user.id)

    # Bound memory use: read at most one byte beyond the configured cap.
    # The service still owns the authoritative validation and rejection audit.
    max_bytes = int(policy_service.get_active_config(db)["limits"]["max_image_bytes"])
    file_bytes = file.file.read(max_bytes + 1)

    return liveness_service.evaluate_liveness(
        db=db,
        file_bytes=file_bytes,
        claimed_name=file.filename,
        actor_id=user.id,
        actor_role=user.role,
        ip=client_ip(request),
    )
