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
