"""FR-5 API tests: validation, explainable result, audit, authz, CSRF, misuse.

Uses the full app fixtures from tests/conftest.py.
"""

from __future__ import annotations

import io
import json

from fastapi.testclient import TestClient
from PIL import Image, ImageDraw
from sqlalchemy import select

from app.db.session import SessionLocal
from app.main import app
from app.models.audit import AuditLog
from tests.conftest import ApiHelper

LIVENESS = "/api/v1/liveness/check"
ADMIN = "liveness-admin@example.com"
AUDITOR = "liveness-auditor@example.com"


def _png(*, attack: bool = False) -> bytes:
    """Build a deterministic PNG that passes validation.

    The attack image is flat and dark, which fires LIV-BLURRY and LIV-TOO-DARK.
    """
    if attack:
        img = Image.new("RGB", (120, 120), color=(25, 25, 25))
    else:
        img = Image.new("RGB", (150, 150), color=(120, 140, 160))
        draw = ImageDraw.Draw(img)
        draw.rectangle([20, 20, 130, 130], fill=(200, 180, 150), outline=(0, 0, 0))
        draw.ellipse([40, 40, 60, 60], fill=(30, 30, 30))
        draw.ellipse([90, 40, 110, 60], fill=(30, 30, 30))
        draw.line([75, 65, 75, 85], fill=(70, 40, 40), width=3)
        draw.arc([50, 85, 100, 110], start=0, end=180, fill=(150, 50, 50), width=3)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _upload(client: TestClient, *, attack: bool = False, headers: dict | None = None):
    name = "spoof.png" if attack else "live.png"
    return client.post(
        LIVENESS,
        files={"file": (name, _png(attack=attack), "image/png")},
        headers=headers,
    )


def _audit_events(event: str) -> list[dict]:
    with SessionLocal() as db:
        rows = db.scalars(
            select(AuditLog).where(AuditLog.event == event).order_by(AuditLog.seq)
        ).all()
        return [json.loads(row.payload_json) for row in rows]
