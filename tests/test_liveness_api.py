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

def test_unauthenticated_check_is_rejected(client: TestClient):
    response = _upload(client)
    assert response.status_code == 401
    assert response.json()["error_code"] == "AUTH-SESSION-INVALID"


def test_missing_csrf_is_rejected(api: ApiHelper):
    api.register_and_login(ADMIN)
    response = _upload(api.client)
    assert response.status_code == 403
    assert response.json()["error_code"] == "AUTH-CSRF-INVALID"


def test_live_and_attack_results_are_explainable_and_audited(admin: ApiHelper):
    live = _upload(admin.client, headers=admin.csrf_headers())
    assert live.status_code == 200, live.text
    live_body = live.json()

    assert live_body["status"] == "completed"
    assert live_body["result"] == "genuine"
    assert live_body["score"] >= 0.7
    assert live_body["reasons"]
    assert live_body["recommended_action"] == "accept_as_live_candidate"
    assert live_body["metrics"]["blur_variance"] >= 0
    assert live_body["input_ref"].startswith("sha256:")
    assert live_body["clean_ref"].startswith("sha256:")

    attack = _upload(admin.client, attack=True, headers=admin.csrf_headers())
    assert attack.status_code == 200, attack.text
    attack_body = attack.json()

    assert attack_body["status"] == "flagged"
    assert attack_body["result"] == "suspicious"
    assert "LIV-BLURRY" in attack_body["rules_fired"]
    assert "LIV-TOO-DARK" in attack_body["rules_fired"]
    assert attack_body["reasons"]
    assert attack_body["recommended_action"] == "manual_review_or_retry"
    assert attack_body["score"] < live_body["score"]

    completed = _audit_events("LIVENESS_CHECK_COMPLETED")
    assert len(completed) == 2
    assert completed[-1]["is_attack"] is True
    assert completed[-1]["outcome"] == "PRESENTATION_ATTACK_DETECTED"
    assert "filename" not in completed[-1]
    assert "file_bytes" not in completed[-1]


def test_invalid_file_is_rejected_and_audited_without_sensitive_data(admin: ApiHelper):
    response = admin.client.post(
        LIVENESS,
        files={"file": ("secret-name.png", b"not-an-image", "image/png")},
        headers=admin.csrf_headers(),
    )
    assert response.status_code == 400
    assert response.json()["error_code"] == "FILE-TYPE-INVALID"

    failed = _audit_events("LIVENESS_CHECK_FAILED")
    assert len(failed) == 1
    assert failed[0]["error_code"] == "FILE-TYPE-INVALID"
    assert failed[0]["input_ref"].startswith("sha256:")
    assert "secret-name" not in json.dumps(failed[0])
    assert "not-an-image" not in json.dumps(failed[0])
