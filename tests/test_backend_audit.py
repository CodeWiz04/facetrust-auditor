"""Backend 1: hash-chained audit log integrity and PII hygiene."""

from __future__ import annotations

import json

from sqlalchemy import select

from app.core.audit import GENESIS_HASH, sanitize
from app.db.session import SessionLocal
from app.models.audit import AuditLog
from tests.conftest import ApiHelper

EMAIL = "auditor@example.com"


def _events(api: ApiHelper) -> list[dict]:
    response = api.client.get("/api/v1/audit/events?limit=500")
    assert response.status_code == 200, response.text
    return response.json()["items"]


def test_audit_records_auth_events_and_verifies(api: ApiHelper):
    api.register_and_login(EMAIL)
    api.client.post("/api/v1/auth/logout", headers=api.csrf_headers())
    # Log back in to read the audit trail (logout cleared the cookies).
    assert api.login(EMAIL).status_code == 200

    events = _events(api)
    names = [event["event"] for event in events]
    assert "user.registered" in names
    assert "auth.login_succeeded" in names
    assert "auth.logout" in names

    assert events[0]["seq"] == 1
    assert events[0]["prev_hash"] == GENESIS_HASH
    for previous, current in zip(events, events[1:]):
        assert current["prev_hash"] == previous["entry_hash"]

    verified = api.client.get("/api/v1/audit/verify")
    assert verified.status_code == 200
    assert verified.json()["chain_ok"] is True
    assert verified.json()["entries"] == len(events)


def test_audit_never_contains_password_or_raw_email(api: ApiHelper):
    api.register(EMAIL)
    # Unknown-account failures store only a hash of the attempted email.
    api.login("ghost@example.com", password="WrongPassword123!")
    assert api.login(EMAIL).status_code == 200

    events = _events(api)
    serialized = json.dumps(events)
    assert "WrongPassword123!" not in serialized
    assert EMAIL not in serialized
    assert "email_sha256" in serialized


def test_tampering_with_an_entry_breaks_the_chain(api: ApiHelper):
    api.register_and_login(EMAIL)
    assert api.client.get("/api/v1/audit/verify").json()["chain_ok"] is True

    with SessionLocal() as db:
        entry = db.execute(
            select(AuditLog).order_by(AuditLog.seq).limit(1)
        ).scalar_one()
        entry.payload_json = json.dumps({"tampered": True})
        db.commit()

    verified = api.client.get("/api/v1/audit/verify").json()
    assert verified["chain_ok"] is False
    assert verified["broken_at"] == 1
    assert verified["reason"] == "entry hash mismatch"


def test_sanitize_redacts_secret_fields():
    cleaned = sanitize(
        {
            "password": "hunter2",
            "nested": {"new_password": "x", "safe": "value"},
            "list": [{"csrf_token": "abc"}],
            "bad_float": float("nan"),
        }
    )
    assert cleaned["password"] == "[REDACTED]"
    assert cleaned["nested"]["new_password"] == "[REDACTED]"
    assert cleaned["nested"]["safe"] == "value"
    assert cleaned["list"][0]["csrf_token"] == "[REDACTED]"
    assert cleaned["bad_float"] is None
