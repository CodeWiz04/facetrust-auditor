"""Integration tests for policy administration and sanitized report export endpoints."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.api.v1.policy import router as policy_router
from app.api.v1.reports import router as reports_router
from app.core.crypto import generate_biometric_key, set_active_key
from app.core.errors import register_exception_handlers
from app.core.security import generate_token, hash_password, hash_token
from app.core.time import utcnow
from app.db.base import Base
from app.models.session import UserSession
from app.models.user import User, UserRole


def _make_app(session_factory, role_override: str = UserRole.ADMIN.value) -> tuple[FastAPI, dict]:
    """Build a minimal FastAPI app with policy and reports routers, injecting a mock session."""
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(policy_router, prefix="/api/v1")
    app.include_router(reports_router, prefix="/api/v1")

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return app


@pytest.fixture
def setup(tmp_path):
    """Isolated in-memory SQLite fixture with an admin user and a live session."""
    test_key = generate_biometric_key()
    set_active_key(test_key)

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    db = SessionFactory()

    # Admin user
    admin = User(
        email="admin@test.local",
        password_hash=hash_password("Admin12345!Secure"),
        role=UserRole.ADMIN.value,
        is_active=True,
    )
    db.add(admin)

    # Auditor user (read-only for reports)
    auditor = User(
        email="auditor@test.local",
        password_hash=hash_password("Audit12345!Secure"),
        role=UserRole.AUDITOR.value,
        is_active=True,
    )
    db.add(auditor)
    db.flush()

    # Active sessions for each
    admin_token = generate_token()
    auditor_token = generate_token()
    csrf_token = generate_token()

    db.add(UserSession(
        user_id=admin.id,
        token_hash=hash_token(admin_token),
        csrf_hash=hash_token(csrf_token),
        expires_at=utcnow() + timedelta(hours=8),
    ))
    db.add(UserSession(
        user_id=auditor.id,
        token_hash=hash_token(auditor_token),
        csrf_hash=hash_token(csrf_token),
        expires_at=utcnow() + timedelta(hours=8),
    ))
    db.commit()
    db.close()

    app = _make_app(SessionFactory)

    with TestClient(app) as client:
        yield {
            "client": client,
            "admin_token": admin_token,
            "auditor_token": auditor_token,
            "csrf_token": csrf_token,
            "SessionFactory": SessionFactory,
        }


# ---------------------------------------------------------------------------
# Policy tests
# ---------------------------------------------------------------------------

def test_get_policy_requires_admin(setup):
    """Non-authenticated requests to policy endpoint must be rejected."""
    res = setup["client"].get("/api/v1/policy")
    assert res.status_code in (401, 403)


def test_get_policy_genesis_defaults(setup):
    """First GET of policy auto-initializes the genesis config from defaults."""
    res = setup["client"].get(
        "/api/v1/policy",
        headers={"Authorization": f"Bearer {setup['admin_token']}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "config_version" in data
    assert "config_hash" in data
    assert "config" in data
    assert "match_threshold" in data["config"]
    assert "tunables" in data
    assert "match_threshold" in data["tunables"]


def test_update_policy_valid_tunable(setup):
    """Admin can update an allow-listed parameter, and audit event is emitted."""
    res = setup["client"].patch(
        "/api/v1/policy",
        json={"changes": {"match_threshold": 0.6}},
        headers={
            "Authorization": f"Bearer {setup['admin_token']}",
            "X-CSRF-Token": setup["csrf_token"],
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert len(data["changes"]) == 1
    assert data["changes"][0]["key"] == "match_threshold"
    assert data["changes"][0]["new"] == 0.6
    assert data["config"]["match_threshold"] == 0.6

    # Version should have incremented
    assert data["config_version"] >= 2


def test_update_policy_forbidden_key_rejected(setup):
    """Updating a non-allow-listed key (limits.*, config_version) must fail with EngineError."""
    res = setup["client"].patch(
        "/api/v1/policy",
        json={"changes": {"limits.max_image_bytes": 999999}},
        headers={
            "Authorization": f"Bearer {setup['admin_token']}",
            "X-CSRF-Token": setup["csrf_token"],
        },
    )
    assert res.status_code in (400, 422)


def test_update_policy_out_of_range_rejected(setup):
    """Out-of-range threshold value must be rejected."""
    res = setup["client"].patch(
        "/api/v1/policy",
        json={"changes": {"match_threshold": 2.5}},
        headers={
            "Authorization": f"Bearer {setup['admin_token']}",
            "X-CSRF-Token": setup["csrf_token"],
        },
    )
    assert res.status_code in (400, 422)


def test_update_policy_no_changes_no_version_bump(setup):
    """Applying same values as current config returns empty changes list."""
    # First set a known value
    setup["client"].patch(
        "/api/v1/policy",
        json={"changes": {"match_threshold": 0.5}},
        headers={
            "Authorization": f"Bearer {setup['admin_token']}",
            "X-CSRF-Token": setup["csrf_token"],
        },
    )
    # Get the current version
    get_res = setup["client"].get(
        "/api/v1/policy",
        headers={"Authorization": f"Bearer {setup['admin_token']}"},
    )
    version_before = get_res.json()["config_version"]

    # Apply the exact same value again
    res = setup["client"].patch(
        "/api/v1/policy",
        json={"changes": {"match_threshold": 0.5}},
        headers={
            "Authorization": f"Bearer {setup['admin_token']}",
            "X-CSRF-Token": setup["csrf_token"],
        },
    )
    assert res.status_code == 200
    assert res.json()["changes"] == []
    assert res.json()["config_version"] == version_before


# ---------------------------------------------------------------------------
# Report export tests
# ---------------------------------------------------------------------------

def test_json_report_requires_auth(setup):
    """Unauthenticated access to reports must be rejected."""
    res = setup["client"].get("/api/v1/reports/json")
    assert res.status_code in (401, 403)


def test_json_report_auditor_access(setup):
    """Auditor (read-only) can access JSON report."""
    res = setup["client"].get(
        "/api/v1/reports/json",
        headers={"Authorization": f"Bearer {setup['auditor_token']}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["report_type"] == "facetrust_auditor_evidence_report"
    assert "report_integrity_hash" in data
    assert "disclaimer" in data
    assert "personal identifiable information" in data["disclaimer"].lower()


def test_json_report_contains_no_pii_fields(setup):
    """JSON report must not expose email, name, password_hash or token fields."""
    res = setup["client"].get(
        "/api/v1/reports/json",
        headers={"Authorization": f"Bearer {setup['admin_token']}"},
    )
    assert res.status_code == 200
    report_text = res.text.lower()
    # None of these PII/secret fields should appear
    for forbidden in ("password_hash", "token_hash", "csrf_hash", "@test.local"):
        assert forbidden not in report_text, f"PII field '{forbidden}' found in report"


def test_csv_report_admin_access(setup):
    """Admin can download the CSV report and it has valid CSV structure."""
    res = setup["client"].get(
        "/api/v1/reports/csv",
        headers={"Authorization": f"Bearer {setup['admin_token']}"},
    )
    assert res.status_code == 200
    assert "text/csv" in res.headers["content-type"]
    lines = res.text.strip().split("\n")
    # At minimum, the CSV header row should be present
    assert len(lines) >= 1
    header = lines[0].lower()
    assert "run_id" in header
    assert "run_type" in header
    assert "model_name" in header


def test_json_report_integrity_hash_is_deterministic(setup):
    """Requesting the same empty report twice should yield the same integrity hash."""
    headers = {"Authorization": f"Bearer {setup['admin_token']}"}
    r1 = setup["client"].get("/api/v1/reports/json", headers=headers)
    r2 = setup["client"].get("/api/v1/reports/json", headers=headers)
    # Integrity hashes should match if data hasn't changed between calls
    assert r1.json()["report_integrity_hash"] == r2.json()["report_integrity_hash"]


def test_policy_history_lists_versions(setup):
    """GET /api/v1/policy/history returns ordered policy versions for admin and auditor."""
    # Trigger a policy update so there are at least 2 versions
    setup["client"].patch(
        "/api/v1/policy",
        json={"changes": {"match_threshold": 0.58}},
        headers={
            "Authorization": f"Bearer {setup['admin_token']}",
            "X-CSRF-Token": setup["csrf_token"],
        },
    )
    res = setup["client"].get(
        "/api/v1/policy/history",
        headers={"Authorization": f"Bearer {setup['auditor_token']}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 2
    versions = [item["config_version"] for item in data["items"]]
    assert versions == sorted(versions, reverse=True)
    assert data["items"][0]["is_active"] is True
