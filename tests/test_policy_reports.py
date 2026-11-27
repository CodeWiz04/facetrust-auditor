"""Integration tests for policy administration and sanitized report export endpoints.

Uses the full app (conftest `client` / `api` fixtures).
"""

from __future__ import annotations

import json
import pytest
from fastapi.testclient import TestClient

from app.models.user import UserRole
from tests.conftest import ApiHelper


@pytest.fixture
def auth_users(api: ApiHelper):
    """Set up admin and auditor users with active sessions on the full app."""
    # First registered user is automatically ADMIN
    api.register_and_login("admin@example.com", "Admin12345!Secure")
    
    # Register second user (starts as ANALYST) and promote to AUDITOR
    created = api.register("auditor@example.com", "Audit12345!Secure").json()
    role_res = api.client.patch(
        f"/api/v1/users/{created['id']}/role",
        json={"role": UserRole.AUDITOR.value},
        headers=api.csrf_headers(),
    )
    assert role_res.status_code == 200, role_res.text

    with TestClient(api.client.app) as auditor_client:
        auditor_api = ApiHelper(auditor_client)
        login_res = auditor_api.login("auditor@example.com", "Audit12345!Secure")
        assert login_res.status_code == 200, login_res.text
        yield {
            "admin": api,
            "auditor": auditor_api,
        }


# ---------------------------------------------------------------------------
# Policy tests
# ---------------------------------------------------------------------------

def test_get_policy_requires_admin(client: TestClient):
    """Non-authenticated requests to policy endpoint must be rejected."""
    res = client.get("/api/v1/policy")
    assert res.status_code in (401, 403)


def test_get_policy_genesis_defaults(auth_users):
    """First GET of policy auto-initializes the genesis config from defaults."""
    admin: ApiHelper = auth_users["admin"]
    res = admin.client.get("/api/v1/policy")
    assert res.status_code == 200
    data = res.json()
    assert "config_version" in data
    assert "config_hash" in data
    assert "config" in data
    assert "match_threshold" in data["config"]
    assert "tunables" in data
    assert "match_threshold" in data["tunables"]


def test_update_policy_valid_tunable(auth_users):
    """Admin can update an allow-listed parameter, and audit event is emitted."""
    admin: ApiHelper = auth_users["admin"]
    res = admin.client.patch(
        "/api/v1/policy",
        json={"changes": {"match_threshold": 0.6}},
        headers=admin.csrf_headers(),
    )
    assert res.status_code == 200
    data = res.json()
    assert len(data["changes"]) == 1
    assert data["changes"][0]["key"] == "match_threshold"
    assert data["changes"][0]["new"] == 0.6
    assert data["config"]["match_threshold"] == 0.6

    # Version should have incremented
    assert data["config_version"] >= 2


def test_update_policy_forbidden_key_rejected(auth_users):
    """Updating a non-allow-listed key (limits.*, config_version) must fail with EngineError."""
    admin: ApiHelper = auth_users["admin"]
    res = admin.client.patch(
        "/api/v1/policy",
        json={"changes": {"limits.max_image_bytes": 999999}},
        headers=admin.csrf_headers(),
    )
    assert res.status_code in (400, 422)


def test_update_policy_out_of_range_rejected(auth_users):
    """Out-of-range threshold value must be rejected."""
    admin: ApiHelper = auth_users["admin"]
    res = admin.client.patch(
        "/api/v1/policy",
        json={"changes": {"match_threshold": 2.5}},
        headers=admin.csrf_headers(),
    )
    assert res.status_code in (400, 422)


def test_update_policy_no_changes_no_version_bump(auth_users):
    """Applying same values as current config returns empty changes list."""
    admin: ApiHelper = auth_users["admin"]
    # First set a known value
    admin.client.patch(
        "/api/v1/policy",
        json={"changes": {"match_threshold": 0.5}},
        headers=admin.csrf_headers(),
    )
    # Get the current version
    get_res = admin.client.get("/api/v1/policy")
    version_before = get_res.json()["config_version"]

    # Apply the exact same value again
    res = admin.client.patch(
        "/api/v1/policy",
        json={"changes": {"match_threshold": 0.5}},
        headers=admin.csrf_headers(),
    )
    assert res.status_code == 200
    assert res.json()["changes"] == []
    assert res.json()["config_version"] == version_before


# ---------------------------------------------------------------------------
# Report export tests
# ---------------------------------------------------------------------------

def test_json_report_requires_auth(client: TestClient):
    """Unauthenticated access to reports must be rejected."""
    res = client.get("/api/v1/reports/json")
    assert res.status_code in (401, 403)


def test_json_report_auditor_access(auth_users):
    """Auditor (read-only) can access JSON report."""
    auditor: ApiHelper = auth_users["auditor"]
    res = auditor.client.get("/api/v1/reports/json")
    assert res.status_code == 200
    data = res.json()
    assert data["report_type"] == "facetrust_auditor_evidence_report"
    assert "report_integrity_hash" in data
    assert "disclaimer" in data
    assert "personal identifiable information" in data["disclaimer"].lower()


def test_json_report_contains_no_pii_fields(auth_users):
    """JSON report must not expose email, name, password_hash or token fields."""
    admin: ApiHelper = auth_users["admin"]
    res = admin.client.get("/api/v1/reports/json")
    assert res.status_code == 200
    report_text = res.text.lower()
    for forbidden in ("password_hash", "token_hash", "csrf_hash", "@example.com"):
        assert forbidden not in report_text, f"PII field '{forbidden}' found in report"


def test_csv_report_admin_access(auth_users):
    """Admin can download the CSV report and it has valid CSV structure."""
    admin: ApiHelper = auth_users["admin"]
    res = admin.client.get("/api/v1/reports/csv")
    assert res.status_code == 200
    assert "text/csv" in res.headers["content-type"]
    lines = res.text.strip().split("\n")
    assert len(lines) >= 1
    header = lines[0].lower()
    assert "run_id" in header
    assert "run_type" in header
    assert "model_name" in header


def test_json_report_integrity_hash_is_deterministic(auth_users):
    """Requesting the same empty report twice should yield the same integrity hash."""
    admin: ApiHelper = auth_users["admin"]
    r1 = admin.client.get("/api/v1/reports/json")
    r2 = admin.client.get("/api/v1/reports/json")
    assert r1.json()["report_integrity_hash"] == r2.json()["report_integrity_hash"]


def test_policy_history_lists_versions(auth_users):
    """GET /api/v1/policy/history returns ordered policy versions for admin and auditor."""
    admin: ApiHelper = auth_users["admin"]
    auditor: ApiHelper = auth_users["auditor"]
    # Trigger a policy update so there are at least 2 versions
    admin.client.patch(
        "/api/v1/policy",
        json={"changes": {"match_threshold": 0.58}},
        headers=admin.csrf_headers(),
    )
    res = auditor.client.get("/api/v1/policy/history")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 2
    versions = [item["config_version"] for item in data["items"]]
    assert versions == sorted(versions, reverse=True)
    assert data["items"][0]["is_active"] is True
