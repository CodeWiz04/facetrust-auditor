"""Backend 1: CSRF protection and role-based authorization."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import ApiHelper

ADMIN = "admin@example.com"
ANALYST = "analyst@example.com"


def test_mutating_route_requires_csrf_header(api: ApiHelper):
    api.register_and_login(ADMIN)

    missing = api.client.post("/api/v1/auth/logout")
    assert missing.status_code == 403
    assert missing.json()["error_code"] == "AUTH-CSRF-INVALID"

    wrong = api.client.post(
        "/api/v1/auth/logout", headers={"X-CSRF-Token": "not-the-token"}
    )
    assert wrong.status_code == 403
    assert wrong.json()["error_code"] == "AUTH-CSRF-INVALID"

    ok = api.client.post("/api/v1/auth/logout", headers=api.csrf_headers())
    assert ok.status_code == 200, ok.text


def test_read_only_routes_do_not_need_csrf(api: ApiHelper):
    api.register_and_login(ADMIN)
    assert api.client.get("/api/v1/auth/me").status_code == 200
    assert api.client.get("/api/v1/auth/sessions").status_code == 200


def test_analyst_cannot_access_admin_routes(api: ApiHelper):
    api.register_and_login(ADMIN)

    with TestClient(app) as analyst_client:
        analyst = ApiHelper(analyst_client)
        analyst.register_and_login(ANALYST)

        forbidden = analyst.client.get("/api/v1/users")
        assert forbidden.status_code == 403
        assert forbidden.json()["error_code"] == "AUTH-FORBIDDEN"

        assert analyst.client.get("/api/v1/audit/events").status_code == 403

    allowed = api.client.get("/api/v1/users")
    assert allowed.status_code == 200
    assert allowed.json()["total"] == 2


def test_admin_can_change_role_but_cannot_remove_last_admin(api: ApiHelper):
    api.register_and_login(ADMIN)
    analyst = api.register(ANALYST).json()

    # Missing CSRF -> 403 even for an admin.
    assert (
        api.client.patch(
            f"/api/v1/users/{analyst['id']}/role", json={"role": "auditor"}
        ).status_code
        == 403
    )

    promoted = api.client.patch(
        f"/api/v1/users/{analyst['id']}/role",
        json={"role": "auditor"},
        headers=api.csrf_headers(),
    )
    assert promoted.status_code == 200, promoted.text
    assert promoted.json()["role"] == "auditor"

    me = api.client.get("/api/v1/auth/me").json()
    demote_self = api.client.patch(
        f"/api/v1/users/{me['id']}/role",
        json={"role": "analyst"},
        headers=api.csrf_headers(),
    )
    assert demote_self.status_code == 409
    assert demote_self.json()["error_code"] == "USER-LAST-ADMIN"


def test_admin_cannot_deactivate_self_and_deactivation_blocks_login(api: ApiHelper):
    api.register_and_login(ADMIN)
    analyst = api.register(ANALYST).json()

    me = api.client.get("/api/v1/auth/me").json()
    assert (
        api.client.post(
            f"/api/v1/users/{me['id']}/deactivate", headers=api.csrf_headers()
        ).status_code
        == 409
    )

    disabled = api.client.post(
        f"/api/v1/users/{analyst['id']}/deactivate", headers=api.csrf_headers()
    )
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["is_active"] is False

    with TestClient(app) as other:
        login = ApiHelper(other).login(ANALYST)
        assert login.status_code == 403
        assert login.json()["error_code"] == "AUTH-ACCOUNT-DISABLED"
