"""Backend 1: registration, password hashing, login, sessions and passwords."""

from __future__ import annotations

from sqlalchemy import select

import pytest
from fastapi.testclient import TestClient

from app.db.session import SessionLocal
from app.main import app
from app.models.user import User, UserRole

DEFAULT_PASSWORD = "CorrectHorseBattery1!"


def test_first_user_becomes_admin_and_second_is_analyst(api):
    response = api.register("first@example.com")
    assert response.status_code == 201, response.text
    assert response.json()["role"] == UserRole.ADMIN.value

    response = api.register("second@example.com")
    assert response.status_code == 201, response.text
    assert response.json()["role"] == UserRole.ANALYST.value


def test_password_is_hashed_not_stored_plaintext(api):
    api.register("hash@example.com")
    with SessionLocal() as db:
        user = db.execute(select(User)).scalars().one()
    assert user.password_hash != DEFAULT_PASSWORD
    assert user.password_hash.startswith("$2")
    assert DEFAULT_PASSWORD not in user.password_hash


def test_duplicate_email_is_rejected(api):
    assert api.register("dupe@example.com").status_code == 201
    response = api.register("DUPE@example.com")
    assert response.status_code == 409
    assert response.json()["error_code"] == "USER-EXISTS"


def test_weak_password_is_rejected(api):
    response = api.register("weak@example.com", password="short1")
    assert response.status_code == 422


def test_login_sets_httponly_session_cookie_and_readable_csrf_cookie(api):
    api.register("cookies@example.com")
    response = api.login("cookies@example.com")
    assert response.status_code == 200, response.text

    raw = "; ".join(response.headers.get_list("set-cookie"))
    assert "ft_session=" in raw
    assert "HttpOnly" in raw
    assert "ft_csrf=" in raw

    cookies = response.headers.get_list("set-cookie")
    session_cookie = next(
        part for part in cookies if part.startswith("ft_session=")
    )
    assert "httponly" in session_cookie.lower()

    csrf_cookie = next(part for part in cookies if part.startswith("ft_csrf="))
    assert "httponly" not in csrf_cookie.lower()
    assert response.json()["csrf_token"] == api.csrf_token()


def test_login_me_logout_flow(api):
    api.register_and_login("flow@example.com")

    me = api.client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == "flow@example.com"

    logout = api.client.post(
        "/api/v1/auth/logout", headers=api.csrf_headers()
    )
    assert logout.status_code == 200, logout.text

    assert api.client.get("/api/v1/auth/me").status_code == 401


def test_wrong_password_is_generic_and_unknown_user_is_identical(api):
    api.register("known@example.com")
    wrong = api.login("known@example.com", password="WrongPassword123!")
    unknown = api.login("nobody@example.com", password="WrongPassword123!")

    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["error_code"] == unknown.json()["error_code"]
    assert wrong.json()["message"] == unknown.json()["message"]


def test_login_without_cookie_is_unauthenticated(api):
    response = api.client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["error_code"] == "AUTH-SESSION-INVALID"


def test_password_change_revokes_other_sessions_and_rotates_credentials(api):
    api.register_and_login("rotate@example.com")

    with TestClient(app) as second:
        login = second.post(
            "/api/v1/auth/login",
            json={"email": "rotate@example.com", "password": DEFAULT_PASSWORD},
        )
        assert login.status_code == 200, login.text

        changed = api.client.post(
            "/api/v1/auth/password",
            json={
                "current_password": DEFAULT_PASSWORD,
                "new_password": "BrandNewPassword99!",
            },
            headers=api.csrf_headers(),
        )
        assert changed.status_code == 200, changed.text

        # The other session was revoked by the password change.
        assert second.get("/api/v1/auth/me").status_code == 401

    api.client.post("/api/v1/auth/logout", headers=api.csrf_headers())
    assert api.login("rotate@example.com").status_code == 401
    assert (
        api.login("rotate@example.com", password="BrandNewPassword99!").status_code
        == 200
    )


def test_session_listing_marks_current_session(api):
    api.register_and_login("sessions@example.com")
    response = api.client.get("/api/v1/auth/sessions")
    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["current"] is True


def test_session_can_be_revoked(api):
    api.register_and_login("revoke@example.com")
    sessions = api.client.get("/api/v1/auth/sessions").json()["items"]
    session_id = sessions[0]["id"]

    response = api.client.delete(
        f"/api/v1/auth/sessions/{session_id}", headers=api.csrf_headers()
    )
    assert response.status_code == 200, response.text
    assert api.client.get("/api/v1/auth/me").status_code == 401


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"email": "not-an-email", "password": DEFAULT_PASSWORD},
        {"email": "ok@example.com"},
    ],
)
def test_invalid_registration_payload_is_422(client: TestClient, payload):
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 422
    assert response.json()["error_code"] in {"VALIDATION-FAILED", "AUTH-PASSWORD-WEAK"}
