"""Backend 1: rate limiting, lockout, safe errors, config and headers."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.config import (
    INSECURE_DEFAULT_SECRET,
    Settings,
    get_settings,
)
from app.core.rate_limit import reset_rate_limiters
from app.main import create_app
from engine.errors import EngineError
from tests.conftest import ApiHelper, DEFAULT_PASSWORD


def test_login_rate_limit_returns_429_with_retry_after(api: ApiHelper, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "login_rate_limit", 2)
    reset_rate_limiters()

    assert api.login("nobody@example.com").status_code == 401
    assert api.login("nobody@example.com").status_code == 401

    blocked = api.login("nobody@example.com")
    assert blocked.status_code == 429
    assert blocked.json()["error_code"] == "RATE-LIMITED"
    assert int(blocked.headers["Retry-After"]) >= 1


def test_account_locks_after_repeated_failures(api: ApiHelper):
    api.register("lock@example.com")
    for _ in range(3):  # LOGIN_MAX_FAILED_ATTEMPTS=3 in tests
        assert api.login("lock@example.com", password="WrongPassword123!").status_code == 401

    locked = api.login("lock@example.com")
    assert locked.status_code == 423
    assert locked.json()["error_code"] == "AUTH-ACCOUNT-LOCKED"


def test_unhandled_exceptions_never_leak_details():
    test_app = create_app()

    @test_app.get("/api/v1/_boom")
    def boom() -> None:
        raise RuntimeError("super-secret internal detail and stack text")

    with TestClient(test_app, raise_server_exceptions=False) as client:
        response = client.get("/api/v1/_boom")

    assert response.status_code == 500
    body = response.text
    assert "super-secret" not in body
    assert "Traceback" not in body
    assert response.json()["error_code"] == "ENG-INTERNAL"
    assert response.json()["request_id"]


def test_engine_errors_keep_code_but_hide_detail():
    test_app = create_app()

    @test_app.get("/api/v1/_engine")
    def engine_boom() -> None:
        raise EngineError("CFG-OUT-OF-RANGE", detail="secret internal bound")

    with TestClient(test_app, raise_server_exceptions=False) as client:
        response = client.get("/api/v1/_engine")

    assert response.status_code == 422
    assert response.json()["error_code"] == "CFG-OUT-OF-RANGE"
    assert "secret" not in response.text


def test_health_and_security_headers(client: TestClient):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Request-ID"]

    echoed = client.get("/api/v1/health", headers={"X-Request-ID": "abc-123"})
    assert echoed.headers["X-Request-ID"] == "abc-123"


def test_production_configuration_is_enforced():
    base = {
        "environment": "production",
        "biometric_encryption_key": "cR9q82ftW2RUlofawQkkJXkRwhf1_dGhJ0y5l10Q41I=",
        "cookie_secure": True,
    }

    weak = Settings(secret_key=INSECURE_DEFAULT_SECRET, **base)
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        weak.validate_for_runtime()

    insecure_cookie = Settings(
        secret_key="prod-secret-" + "b3c9d1e7f2a4" * 4,
        **{**base, "cookie_secure": False},
    )
    with pytest.raises(RuntimeError, match="COOKIE_SECURE"):
        insecure_cookie.validate_for_runtime()

    valid = Settings(secret_key="prod-secret-" + "b3c9d1e7f2a4" * 4, **base)
    valid.validate_for_runtime()  # must not raise


def test_password_policy_requires_length_letter_and_digit(api: ApiHelper):
    assert api.register("noshort@example.com", password="Abcdefghij1!").status_code == 201
    assert api.register("nodigit@example.com", password="OnlyLettersHere!").status_code == 422
    assert api.register("short@example.com", password="Short1!").status_code == 422
