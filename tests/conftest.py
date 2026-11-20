"""Shared test setup: isolated SQLite database, fast bcrypt, clean state."""

from __future__ import annotations

import os
import pathlib
import tempfile
import uuid

# Settings are read at import time, so configure the environment first.
_TMP = pathlib.Path(tempfile.gettempdir()) / "facetrust_auditor_tests"
_TMP.mkdir(parents=True, exist_ok=True)
_DB_PATH = _TMP / f"test_{uuid.uuid4().hex}.db"

os.environ["ENVIRONMENT"] = "testing"
os.environ["SECRET_KEY"] = "test-secret-key-" + "a" * 40
os.environ["BIOMETRIC_ENCRYPTION_KEY"] = (
    "cR9q82ftW2RUlofawQkkJXkRwhf1_dGhJ0y5l10Q41I="
)
os.environ["DATABASE_URL"] = f"sqlite:///{_DB_PATH.as_posix()}"
os.environ["BCRYPT_ROUNDS"] = "4"  # keep the suite fast
os.environ["LOGIN_MAX_FAILED_ATTEMPTS"] = "3"
os.environ["LOGIN_RATE_LIMIT"] = "5"
os.environ["REGISTER_RATE_LIMIT"] = "20"
os.environ["AUTO_CREATE_TABLES"] = "true"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.rate_limit import reset_rate_limiters  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.session import engine  # noqa: E402
from app.main import app  # noqa: E402

DEFAULT_PASSWORD = "CorrectHorseBattery1!"


@pytest.fixture(autouse=True)
def clean_state():
    """Fresh schema and empty rate-limit counters for every test."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    reset_rate_limiters()
    yield
    reset_rate_limiters()


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


class ApiHelper:
    """Small wrapper for the common register/login flows."""

    def __init__(self, client: TestClient) -> None:
        self.client = client

    def register(
        self, email: str, password: str = DEFAULT_PASSWORD
    ):
        return self.client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": password},
        )

    def login(self, email: str, password: str = DEFAULT_PASSWORD):
        return self.client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )

    def register_and_login(
        self, email: str, password: str = DEFAULT_PASSWORD
    ) -> None:
        response = self.register(email, password)
        assert response.status_code == 201, response.text
        response = self.login(email, password)
        assert response.status_code == 200, response.text

    def csrf_token(self) -> str:
        token = self.client.cookies.get("ft_csrf")
        assert token, "CSRF cookie is missing after login"
        return token

    def csrf_headers(self) -> dict[str, str]:
        return {"X-CSRF-Token": self.csrf_token()}


@pytest.fixture()
def api(client: TestClient) -> ApiHelper:
    return ApiHelper(client)
