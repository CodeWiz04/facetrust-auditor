"""Stable public error codes and safe exception handlers.

Rules:
- Public responses only carry `error_code`, `message`, `request_id` (and safe
  validation field names). Stack traces, SQL, file paths and secrets never
  leave the server.
- Details are written to the server log only.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from engine.errors import EngineError

logger = logging.getLogger("facetrust.errors")

# code -> (http status, public message)
ERROR_CATALOG: dict[str, tuple[int, str]] = {
    # Generic
    "VALIDATION-FAILED": (422, "The request body or parameters are invalid."),
    "ENG-INTERNAL": (500, "An internal error occurred."),
    "NOT-FOUND": (404, "The requested resource was not found."),
    "METHOD-NOT-ALLOWED": (405, "That method is not allowed for this endpoint."),
    # Authentication / sessions
    "AUTH-INVALID-CREDENTIALS": (401, "Email or password is incorrect."),
    "AUTH-SESSION-INVALID": (401, "Your session is missing, expired, or revoked."),
    "AUTH-ACCOUNT-LOCKED": (423, "This account is temporarily locked. Try again later."),
    "AUTH-ACCOUNT-DISABLED": (403, "This account is disabled."),
    "AUTH-FORBIDDEN": (403, "You do not have permission to perform this action."),
    "AUTH-CSRF-INVALID": (403, "CSRF token is missing or invalid."),
    "AUTH-PASSWORD-WEAK": (422, "The password does not meet the minimum policy."),
    "AUTH-PASSWORD-TOO-LONG": (422, "The password is longer than the supported limit."),
    # Users
    "USER-EXISTS": (409, "An account with that email already exists."),
    "USER-NOT-FOUND": (404, "User not found."),
    "USER-LAST-ADMIN": (409, "At least one active administrator must remain."),
    "USER-SELF-ACTION": (409, "You cannot perform this action on your own account."),
    # Abuse / limits
    "RATE-LIMITED": (429, "Too many requests. Slow down and try again."),
    # Crypto / storage
    "FILE-CORRUPT": (422, "The file could not be read."),
    "DEL-VERIFY-FAILED": (409, "Verification failed."),
}


class AppError(Exception):
    """Domain error with a stable public code and safe message."""

    def __init__(
        self,
        code: str,
        status_code: int | None = None,
        detail: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        if code not in ERROR_CATALOG:
            code = "ENG-INTERNAL"
        self.code = code
        self.status_code = status_code or ERROR_CATALOG[code][0]
        self.public_message = ERROR_CATALOG[code][1]
        self.detail = detail
        self.headers = headers or {}
        super().__init__(code)

    def to_payload(self, request_id: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "error_code": self.code,
            "message": self.public_message,
        }
        if request_id:
            payload["request_id"] = request_id
        return payload


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def _validation_details(exc: RequestValidationError) -> list[dict[str, str]]:
    """Return field locations and error types only - never user input."""
    details: list[dict[str, str]] = []
    for error in exc.errors():
        loc = ".".join(str(part) for part in error.get("loc", ()) if part != "body")
        details.append({"field": loc or "body", "type": str(error.get("type", "invalid"))})
    return details


def register_exception_handlers(app: FastAPI) -> None:
    """Register handlers so no endpoint can leak an internal exception."""

    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError) -> JSONResponse:
        if exc.detail:
            logger.info(
                "app_error code=%s request_id=%s detail=%s",
                exc.code,
                _request_id(request),
                exc.detail,
            )
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_payload(_request_id(request)),
            headers=exc.headers or None,
        )

    @app.exception_handler(EngineError)
    async def _engine_error(request: Request, exc: EngineError) -> JSONResponse:
        """Engine errors keep their stable codes but never expose `detail`."""
        status_code = 422 if str(exc.code).startswith("CFG-") else 400
        if exc.detail:
            logger.info(
                "engine_error code=%s request_id=%s detail=%s",
                exc.code,
                _request_id(request),
                exc.detail,
            )
        payload = exc.to_dict()
        request_id = _request_id(request)
        if request_id:
            payload["request_id"] = request_id
        return JSONResponse(status_code=status_code, content=payload)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        payload = {
            "error_code": "VALIDATION-FAILED",
            "message": ERROR_CATALOG["VALIDATION-FAILED"][1],
            "details": _validation_details(exc),
        }
        request_id = _request_id(request)
        if request_id:
            payload["request_id"] = request_id
        return JSONResponse(status_code=422, content=payload)

    @app.exception_handler(Exception)
    async def _unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        # Full traceback stays in the server log. The client gets a safe body.
        logger.exception(
            "unhandled_error request_id=%s method=%s path=%s",
            _request_id(request),
            request.method,
            request.url.path,
        )
        payload: dict[str, Any] = {
            "error_code": "ENG-INTERNAL",
            "message": ERROR_CATALOG["ENG-INTERNAL"][1],
        }
        request_id = _request_id(request)
        if request_id:
            payload["request_id"] = request_id
        return JSONResponse(status_code=500, content=payload)
