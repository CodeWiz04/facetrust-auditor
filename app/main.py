<<<<<<< HEAD
"""Main FastAPI application entrypoint for FaceTrust Auditor."""

from __future__ import annotations

from contextlib import asynccontextmanager
=======
"""FastAPI application entry point.

Run in development:

    uvicorn app.main:app --reload --port 8000
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

>>>>>>> 4d922c7c998ebd8347531df4389d8383819e3c11
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.errors import register_exception_handlers
from app.core.middleware import SecurityHeadersMiddleware
<<<<<<< HEAD
from app.db.session import init_db

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.auto_create_tables:
        init_db()
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
)

register_exception_handlers(app)
app.add_middleware(SecurityHeadersMiddleware)

origins = settings.cors_origin_list
if not origins:
    origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)
=======
from app.db.session import dispose_engine, init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpx2").setLevel(logging.WARNING)
logger = logging.getLogger("facetrust")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Validate configuration and prepare the database at startup."""
    settings = get_settings()
    settings.validate_for_runtime()

    if not settings.is_production:
        for problem in settings.insecure_defaults_in_use:
            logger.warning("development setting: %s", problem)

    if settings.biometric_encryption_key:
        from app.core.crypto import set_active_key
        set_active_key(settings.biometric_encryption_key)

    if settings.auto_create_tables:
        init_db()
        logger.info("database tables ready (%s)", settings.database_url.split("?")[0])

    yield
    dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    is_prod = settings.is_production

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "Consent-based facial recognition security lab. "
            "Backend 1: authentication, sessions, RBAC, rate limiting and audit chain."
        ),
        lifespan=lifespan,
        docs_url=None if is_prod else "/docs",
        redoc_url=None,
        openapi_url=None if is_prod else "/openapi.json",
    )

    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Content-Type", "X-CSRF-Token", "X-Request-ID"],
        )

    # Added last so it wraps CORS preflight responses too.
    app.add_middleware(SecurityHeadersMiddleware)

    register_exception_handlers(app)
    app.include_router(api_router)

    @app.get("/", include_in_schema=False)
    def root() -> dict[str, str]:
        return {
            "service": settings.app_name,
            "version": settings.app_version,
            "docs": "/docs" if not is_prod else "disabled",
            "health": "/api/v1/health",
        }

    return app


app = create_app()
>>>>>>> 4d922c7c998ebd8347531df4389d8383819e3c11
