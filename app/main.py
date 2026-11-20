"""FastAPI application entry point.

Run in development:

    uvicorn app.main:app --reload --port 8000
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.errors import register_exception_handlers
from app.core.middleware import SecurityHeadersMiddleware
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
