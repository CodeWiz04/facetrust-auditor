"""All /api/v1 routers."""

from fastapi import APIRouter

from app.api.v1 import audit, auth, dataset, health, users

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(audit.router)
api_router.include_router(dataset.router)
