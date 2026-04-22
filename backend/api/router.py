"""
SentinelX — API Router
Top-level router that mounts all v1 API routes.
"""

from fastapi import APIRouter

from backend.api.v1.auth import router as auth_router
from backend.api.v1.health import router as health_router
from backend.api.v1.scans import router as scans_router
from backend.api.v1.reports import router as reports_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(scans_router)
api_router.include_router(reports_router)
