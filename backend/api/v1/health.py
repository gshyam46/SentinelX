"""
SentinelX — Health Check Router
"""

from fastapi import APIRouter
from datetime import datetime, timezone

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    """Application health check endpoint."""
    return {
        "status": "healthy",
        "service": "SentinelX",
        "version": "0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
