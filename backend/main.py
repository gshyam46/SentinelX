"""
SentinelX — FastAPI Application
Main entry point. Sets up middleware, routers, and lifespan events.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import get_settings
from backend.api.router import api_router
from backend.db.session import init_db, close_db

settings = get_settings()

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("sentinelx")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    logger.info("🛡️  SentinelX starting up...")

    # Initialize database tables (dev mode — use Alembic in production)
    if settings.is_development:
        try:
            await init_db()
            logger.info("✅ Database tables initialized")
        except Exception as e:
            logger.warning(f"⚠️  Database init skipped (not connected): {e}")
    
    logger.info("🚀 SentinelX is ready")
    yield
    
    # Shutdown
    await close_db()
    logger.info("👋 SentinelX shut down")


def create_app() -> FastAPI:
    """Application factory."""
    app = FastAPI(
        title="SentinelX",
        description=(
            "AI-Powered Cybersecurity Assessment Platform. "
            "Passive reconnaissance, vulnerability scanning, "
            "and intelligent threat analysis."
        ),
        version="0.1.0",
        docs_url="/docs" if settings.is_development else None,
        redoc_url="/redoc" if settings.is_development else None,
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount API routes
    app.include_router(api_router)

    return app


# Create the app instance
app = create_app()
