"""
SentinelX — FastAPI Application
Main entry point. Sets up middleware, routers, and lifespan events.
"""

import logging
import re
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from backend.config import get_settings
from backend.api.router import api_router
from backend.db.session import init_db, close_db
from backend.modules.ai.knowledge_base.kev_loader import load_kev_entries

settings = get_settings()


# ---------------------------------------------------------------------------
# Logging — mask secrets in all log messages
# ---------------------------------------------------------------------------

class _SecretMaskingFilter(logging.Filter):
    """Redact sensitive key=value pairs from log messages and args."""

    _pattern = re.compile(
        r"(?i)(\b(?:secret|password|token|api_?key|groq|openai|anthropic|"
        r"shodan|hibp|otx|cookie|authorization)\b\s*[=:]\s*)['\"]?\S+['\"]?",
    )

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._redact(record.msg)
        if isinstance(record.args, dict):
            record.args = {
                k: self._redact(v) if isinstance(v, str) else v
                for k, v in record.args.items()
            }
        elif isinstance(record.args, tuple):
            record.args = tuple(
                self._redact(a) if isinstance(a, str) else a
                for a in record.args
            )
        return True

    def _redact(self, value: object) -> object:
        if isinstance(value, str):
            return self._pattern.sub(r"\1***", value)
        return value


logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Attach masking filter to root logger so it covers all child loggers
_mask_filter = _SecretMaskingFilter()
logging.getLogger().addFilter(_mask_filter)

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

    # Pre-warm KEV catalog cache — failure must never block startup
    try:
        entries = await load_kev_entries()
        logger.info("KEV pre-warm loaded %d entries", len(entries))
    except Exception as exc:
        logger.warning("KEV pre-warm skipped: %s", exc)

    # ── LLM connectivity check ────────────────────────────────────────────
    # Verify the configured model is reachable before accepting traffic.
    # Failure is non-fatal — system still starts (rule-based fallback works).
    await _check_llm_connectivity()

    logger.info("🚀 SentinelX is ready")
    yield

    # Shutdown
    await close_db()
    logger.info("👋 SentinelX shut down")


async def _check_llm_connectivity() -> None:
    """
    Probe the configured LLM model with a minimal single-token request.
    Logs clearly whether LLM is ready, which model succeeded, or what failed.
    Never raises — startup must always succeed.
    """
    if not settings.GROQ_API_KEY and not settings.OPENAI_API_KEY and not settings.ANTHROPIC_API_KEY:
        logger.warning(
            "⚠️  LLM: No API key configured (GROQ_API_KEY / OPENAI_API_KEY / ANTHROPIC_API_KEY). "
            "Analyst will use rule-based fallback. Set a key in .env to enable AI analysis."
        )
        return

    models_to_probe = [settings.LITELLM_MODEL]
    fallback = getattr(settings, "LITELLM_FALLBACK_MODEL", None)
    if fallback and fallback != settings.LITELLM_MODEL:
        models_to_probe.append(fallback)

    try:
        import litellm
        litellm.suppress_debug_info = True
    except ImportError:
        logger.warning("⚠️  LLM: litellm not installed — pip install litellm")
        return

    for model in models_to_probe:
        try:
            resp = await litellm.acompletion(
                model=model,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=1,
                timeout=10,
            )
            logger.info(
                "✅ LLM: connected — model=%s  (finish_reason=%s)",
                model,
                resp.choices[0].finish_reason,
            )
            # Update the live settings so all subsequent calls use the working model
            if model != settings.LITELLM_MODEL:
                logger.info("🔄 LLM: switching primary model to working fallback: %s", model)
                settings.__dict__["LITELLM_MODEL"] = model
            return  # success — stop probing
        except Exception as exc:
            logger.warning("⚠️  LLM: model '%s' probe failed — %s: %s", model, type(exc).__name__, exc)

    logger.error(
        "❌ LLM: ALL configured models failed connectivity check. "
        "Analyst will use rule-based fallback. "
        "Check GROQ_API_KEY and LITELLM_MODEL in .env. "
        "Current model: %s  Fallback: %s",
        settings.LITELLM_MODEL,
        getattr(settings, "LITELLM_FALLBACK_MODEL", "none"),
    )



async def _global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all for unhandled exceptions — never expose stack traces to clients."""
    logger.exception(
        "Unhandled server error | %s %s", request.method, request.url.path
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred."},
    )


async def _validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Return structured 422 without Pydantic internals leaking."""
    errors = [
        {"field": " → ".join(str(l) for l in e["loc"]), "message": e["msg"]}
        for e in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": errors})


def create_app() -> FastAPI:
    """Application factory."""
    from backend.api.deps import limiter  # local import avoids circular at module load

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

    # Rate limiting (slowapi)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Exception handlers — no stack traces in responses
    app.add_exception_handler(RequestValidationError, _validation_exception_handler)
    app.add_exception_handler(Exception, _global_exception_handler)

    # Mount API routes
    app.include_router(api_router)

    return app


# Create the app instance
app = create_app()
