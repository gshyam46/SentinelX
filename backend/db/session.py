"""
SentinelX — Database Session Management
Async SQLAlchemy engine + session factory for FastAPI dependency injection.
"""

import asyncio
import functools
import threading
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from backend.config import get_settings

settings = get_settings()

# ── FastAPI engine — pooled, bound to the uvicorn event loop ─────────────
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.is_development,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# ── Celery worker engine — NullPool, safe across asyncio.run() calls ─────
# asyncpg connection pools are bound to the event loop in which they were
# created.  Celery prefork workers call asyncio.run() multiple times in the
# same OS process, creating a new event loop each time.  A pooled engine
# carries stale connections from the previous loop, causing:
#   "Future <...> is attached to a different loop"
#   "Event loop is closed"
# NullPool never reuses connections, so every async with session: block
# opens a fresh asyncpg connection in whatever loop is currently active.
@functools.lru_cache(maxsize=1)
def _make_worker_engine():
    from sqlalchemy.pool import NullPool
    return create_async_engine(
        settings.DATABASE_URL,
        poolclass=NullPool,
        echo=False,
    )

@functools.lru_cache(maxsize=1)
def _make_worker_session_factory() -> async_sessionmaker:
    return async_sessionmaker(
        _make_worker_engine(),
        class_=AsyncSession,
        expire_on_commit=False,
    )

def worker_async_session_factory() -> AsyncSession:
    """
    Return a new async session from the NullPool (Celery-safe) engine.
    Usage: async with worker_async_session_factory() as db: ...
    """
    return _make_worker_session_factory()()


# ── Persistent per-worker event loop ─────────────────────────────────────────
# asyncio.run() creates AND DESTROYS a new event loop on every call.
# In Celery prefork workers that call asyncio.run() multiple times per process
# this causes event-loop churn: asyncpg connections bound to the old (closed)
# loop become unusable, aioredis handles get orphaned, etc.
#
# run_in_worker_loop() uses a module-level loop that is created once and kept
# open for the lifetime of the worker process.  loop.run_until_complete() blocks
# until the coroutine finishes, then returns — the loop stays alive for the next
# call.  This is safe because Celery prefork workers are sequential: one task
# at a time, so the loop is never entered while already running.

_worker_loop: asyncio.AbstractEventLoop | None = None
_worker_loop_lock = threading.Lock()


def _get_worker_loop() -> asyncio.AbstractEventLoop:
    global _worker_loop
    if _worker_loop is not None and not _worker_loop.is_closed():
        return _worker_loop
    with _worker_loop_lock:
        if _worker_loop is None or _worker_loop.is_closed():
            _worker_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(_worker_loop)
    return _worker_loop


def run_in_worker_loop(coro) -> Any:
    """
    Run a coroutine in the persistent per-worker event loop.

    Drop-in replacement for asyncio.run() inside Celery prefork tasks.
    The loop is created once per worker process and reused across all tasks.
    """
    return _get_worker_loop().run_until_complete(coro)


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for all models."""
    pass


async def get_db() -> AsyncSession:
    """FastAPI dependency — yields an async DB session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    # Schema managed by Alembic — run: alembic upgrade head
    pass


async def close_db():
    """Dispose engine connections on shutdown."""
    await engine.dispose()
