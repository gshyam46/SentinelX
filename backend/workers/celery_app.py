"""
SentinelX — Celery Application Factory
Central Celery instance shared across all worker modules.
Uses Redis as both broker and result backend.
"""

from __future__ import annotations

import logging
from celery import Celery
from kombu import Queue

from backend.config import get_settings

logger = logging.getLogger("sentinelx.celery")
settings = get_settings()

# ---------------------------------------------------------------------------
# Celery application instance
# ---------------------------------------------------------------------------

celery_app = Celery(
    "sentinelx",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "backend.workers.scan_tasks",
        "backend.workers.analyst_tasks",
    ],
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

celery_app.conf.update(
    # Serialisation
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    # Time
    timezone="UTC",
    enable_utc=True,
    # Task behaviour
    task_track_started=True,
    task_acks_late=True,           # ack after task completes (safe re-delivery on crash)
    worker_prefetch_multiplier=1,  # one task at a time per worker (long-running scans)
    # Result TTL — keep results 24 h for progress polling
    result_expires=86_400,
    # Routing — separate queues so analyst tasks don't block scan slots
    task_queues=(
        Queue("scans",   routing_key="scans.#"),
        Queue("analyst", routing_key="analyst.#"),
        Queue("default", routing_key="default.#"),
    ),
    task_default_queue="default",
    task_routes={
        "orchestrate_scan": {"queue": "scans",   "routing_key": "scans.orchestrate"},
        "run_analyst":      {"queue": "analyst",  "routing_key": "analyst.run"},
        "generate_report":  {"queue": "analyst",  "routing_key": "analyst.report"},
    },
    # Soft / hard time limits (seconds)
    # Scans can run up to 40 min (pro nuclei timeout is 1200 s × potential retries)
    task_soft_time_limit=2_400,
    task_time_limit=2_700,
    # Redis visibility timeout must exceed the longest task (keep >= task_time_limit)
    broker_transport_options={
        "visibility_timeout": 3_600,  # 1 hour
    },
)

logger.info(
    "Celery configured — broker=%s queues=[scans, analyst, default]",
    settings.REDIS_URL,
)
