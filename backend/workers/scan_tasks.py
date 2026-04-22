"""
SentinelX — Core Orchestration Celery Task
Consumes the OrchestratorAgent async generator inside a Celery worker
using asyncio.run() with careful event-loop lifecycle management.

Task chain: orchestrate_scan → run_analyst → generate_report
"""

from __future__ import annotations

import asyncio
import json
import logging
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any

from celery import states
from sqlalchemy import select

from backend.workers.celery_app import celery_app
from backend.config import get_settings

logger = logging.getLogger("sentinelx.workers.scan")
settings = get_settings()

# ---------------------------------------------------------------------------
# Helpers — synchronous DB writes with automatic 3-retry backoff
# ---------------------------------------------------------------------------

def _sync_db_write(coro_factory, *, max_retries: int = 3, base_delay: float = 0.5) -> Any:
    """
    Execute an async DB coroutine synchronously with exponential-backoff retries.
    `coro_factory` is a zero-argument callable that returns a fresh coroutine each call.
    This avoids the "coroutine already awaited" error on retry.
    """
    last_exc: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            return asyncio.run(coro_factory())
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < max_retries:
                delay = base_delay * (2 ** (attempt - 1))
                logger.warning(
                    "DB write attempt %d/%d failed (%s) — retrying in %.1fs",
                    attempt, max_retries, exc, delay,
                )
                import time
                time.sleep(delay)
    logger.error("DB write failed after %d retries: %s", max_retries, last_exc)
    raise last_exc  # type: ignore[misc]


def _sync_redis_publish(channel: str, payload: dict) -> None:
    """Fire-and-forget Redis PUBLISH. Swallows errors so the scan loop is unaffected."""
    try:
        import redis as sync_redis

        r = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
        r.publish(channel, json.dumps(payload))
        r.close()
    except Exception as exc:  # noqa: BLE001
        logger.debug("Redis publish skipped: %s", exc)


# ---------------------------------------------------------------------------
# DB helpers (async, executed via _sync_db_write)
# ---------------------------------------------------------------------------

async def _db_set_scan_running(scan_id: uuid.UUID) -> None:
    from backend.db.session import async_session_factory
    from backend.models.scan import Scan

    async with async_session_factory() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        scan.status = "running"
        scan.current_step = "Orchestrator initialising"
        scan.progress = 0
        await db.commit()


async def _db_update_tool_started(scan_id: uuid.UUID, tool: str, budget_remaining: int) -> None:
    from backend.db.session import async_session_factory
    from backend.models.scan import Scan

    async with async_session_factory() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        scan.current_step = f"Running: {tool}"
        # Rough progress from budget consumption
        from backend.agents.orchestrator import TIER_BUDGETS
        # We don't have tier here; compute from budget_remaining field compared to results
        # Simple heuristic: budget_remaining drives the progress bar
        scan.progress = max(0, min(90, 90 - int(budget_remaining * 5)))
        await db.commit()


async def _db_append_finding(scan_id: uuid.UUID, finding_dict: dict) -> None:
    """Append a single finding to scan.results['findings'] (JSONB merge)."""
    from backend.db.session import async_session_factory
    from backend.models.scan import Scan
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    async with async_session_factory() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()

        # Initialise results blob if first finding
        if scan.results is None:
            scan.results = {"findings": [], "tools_run": [], "ai_report": None}

        findings = scan.results.get("findings", [])
        findings.append(finding_dict)
        scan.results = {**scan.results, "findings": findings}

        # Update severity counters
        sev = finding_dict.get("severity", "info")
        if sev == "critical":
            scan.critical_count += 1
        elif sev == "high":
            scan.high_count += 1
        elif sev == "medium":
            scan.medium_count += 1
        elif sev == "low":
            scan.low_count += 1
        else:
            scan.info_count += 1
        scan.findings_count += 1

        await db.commit()


async def _db_complete_scan(scan_id: uuid.UUID, metadata: dict, tools_run: list[str]) -> None:
    from backend.db.session import async_session_factory
    from backend.models.scan import Scan

    async with async_session_factory() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        scan.status = "complete"
        scan.progress = 100
        scan.current_step = "Scan complete — running analysis"
        scan.completed_at = datetime.now(timezone.utc)

        existing = scan.results or {}
        scan.results = {**existing, "tools_run": tools_run, "scan_metadata": metadata}

        # Risk score — weighted severity counts
        risk = min(
            100,
            (scan.critical_count * 25)
            + (scan.high_count * 10)
            + (scan.medium_count * 4)
            + (scan.low_count * 1),
        )
        scan.risk_score = float(risk)
        await db.commit()


async def _db_fail_scan(scan_id: uuid.UUID, error: str) -> None:
    from backend.db.session import async_session_factory
    from backend.models.scan import Scan

    async with async_session_factory() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan:
            scan.status = "failed"
            scan.error_message = error[:2000]  # column is Text but guard length
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()


# ---------------------------------------------------------------------------
# Async inner loop — runs inside asyncio.run()
# ---------------------------------------------------------------------------

async def _run_orchestrator_loop(
    scan_id: uuid.UUID,
    target: str,
    tier: str,
    redis_channel: str,
    task_self,  # the bound Celery task for update_state()
) -> dict:
    """
    Async inner function that drives the OrchestratorAgent generator.
    Returns a summary dict on completion or raises on hard failure.
    """
    from backend.agents.orchestrator import run_orchestrator, ScanEvent

    findings_count = 0
    tools_run: list[str] = []
    scan_metadata: dict = {}

    async for event in run_orchestrator(target=target, tier=tier, scan_id=scan_id):
        event_dict = event.to_dict()
        etype = event.type

        # ── Publish every event to Redis for WebSocket consumers ──────────
        _sync_redis_publish(redis_channel, event_dict)

        # ── Handle each event type ─────────────────────────────────────────
        if etype == "tool_started":
            tool_name = event.tool or "unknown"
            task_self.update_state(
                state="PROGRESS",
                meta={
                    "step": f"Running: {tool_name}",
                    "tool": tool_name,
                    "budget_remaining": event.budget_remaining,
                    "findings_count": findings_count,
                },
            )
            _sync_db_write(
                lambda t=tool_name, b=event.budget_remaining: _db_update_tool_started(
                    scan_id, t, b
                )
            )

        elif etype == "finding":
            findings_count += 1
            if event.finding:
                finding_dict = event.finding.to_dict()
                _sync_db_write(
                    lambda fd=finding_dict: _db_append_finding(scan_id, fd)
                )
                _sync_redis_publish(
                    redis_channel,
                    {
                        "type": "findings_count",
                        "findings_count": findings_count,
                        "latest_severity": finding_dict.get("severity"),
                    },
                )

        elif etype == "tool_complete":
            if event.tool:
                tools_run.append(event.tool)
            _sync_redis_publish(
                redis_channel,
                {
                    "type": "tool_complete",
                    "tool": event.tool,
                    "findings_count": findings_count,
                    "budget_remaining": event.budget_remaining,
                    "owasp_coverage": (event.metadata or {}).get("owasp_coverage", []),
                },
            )

        elif etype == "agent_reasoning":
            # Streamed directly to UI — no DB write needed
            pass  # already published above

        elif etype in ("scan_complete", "exit_condition"):
            scan_metadata = event.metadata or {}
            # Final update_state before handing off to analyst
            task_self.update_state(
                state="PROGRESS",
                meta={
                    "step": "Scan complete — queuing analyst",
                    "budget_remaining": event.budget_remaining,
                    "findings_count": findings_count,
                },
            )

    return {
        "tools_run": list(dict.fromkeys(tools_run)),  # dedup, preserve order
        "findings_count": findings_count,
        "scan_metadata": scan_metadata,
    }


# ---------------------------------------------------------------------------
# @task: orchestrate_scan
# ---------------------------------------------------------------------------

@celery_app.task(
    bind=True,
    name="orchestrate_scan",
    max_retries=0,          # never auto-retry — scan failures are explicit
    track_started=True,
    acks_late=True,
)
def orchestrate_scan(self, scan_id: str, target: str, tier: str) -> dict:
    """
    Core agentic scan task.

    Drives the OrchestratorAgent generator and handles each ScanEvent:
      - tool_started  → update scan.progress in DB, publish to Redis
      - tool_complete → store ToolResult summary, publish findings count
      - finding       → append to scan.findings in DB (incremental, not batch)
      - agent_reasoning → publish reasoning event (shown in UI live)
      - scan_complete → trigger run_analyst.delay(scan_id)

    Error handling:
      - ToolNotFoundError or ModuleNotFoundError → logged, tool skipped, loop continues
        (handled inside OrchestratorAgent._execute_tool)
      - LLM call fails → Orchestrator falls back to rule-based next-tool selection
        (handled inside _llm_decide)
      - DB write fails → retried 3× with exponential backoff via _sync_db_write
      - Task-level crash → scan.status="failed", full traceback stored
    """
    _scan_id = uuid.UUID(scan_id)
    redis_channel = f"scan:{scan_id}:events"

    logger.info(
        "[%s] orchestrate_scan starting — target=%s tier=%s", scan_id, target, tier
    )

    # Mark scan as running
    try:
        _sync_db_write(lambda: _db_set_scan_running(_scan_id))
    except Exception as exc:
        logger.error("[%s] Could not mark scan as running: %s", scan_id, exc)
        # Not fatal — continue anyway (scan was already committed as pending)

    try:
        result = asyncio.run(
            _run_orchestrator_loop(
                scan_id=_scan_id,
                target=target,
                tier=tier,
                redis_channel=redis_channel,
                task_self=self,
            )
        )

        # Persist completion to DB
        _sync_db_write(
            lambda: _db_complete_scan(
                _scan_id,
                result["scan_metadata"],
                result["tools_run"],
            )
        )

        # Publish completion banner to Redis
        _sync_redis_publish(
            redis_channel,
            {
                "type": "orchestration_complete",
                "scan_id": scan_id,
                "findings_count": result["findings_count"],
                "tools_run": result["tools_run"],
            },
        )

        # ── Chain to analyst ───────────────────────────────────────────────
        from backend.workers.analyst_tasks import run_analyst  # lazy import avoids circulars

        run_analyst.delay(scan_id)
        logger.info(
            "[%s] orchestrate_scan complete — %d findings, chained run_analyst",
            scan_id,
            result["findings_count"],
        )
        return result

    except Exception as exc:
        tb = traceback.format_exc()
        logger.error("[%s] orchestrate_scan CRASHED:\n%s", scan_id, tb)

        # Persist failure state
        try:
            _sync_db_write(lambda: _db_fail_scan(_scan_id, tb))
        except Exception as db_exc:
            logger.critical(
                "[%s] Could not write failed status to DB: %s", scan_id, db_exc
            )

        # Publish failure event so WebSocket clients know
        _sync_redis_publish(
            redis_channel,
            {"type": "scan_failed", "scan_id": scan_id, "error": str(exc)},
        )

        # Re-raise so Celery marks task as FAILURE
        raise
