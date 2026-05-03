"""
SentinelX - Core scan orchestration Celery task.

Task chain: orchestrate_scan -> run_analyst -> generate_report

Schema contract (scan.results JSONB):
  scan_findings  - list[dict]   written ONLY by _db_append_finding (atomic jsonb_set)
  tools_run      - list[str]    written ONLY by _db_complete_scan
  scan_metadata  - dict         written ONLY by _db_complete_scan
  execution_graph- dict|None    written ONLY by _db_complete_scan
  analysis       - dict         written ONLY by analyst_tasks._db_save_ai_report
  report         - dict         written ONLY by analyst_tasks._db_save_remediation_plan
  report_ready   - bool         written ONLY by analyst_tasks._mark_report_ready
  auth_config    - dict|None    written ONLY at scan creation (API layer)

All JSONB writes use the PostgreSQL || operator or jsonb_set so each owner
only touches its own keys — no read-modify-write across ownership boundaries.
"""

from __future__ import annotations

import json
import logging
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from sqlalchemy import select, text

from backend.config import get_settings
from backend.db.session import run_in_worker_loop, worker_async_session_factory
from backend.workers.celery_app import celery_app

logger = logging.getLogger("sentinelx.workers.scan")
settings = get_settings()

ScanMode = Literal["deterministic", "adaptive"]
DEFAULT_SCAN_MODE: ScanMode = "adaptive"
VALID_SCAN_MODES = {"deterministic", "adaptive"}

# ---------------------------------------------------------------------------
# Tier-based scan parameters
# ---------------------------------------------------------------------------

_TIER_BUDGETS: dict[str, int] = {"free": 8, "pro": 30}
_PRO_ONLY_TOOLS = {"sqlmap_scan", "dalfox_scan", "feroxbuster"}


def _scan_params_for_tier(tier: str) -> tuple[int, list[str]]:
    from backend.agents.orchestrator import TOOL_REGISTRY
    from backend.modules.pentest.tool_registry import OPERATIONAL_REGISTRY

    budget = _TIER_BUDGETS.get(tier, _TIER_BUDGETS["free"])
    is_pro = tier in ("pro", "paid", "enterprise")
    allowed = [
        name
        for name in TOOL_REGISTRY
        if name in OPERATIONAL_REGISTRY and (is_pro or name not in _PRO_ONLY_TOOLS)
    ]
    return budget, allowed


def _normalise_scan_mode(mode: str | None) -> ScanMode:
    if mode in VALID_SCAN_MODES:
        return mode
    if mode is not None:
        logger.warning("Invalid scan mode '%s' — falling back to %s", mode, DEFAULT_SCAN_MODE)
    return DEFAULT_SCAN_MODE


# ---------------------------------------------------------------------------
# Atomic SQL constants
# Ownership: scan_tasks owns scan_findings, tools_run, scan_metadata, execution_graph.
# The || operator merges ONLY the keys in the patch — all other keys are preserved.
# ---------------------------------------------------------------------------

# Appends one finding (wrapped as a single-element JSON array) to scan_findings.
# Also atomically increments the matching severity counter and findings_count.
# No read needed — pure SQL.
_APPEND_FINDING_SQL = text("""
    UPDATE scans SET
        results = jsonb_set(
            COALESCE(results, '{}'),
            '{scan_findings}',
            COALESCE(results->'scan_findings', '[]') || :finding::jsonb
        ),
        findings_count = findings_count + 1,
        critical_count = critical_count + CASE WHEN :severity = 'critical' THEN 1 ELSE 0 END,
        high_count     = high_count     + CASE WHEN :severity = 'high'     THEN 1 ELSE 0 END,
        medium_count   = medium_count   + CASE WHEN :severity = 'medium'   THEN 1 ELSE 0 END,
        low_count      = low_count      + CASE WHEN :severity = 'low'      THEN 1 ELSE 0 END,
        info_count     = info_count     + CASE WHEN :severity NOT IN ('critical','high','medium','low') THEN 1 ELSE 0 END
    WHERE id = :scan_id
""")

# Marks the scan complete, computes risk_score from the live counter columns
# (never from a Python snapshot that could be stale), and merges metadata.
# scan_findings is NOT in the patch so it is preserved untouched by ||.
_COMPLETE_SCAN_SQL = text("""
    UPDATE scans SET
        status       = 'complete',
        progress     = 100,
        current_step = 'Scan complete - running analysis',
        completed_at = :completed_at,
        risk_score   = LEAST(100.0, critical_count * 25.0
                                  + high_count     * 10.0
                                  + medium_count   *  4.0
                                  + low_count      *  1.0),
        results      = COALESCE(results, '{}') || :patch::jsonb
    WHERE id = :scan_id
""")


# ---------------------------------------------------------------------------
# Helpers — DB writes with automatic 3-retry backoff
# ---------------------------------------------------------------------------

def _sync_db_write(coro_factory, *, max_retries: int = 3, base_delay: float = 0.5) -> Any:
    """
    Execute an async DB coroutine synchronously with exponential-backoff retries.
    Uses the persistent per-worker loop (not asyncio.run) to avoid loop churn.
    """
    import time
    last_exc: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            return run_in_worker_loop(coro_factory())
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < max_retries:
                delay = base_delay * (2 ** (attempt - 1))
                logger.warning(
                    "DB write attempt %d/%d failed (%s) — retrying in %.1fs",
                    attempt, max_retries, exc, delay,
                )
                time.sleep(delay)
    logger.error("DB write failed after %d retries: %s", max_retries, last_exc)
    raise last_exc  # type: ignore[misc]


async def _async_db_write(coro_factory, *, max_retries: int = 3, base_delay: float = 0.5) -> Any:
    """Execute an async DB coroutine with retries from inside a running event loop."""
    import asyncio
    last_exc: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            return await coro_factory()
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < max_retries:
                delay = base_delay * (2 ** (attempt - 1))
                logger.warning(
                    "Async DB write attempt %d/%d failed (%s) — retrying in %.1fs",
                    attempt, max_retries, exc, delay,
                )
                await asyncio.sleep(delay)
    logger.error("Async DB write failed after %d retries: %s", max_retries, last_exc)
    raise last_exc  # type: ignore[misc]


def _sync_redis_publish(channel: str, payload: dict) -> None:
    try:
        import redis as sync_redis
        redis_client = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
        redis_client.publish(channel, json.dumps(payload))
        redis_client.close()
    except Exception as exc:  # noqa: BLE001
        logger.debug("Redis publish skipped: %s", exc)


# ---------------------------------------------------------------------------
# DB helpers — atomic JSONB writes, no read-modify-write
# ---------------------------------------------------------------------------

async def _db_set_scan_running(scan_id: uuid.UUID) -> None:
    from backend.models.scan import Scan

    async with worker_async_session_factory() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        scan.status = "running"
        scan.current_step = "Orchestrator initialising"
        scan.progress = 0
        await db.commit()


async def _db_update_tool_started(scan_id: uuid.UUID, tool: str, budget_remaining: int) -> None:
    from backend.models.scan import Scan

    async with worker_async_session_factory() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        scan.current_step = f"Running: {tool}"
        scan.progress = max(0, min(90, 90 - int(budget_remaining * 5)))
        await db.commit()


async def _db_update_scan_progress(scan_id: uuid.UUID, step: str, progress: int) -> None:
    from backend.models.scan import Scan

    async with worker_async_session_factory() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        scan.current_step = step
        scan.progress = max(0, min(95, progress))
        await db.commit()


async def _db_append_finding(scan_id: uuid.UUID, finding_dict: dict) -> None:
    """
    Atomically append one finding to scan.results['scan_findings'].

    Pure SQL — no ORM read, no read-modify-write.
    The jsonb_set call touches ONLY the scan_findings key; all other result
    keys (analysis, report, auth_config, etc.) are left untouched.
    Severity counters and findings_count are updated in the same statement.
    """
    async with worker_async_session_factory() as db:
        await db.execute(
            _APPEND_FINDING_SQL,
            {
                "finding": json.dumps([finding_dict], default=str),  # array for || concat
                "severity": finding_dict.get("severity", "info"),
                "scan_id": scan_id,  # uuid.UUID — asyncpg requires native UUID, not str
            },
        )
        await db.commit()


async def _db_complete_scan(scan_id: uuid.UUID, metadata: dict, tools_run: list[str]) -> None:
    """
    Mark scan complete and persist tools_run / scan_metadata / execution_graph.

    Pure SQL — risk_score is computed from the live counter columns (never a
    stale Python snapshot), and the || merge leaves scan_findings untouched.
    """
    execution_graph = metadata.get("execution_graph")

    # Size guard — warn but never fail the scan over it
    if execution_graph:
        graph_bytes = len(json.dumps(execution_graph, default=str))
        if graph_bytes > 500_000:
            logger.warning(
                "execution_graph size %d bytes exceeds 500 KB threshold for scan %s",
                graph_bytes, scan_id,
            )

    persisted_metadata = {
        **metadata,
        "execution_graph_present": bool(execution_graph),
    }

    patch = {
        "tools_run": tools_run,
        "scan_metadata": persisted_metadata,
        "execution_graph": execution_graph,
    }

    async with worker_async_session_factory() as db:
        await db.execute(
            _COMPLETE_SCAN_SQL,
            {
                "completed_at": datetime.now(timezone.utc),  # datetime, not str
                "patch": json.dumps(patch, default=str),
                "scan_id": scan_id,  # uuid.UUID
            },
        )
        await db.commit()

    logger.debug("[%s] _db_complete_scan committed — tools=%d", scan_id, len(tools_run))


async def _db_fail_scan(scan_id: uuid.UUID, error: str) -> None:
    from backend.models.scan import Scan

    async with worker_async_session_factory() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan:
            scan.status = "failed"
            scan.error_message = error[:2000]
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()


def _normalise_passive_finding(target: str, finding_dict: dict[str, Any]) -> dict[str, Any]:
    return {
        **finding_dict,
        "target": finding_dict.get("target", target),
        "source_tool": finding_dict.get(
            "source_tool",
            finding_dict.get("source_module", finding_dict.get("category", "passive_recon")),
        ),
        "owasp_categories": finding_dict.get("owasp_categories", []),
    }


# ---------------------------------------------------------------------------
# Async inner loops — run inside run_in_worker_loop()
# ---------------------------------------------------------------------------

async def _run_active_scan_loop(
    scan_id: uuid.UUID,
    target: str,
    budget: int,
    allowed_tools: list[str],
    mode: ScanMode,
    redis_channel: str,
    task_self,
) -> dict:
    from backend.modules.pentest.active_scan import run_active_scan

    findings_count = 0
    tools_run: list[str] = []
    scan_metadata: dict = {}

    async for event in run_active_scan(
        target=target,
        scan_id=scan_id,
        budget=budget,
        allowed_tools=allowed_tools,
        mode=mode,
    ):
        event_dict = event.to_dict()
        event_type = event.type

        _sync_redis_publish(redis_channel, event_dict)

        if event_type == "tool_started":
            tool_name = event.tool or "unknown"
            task_self.update_state(
                state="PROGRESS",
                meta={
                    "step": f"Running: {tool_name}",
                    "tool": tool_name,
                    "mode": mode,
                    "budget_remaining": event.budget_remaining,
                    "findings_count": findings_count,
                },
            )
            await _async_db_write(
                lambda t=tool_name, b=event.budget_remaining: _db_update_tool_started(
                    scan_id, t, b
                )
            )

        elif event_type == "finding":
            findings_count += 1
            if event.finding:
                finding_dict = event.finding.to_dict()
                await _async_db_write(lambda fd=finding_dict: _db_append_finding(scan_id, fd))
                _sync_redis_publish(
                    redis_channel,
                    {
                        "type": "findings_count",
                        "findings_count": findings_count,
                        "latest_severity": finding_dict.get("severity"),
                    },
                )

        elif event_type == "tool_complete":
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

        elif event_type in ("scan_complete", "exit_condition"):
            scan_metadata = event.metadata or {}
            task_self.update_state(
                state="PROGRESS",
                meta={
                    "step": "Scan complete - queuing analyst",
                    "mode": mode,
                    "budget_remaining": event.budget_remaining,
                    "findings_count": findings_count,
                },
            )

    return {
        "tools_run": list(dict.fromkeys(tools_run)),
        "findings_count": findings_count,
        "scan_metadata": scan_metadata,
    }


async def _run_passive_recon_loop(
    scan_id: uuid.UUID,
    target: str,
    redis_channel: str,
    task_self,
) -> dict:
    from backend.modules.recon.passive_recon import SCAN_STEPS, run_passive_recon

    findings_count = 0
    started_at = datetime.now(timezone.utc)
    tools_run = [step[0] for step in SCAN_STEPS] + ["exposed_paths"]

    async def progress_callback(step_name: str, progress_pct: int) -> None:
        task_self.update_state(
            state="PROGRESS",
            meta={"step": step_name, "tool": "passive_recon", "findings_count": findings_count},
        )
        await _async_db_write(
            lambda s=step_name, p=progress_pct: _db_update_scan_progress(scan_id, s, p)
        )
        _sync_redis_publish(
            redis_channel,
            {"type": "passive_progress", "step": step_name, "progress": progress_pct},
        )

    results = await run_passive_recon(target, progress_callback=progress_callback)

    for raw_finding in results.get("all_findings", []):
        findings_count += 1
        finding = _normalise_passive_finding(target, raw_finding)
        await _async_db_write(lambda fd=finding: _db_append_finding(scan_id, fd))
        _sync_redis_publish(
            redis_channel,
            {"type": "finding", "tool": finding.get("source_tool", "passive_recon"), "finding": finding},
        )

    summary = results.get("summary", {})
    task_self.update_state(
        state="PROGRESS",
        meta={"step": "Scan complete - queuing analyst", "findings_count": findings_count},
    )

    return {
        "tools_run": tools_run,
        "findings_count": findings_count,
        "scan_metadata": {
            "target": target,
            "scan_type": "passive",
            "execution_mode": "passive",
            "tools_run": tools_run,
            "total_findings": findings_count,
            "severity_summary": summary.get("severity_counts", {}),
            "risk_score": summary.get("risk_score", 0),
            "scan_duration_seconds": (datetime.now(timezone.utc) - started_at).total_seconds(),
        },
    }


# ---------------------------------------------------------------------------
# PTT expansion helper (Phase 2) — adaptive mode only
# ---------------------------------------------------------------------------

async def _run_ptt_if_adaptive(
    scan_id: uuid.UUID,
    target: str,
    scan_metadata: dict,
) -> dict | None:
    from backend.agents.ptt import PTTState
    from backend.agents.ptt_orchestrator import dispatch_pending_ptt_nodes, expand_ptt
    from backend.models.scan import Scan

    try:
        async with worker_async_session_factory() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if not scan or not scan.results:
                return None
            # scan_findings key (new schema); fall back to findings for old records
            findings: list[dict] = list(
                scan.results.get("scan_findings") or scan.results.get("findings", [])
            )
    except Exception as exc:
        logger.warning("[%s] PTT: DB read failed — skipping: %s", scan_id, exc)
        return None

    if not findings:
        logger.info("[%s] PTT: no findings after first pass — skipping", scan_id)
        return None

    execution_graph: dict = scan_metadata.get("execution_graph") or {}
    kev_matches: list[str] = scan_metadata.get("kev_matches") or []

    ptt = PTTState(scan_id=str(scan_id))

    for iteration in range(2):
        ptt = await expand_ptt(ptt, findings, execution_graph, kev_matches)
        new_findings, ptt = await dispatch_pending_ptt_nodes(ptt, target, scan_id)

        for fd in new_findings:
            try:
                await _async_db_write(lambda f=fd: _db_append_finding(scan_id, f))
            except Exception as exc:
                logger.warning("[%s] PTT: failed to persist finding: %s", scan_id, exc)

        findings.extend(new_findings)
        logger.info(
            "[%s] PTT iteration %d: %d new findings, %d total nodes",
            scan_id, iteration + 1, len(new_findings), len(ptt.nodes),
        )

        if not new_findings:
            logger.info("[%s] PTT: no new findings in iteration %d — stopping", scan_id, iteration + 1)
            break

    return ptt.export() if ptt.nodes else None


# ---------------------------------------------------------------------------
# @task: orchestrate_scan
# ---------------------------------------------------------------------------

@celery_app.task(
    bind=True,
    name="orchestrate_scan",
    max_retries=0,
    track_started=True,
    acks_late=True,
)
def orchestrate_scan(
    self,
    scan_id: str,
    target: str,
    tier: str,
    scan_type: str = "passive",
    mode: str = DEFAULT_SCAN_MODE,
) -> dict:
    """Execute a scan and chain the analyst task on completion."""
    parsed_scan_id = uuid.UUID(scan_id)
    scan_mode = _normalise_scan_mode(mode)
    redis_channel = f"scan:{scan_id}:events"

    budget, allowed_tools = _scan_params_for_tier(tier)
    logger.info(
        "[%s] orchestrate_scan starting — target=%s tier=%s scan_type=%s mode=%s budget=%d tools=%d",
        scan_id, target, tier, scan_type, scan_mode, budget, len(allowed_tools),
    )

    try:
        _sync_db_write(lambda: _db_set_scan_running(parsed_scan_id))
    except Exception as exc:
        logger.error("[%s] Could not mark scan as running: %s", scan_id, exc)

    try:
        if scan_type == "passive":
            result = run_in_worker_loop(
                _run_passive_recon_loop(
                    scan_id=parsed_scan_id,
                    target=target,
                    redis_channel=redis_channel,
                    task_self=self,
                )
            )

        elif scan_type == "full":
            passive_result = run_in_worker_loop(
                _run_passive_recon_loop(
                    scan_id=parsed_scan_id,
                    target=target,
                    redis_channel=redis_channel,
                    task_self=self,
                )
            )
            active_result = run_in_worker_loop(
                _run_active_scan_loop(
                    scan_id=parsed_scan_id,
                    target=target,
                    budget=budget,
                    allowed_tools=allowed_tools,
                    mode=scan_mode,
                    redis_channel=redis_channel,
                    task_self=self,
                )
            )
            if scan_mode == "adaptive" and active_result["findings_count"] > 0:
                ptt_state = run_in_worker_loop(
                    _run_ptt_if_adaptive(
                        scan_id=parsed_scan_id,
                        target=target,
                        scan_metadata=active_result["scan_metadata"],
                    )
                )
                if ptt_state:
                    active_result["scan_metadata"]["ptt_state"] = ptt_state

            active_meta = active_result["scan_metadata"]
            full_scan_metadata: dict = {
                **active_meta,
                "scan_type": "full",
                "passive_phase": passive_result["scan_metadata"],
                "active_phase": active_meta,
            }
            active_phase = full_scan_metadata.get("active_phase") or {}
            if "execution_graph" in active_phase:
                full_scan_metadata["execution_graph"] = active_phase["execution_graph"]

            result = {
                "tools_run": list(
                    dict.fromkeys(passive_result["tools_run"] + active_result["tools_run"])
                ),
                "findings_count": passive_result["findings_count"] + active_result["findings_count"],
                "scan_metadata": full_scan_metadata,
            }

        else:  # "active"
            result = run_in_worker_loop(
                _run_active_scan_loop(
                    scan_id=parsed_scan_id,
                    target=target,
                    budget=budget,
                    allowed_tools=allowed_tools,
                    mode=scan_mode,
                    redis_channel=redis_channel,
                    task_self=self,
                )
            )
            if scan_mode == "adaptive" and result["findings_count"] > 0:
                ptt_state = run_in_worker_loop(
                    _run_ptt_if_adaptive(
                        scan_id=parsed_scan_id,
                        target=target,
                        scan_metadata=result["scan_metadata"],
                    )
                )
                if ptt_state:
                    result["scan_metadata"]["ptt_state"] = ptt_state

        _sync_db_write(
            lambda: _db_complete_scan(
                parsed_scan_id,
                result["scan_metadata"],
                result["tools_run"],
            )
        )

        _sync_redis_publish(
            redis_channel,
            {
                "type": "orchestration_complete",
                "scan_id": scan_id,
                "scan_type": scan_type,
                "mode": result["scan_metadata"].get("execution_mode", scan_mode),
                "findings_count": result["findings_count"],
                "tools_run": result["tools_run"],
            },
        )

        from backend.workers.analyst_tasks import run_analyst

        run_analyst.delay(scan_id)
        logger.info(
            "[%s] orchestrate_scan complete — %d findings, chained run_analyst",
            scan_id, result["findings_count"],
        )
        return result

    except Exception as exc:
        traceback_text = traceback.format_exc()
        logger.error("[%s] orchestrate_scan crashed:\n%s", scan_id, traceback_text)

        try:
            _sync_db_write(lambda: _db_fail_scan(parsed_scan_id, traceback_text))
        except Exception as db_exc:
            logger.critical("[%s] Could not write failed status to DB: %s", scan_id, db_exc)

        _sync_redis_publish(
            redis_channel,
            {"type": "scan_failed", "scan_id": scan_id, "error": str(exc)},
        )
        raise
