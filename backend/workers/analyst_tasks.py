"""
SentinelX — Analyst Agent Celery Task
Runs after orchestrate_scan completes.

Chain: orchestrate_scan → run_analyst → generate_report

Schema contract (scan.results JSONB — analyst ownership):
  analysis.ai_report      — written ONLY by _db_save_ai_report
  analysis.kev_matches    — written ONLY by _db_save_ai_report
  analysis.attack_chains  — written ONLY by _db_save_ai_report
  report.remediation_plan — written ONLY by _db_save_remediation_plan
  report_ready            — written ONLY by _mark_report_ready

All writes use atomic PostgreSQL || operator — scan_findings is never touched.
"""

from __future__ import annotations

import json
import logging
import traceback
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, text

from backend.workers.celery_app import celery_app
from backend.config import get_settings
from backend.db.session import run_in_worker_loop, worker_async_session_factory
from backend.modules.ai.analyst_agent import analyze_findings

logger = logging.getLogger("sentinelx.workers.analyst")
settings = get_settings()

# ---------------------------------------------------------------------------
# Atomic SQL constants — analyst owns the "analysis" and "report" top-level keys.
# ---------------------------------------------------------------------------

_MERGE_SQL = text(
    "UPDATE scans SET results = COALESCE(results, '{}') || :patch::jsonb WHERE id = :scan_id"
)

_MERGE_STEP_SQL = text(
    "UPDATE scans SET results = COALESCE(results, '{}') || :patch::jsonb,"
    " current_step = :step WHERE id = :scan_id"
)


def _risk_level(score: float) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    if score > 0:
        return "Low"
    return "Minimal"


# ---------------------------------------------------------------------------
# DB helpers — all use atomic SQL, never touch scan_findings
# ---------------------------------------------------------------------------

async def _db_get_findings(scan_id: uuid.UUID) -> tuple[list[dict], dict]:
    """Return (findings_list, scan_meta_dict).  Reads scan_findings with legacy fallback."""
    from backend.models.scan import Scan

    async with worker_async_session_factory() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        results = scan.results or {}
        # scan_findings is the new key; fall back to findings for old scan records
        findings = results.get("scan_findings") or results.get("findings", [])
        return findings, {
            "domain": scan.domain,
            "scan_type": scan.scan_type,
            "execution_graph": results.get("execution_graph"),
            "auth_config": results.get("auth_config"),
        }


async def _db_save_ai_report(
    scan_id: uuid.UUID,
    report: dict,
    attack_chains: list[dict] | None = None,
) -> None:
    """
    Write AI analysis results under the 'analysis' key.

    Atomic || merge — never touches scan_findings, report, or any other key.
    """
    kev_matches: list[str] = report.get("kev_matches", [])
    analysis: dict = {
        "ai_report": report,
        "kev_matches": kev_matches,
    }
    if attack_chains is not None:
        analysis["attack_chains"] = attack_chains

    async with worker_async_session_factory() as db:
        await db.execute(
            _MERGE_STEP_SQL,
            {
                "patch": json.dumps({"analysis": analysis}, default=str),
                "step": "AI analysis complete",
                "scan_id": scan_id,  # uuid.UUID
            },
        )
        await db.commit()


async def _db_save_remediation_plan(scan_id: uuid.UUID, plan: dict) -> None:
    """Write remediation plan under 'report' key — never touches scan_findings or analysis."""
    async with worker_async_session_factory() as db:
        await db.execute(
            _MERGE_SQL,
            {
                "patch": json.dumps({"report": {"remediation_plan": plan}}, default=str),
                "scan_id": scan_id,  # uuid.UUID
            },
        )
        await db.commit()


async def _db_fail_analyst(scan_id: uuid.UUID, error: str) -> None:
    async with worker_async_session_factory() as db:
        await db.execute(
            _MERGE_STEP_SQL,
            {
                "patch": json.dumps({"analyst_error": error[:2000]}),
                "step": "Analysis failed — see error",
                "scan_id": scan_id,  # uuid.UUID
            },
        )
        await db.commit()


def _sync_db_run(coro_factory, *, max_retries: int = 3, base_delay: float = 0.5) -> Any:
    """Synchronous retry wrapper for async DB coroutines — uses persistent worker loop."""
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
                    "Analyst DB write attempt %d/%d failed (%s) — retrying in %.1fs",
                    attempt, max_retries, exc, delay,
                )
                time.sleep(delay)
    raise last_exc  # type: ignore[misc]


def _sync_redis_publish(channel: str, payload: dict) -> None:
    try:
        import redis as sync_redis
        r = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
        r.publish(channel, json.dumps(payload))
        r.close()
    except Exception as exc:  # noqa: BLE001
        logger.debug("Analyst Redis publish skipped: %s", exc)


async def _async_redis_publish(channel: str, payload: dict) -> None:
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        try:
            await r.publish(channel, json.dumps(payload))
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001
        logger.debug("Analyst async Redis publish skipped: %s", exc)


# ---------------------------------------------------------------------------
# run_analyst — async implementation
# ---------------------------------------------------------------------------

async def _run_analyst_async(scan_id: str) -> dict:
    """Full async body of the analyst task — called via run_in_worker_loop."""
    _scan_id = uuid.UUID(scan_id)
    redis_channel = f"scan:{scan_id}:events"

    logger.info("[%s] run_analyst starting", scan_id)
    await _async_redis_publish(redis_channel, {"type": "analyst_started", "scan_id": scan_id})

    try:
        # ── 1. Fetch findings ──────────────────────────────────────────────
        findings, scan_meta = await _db_get_findings(_scan_id)
        domain = scan_meta["domain"]
        execution_graph: dict | None = scan_meta.get("execution_graph")
        auth_config: dict | None = scan_meta.get("auth_config")

        logger.info("[%s] Analyst processing %d findings", scan_id, len(findings))

        # ── 2. Build scan_results shape expected by AnalystAgent ──────────
        severity_counts = Counter(f.get("severity", "info") for f in findings)
        scan_results = {
            "domain": domain,
            "all_findings": findings,
            "summary": {
                "risk_score": 0,
                "risk_level": "Unknown",
                "total_findings": len(findings),
                "severity_counts": dict(severity_counts),
            },
        }

        # ── 3. Validation layer ────────────────────────────────────────────
        from backend.modules.pentest.validation.engine import run_validation
        validated_findings = await run_validation(findings, domain, auth_config=auth_config)
        scan_results["all_findings"] = validated_findings

        # ── 4. Agent 2 analysis (LLM + RAG, with rule-based fallback) ─────
        report = await analyze_findings(scan_results)
        report["scan_id"] = scan_id
        report["generated_at"] = datetime.now(timezone.utc).isoformat()
        report["model_used"] = report.get("model_used", settings.LITELLM_MODEL)

        # ── 5. Attack chain derivation ─────────────────────────────────────
        from backend.modules.pentest.attack_chain import derive_chains, narrate_chains
        _attack_chains: list[dict] | None = None
        if execution_graph:
            _raw_chains = derive_chains(
                execution_graph, validated_findings, report.get("kev_matches", [])
            )
            if _raw_chains:
                _raw_chains = await narrate_chains(_raw_chains)
            _attack_chains = [c.model_dump() for c in _raw_chains]
            logger.info("[%s] Attack chains: %d derived", scan_id, len(_raw_chains))

        # ── 6. Persist report + attack chains (atomic, owns 'analysis' key) ──
        await _db_save_ai_report(_scan_id, report, _attack_chains)
        await _async_redis_publish(
            redis_channel,
            {
                "type": "analyst_complete",
                "scan_id": scan_id,
                "risk_score": report.get("risk_score", 0),
                "kev_matches": report.get("kev_matches", []),
            },
        )

        # ── 7. Chain to report generation ─────────────────────────────────
        generate_report.delay(scan_id)

        logger.info("[%s] run_analyst done — risk_score=%s", scan_id, report.get("risk_score"))
        return {
            "scan_id": scan_id,
            "risk_score": report.get("risk_score", 0),
            "findings_analysed": len(findings),
        }

    except Exception as exc:
        tb = traceback.format_exc()
        logger.error("[%s] run_analyst CRASHED:\n%s", scan_id, tb)
        await _db_fail_analyst(_scan_id, tb)
        await _async_redis_publish(
            redis_channel,
            {"type": "analyst_failed", "scan_id": scan_id, "error": str(exc)},
        )
        raise


# ---------------------------------------------------------------------------
# @task: run_analyst  (sync wrapper — Celery prefork compatible)
# ---------------------------------------------------------------------------

@celery_app.task(
    name="run_analyst",
    track_started=True,
    acks_late=True,
    queue="analyst",
)
def run_analyst(scan_id: str) -> dict:
    """Analyst task — sync wrapper around _run_analyst_async."""
    return run_in_worker_loop(_run_analyst_async(scan_id))


# ---------------------------------------------------------------------------
# @task: generate_report  (terminal task)
# ---------------------------------------------------------------------------

@celery_app.task(
    name="generate_report",
    track_started=True,
    acks_late=True,
    queue="analyst",
)
def generate_report(scan_id: str) -> dict:
    """Terminal task — runs remediation agent and marks report_ready."""
    _scan_id = uuid.UUID(scan_id)
    redis_channel = f"scan:{scan_id}:events"

    logger.info("[%s] generate_report starting", scan_id)

    async def _fetch_report_data() -> dict:
        from backend.models.scan import Scan

        async with worker_async_session_factory() as db:
            result = await db.execute(select(Scan).where(Scan.id == _scan_id))
            scan = result.scalar_one()
            results = scan.results or {}
            # scan_findings key (new schema); fallback to findings for old records
            findings = results.get("scan_findings") or results.get("findings", [])
            # ai_report under analysis key (new schema); fallback to top-level
            analysis = results.get("analysis") or {}
            ai_report = analysis.get("ai_report") or results.get("ai_report") or {}
            return {
                "domain": scan.domain,
                "scan_type": scan.scan_type,
                "ai_report": ai_report,
                "findings": findings,
                "findings_count": scan.findings_count,
                "risk_score": scan.risk_score,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "scan_results_for_remediation": {
                    "domain": scan.domain,
                    "all_findings": findings,
                    "summary": {
                        "risk_score": scan.risk_score,
                        "risk_level": _risk_level(scan.risk_score),
                        "total_findings": scan.findings_count,
                    },
                },
            }

    async def _run_remediation(data: dict) -> dict:
        from backend.modules.ai.remediation_agent import generate_remediation_plan
        return await generate_remediation_plan(
            scan_results=data["scan_results_for_remediation"],
            analyst_output=data.get("ai_report"),
        )

    async def _mark_report_ready() -> None:
        """Atomic write — sets report_ready at top level (frontend compatibility)."""
        async with worker_async_session_factory() as db:
            await db.execute(
                text(
                    "UPDATE scans SET"
                    " results = COALESCE(results, '{}') || :patch::jsonb,"
                    " current_step = 'Report ready'"
                    " WHERE id = :scan_id"
                ),
                {"patch": json.dumps({"report_ready": True}), "scan_id": _scan_id},  # uuid.UUID
            )
            await db.commit()

    try:
        data = run_in_worker_loop(_fetch_report_data())

        remediation_plan = run_in_worker_loop(_run_remediation(data))
        _sync_db_run(lambda: _db_save_remediation_plan(_scan_id, remediation_plan))
        logger.info(
            "[%s] Remediation plan generated — %d items",
            scan_id, len(remediation_plan.get("remediation_plan", [])),
        )

        _sync_db_run(_mark_report_ready)

        _sync_redis_publish(
            redis_channel,
            {
                "type": "report_ready",
                "scan_id": scan_id,
                "domain": data["domain"],
                "risk_score": data["risk_score"],
                "findings_count": data["findings_count"],
            },
        )

        logger.info("[%s] generate_report done — report_ready published", scan_id)
        return {"scan_id": scan_id, "report_ready": True, "risk_score": data["risk_score"]}

    except Exception as exc:
        logger.error("[%s] generate_report failed: %s", scan_id, exc, exc_info=True)
        _sync_redis_publish(
            redis_channel,
            {"type": "report_failed", "scan_id": scan_id, "error": str(exc)},
        )
        raise
