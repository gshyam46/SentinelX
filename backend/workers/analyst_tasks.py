"""
SentinelX — Analyst Agent Celery Task
Runs after orchestrate_scan completes.

Chain: orchestrate_scan → run_analyst → generate_report

The analyst fetches all findings from the DB, generates a structured
AnalysisReport via LiteLLM, then chains to generate_report (Agent 3).
"""

from __future__ import annotations

import asyncio
import json
import logging
import traceback
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from backend.workers.celery_app import celery_app
from backend.config import get_settings
from backend.modules.ai.analyst_agent import analyze_findings

logger = logging.getLogger("sentinelx.workers.analyst")
settings = get_settings()


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
# DB helpers
# ---------------------------------------------------------------------------

async def _db_get_findings(scan_id: uuid.UUID) -> tuple[list[dict], dict]:
    """Return (findings_list, scan_meta_dict)."""
    from backend.db.session import async_session_factory
    from backend.models.scan import Scan

    async with async_session_factory() as db:
        from sqlalchemy import select
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        results = scan.results or {}
        findings = results.get("findings", [])
        return findings, {
            "domain": scan.domain,
            "scan_type": scan.scan_type,
            "execution_graph": results.get("execution_graph"),
            "auth_config": results.get("auth_config"),  # None for unauthenticated scans
        }


async def _db_save_ai_report(
    scan_id: uuid.UUID,
    report: dict,
    attack_chains: list[dict] | None = None,
) -> None:
    from backend.db.session import async_session_factory
    from backend.models.scan import Scan
    from sqlalchemy import select

    async with async_session_factory() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        existing = scan.results or {}
        # kev_matches is promoted to a top-level results key so it is
        # accessible to the analyst context and any future downstream readers
        # without having to dig into ai_report.
        kev_matches: list[str] = report.get("kev_matches", [])
        new_results: dict = {
            **existing,
            "ai_report": report,
            "kev_matches": kev_matches,
        }
        if attack_chains is not None:
            new_results["attack_chains"] = attack_chains
        scan.results = new_results
        scan.current_step = "AI analysis complete"
        await db.commit()


async def _db_save_remediation_plan(scan_id: uuid.UUID, plan: dict) -> None:
    from backend.db.session import async_session_factory
    from backend.models.scan import Scan
    from sqlalchemy import select

    async with async_session_factory() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        existing = scan.results or {}
        scan.results = {**existing, "remediation_plan": plan}
        await db.commit()


async def _db_fail_analyst(scan_id: uuid.UUID, error: str) -> None:
    from backend.db.session import async_session_factory
    from backend.models.scan import Scan
    from sqlalchemy import select

    async with async_session_factory() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan:
            existing = scan.results or {}
            scan.results = {**existing, "analyst_error": error[:2000]}
            scan.current_step = "Analysis failed — see error"
            await db.commit()


def _sync_db_run(coro_factory, *, max_retries: int = 3, base_delay: float = 0.5) -> Any:
    """Synchronous retry wrapper for async DB coroutines (mirrors scan_tasks._sync_db_write)."""
    import time
    last_exc: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            return asyncio.run(coro_factory())
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
        import redis.asyncio as aioredis

        async def _publish() -> None:
            r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            try:
                await r.publish(channel, json.dumps(payload))
            finally:
                await r.aclose()

        asyncio.run(_publish())
    except Exception as exc:  # noqa: BLE001
        logger.debug("Analyst Redis publish skipped: %s", exc)


# ---------------------------------------------------------------------------
# @task: run_analyst
# ---------------------------------------------------------------------------

@celery_app.task(
    name="run_analyst",
    track_started=True,
    acks_late=True,
    queue="analyst",
)
async def run_analyst(scan_id: str) -> dict:
    """
    Analyst task — chained after orchestrate_scan.

    1. Fetch all findings from DB.
    2. Run LLM AnalysisReport generation (with rule-based fallback).
    3. Store ai_report in scan.results.
    4. Chain to generate_report (Agent 3 — remediation + report_ready).
    """
    _scan_id = uuid.UUID(scan_id)
    redis_channel = f"scan:{scan_id}:events"

    logger.info("[%s] run_analyst starting", scan_id)
    _sync_redis_publish(redis_channel, {"type": "analyst_started", "scan_id": scan_id})

    try:
        # ── 1. Fetch findings ──────────────────────────────────────────────
        findings, scan_meta = _sync_db_run(lambda: _db_get_findings(_scan_id))
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
                "risk_score": 0,  # computed by agent
                "risk_level": "Unknown",
                "total_findings": len(findings),
                "severity_counts": dict(severity_counts),
            },
        }

        # ── 3. Validation layer (Phase 2) ──────────────────────────────────
        from backend.modules.pentest.validation.engine import run_validation
        validated_findings = await run_validation(findings, domain, auth_config=auth_config)
        scan_results["all_findings"] = validated_findings

        # ── 4. Agent 2 analysis (LLM + RAG, with rule-based fallback) ─────
        report = asyncio.run(analyze_findings(scan_results))

        # Stamp metadata
        report["scan_id"] = scan_id
        report["generated_at"] = datetime.now(timezone.utc).isoformat()
        report["model_used"] = report.get("model_used", settings.LITELLM_MODEL)

        # ── 5. Attack chain derivation (Phase 2 P2-05) ────────────────────
        from backend.modules.pentest.attack_chain import (
            derive_chains,
            narrate_chains,
        )
        _attack_chains: list[dict] | None = None
        if execution_graph:
            _raw_chains = derive_chains(
                execution_graph,
                validated_findings,
                report.get("kev_matches", []),
            )
            if _raw_chains:
                _raw_chains = await narrate_chains(_raw_chains)
            _attack_chains = [c.model_dump() for c in _raw_chains]
            logger.info(
                "[%s] Attack chain derivation: %d chain(s)", scan_id, len(_raw_chains)
            )

        # ── 6. Persist report + attack chains ─────────────────────────────
        _sync_db_run(lambda: _db_save_ai_report(_scan_id, report, _attack_chains))
        _sync_redis_publish(
            redis_channel,
            {
                "type": "analyst_complete",
                "scan_id": scan_id,
                "risk_score": report.get("risk_score", 0),
                "kev_matches": report.get("kev_matches", []),
            },
        )

        # ── 4. Chain to report generation (always — no follow-up mini-scans) ─
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
        _sync_db_run(lambda: _db_fail_analyst(_scan_id, tb))
        _sync_redis_publish(
            redis_channel,
            {"type": "analyst_failed", "scan_id": scan_id, "error": str(exc)},
        )
        raise


# ---------------------------------------------------------------------------
# @task: generate_report  (terminal task — runs remediation agent, marks ready)
# ---------------------------------------------------------------------------

@celery_app.task(
    name="generate_report",
    track_started=True,
    acks_late=True,
    queue="analyst",
)
def generate_report(scan_id: str) -> dict:
    """
    Terminal task — generates a structured PDF/JSON report from ai_report data.
    This is a stub; the full PDF renderer uses ReportLab (backend/reports/).
    """
    _scan_id = uuid.UUID(scan_id)
    redis_channel = f"scan:{scan_id}:events"

    logger.info("[%s] generate_report starting", scan_id)

    async def _fetch_report_data() -> dict:
        from backend.db.session import async_session_factory
        from backend.models.scan import Scan
        from sqlalchemy import select

        async with async_session_factory() as db:
            result = await db.execute(select(Scan).where(Scan.id == _scan_id))
            scan = result.scalar_one()
            findings = (scan.results or {}).get("findings", [])
            ai_report = (scan.results or {}).get("ai_report", {})
            return {
                "domain": scan.domain,
                "scan_type": scan.scan_type,
                "ai_report": ai_report,
                "findings": findings,
                "findings_count": scan.findings_count,
                "risk_score": scan.risk_score,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                # Adapts DB structure → RemediationAgent.advise() expected shape
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

    async def _mark_report_ready():
        from backend.db.session import async_session_factory
        from backend.models.scan import Scan
        from sqlalchemy import select

        async with async_session_factory() as db:
            result = await db.execute(select(Scan).where(Scan.id == _scan_id))
            scan = result.scalar_one()
            scan.current_step = "Report ready"
            existing = scan.results or {}
            scan.results = {**existing, "report_ready": True}
            await db.commit()

    try:
        data = asyncio.run(_fetch_report_data())

        # Run Agent 3 — Remediation Advisor
        remediation_plan = asyncio.run(_run_remediation(data))
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
