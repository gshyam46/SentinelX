"""
SentinelX — Analyst Agent Celery Task
Runs after orchestrate_scan completes.

Chain: orchestrate_scan → run_analyst → generate_report

The analyst fetches all findings from the DB, generates a structured
AnalysisReport via LiteLLM, and optionally re-queues a focused mini-scan
(budget=1) if it needs more data, up to MAX_ANALYST_ITERATIONS.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any

from backend.workers.celery_app import celery_app
from backend.config import get_settings

logger = logging.getLogger("sentinelx.workers.analyst")
settings = get_settings()

# Maximum times the analyst may request a follow-up mini-scan per scan job
MAX_ANALYST_ITERATIONS = 2


# ---------------------------------------------------------------------------
# AnalysisReport schema (stored as JSONB in scan.results['ai_report'])
# ---------------------------------------------------------------------------

def _empty_report(scan_id: str) -> dict:
    return {
        "scan_id": scan_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "executive_summary": "",
        "risk_score": 0,
        "attack_chains": [],
        "owasp_coverage": {},
        "critical_findings": [],
        "remediation_priorities": [],
        "follow_up_tools": [],
        "analyst_notes": "",
        "model_used": settings.LITELLM_MODEL,
    }


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

async def _db_get_findings(scan_id: uuid.UUID) -> tuple[list[dict], dict]:
    """Return (findings_list, scan_row_dict)."""
    from backend.db.session import async_session_factory
    from backend.models.scan import Scan

    async with async_session_factory() as db:
        from sqlalchemy import select
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        findings = (scan.results or {}).get("findings", [])
        return findings, {
            "domain": scan.domain,
            "scan_type": scan.scan_type,
            "tier": "free",  # NOTE: tier is on User; default to free for report gating
            "analyst_iteration": (scan.results or {}).get("analyst_iteration", 0),
        }


async def _db_save_ai_report(scan_id: uuid.UUID, report: dict) -> None:
    from backend.db.session import async_session_factory
    from backend.models.scan import Scan
    from sqlalchemy import select

    async with async_session_factory() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        existing = scan.results or {}
        scan.results = {**existing, "ai_report": report}
        scan.current_step = "AI analysis complete"
        await db.commit()


async def _db_increment_analyst_iteration(scan_id: uuid.UUID) -> int:
    """Bump analyst_iteration counter; return the new value."""
    from backend.db.session import async_session_factory
    from backend.models.scan import Scan
    from sqlalchemy import select

    async with async_session_factory() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        existing = scan.results or {}
        iteration = existing.get("analyst_iteration", 0) + 1
        scan.results = {**existing, "analyst_iteration": iteration}
        await db.commit()
        return iteration


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
        import redis as sync_redis

        r = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
        r.publish(channel, json.dumps(payload))
        r.close()
    except Exception as exc:  # noqa: BLE001
        logger.debug("Analyst Redis publish skipped: %s", exc)


# ---------------------------------------------------------------------------
# LLM call — generate AnalysisReport
# ---------------------------------------------------------------------------

_ANALYST_SYSTEM_PROMPT = """\
You are the SentinelX Analyst — a senior penetration tester reviewing scan findings.
Given a list of raw security findings from automated tools, you must:

1. Identify attack chains (how individual findings could be combined).
2. Prioritise remediation by business impact (CVSS-weighted, then OWASP category).
3. Highlight which OWASP Top 10 categories are covered and which are missing.
4. Decide whether additional tool runs are needed to complete the picture.

RESPONSE FORMAT — respond with valid JSON only, no prose:
{
  "executive_summary": "<2-3 sentences for a non-technical stakeholder>",
  "risk_score": <0-100 integer>,
  "attack_chains": [
    {"name": "<chain name>", "steps": ["<finding title>", ...], "impact": "<high|medium|low>"}
  ],
  "owasp_coverage": {
    "A01": "covered|partial|missing", "A02": "...", "A03": "...", "A04": "...",
    "A05": "...", "A06": "...", "A07": "...", "A08": "...", "A09": "...", "A10": "..."
  },
  "critical_findings": ["<title of top critical/high finding>", ...],
  "remediation_priorities": [
    {"priority": 1, "finding": "<title>", "action": "<concrete fix>", "effort": "low|medium|high"}
  ],
  "follow_up_tools": [],
  "analyst_notes": "<anything else the team should know>"
}

If you need more data, populate "follow_up_tools" with tool names from:
[subfinder, dnsx, httpx_probe, testssl, shodan_lookup, trufflehog, nuclei, nmap_scan,
 nikto, sqlmap_scan, dalfox_scan, ffuf_fuzz, wpscan, jwt_tool, arjun, feroxbuster, gitleaks]
Limit follow_up_tools to at most 2 items.
"""


async def _llm_analyze(findings: list[dict], domain: str, tier: str) -> dict:
    """Call LiteLLM to produce the AnalysisReport JSON."""
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    top_findings = sorted(findings, key=lambda f: sev_rank.get(f.get("severity", "info"), 4))[:30]

    findings_text = "\n".join(
        f"  [{f.get('severity','?').upper()}] {f.get('title','?')} "
        f"(tool={f.get('source_tool','?')}, owasp={f.get('owasp_categories',[])})"
        for f in top_findings
    ) or "  No findings recorded."

    user_msg = (
        f"TARGET: {domain}\n"
        f"TIER: {tier}\n"
        f"TOTAL FINDINGS: {len(findings)}\n\n"
        f"FINDINGS (top {len(top_findings)} by severity):\n"
        f"{findings_text}\n\n"
        "Produce the AnalysisReport JSON."
    )

    try:
        import litellm

        response = await litellm.acompletion(
            model=settings.LITELLM_MODEL,
            messages=[
                {"role": "system", "content": _ANALYST_SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            max_tokens=1200,
            temperature=0.1,
            response_format={"type": "json_object"},
        )
        raw = response.choices[0].message.content.strip()
        # Strip markdown fences if present
        match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", raw)
        if match:
            raw = match.group(1)
        return json.loads(raw)
    except ImportError:
        logger.warning("litellm not installed — returning stub report")
        return _rule_based_report(findings, domain)
    except Exception as exc:
        logger.error("LLM analyst call failed: %s", exc, exc_info=True)
        return _rule_based_report(findings, domain)


def _rule_based_report(findings: list[dict], domain: str) -> dict:
    """Deterministic fallback report when LLM is unavailable."""
    from collections import Counter

    sev_counts: Counter = Counter(f.get("severity", "info") for f in findings)
    risk = min(
        100,
        sev_counts["critical"] * 25
        + sev_counts["high"] * 10
        + sev_counts["medium"] * 4
        + sev_counts["low"] * 1,
    )
    owasp_seen: set[str] = set()
    for f in findings:
        owasp_seen.update(f.get("owasp_categories", []))
    owasp_all = {f"A{i:02d}" for i in range(1, 11)}
    owasp_coverage = {
        cat: ("covered" if cat in owasp_seen else "missing") for cat in sorted(owasp_all)
    }
    critical = [f.get("title", "?") for f in findings if f.get("severity") == "critical"][:5]
    high = [f.get("title", "?") for f in findings if f.get("severity") == "high"][:5]

    return {
        "executive_summary": (
            f"Automated scan of {domain} found {len(findings)} findings "
            f"({sev_counts['critical']} critical, {sev_counts['high']} high). "
            "Manual analyst review recommended."
        ),
        "risk_score": risk,
        "attack_chains": [],
        "owasp_coverage": owasp_coverage,
        "critical_findings": critical + high,
        "remediation_priorities": [
            {"priority": i + 1, "finding": title, "action": "Investigate and remediate.", "effort": "medium"}
            for i, title in enumerate((critical + high)[:5])
        ],
        "follow_up_tools": [],
        "analyst_notes": "LLM analyst unavailable — this report was generated by rule-based fallback.",
        "model_used": "rule_based_fallback",
    }


# ---------------------------------------------------------------------------
# @task: run_analyst
# ---------------------------------------------------------------------------

@celery_app.task(
    name="run_analyst",
    track_started=True,
    acks_late=True,
)
def run_analyst(scan_id: str) -> dict:
    """
    Analyst task — chained after orchestrate_scan.

    1. Fetch all findings from DB.
    2. Run LLM AnalysisReport generation (with rule-based fallback).
    3. Store ai_report in scan.results.
    4. If analyst requests follow-up tools AND iteration < MAX_ANALYST_ITERATIONS:
       - Re-queue orchestrate_scan (single tool, budget=1) via a mini orchestration.
       - Re-queue run_analyst to process new findings.
    5. Otherwise, chain to generate_report.
    """
    _scan_id = uuid.UUID(scan_id)
    redis_channel = f"scan:{scan_id}:events"

    logger.info("[%s] run_analyst starting", scan_id)
    _sync_redis_publish(redis_channel, {"type": "analyst_started", "scan_id": scan_id})

    try:
        # ── 1. Fetch findings ──────────────────────────────────────────────
        findings, scan_meta = _sync_db_run(lambda: _db_get_findings(_scan_id))
        domain = scan_meta["domain"]
        tier = scan_meta["tier"]
        current_iteration = scan_meta["analyst_iteration"]

        logger.info(
            "[%s] Analyst processing %d findings (iteration=%d)",
            scan_id, len(findings), current_iteration,
        )

        # ── 2. LLM analysis ────────────────────────────────────────────────
        report = asyncio.run(_llm_analyze(findings, domain, tier))

        # Stamp metadata
        report["scan_id"] = scan_id
        report["generated_at"] = datetime.now(timezone.utc).isoformat()
        report["model_used"] = report.get("model_used", settings.LITELLM_MODEL)
        report["analyst_iteration"] = current_iteration

        # ── 3. Persist report ──────────────────────────────────────────────
        _sync_db_run(lambda: _db_save_ai_report(_scan_id, report))
        _sync_redis_publish(
            redis_channel,
            {
                "type": "analyst_complete",
                "scan_id": scan_id,
                "risk_score": report.get("risk_score", 0),
                "iteration": current_iteration,
            },
        )

        # ── 4. Follow-up mini-scan? ────────────────────────────────────────
        follow_up_tools: list[str] = report.get("follow_up_tools", [])

        if follow_up_tools and current_iteration < MAX_ANALYST_ITERATIONS:
            next_tool = follow_up_tools[0]  # one tool at a time for budget=1 mini-scan
            new_iteration = _sync_db_run(lambda: _db_increment_analyst_iteration(_scan_id))

            logger.info(
                "[%s] Analyst requests follow-up tool '%s' (iteration %d/%d)",
                scan_id, next_tool, new_iteration, MAX_ANALYST_ITERATIONS,
            )
            _sync_redis_publish(
                redis_channel,
                {
                    "type": "analyst_followup",
                    "scan_id": scan_id,
                    "tool": next_tool,
                    "iteration": new_iteration,
                },
            )

            # Re-queue mini orchestrate_scan (budget capped to 1 inside mini mode)
            orchestrate_mini_scan.delay(scan_id, domain, tier, next_tool)
            # run_analyst will be re-queued by orchestrate_mini_scan on completion

        else:
            # ── 5. Chain to report generation ─────────────────────────────
            from backend.workers.analyst_tasks import generate_report  # self-import OK

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
# @task: orchestrate_mini_scan  (budget=1 follow-up)
# ---------------------------------------------------------------------------

@celery_app.task(
    name="orchestrate_mini_scan",
    track_started=True,
    acks_late=True,
    queue="scans",
)
def orchestrate_mini_scan(scan_id: str, target: str, tier: str, tool: str) -> dict:
    """
    A stripped-down orchestration that runs exactly ONE specific tool.
    Used when the analyst requests a targeted follow-up after its initial report.
    On completion, re-queues run_analyst.
    """
    from backend.workers.scan_tasks import _sync_db_write, _sync_redis_publish  # type: ignore[attr-defined]

    _scan_id = uuid.UUID(scan_id)
    redis_channel = f"scan:{scan_id}:events"

    logger.info("[%s] orchestrate_mini_scan — tool=%s", scan_id, tool)
    _sync_redis_publish(
        redis_channel,
        {"type": "mini_scan_started", "scan_id": scan_id, "tool": tool},
    )

    async def _run_one_tool() -> list[dict]:
        from backend.agents.orchestrator import (
            _execute_tool,
            Finding,
            ScanState,
        )

        state = ScanState(target=target, tier=tier, scan_id=_scan_id)

        findings = await _execute_tool(tool, {"target": target}, state)
        return [f.to_dict() if isinstance(f, Finding) else f for f in findings]

    try:
        findings_dicts = asyncio.run(_run_one_tool())

        for fd in findings_dicts:
            _sync_db_run(lambda f=fd: _db_append_finding(_scan_id, f))

        _sync_redis_publish(
            redis_channel,
            {
                "type": "mini_scan_complete",
                "scan_id": scan_id,
                "tool": tool,
                "new_findings": len(findings_dicts),
            },
        )

        # Re-queue analyst with fresh data
        run_analyst.delay(scan_id)
        return {"tool": tool, "new_findings": len(findings_dicts)}

    except Exception as exc:
        logger.error("[%s] orchestrate_mini_scan failed: %s", scan_id, exc, exc_info=True)
        _sync_redis_publish(
            redis_channel,
            {"type": "mini_scan_failed", "scan_id": scan_id, "tool": tool, "error": str(exc)},
        )
        # Still re-queue analyst so the report is generated with existing data
        run_analyst.delay(scan_id)
        return {"tool": tool, "error": str(exc)}


# ---------------------------------------------------------------------------
# @task: generate_report  (terminal task — produces downloadable report)
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

    async def _fetch_report_data():
        from backend.db.session import async_session_factory
        from backend.models.scan import Scan
        from sqlalchemy import select

        async with async_session_factory() as db:
            result = await db.execute(select(Scan).where(Scan.id == _scan_id))
            scan = result.scalar_one()
            return {
                "domain": scan.domain,
                "scan_type": scan.scan_type,
                "ai_report": (scan.results or {}).get("ai_report", {}),
                "findings": (scan.results or {}).get("findings", []),
                "findings_count": scan.findings_count,
                "risk_score": scan.risk_score,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            }

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
