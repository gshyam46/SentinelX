"""
SentinelX — Orchestrator Agent
Central agentic brain. An LLM reasoning loop that decides which
security tools to run based on live findings, not a fixed pipeline.

Exit conditions are structural — no while True, no StopIteration hacks.
The async generator terminates when any exit condition becomes true.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import AsyncGenerator, Literal, Optional

logger = logging.getLogger("sentinelx.orchestrator")

# ---------------------------------------------------------------------------
# Tool registry — every tool the orchestrator can invoke
# ---------------------------------------------------------------------------
TOOL_REGISTRY: dict[str, dict] = {
    # ── Reconnaissance ──────────────────────────────────────────────────────
    "subfinder": {
        "category": "recon",
        "description": "Passive subdomain enumeration via multiple DNS sources",
        "owasp": ["A05"],
        "timeout": 120,
    },
    "dnsx": {
        "category": "recon",
        "description": "DNS resolution and brute-force for discovered subdomains",
        "owasp": ["A05"],
        "timeout": 90,
    },
    "httpx_probe": {
        "category": "recon",
        "description": "Probes live hosts: status, tech stack, headers, response fingerprinting",
        "owasp": ["A05", "A06"],
        "timeout": 60,
    },
    "testssl": {
        "category": "recon",
        "description": "Comprehensive TLS/SSL version, cipher, and certificate analysis",
        "owasp": ["A02"],
        "timeout": 90,
    },
    "shodan_lookup": {
        "category": "recon",
        "description": "Passive Shodan lookup for open ports and known CVEs (no active traffic)",
        "owasp": ["A05", "A06"],
        "timeout": 30,
    },
    "trufflehog": {
        "category": "recon",
        "description": "Secret/credential scanning in exposed repos and files",
        "owasp": ["A02", "A05"],
        "timeout": 120,
    },
    # ── Active Scanning ──────────────────────────────────────────────────────
    "nuclei": {
        "category": "active",
        "description": "Template-based CVE and misconfiguration scanning (ProjectDiscovery)",
        "owasp": ["A01", "A05", "A06"],
        "timeout": 1200,
    },
    "nmap_scan": {
        "category": "active",
        "description": "TCP port enumeration and service/version detection",
        "owasp": ["A05"],
        "timeout": 600,
    },
    "zap": {
        "category": "active",
        "description": "OWASP ZAP web application scanner — passive spider + active attack templates",
        "owasp": ["A01", "A02", "A03", "A05", "A07"],
        "timeout": 900,
    },
    "gobuster": {
        "category": "active",
        "description": "Directory and file brute-forcing via wordlist (optional, high noise)",
        "owasp": ["A01", "A05"],
        "timeout": 300,
    },
    "nikto": {
        "category": "active",
        "description": "Web server misconfiguration and outdated software scanner",
        "owasp": ["A05", "A06"],
        "timeout": 300,
    },
    "sqlmap_scan": {
        "category": "active",
        "description": "Automated SQL injection detection and exploitation [PRO ONLY]",
        "owasp": ["A03"],
        "timeout": 600,
        "pro_only": True,
    },
    "dalfox_scan": {
        "category": "active",
        "description": "XSS parameter analysis and blind XSS detection [PRO ONLY]",
        "owasp": ["A03"],
        "timeout": 300,
        "pro_only": True,
    },
    "ffuf_fuzz": {
        "category": "active",
        "description": "Directory and endpoint fuzzing with wordlist",
        "owasp": ["A01", "A05"],
        "timeout": 300,
    },
    # ── Targeted / Conditional ───────────────────────────────────────────────
    "wpscan": {
        "category": "targeted",
        "description": "WordPress vulnerability scanner — runs only when WordPress detected",
        "owasp": ["A06"],
        "timeout": 300,
        "trigger": "WordPress detected by httpx_probe",
    },
    "jwt_tool": {
        "category": "targeted",
        "description": "JWT attack suite — runs only when Bearer tokens observed in responses",
        "owasp": ["A01", "A07"],
        "timeout": 120,
        "trigger": "JWT/Bearer token in httpx_probe response headers",
    },
    "arjun": {
        "category": "targeted",
        "description": "HTTP parameter discovery for dynamic endpoints",
        "owasp": ["A01", "A03"],
        "timeout": 180,
        "trigger": "Dynamic /api/ endpoints found by ffuf_fuzz",
    },
    "feroxbuster": {
        "category": "targeted",
        "description": "Recursive directory brute-forcer — runs after ffuf finds dirs [PRO ONLY]",
        "owasp": ["A01"],
        "timeout": 600,
        "trigger": "ffuf_fuzz found directories",
        "pro_only": True,
    },
    "gitleaks": {
        "category": "targeted",
        "description": "Git secret scanning — runs immediately when .git path is exposed (200)",
        "owasp": ["A02"],
        "timeout": 120,
        "trigger": ".git path responds HTTP 200",
    },
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    description: str
    target: str
    source_tool: str
    owasp_categories: list[str] = field(default_factory=list)
    cve_id: Optional[str] = None
    remediation: Optional[str] = None
    raw: Optional[dict] = None
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "target": self.target,
            "source_tool": self.source_tool,
            "owasp_categories": self.owasp_categories,
            "cve_id": self.cve_id,
            "remediation": self.remediation,
            "discovered_at": self.discovered_at.isoformat(),
        }


@dataclass
class ScanState:
    target: str
    scan_id: uuid.UUID
    budget: int
    allowed_tools: list[str]
    findings: list[Finding] = field(default_factory=list)
    tools_run: list[str] = field(default_factory=list)
    tool_budget: int = field(init=False)
    consecutive_empty_runs: int = 0
    coverage_flags: set[str] = field(default_factory=set)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        self.tool_budget = self.budget

    # ── Exit condition checks (evaluated at the top of every iteration) ──────

    def budget_exhausted(self) -> bool:
        return self.tool_budget <= 0

    def stalled(self) -> bool:
        """Three consecutive tool runs that produced zero new findings."""
        return self.consecutive_empty_runs >= 3

    def should_exit(self) -> tuple[bool, str]:
        if self.budget_exhausted():
            return True, f"Tool budget exhausted ({self.budget} calls)"
        if self.stalled():
            return True, "3 consecutive empty tool runs — target sufficiently covered"
        return False, ""

    # ── Helpers ──────────────────────────────────────────────────────────────

    def severity_summary(self) -> dict[str, int]:
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def available_tools(self) -> list[str]:
        """Tools not yet run and within the caller-enforced allowed list."""
        return [
            name for name in self.allowed_tools
            if name not in self.tools_run and name in TOOL_REGISTRY
        ]

    def record_tool_result(self, tool: str, new_findings: list[Finding]) -> None:
        self.tools_run.append(tool)
        self.tool_budget -= 1
        if new_findings:
            self.findings.extend(new_findings)
            for f in new_findings:
                self.coverage_flags.update(f.owasp_categories)
            self.consecutive_empty_runs = 0
        else:
            self.consecutive_empty_runs += 1


@dataclass
class ScanEvent:
    type: Literal[
        "tool_started",
        "tool_complete",
        "finding",
        "agent_reasoning",
        "scan_complete",
        "exit_condition",
    ]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tool: Optional[str] = None
    finding: Optional[Finding] = None
    reasoning: Optional[str] = None
    budget_remaining: int = 0
    metadata: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "timestamp": self.timestamp.isoformat(),
            "tool": self.tool,
            "finding": self.finding.to_dict() if self.finding else None,
            "reasoning": self.reasoning,
            "budget_remaining": self.budget_remaining,
            "metadata": self.metadata or {},
        }


# ---------------------------------------------------------------------------
# LLM Decision Call
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are the SentinelX Orchestrator — an autonomous security analysis agent.
Your job is to decide which security tool to run NEXT based on what has already been discovered.

ADAPTIVE SELECTION RULES (apply these in order):
1. If httpx_probe found WordPress -> next tool: wpscan
2. If nmap_scan found open port 3306 or 5432 -> next tool: sqlmap_scan (pro tier only)
3. If httpx_probe response contained "Authorization: Bearer" -> next tool: jwt_tool
4. If ffuf_fuzz found /api/ endpoints -> next tool: arjun, then dalfox_scan
5. If any tool found an HTTP 200 on /.git/ -> next tool: gitleaks (IMMEDIATE, highest priority)
6. If nuclei already confirmed SQLi -> DO NOT run sqlmap_scan (already confirmed, save budget)
7. Never run the same tool twice on the same target
8. Only select tools from the AVAILABLE TOOLS list shown below — selecting any other tool name is invalid

RESPONSE FORMAT — respond with valid JSON only, no prose:
{
  "action": "run_tool" | "complete",
  "tool": "<tool_name or null>",
  "params": {"target": "<target>", "<key>": "<value>"},
  "reasoning": "<why this tool now, max 2 sentences>",
  "owasp_categories": ["A01", "A06"]
}

If "action" is "complete", set "tool" to null and explain in "reasoning" why scanning is done.
"""


async def _llm_decide(state: ScanState) -> dict:
    """
    Call the LLM with current scan state and get the next tool decision.
    Returns the parsed JSON decision dict.
    """
    severity_summary = state.severity_summary()
    available = state.available_tools()

    # Build a compact tools reference for the LLM
    tool_descriptions = "\n".join(
        f"  {name}: {meta['description']} [OWASP: {', '.join(meta['owasp'])}]"
        + (" [PRO ONLY]" if meta.get("pro_only") else "")
        for name, meta in TOOL_REGISTRY.items()
        if name in available
    )

    # Compact findings summary (most recent 10 by severity)
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    top_findings = sorted(state.findings, key=lambda f: sev_rank.get(f.severity, 4))[:10]
    findings_text = "\n".join(
        f"  [{f.severity.upper()}] {f.title} (tool={f.source_tool}, target={f.target})"
        for f in top_findings
    ) or "  None yet."

    user_msg = f"""TARGET: {state.target}
BUDGET REMAINING: {state.tool_budget} tool calls
TOOLS ALREADY RUN: {', '.join(state.tools_run) or 'None'}
OWASP COVERAGE SO FAR: {', '.join(sorted(state.coverage_flags)) or 'None'}
CONSECUTIVE EMPTY RUNS: {state.consecutive_empty_runs}

CURRENT FINDINGS ({severity_summary['critical']}C / {severity_summary['high']}H / \
{severity_summary['medium']}M / {severity_summary['low']}L):
{findings_text}

AVAILABLE TOOLS:
{tool_descriptions or '  None remaining.'}

Decide the next action."""

    try:
        import litellm
        from backend.config import get_settings

        settings = get_settings()
        models_to_try = [settings.LITELLM_MODEL]
        fallback = getattr(settings, "LITELLM_FALLBACK_MODEL", None)
        if fallback and fallback != settings.LITELLM_MODEL:
            models_to_try.append(fallback)

        last_exc: Exception | None = None
        for model in models_to_try:
            try:
                response = await litellm.acompletion(
                    model=model,
                    messages=[
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": user_msg},
                    ],
                    max_tokens=400,
                    temperature=0.1,
                    # NOTE: response_format=json_object intentionally omitted —
                    # Groq llama3 models return 400 for this parameter.
                )
                raw = response.choices[0].message.content.strip()
                logger.info("[%s] LLM orchestrator decision: model=%s", state.scan_id, model)
                return _parse_llm_json(raw, state)
            except Exception as exc:
                last_exc = exc
                logger.warning(
                    "[%s] LLM decision failed for model '%s': %s — trying next",
                    state.scan_id, model, exc,
                )

        logger.error("[%s] All LLM models failed for orchestrator decision: %s", state.scan_id, last_exc)
        return _rule_based_decision(state)

    except ImportError:
        logger.warning("litellm not installed — using rule-based fallback decision")
        return _rule_based_decision(state)


def _parse_llm_json(raw: str, state: ScanState) -> dict:
    """Extract and validate the JSON decision from LLM output."""
    # Strip markdown code fences if present
    match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", raw)
    if match:
        raw = match.group(1)
    try:
        decision = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("LLM returned non-JSON — falling back to rule-based")
        return _rule_based_decision(state)

    action = decision.get("action")
    tool = decision.get("tool")

    # Guard: validate tool against the code-enforced allowed list
    if action == "run_tool":
        if tool not in TOOL_REGISTRY:
            logger.warning(f"LLM selected unknown tool '{tool}' — falling back")
            return _rule_based_decision(state)
        if tool in state.tools_run:
            logger.warning(f"LLM tried to re-run '{tool}' — falling back")
            return _rule_based_decision(state)
        if tool not in state.allowed_tools:
            logger.warning(f"LLM selected disallowed tool '{tool}' — falling back")
            return _rule_based_decision(state)
        logger.info(
            "[%s] LLM→tool_selected: %s | reasoning: %s",
            state.scan_id, tool, decision.get("reasoning", "")[:120],
        )

    return decision


def _rule_based_decision(state: ScanState) -> dict:
    """
    Deterministic fallback when LLM is unavailable.
    Applies priority rules in fixed order.
    """
    available = set(state.available_tools())

    # Priority 1: .git exposed → gitleaks
    git_exposed = any(
        ".git" in f.title.lower() and f.severity in ("critical", "high")
        for f in state.findings
    )
    if git_exposed and "gitleaks" in available:
        return {
            "action": "run_tool",
            "tool": "gitleaks",
            "params": {"target": state.target},
            "reasoning": "Exposed .git path detected — scanning for leaked secrets immediately.",
            "owasp_categories": ["A02"],
        }

    # Priority 2: WordPress → wpscan
    wp_detected = any("wordpress" in f.title.lower() for f in state.findings)
    if wp_detected and "wpscan" in available:
        return {
            "action": "run_tool",
            "tool": "wpscan",
            "params": {"target": state.target},
            "reasoning": "WordPress detected — checking for known plugin/theme CVEs.",
            "owasp_categories": ["A06"],
        }

    # Priority 3: Open DB ports → sqlmap (pro only)
    db_open = any(
        f.source_tool == "nmap_scan" and ("3306" in f.target or "5432" in f.target)
        for f in state.findings
    )
    if db_open and "sqlmap_scan" in available:
        return {
            "action": "run_tool",
            "tool": "sqlmap_scan",
            "params": {"target": state.target},
            "reasoning": "Database port open on target — testing for SQL injection.",
            "owasp_categories": ["A03"],
        }

    # Default: pick next available tool in preferred order
    preferred_order = [
        "httpx_probe", "subfinder", "dnsx", "testssl",
        "shodan_lookup", "nmap_scan", "nuclei", "ffuf_fuzz",
        "nikto", "arjun", "trufflehog",
    ]
    for tool in preferred_order:
        if tool in available:
            meta = TOOL_REGISTRY[tool]
            return {
                "action": "run_tool",
                "tool": tool,
                "params": {"target": state.target},
                "reasoning": f"Running {tool} as next logical step in reconnaissance chain.",
                "owasp_categories": meta["owasp"],
            }

    # No tools left
    return {
        "action": "complete",
        "tool": None,
        "params": {},
        "reasoning": "No additional tools available for this tier and target.",
        "owasp_categories": [],
    }


# ---------------------------------------------------------------------------
# Redis pub/sub publisher
# ---------------------------------------------------------------------------

async def _publish_event(scan_id: uuid.UUID, event: ScanEvent) -> None:
    """
    Publish a ScanEvent to Redis channel `scan:{scan_id}:events`.
    Silently swallows connection errors so scanning continues uninterrupted.
    """
    try:
        import redis.asyncio as aioredis
        from backend.config import get_settings

        settings = get_settings()
        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        channel = f"scan:{scan_id}:events"
        await r.publish(channel, json.dumps(event.to_dict()))
        await r.aclose()
    except Exception as exc:
        logger.debug(f"Redis publish skipped ({exc})")


# ---------------------------------------------------------------------------
# Tool executor stub — dispatches to real tool modules
# ---------------------------------------------------------------------------

async def _execute_tool(
    tool: str,
    params: dict,
    state: ScanState,
) -> list[Finding]:
    """
    Dispatch a tool call through the operational registry.
    Returns a list of new Finding objects.

    All tool implementations live in backend/modules/pentest/ and are
    registered in backend/modules/pentest/tool_registry.OPERATIONAL_REGISTRY.
    """
    try:
        from backend.modules.pentest.tool_registry import OPERATIONAL_REGISTRY

        executor = OPERATIONAL_REGISTRY.get(tool)
        if executor is None:
            logger.warning(f"Tool '{tool}' has no operational implementation — skipping")
            return []

        target = params.get("target", state.target)
        raw_findings = await executor(target=target, scan_id=state.scan_id, params=params)

        findings = []
        for r in raw_findings:
            if isinstance(r, Finding):
                findings.append(r)
            elif isinstance(r, dict):
                findings.append(Finding(
                    title=r.get("title", "Unknown"),
                    severity=r.get("severity", "info"),
                    description=r.get("description", ""),
                    target=r.get("target", target),
                    source_tool=tool,
                    owasp_categories=r.get("owasp_categories", []),
                    cve_id=r.get("cve_id"),
                    remediation=r.get("remediation"),
                    raw=r,
                ))
        return findings

    except Exception as exc:
        logger.error(f"Tool '{tool}' raised an exception: {exc}", exc_info=True)
        return []


# ---------------------------------------------------------------------------
# OrchestratorAgent — the agentic loop
# ---------------------------------------------------------------------------

class OrchestratorAgent:
    """
    The central agentic brain of SentinelX.

    Implements a budget-aware async generator loop where the LLM
    decides the next tool on every iteration. The loop exits naturally
    when any exit condition becomes true — no hard kills.
    """

    async def run(
        self,
        state: ScanState,
    ) -> AsyncGenerator[ScanEvent, None]:
        """
        Agentic reasoning loop.

        Yields ScanEvent objects consumed by:
        - The Celery worker (to update DB progress)
        - The Redis publisher (for WebSocket delivery to the frontend)

        Final event is always type="scan_complete".
        """
        logger.info(
            "[%s] Orchestrator starting — target=%s budget=%d tools_allowed=%d",
            state.scan_id, state.target, state.tool_budget, len(state.allowed_tools),
        )

        # ── Main loop — not while True ──────────────────────────────────────
        # The loop is driven by a budget counter. When budget reaches 0
        # (or another exit condition fires), we fall through to the final yield.
        for iteration in range(state.tool_budget + 1):  # +1 guards the final check

            # ── 1. Check all exit conditions at the top ──────────────────────
            should_exit, exit_reason = state.should_exit()
            if should_exit:
                logger.info(f"[{state.scan_id}] Exit condition: {exit_reason}")
                event = ScanEvent(
                    type="exit_condition",
                    reasoning=exit_reason,
                    budget_remaining=state.tool_budget,
                )
                await _publish_event(state.scan_id, event)
                yield event
                break

            # ── 2. LLM decision call ─────────────────────────────────────────
            decision = await _llm_decide(state)
            action = decision.get("action", "complete")
            reasoning = decision.get("reasoning", "")
            tool = decision.get("tool")
            params = decision.get("params", {"target": state.target})
            owasp_cats = decision.get("owasp_categories", [])

            # Emit the reasoning event
            reasoning_event = ScanEvent(
                type="agent_reasoning",
                reasoning=reasoning,
                tool=tool,
                budget_remaining=state.tool_budget,
                metadata={"iteration": iteration, "owasp_categories": owasp_cats},
            )
            await _publish_event(state.scan_id, reasoning_event)
            yield reasoning_event

            # ── 3. LLM chose to stop ─────────────────────────────────────────
            if action == "complete" or not tool:
                logger.info(
                    f"[{state.scan_id}] LLM signalled complete: {reasoning}"
                )
                break

            # ── 4. Start tool ────────────────────────────────────────────────
            started_event = ScanEvent(
                type="tool_started",
                tool=tool,
                reasoning=reasoning,
                budget_remaining=state.tool_budget,
                metadata={"params": params, "owasp_categories": owasp_cats},
            )
            await _publish_event(state.scan_id, started_event)
            yield started_event

            logger.info(
                f"[{state.scan_id}] Running tool '{tool}' "
                f"(iteration {iteration}, budget={state.tool_budget})"
            )

            # ── 5. Execute the tool with its declared timeout ─────────────────
            timeout = TOOL_REGISTRY.get(tool, {}).get("timeout", 300)
            try:
                new_findings: list[Finding] = await asyncio.wait_for(
                    _execute_tool(tool, params, state),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    f"[{state.scan_id}] Tool '{tool}' timed out after {timeout}s"
                )
                new_findings = []
            except Exception as exc:
                logger.error(
                    f"[{state.scan_id}] Unexpected error from '{tool}': {exc}",
                    exc_info=True,
                )
                new_findings = []

            # ── 6. Record result in state ────────────────────────────────────
            state.record_tool_result(tool, new_findings)

            # Emit individual finding events (consumers can react in real-time)
            for finding in new_findings:
                finding_event = ScanEvent(
                    type="finding",
                    tool=tool,
                    finding=finding,
                    budget_remaining=state.tool_budget,
                )
                await _publish_event(state.scan_id, finding_event)
                yield finding_event

            # Emit tool_complete summary
            complete_event = ScanEvent(
                type="tool_complete",
                tool=tool,
                budget_remaining=state.tool_budget,
                metadata={
                    "new_findings_count": len(new_findings),
                    "consecutive_empty_runs": state.consecutive_empty_runs,
                    "owasp_coverage": sorted(state.coverage_flags),
                },
            )
            await _publish_event(state.scan_id, complete_event)
            yield complete_event

            logger.info(
                f"[{state.scan_id}] Tool '{tool}' done — "
                f"{len(new_findings)} new findings, "
                f"budget={state.tool_budget}, "
                f"empty_streak={state.consecutive_empty_runs}"
            )

        # ── Final summary event — always emitted ────────────────────────────
        severity_summary = state.severity_summary()
        summary_event = ScanEvent(
            type="scan_complete",
            budget_remaining=state.tool_budget,
            reasoning=(
                f"Scan complete for {state.target}. "
                f"Ran {len(state.tools_run)} tools. "
                f"Found {len(state.findings)} findings "
                f"({severity_summary['critical']}C / {severity_summary['high']}H / "
                f"{severity_summary['medium']}M / {severity_summary['low']}L)."
            ),
            metadata={
                "target": state.target,
                "tools_run": state.tools_run,
                "total_findings": len(state.findings),
                "severity_summary": severity_summary,
                "owasp_coverage": sorted(state.coverage_flags),
                "budget_used": state.budget - state.tool_budget,
                "scan_duration_seconds": (
                    datetime.now(timezone.utc) - state.started_at
                ).total_seconds(),
            },
        )
        await _publish_event(state.scan_id, summary_event)
        yield summary_event

        logger.info(
            f"[{state.scan_id}] Orchestrator finished — "
            f"{len(state.findings)} total findings across "
            f"{len(state.tools_run)} tools"
        )


# ---------------------------------------------------------------------------
# Module-level entry point
# ---------------------------------------------------------------------------

async def run_orchestrator(
    target: str,
    scan_id: uuid.UUID,
    budget: int,
    allowed_tools: list[str],
    initial_findings: Optional[list[Finding]] = None,
) -> AsyncGenerator[ScanEvent, None]:
    """
    Entry point. Creates ScanState and starts the constrained adaptive loop.

    The caller (Celery worker) is responsible for computing budget and
    allowed_tools from the user's tier. The orchestrator is tier-agnostic.

    Usage:
        async for event in run_orchestrator(target, scan_id, budget, allowed_tools):
            ...
    """
    state = ScanState(
        target=target,
        scan_id=scan_id,
        budget=budget,
        allowed_tools=allowed_tools,
        findings=list(initial_findings or []),
    )
    agent = OrchestratorAgent()
    async for event in agent.run(state):
        yield event
