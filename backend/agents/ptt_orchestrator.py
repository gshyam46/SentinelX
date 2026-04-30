"""
SentinelX — PTT Orchestrator (Phase 2, ADR-024)

expand_ptt              — queries LLM for follow-up hypotheses; validates each
                          suggested_tool against OPERATIONAL_REGISTRY before
                          adding as a tool_run node. Invalid tools → hypothesis
                          node + warning log. Max 3 tool_run nodes per call.

dispatch_pending_ptt_nodes — runs pending tool_run nodes via OPERATIONAL_REGISTRY;
                          returns new findings for the caller to persist. Never
                          calls tools outside the operational registry.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from backend.agents.ptt import PTTNode, PTTNodeStatus, PTTState

logger = logging.getLogger("sentinelx.ptt_orchestrator")

_MAX_TOOL_RUNS_PER_EXPAND = 3

_EXPAND_SYSTEM_PROMPT = """\
You are SentinelX PTT Analyst. Given security scan findings, suggest follow-up
investigation hypotheses for adaptive pentesting.

Respond ONLY with valid JSON — no prose, no markdown fences:
{
  "hypotheses": [
    {
      "label": "Check if SQLi finding leads to auth bypass",
      "suggested_tool": "nuclei",
      "basis_finding_ids": ["<uuid>"]
    }
  ]
}

Rules:
- Maximum 5 hypotheses total
- suggested_tool must be one of the AVAILABLE_TOOLS listed in the user message
- basis_finding_ids lists finding IDs from provided findings (may be empty list)
- Prioritise critical and high severity findings
- Do not suggest tools already queued or completed"""


async def _llm_hypotheses(
    findings: list[dict],
    execution_graph: dict,
    kev_matches: list[str],
    available_tools: list[str],
) -> list[dict]:
    """
    Call LLM and return a list of hypothesis dicts.
    Falls back to _rule_based_hypotheses on any error.
    """
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    top = sorted(findings, key=lambda f: sev_rank.get(f.get("severity", "info"), 4))[:10]
    findings_text = "\n".join(
        f"  id={f.get('id', 'n/a')} [{f.get('severity', '?').upper()}] "
        f"{f.get('title', 'unknown')} (tool={f.get('source_tool', '?')})"
        for f in top
    ) or "  None."

    kev_text = ", ".join(kev_matches) if kev_matches else "None"
    tools_text = ", ".join(available_tools) if available_tools else "None"

    user_msg = (
        f"AVAILABLE_TOOLS: {tools_text}\n"
        f"KEV MATCHES: {kev_text}\n\n"
        f"CURRENT FINDINGS:\n{findings_text}\n\n"
        "Generate follow-up investigation hypotheses."
    )

    try:
        import litellm
        from backend.config import get_settings

        settings = get_settings()
        response = await litellm.acompletion(
            model=settings.LITELLM_MODEL,
            messages=[
                {"role": "system", "content": _EXPAND_SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            max_tokens=500,
            temperature=0.1,
            response_format={"type": "json_object"},
        )
        raw = response.choices[0].message.content.strip()
        # Strip markdown fences when present
        m = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", raw)
        if m:
            raw = m.group(1)
        parsed = json.loads(raw)
        hyps = parsed.get("hypotheses", [])
        if isinstance(hyps, list):
            return hyps
        return []

    except ImportError:
        logger.warning("PTT: litellm not installed — using rule-based hypotheses")
    except Exception as exc:
        logger.error("PTT: LLM hypotheses call failed: %s", exc)

    return _rule_based_hypotheses(findings, set(available_tools))


def _rule_based_hypotheses(findings: list[dict], available: set[str]) -> list[dict]:
    """Deterministic fallback used when LLM is unavailable."""
    hyps: list[dict] = []

    sqli = [f for f in findings if "sql" in f.get("title", "").lower()]
    if sqli and "nuclei" in available:
        hyps.append({
            "label": "Confirm SQL injection via nuclei targeted templates",
            "suggested_tool": "nuclei",
            "basis_finding_ids": [f.get("id", "") for f in sqli[:2]],
        })

    critical_high = [f for f in findings if f.get("severity") in ("critical", "high")]
    if critical_high and "zap" in available and len(hyps) < _MAX_TOOL_RUNS_PER_EXPAND:
        hyps.append({
            "label": "Run ZAP active scan against critical/high severity paths",
            "suggested_tool": "zap",
            "basis_finding_ids": [f.get("id", "") for f in critical_high[:2]],
        })

    if findings and "nmap_scan" in available and len(hyps) < _MAX_TOOL_RUNS_PER_EXPAND:
        hyps.append({
            "label": "Enumerate remaining ports for lateral attack surface",
            "suggested_tool": "nmap_scan",
            "basis_finding_ids": [],
        })

    return hyps[:_MAX_TOOL_RUNS_PER_EXPAND]


async def expand_ptt(
    ptt: PTTState,
    findings: list[dict],
    execution_graph: dict,
    kev_matches: list[str],
) -> PTTState:
    """
    Call LLM with current findings + graph to get next hypotheses.
    LLM returns structured JSON only — ADR-001 preserved (LLM never executes tools).
    Each suggested_tool is validated against OPERATIONAL_REGISTRY before a
    tool_run node is added. Invalid → hypothesis node + warning log.
    Max _MAX_TOOL_RUNS_PER_EXPAND tool_run nodes per expand call.
    """
    from backend.modules.pentest.tool_registry import OPERATIONAL_REGISTRY

    # Exclude tools already queued so the LLM prompt stays accurate
    queued_tools: set[str] = {
        n.tool
        for n in ptt.nodes
        if n.node_type == "tool_run"
        and n.tool
        and n.status in (PTTNodeStatus.pending, PTTNodeStatus.running)
    }
    available = [t for t in OPERATIONAL_REGISTRY if t not in queued_tools]

    hypotheses = await _llm_hypotheses(findings, execution_graph, kev_matches, available)

    tool_run_count = 0
    for hyp in hypotheses:
        label = str(hyp.get("label", "Unknown hypothesis"))
        suggested_tool = hyp.get("suggested_tool")
        basis_ids = [str(fid) for fid in hyp.get("basis_finding_ids", [])]
        node_id = str(uuid.uuid4())

        if (
            suggested_tool
            and suggested_tool in OPERATIONAL_REGISTRY
            and tool_run_count < _MAX_TOOL_RUNS_PER_EXPAND
        ):
            node = PTTNode(
                node_id=node_id,
                parent_id=None,
                node_type="tool_run",
                label=label,
                tool=suggested_tool,
                status=PTTNodeStatus.pending,
                finding_ids=basis_ids,
                suggested_by="llm",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            tool_run_count += 1
            logger.info("PTT expand: tool_run node added — tool=%s label=%.60s", suggested_tool, label)
        else:
            if suggested_tool and suggested_tool not in OPERATIONAL_REGISTRY:
                logger.warning(
                    "PTT expand: LLM suggested '%s' — not in OPERATIONAL_REGISTRY; "
                    "rule fallback: adding as hypothesis node",
                    suggested_tool,
                )
            node = PTTNode(
                node_id=node_id,
                parent_id=None,
                node_type="hypothesis",
                label=label,
                tool=None,
                status=PTTNodeStatus.pending,
                finding_ids=basis_ids,
                suggested_by="llm",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            logger.debug("PTT expand: hypothesis node added — label=%.60s", label)

        ptt.add_node(node)

    return ptt


async def dispatch_pending_ptt_nodes(
    ptt: PTTState,
    target: str,
    scan_id: uuid.UUID,
) -> tuple[list[dict], PTTState]:
    """
    Run all pending tool_run nodes via OPERATIONAL_REGISTRY.
    Returns (new_findings, updated_ptt). Caller is responsible for DB persistence.
    Uses asyncio.wait_for with per-tool timeout from the TOOL_REGISTRY catalogue.
    """
    from backend.agents.orchestrator import TOOL_REGISTRY as CATALOGUE
    from backend.modules.pentest.tool_registry import OPERATIONAL_REGISTRY

    pending_tool_nodes = [
        n for n in ptt.get_pending() if n.node_type == "tool_run"
    ]
    all_new_findings: list[dict[str, Any]] = []

    for node in pending_tool_nodes:
        tool = node.tool
        if not tool or tool not in OPERATIONAL_REGISTRY:
            logger.warning(
                "PTT dispatch: skipping node %s — tool '%s' not in OPERATIONAL_REGISTRY",
                node.node_id, tool,
            )
            ptt.mark_completed(node.node_id)
            continue

        ptt.mark_running(node.node_id)
        executor = OPERATIONAL_REGISTRY[tool]
        timeout = CATALOGUE.get(tool, {}).get("timeout", 300)

        logger.info(
            "PTT dispatch: running tool=%s scan_id=%s timeout=%ds", tool, scan_id, timeout
        )

        try:
            raw: list[dict[str, Any]] = await asyncio.wait_for(
                executor(target=target, scan_id=scan_id, params={"target": target}),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("PTT dispatch: tool '%s' timed out after %ds", tool, timeout)
            raw = []
        except Exception as exc:
            logger.error("PTT dispatch: tool '%s' raised: %s", tool, exc, exc_info=True)
            raw = []

        for f in raw:
            f.setdefault("source_tool", tool)
            f.setdefault("owasp_categories", [])
            f.setdefault("ptt_sourced", True)   # marks findings originating from PTT pass

        all_new_findings.extend(raw)
        ptt.mark_completed(node.node_id)
        logger.info("PTT dispatch: tool=%s done — %d new findings", tool, len(raw))

    return all_new_findings, ptt
