"""
SentinelX — Agent 2: Analyst Agent (LLM + RAG)
Controlled AI interpretation layer for security findings.

Role:
  Interprets findings from the scan pipeline. Does NOT execute tools,
  modify scan pipelines, or make security decisions.

Output: Full AnalysisReport schema — single source of truth for what
        analyst_tasks.py persists to DB and remediation agent reads.

Research fields in output:
  rag_context_used  — whether RAG returned non-empty context
  retrieval_method  — "faiss" | "keyword" | "none"
  model_used        — LiteLLM model string

Intelligence correlation fields added to every report:
  known_exploited   — True if any finding has a KEV-matched CVE
  exploit_available — True if any finding has an ExploitDB-matched CVE
  priority_reason   — human-readable string for the highest-priority finding
  attack_chains     — list of {path, impact, confidence} derived from execution_graph

Boundaries (hard-coded, not LLM-configurable):
  - Cannot trigger tool execution
  - Cannot modify finding data
  - Must return structured JSON output
  - Token budget: 3000 context + 1200 output
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from typing import Any, Dict, List, Optional

from backend.modules.ai.rag_engine import get_rag_engine

logger = logging.getLogger("sentinelx.analyst")

_MAX_FINDINGS_IN_PROMPT = 15
_MAX_CONTEXT_TOKENS = 3000
_MAX_OUTPUT_TOKENS = 1200

# OWASP categories for coverage scoring
_ALL_OWASP = {f"A{i:02d}" for i in range(1, 11)}

# Strict CVE pattern used to sanitize kev_matches before prompt insertion.
# Rejects anything with embedded newlines or extra text (prompt injection guard).
_CVE_STRICT = re.compile(r"^CVE-\d{4}-\d+$")

# Loose CVE pattern used to extract CVE IDs from arbitrary finding text.
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# KEV escalation block appended to system prompt when matches are present.
# {cve_list} is replaced at call time with newline-joined CVE IDs.
_KEV_SYSTEM_PROMPT_BLOCK = """\

CRITICAL INTELLIGENCE — KNOWN EXPLOITATION IN THE WILD:
The following CVE IDs are confirmed in CISA's Known Exploited Vulnerabilities (KEV) catalog,
meaning they have been actively exploited by threat actors:
{cve_list}

For any finding related to these CVEs:
- Severity reasoning MUST treat them as CRITICAL regardless of CVSS score
- Include the phrase "known exploited in wild" in your analysis for that finding
- Elevate remediation priority to IMMEDIATE"""


# ---------------------------------------------------------------------------
# Module-level helpers (private)
# ---------------------------------------------------------------------------

def _extract_cves_from_findings(findings: List[Dict[str, Any]]) -> List[str]:
    """
    Extract unique CVE IDs from all string values in a findings list.

    Scans each string value up to 2000 characters to prevent pathological
    input from consuming excess CPU. Returns CVEs in encounter order,
    uppercased, deduplicated.
    """
    cves: List[str] = []
    seen: set[str] = set()
    for finding in findings:
        for val in finding.values():
            if isinstance(val, str):
                for match in _CVE_PATTERN.finditer(val[:2000]):
                    cve = match.group(0).upper()
                    if cve not in seen:
                        seen.add(cve)
                        cves.append(cve)
    return cves


def _enrich_with_kev(
    findings: List[Dict[str, Any]], kev_matches: List[str]
) -> List[Dict[str, Any]]:
    """
    Annotate each finding with known_exploited=True/False based on KEV matches.

    Does not mutate the originals — returns new dicts.
    """
    kev_set = {c.upper() for c in kev_matches}
    enriched: List[Dict[str, Any]] = []
    for f in findings:
        f = dict(f)
        cves = _extract_cves_from_findings([f])
        f["known_exploited"] = any(c in kev_set for c in cves)
        enriched.append(f)
    return enriched


def _build_exploitdb_lookup(kb_sources: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Build a {CVE_ID: exploit_entry} mapping from ExploitDB KB entries.

    ExploitDB entries store CVE IDs in a `codes` list as semicolon-separated
    strings like "CVE-2021-44228;OSVDB-12345". This function parses each
    codes entry with _CVE_PATTERN and maps every extracted CVE ID to the
    entry. Match is on CVE field only — never on description text.

    Always returns a dict; never raises.
    """
    lookup: Dict[str, Dict[str, Any]] = {}
    for entry in kb_sources:
        codes = entry.get("codes", [])
        if not isinstance(codes, list):
            continue
        for code_str in codes:
            if not isinstance(code_str, str):
                continue
            for match in _CVE_PATTERN.finditer(code_str):
                cve_upper = match.group(0).upper()
                if cve_upper not in lookup:
                    lookup[cve_upper] = entry
    return lookup


def _enrich_with_exploitdb(
    findings: List[Dict[str, Any]], exploitdb_lookup: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Annotate each finding with exploit_available=True/False based on ExploitDB lookup.

    Does not mutate the originals — returns new dicts.
    """
    enriched: List[Dict[str, Any]] = []
    for f in findings:
        f = dict(f)
        cves = _extract_cves_from_findings([f])
        f["exploit_available"] = any(c in exploitdb_lookup for c in cves)
        enriched.append(f)
    return enriched


def _apply_priority_logic(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Assign a priority_reason to a finding and escalate severity when needed.

    Priority rules (highest first):
      1. CRITICAL severity + known_exploited + exploit_available
         → "Actively exploited in the wild with public exploit available"
      2. known_exploited (any severity)
         → severity escalated to "CRITICAL"; "Actively exploited in the wild"
      3. exploit_available
         → "Public exploit available"
      4. fallback
         → "No known active exploitation"

    Does not mutate the original — returns a new dict.
    """
    finding = dict(finding)
    severity = (finding.get("severity") or "").upper()
    known_exploited = finding.get("known_exploited", False)
    exploit_available = finding.get("exploit_available", False)

    if severity == "CRITICAL" and known_exploited and exploit_available:
        finding["priority_reason"] = (
            "Actively exploited in the wild with public exploit available"
        )
    elif known_exploited:
        finding["severity"] = "CRITICAL"
        finding["priority_reason"] = "Actively exploited in the wild"
    elif exploit_available:
        finding["priority_reason"] = "Public exploit available"
    else:
        finding["priority_reason"] = "No known active exploitation"
    return finding


def _extract_attack_chains(
    execution_graph: Optional[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Extract attack chains from explicit DAG edges only.

    Derives chains ONLY from the execution_graph node/edge structure exported
    by execution_graph.py. Never infers chains from finding text alone.

    Chain types returned:
      - tool_execution → finding → tool_execution  (confidence: high/medium)
      - tool_execution → finding (no follow-up tool, severity critical/high only)
        (confidence: low)

    Returns [] when execution_graph is absent, empty, or has no nodes/edges.
    """
    if not execution_graph:
        return []

    nodes: Dict[str, Dict[str, Any]] = {
        n["node_id"]: n for n in execution_graph.get("nodes", [])
    }
    edges: List[Dict[str, Any]] = execution_graph.get("edges", [])

    if not nodes or not edges:
        return []

    # Build adjacency: parent_id → list of child_ids
    adjacency: Dict[str, List[str]] = {}
    for edge in edges:
        parent = edge.get("parent_id")
        child = edge.get("child_id")
        if parent and child:
            adjacency.setdefault(parent, []).append(child)

    chains: List[Dict[str, Any]] = []

    # -- Depth-2 chains: tool → finding → tool (highest value) --
    for node_id, node in nodes.items():
        if node.get("node_type") != "tool_execution":
            continue
        children = adjacency.get(node_id, [])
        for child_id in children:
            child = nodes.get(child_id, {})
            if child.get("node_type") != "finding":
                continue
            grandchildren = adjacency.get(child_id, [])
            for gc_id in grandchildren:
                gc = nodes.get(gc_id, {})
                if gc.get("node_type") == "tool_execution":
                    path = [
                        node.get("tool_name", node_id),
                        f'finding:{child.get("finding", {}).get("title", child_id)[:60]}',
                        gc.get("tool_name", gc_id),
                    ]
                    sev = str(
                        child.get("finding", {}).get("severity", "")
                    ).upper()
                    confidence = "high" if sev in ("CRITICAL", "HIGH") else "medium"
                    impact = child.get("finding", {}).get("description", "")[:200]
                    chains.append(
                        {"path": path, "impact": impact, "confidence": confidence}
                    )

    # -- Depth-1 chains: tool → finding (no follow-up tool, critical/high only) --
    for node_id, node in nodes.items():
        if node.get("node_type") != "tool_execution":
            continue
        children = adjacency.get(node_id, [])
        for child_id in children:
            child = nodes.get(child_id, {})
            if child.get("node_type") != "finding":
                continue
            if adjacency.get(child_id):
                # Finding has children — already covered by the depth-2 loop above
                continue
            sev = str(child.get("finding", {}).get("severity", "")).upper()
            if sev in ("CRITICAL", "HIGH"):
                chains.append(
                    {
                        "path": [
                            node.get("tool_name", node_id),
                            f'finding:{child.get("finding", {}).get("title", child_id)[:60]}',
                        ],
                        "impact": child.get("finding", {}).get("description", "")[:200],
                        "confidence": "low",
                    }
                )

    return chains


# ---------------------------------------------------------------------------
# Severity ordering helper (used for priority_reason selection)
# ---------------------------------------------------------------------------

_SEV_ORDER: Dict[str, int] = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4
}

_PRIORITY_ORDER: Dict[str, int] = {
    "Actively exploited in the wild with public exploit available": 0,
    "Actively exploited in the wild": 1,
    "Public exploit available": 2,
    "No known active exploitation": 3,
}


def _pick_top_priority_reason(findings: List[Dict[str, Any]]) -> str:
    """Return the priority_reason string from the highest-priority enriched finding."""
    best_rank = 99
    best_reason = "No known active exploitation"
    for f in findings:
        reason = f.get("priority_reason", "No known active exploitation")
        rank = _PRIORITY_ORDER.get(reason, 3)
        if rank < best_rank:
            best_rank = rank
            best_reason = reason
    return best_reason


# ---------------------------------------------------------------------------
# Agent class
# ---------------------------------------------------------------------------

class AnalystAgent:
    """
    Agent 2 — LLM-powered finding interpreter.

    Uses LiteLLM via LiteLLM abstraction (Groq / OpenAI / Anthropic switchable).
    Queries RAG for contextual knowledge before calling the LLM.
    Output always conforms to the full AnalysisReport schema.
    """

    def __init__(self):
        self._rag = get_rag_engine()

    # ------------------------------------------------------------------
    # ExploitDB lookup — built once per analyze() call
    # ------------------------------------------------------------------

    def _build_exploitdb_lookup_from_rag(self) -> Dict[str, Dict[str, Any]]:
        """
        Build the ExploitDB CVE→entry lookup from the RAG engine's raw KB data.

        Tries self._rag._kb["exploit_db"] first (direct attribute). Catches any
        AttributeError or KeyError and returns {} — never raises.
        """
        try:
            kb: Dict[str, List[Dict[str, Any]]] = self._rag._kb  # type: ignore[attr-defined]
            exploit_entries: List[Dict[str, Any]] = kb.get("exploit_db", [])
            return _build_exploitdb_lookup(exploit_entries)
        except Exception:
            logger.debug("[Analyst] ExploitDB lookup build failed — returning empty dict")
            return {}

    # ------------------------------------------------------------------
    # Main analysis entry point
    # ------------------------------------------------------------------

    async def analyze(
        self,
        scan_results: Dict[str, Any],
        kev_matches: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze scan findings and produce a structured AnalysisReport.

        Args:
            scan_results: {
                "domain": str,
                "all_findings": list[dict],
                "summary": {
                    "risk_score": int,
                    "risk_level": str,
                    "total_findings": int,
                    "severity_counts": dict,
                },
                "scan_metadata": {          # optional
                    "execution_graph": {...} # if present, used for attack chains
                }
            }
            kev_matches: CVE IDs confirmed in CISA KEV catalog. When non-empty
                         the system prompt is augmented with KEV escalation
                         instructions and analyst_notes records the matches.
                         Defaults to None (treated as empty list).

        Returns:
            Full AnalysisReport dict (see _empty_report for schema).
        """
        # CRITICAL-2 fix: resolve mutable default
        kev_matches = kev_matches or []

        domain = scan_results.get("domain", "Unknown")
        all_findings = scan_results.get("all_findings", [])
        summary = scan_results.get("summary", {})

        logger.info(
            "[Analyst] Analyzing %d findings for %s",
            len(all_findings), domain,
        )

        if not all_findings:
            return self._empty_report(domain)

        # 1. RAG retrieval — prioritise critical/high findings for context
        priority_findings = [
            f for f in all_findings if f.get("severity") in ("critical", "high")
        ][:_MAX_FINDINGS_IN_PROMPT]

        context = self._rag.query(priority_findings or all_findings[:10])
        rag_text = self._rag.format_context_for_prompt(context, max_chars=2000)
        rag_used = bool(rag_text.strip())
        retrieval_method = self._rag.get_retrieval_method()

        # GAP-1 fix: merge caller-supplied kev_matches with RAG-derived matches.
        # This ensures KEV escalation fires even when analyst_tasks.py passes no
        # kev_matches argument (the common production path).
        rag_kev: List[str] = context.get("kev_matches", [])
        effective_kev: List[str] = list(
            dict.fromkeys((kev_matches or []) + rag_kev)  # dedup, preserve order
        )

        # 2. Build prompt and (optionally) KEV-augmented system prompt
        prompt = self._build_prompt(domain, all_findings, summary, rag_text)
        system_prompt = self._build_system_prompt(effective_kev)

        # 3. LLM call
        raw = await self._call_llm(prompt, system_prompt=system_prompt)

        # 4. Parse + validate
        report = self._parse_response(raw, domain, summary, all_findings)

        # 5. Stamp research metadata
        report["rag_context_used"] = rag_used
        report["retrieval_method"] = retrieval_method
        # kev_matches: CVE IDs from findings that matched the CISA KEV catalog.
        # Already computed by rag_engine.query(); surface them on the report so
        # analyst_tasks.py can persist them without re-querying the RAG engine.
        report["kev_matches"] = effective_kev

        # 6. Append KEV match record to analyst_notes (additive — never replaces)
        if effective_kev:
            kev_note = (
                f"KEV matches detected: {', '.join(effective_kev)}"
                " — severity elevated per CISA KEV catalog."
            )
            existing_notes = report.get("analyst_notes") or ""
            report["analyst_notes"] = (
                f"{existing_notes}\n{kev_note}" if existing_notes else kev_note
            )
            logger.info(
                "[Analyst] KEV escalation applied for %s: %s",
                domain,
                ", ".join(effective_kev),
            )

        # 7. Intelligence correlation (KEV + ExploitDB + priority logic)
        exploitdb_lookup = self._build_exploitdb_lookup_from_rag()

        enriched_findings = _enrich_with_kev(all_findings, effective_kev)
        enriched_findings = _enrich_with_exploitdb(enriched_findings, exploitdb_lookup)
        enriched_findings = [_apply_priority_logic(f) for f in enriched_findings]

        report["known_exploited"] = any(
            f.get("known_exploited", False) for f in enriched_findings
        )
        report["exploit_available"] = any(
            f.get("exploit_available", False) for f in enriched_findings
        )
        report["priority_reason"] = _pick_top_priority_reason(enriched_findings)

        # 8. Execution graph attack chain extraction
        exec_graph = (
            scan_results.get("scan_metadata", {}).get("execution_graph")
            or scan_results.get("execution_graph")
        )
        report["attack_chains"] = _extract_attack_chains(exec_graph)

        logger.info(
            "[Analyst] Analysis complete for %s — risk_score=%s known_exploited=%s "
            "exploit_available=%s chains=%d",
            domain,
            report.get("risk_score"),
            report["known_exploited"],
            report["exploit_available"],
            len(report["attack_chains"]),
        )
        return report

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    _SYSTEM_PROMPT = """\
You are a senior penetration tester reviewing automated scan results for a client.
Your role is STRICTLY LIMITED to interpreting and explaining the provided findings.
You must NOT suggest running additional tools or modifying the scan process.

Respond with valid JSON only — no prose, no markdown fences, no extra text.

Output schema (all fields required):
{
  "executive_summary": "<2-3 sentences for a non-technical stakeholder>",
  "risk_score": <integer 0-100>,
  "attack_chains": [
    {"name": "<chain name>", "steps": ["<finding title>", ...], "impact": "high|medium|low"}
  ],
  "owasp_coverage": {
    "A01": "covered|partial|missing", "A02": "covered|partial|missing",
    "A03": "covered|partial|missing", "A04": "covered|partial|missing",
    "A05": "covered|partial|missing", "A06": "covered|partial|missing",
    "A07": "covered|partial|missing", "A08": "covered|partial|missing",
    "A09": "covered|partial|missing", "A10": "covered|partial|missing"
  },
  "critical_findings": ["<title of top critical/high finding>"],
  "remediation_priorities": [
    {"priority": 1, "finding": "<title>", "action": "<concrete fix>", "effort": "low|medium|high"}
  ],
  "analyst_notes": "<anything else the team should know, 2-3 sentences>",
  "top_risks": [
    {
      "title": "<finding title>",
      "severity": "critical|high|medium|low",
      "attack_context": "<how an attacker exploits this, 1-2 sentences>",
      "business_impact": "<what business harm results, 1 sentence>"
    }
  ],
  "key_priorities": ["<Priority action 1>", "<Priority action 2>", "<Priority action 3>"]
}

Risk score guide: critical findings × 25, high × 10, medium × 4, low × 1. Cap at 100.
Include top 3-5 findings in top_risks and critical_findings.
Provide concrete, actionable remediation steps — not generic advice.
Think step by step but respond only with the JSON schema."""

    def _build_system_prompt(self, kev_matches: List[str]) -> str:
        """
        Return system prompt, with KEV escalation block appended when matches exist.

        CRITICAL-1 fix: kev_matches are sanitized with _CVE_STRICT before insertion
        into the prompt string, preventing prompt injection via crafted CVE IDs that
        contain embedded newlines or extra instruction text.
        """
        safe_matches = [c for c in kev_matches if _CVE_STRICT.fullmatch(c)]
        if not safe_matches:
            return self._SYSTEM_PROMPT
        kev_block = _KEV_SYSTEM_PROMPT_BLOCK.format(
            cve_list="\n".join(safe_matches)
        )
        return self._SYSTEM_PROMPT + kev_block

    def _build_prompt(
        self,
        domain: str,
        findings: List[Dict[str, Any]],
        summary: Dict[str, Any],
        rag_text: str,
    ) -> str:
        findings_for_prompt = self._format_findings(findings[:_MAX_FINDINGS_IN_PROMPT])
        severity_counts = summary.get("severity_counts", {})

        return (
            f"TARGET: {domain}\n"
            f"SEVERITY DISTRIBUTION: "
            f"Critical={severity_counts.get('critical', 0)}, "
            f"High={severity_counts.get('high', 0)}, "
            f"Medium={severity_counts.get('medium', 0)}, "
            f"Low={severity_counts.get('low', 0)}\n\n"
            f"SECURITY KNOWLEDGE CONTEXT:\n{rag_text or '(none)'}\n\n"
            f"SCAN FINDINGS:\n{findings_for_prompt}\n\n"
            "Produce the AnalysisReport JSON."
        )

    @staticmethod
    def _format_findings(findings: List[Dict[str, Any]]) -> str:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_f = sorted(
            findings, key=lambda f: sev_order.get(f.get("severity", "info"), 4)
        )
        lines = []
        for i, f in enumerate(sorted_f, 1):
            sev = f.get("severity", "info").upper()
            title = f.get("title", "Unknown")
            desc = (f.get("description") or "")[:150]
            target = f.get("target", "")
            lines.append(f"{i}. [{sev}] {title} | {target} | {desc}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # LLM call
    # ------------------------------------------------------------------

    async def _call_llm(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
    ) -> Optional[str]:
        """
        Call the LLM with the user prompt and an optional system prompt override.

        Args:
            prompt:        User-turn message (findings + RAG context).
            system_prompt: System prompt string to use. When None (default) the
                           class-level _SYSTEM_PROMPT is used, preserving
                           backward compatibility for any direct callers.
        """
        resolved_system = system_prompt if system_prompt is not None else self._SYSTEM_PROMPT
        try:
            import litellm
            from backend.config import get_settings

            settings = get_settings()

            # Models to try in order: primary → fallback
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
                            {"role": "system", "content": resolved_system},
                            {"role": "user", "content": prompt},
                        ],
                        max_tokens=_MAX_OUTPUT_TOKENS,
                        temperature=0.1,
                        # NOTE: response_format=json_object is intentionally omitted.
                        # Groq llama3 models do not support it and return a 400 error.
                        # The system prompt already instructs the LLM to output JSON only.
                    )
                    content = response.choices[0].message.content
                    logger.info("[Analyst] LLM call succeeded with model: %s", model)
                    return content
                except Exception as exc:
                    last_exc = exc
                    logger.warning(
                        "[Analyst] LLM call failed for model '%s': %s — %s",
                        model,
                        type(exc).__name__,
                        exc,
                    )

            logger.error("[Analyst] All LLM models failed. Last error: %s", last_exc)
            return None

        except ImportError:
            logger.warning("[Analyst] litellm not installed — using mock response")
            return self._mock_response()
        except Exception as exc:
            logger.error("[Analyst] LLM call unexpected error: %s", exc)
            return None

    def _mock_response(self) -> str:
        return json.dumps({
            "executive_summary": (
                "Mock analysis — configure GROQ_API_KEY or another LLM provider in .env "
                "for real AI-powered analysis. The scan detected several security concerns."
            ),
            "risk_score": 0,
            "attack_chains": [],
            "owasp_coverage": {cat: "missing" for cat in sorted(_ALL_OWASP)},
            "critical_findings": [],
            "remediation_priorities": [],
            "analyst_notes": "Set GROQ_API_KEY in .env and restart for real AI analysis.",
            "top_risks": [{
                "title": "LLM Not Configured",
                "severity": "info",
                "attack_context": "AI analysis requires an LLM API key.",
                "business_impact": "Findings are reported but lack AI-generated context.",
            }],
            "key_priorities": [
                "Configure GROQ_API_KEY in .env",
                "Restart backend server",
                "Re-run scan for AI-powered analysis",
            ],
        })

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(
        self,
        raw: Optional[str],
        domain: str,
        summary: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        if not raw:
            return self._fallback_report(domain, summary, findings)

        json_str = raw.strip()
        if "```" in json_str:
            match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", json_str)
            if match:
                json_str = match.group(1)

        try:
            parsed = json.loads(json_str)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("[Analyst] JSON parse error: %s", exc)
            return self._fallback_report(domain, summary, findings)

        # Normalize field names (handle old schema → new schema transition)
        if "executive_summary" not in parsed and "risk_summary" in parsed:
            parsed["executive_summary"] = parsed.pop("risk_summary")
        if "analyst_notes" not in parsed and "severity_reasoning" in parsed:
            parsed["analyst_notes"] = parsed.pop("severity_reasoning")
        if "attack_chains" not in parsed and "attack_chain" in parsed:
            chain = parsed.pop("attack_chain")
            parsed["attack_chains"] = (
                [{"name": "Primary chain", "steps": [chain], "impact": "high"}]
                if chain else []
            )

        # Ensure all required fields present (including new intel correlation fields)
        defaults = self._fallback_report(domain, summary, findings)
        for key, default_val in defaults.items():
            if key not in parsed or parsed[key] is None:
                parsed[key] = default_val

        # Clamp risk_score
        parsed["risk_score"] = max(0, min(100, int(parsed.get("risk_score", 0))))
        parsed["domain"] = domain
        parsed["ai_generated"] = True
        return parsed

    # ------------------------------------------------------------------
    # Fallback / empty reports (full schema always, including intel fields)
    # ------------------------------------------------------------------

    def _fallback_report(
        self, domain: str, summary: Dict[str, Any], findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        from backend.config import get_settings
        settings = get_settings()

        counts: Counter = Counter(f.get("severity", "info") for f in findings)
        risk = min(
            100,
            counts["critical"] * 25 + counts["high"] * 10
            + counts["medium"] * 4 + counts["low"] * 1,
        )
        owasp_seen: set[str] = set()
        for f in findings:
            owasp_seen.update(f.get("owasp_categories", []))
        owasp_coverage = {
            cat: ("covered" if cat in owasp_seen else "missing")
            for cat in sorted(_ALL_OWASP)
        }
        critical_titles = [
            f.get("title", "?") for f in findings if f.get("severity") == "critical"
        ][:5]
        high_titles = [
            f.get("title", "?") for f in findings if f.get("severity") == "high"
        ][:5]

        return {
            "executive_summary": (
                f"Automated scan of {domain} found {len(findings)} findings "
                f"({counts['critical']} critical, {counts['high']} high). "
                "LLM analysis unavailable — rule-based fallback report generated."
            ),
            "risk_score": risk,
            "attack_chains": [],
            "owasp_coverage": owasp_coverage,
            "critical_findings": (critical_titles + high_titles)[:10],
            "remediation_priorities": [
                {
                    "priority": i + 1,
                    "finding": title,
                    "action": "Investigate and remediate promptly.",
                    "effort": "medium",
                }
                for i, title in enumerate((critical_titles + high_titles)[:5])
            ],
            "analyst_notes": (
                f"Risk score {risk}/100 — weighted: critical×25, high×10, medium×4, low×1. "
                "Manual analyst review recommended."
            ),
            "top_risks": [
                {
                    "title": f.get("title", "?"),
                    "severity": f.get("severity", "info"),
                    "attack_context": f.get("description", "")[:200],
                    "business_impact": "Potential data breach or service disruption.",
                }
                for f in sorted(
                    findings,
                    key=lambda x: {
                        "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4
                    }.get(x.get("severity", "info"), 4),
                )[:3]
            ],
            "key_priorities": [
                "Remediate all critical findings immediately",
                "Address high severity findings within 7 days",
                "Review medium severity findings within 30 days",
            ],
            "domain": domain,
            "ai_generated": False,
            "rag_context_used": False,
            "retrieval_method": self._rag.get_retrieval_method(),
            "model_used": getattr(settings, "LITELLM_MODEL", "rule_based_fallback"),
            # Default empty; populated by analyze() when RAG runs successfully.
            "kev_matches": [],
            # Intelligence correlation defaults
            "known_exploited": False,
            "exploit_available": False,
            "priority_reason": "No known active exploitation",
        }

    def _empty_report(self, domain: str) -> Dict[str, Any]:
        from backend.config import get_settings
        return {
            "executive_summary": (
                f"No vulnerabilities detected for {domain} during this scan. "
                "The target appears to have a minimal attack surface based on the scan parameters."
            ),
            "risk_score": 0,
            "attack_chains": [],
            "owasp_coverage": {cat: "missing" for cat in sorted(_ALL_OWASP)},
            "critical_findings": [],
            "remediation_priorities": [],
            "analyst_notes": (
                "Risk score is minimal as no exploitable vulnerabilities were detected. "
                "Continue regular scanning as the attack surface evolves."
            ),
            "top_risks": [],
            "key_priorities": [
                "Continue regular scanning as attack surface evolves",
                "Monitor for newly disclosed CVEs affecting detected technologies",
                "Consider expanding scan scope for more comprehensive coverage",
            ],
            "domain": domain,
            "ai_generated": True,
            "rag_context_used": False,
            "retrieval_method": self._rag.get_retrieval_method(),
            "model_used": getattr(get_settings(), "LITELLM_MODEL", "unknown"),
            # No findings means no CVE IDs to match against KEV.
            "kev_matches": [],
            # Intelligence correlation defaults
            "known_exploited": False,
            "exploit_available": False,
            "priority_reason": "No known active exploitation",
            "attack_chains": [],
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_analyst_agent: Optional[AnalystAgent] = None


def get_analyst_agent() -> AnalystAgent:
    """Return singleton AnalystAgent instance."""
    global _analyst_agent
    if _analyst_agent is None:
        _analyst_agent = AnalystAgent()
    return _analyst_agent


async def analyze_findings(
    scan_results: Dict[str, Any],
    kev_matches: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Entry-point helper for Agent 2. Called by analyst_tasks.py.

    Args:
        scan_results: Structured findings dict from the scan pipeline.
        kev_matches:  CVE IDs confirmed in CISA KEV catalog (optional).
                      Passed through to AnalystAgent.analyze() for prompt
                      escalation and analyst_notes annotation.
                      Defaults to None (treated as empty list inside analyze()).
    """
    # CRITICAL-2 fix: resolve mutable default at module boundary too
    kev_matches = kev_matches or []
    agent = get_analyst_agent()
    return await agent.analyze(scan_results, kev_matches=kev_matches)
