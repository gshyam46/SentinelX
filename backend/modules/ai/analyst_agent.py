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


class AnalystAgent:
    """
    Agent 2 — LLM-powered finding interpreter.

    Uses LiteLLM via LiteLLM abstraction (Groq / OpenAI / Anthropic switchable).
    Queries RAG for contextual knowledge before calling the LLM.
    Output always conforms to the full AnalysisReport schema.
    """

    def __init__(self):
        self._rag = get_rag_engine()

    async def analyze(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
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
                }
            }

        Returns:
            Full AnalysisReport dict (see _empty_report for schema).
        """
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

        # 2. Build prompt
        prompt = self._build_prompt(domain, all_findings, summary, rag_text)

        # 3. LLM call
        raw = await self._call_llm(prompt)

        # 4. Parse + validate
        report = self._parse_response(raw, domain, summary, all_findings)

        # 5. Stamp research metadata
        report["rag_context_used"] = rag_used
        report["retrieval_method"] = retrieval_method

        logger.info("[Analyst] Analysis complete for %s — risk_score=%s", domain, report.get("risk_score"))
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
"""

    def _build_prompt(
        self,
        domain: str,
        findings: List[Dict],
        summary: Dict,
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
    def _format_findings(findings: List[Dict]) -> str:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_f = sorted(findings, key=lambda f: sev_order.get(f.get("severity", "info"), 4))
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

    async def _call_llm(self, prompt: str) -> Optional[str]:
        try:
            import litellm
            from backend.config import get_settings

            settings = get_settings()
            response = await litellm.acompletion(
                model=settings.LITELLM_MODEL,
                messages=[
                    {"role": "system", "content": self._SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=_MAX_OUTPUT_TOKENS,
                temperature=0.1,
                response_format={"type": "json_object"},
            )
            return response.choices[0].message.content

        except ImportError:
            logger.warning("[Analyst] litellm not installed — using mock response")
            return self._mock_response()
        except Exception as exc:
            logger.error("[Analyst] LLM call failed: %s", exc)
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
        summary: Dict,
        findings: List[Dict],
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
            parsed["attack_chains"] = [{"name": "Primary chain", "steps": [chain], "impact": "high"}] if chain else []

        # Ensure all required fields
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
    # Fallback / empty reports (full schema always)
    # ------------------------------------------------------------------

    def _fallback_report(
        self, domain: str, summary: Dict, findings: List[Dict]
    ) -> Dict[str, Any]:
        from backend.config import get_settings
        settings = get_settings()

        counts: Counter = Counter(f.get("severity", "info") for f in findings)
        risk = min(
            100,
            counts["critical"] * 25 + counts["high"] * 10 + counts["medium"] * 4 + counts["low"] * 1,
        )
        owasp_seen: set[str] = set()
        for f in findings:
            owasp_seen.update(f.get("owasp_categories", []))
        owasp_coverage = {
            cat: ("covered" if cat in owasp_seen else "missing")
            for cat in sorted(_ALL_OWASP)
        }
        critical_titles = [f.get("title", "?") for f in findings if f.get("severity") == "critical"][:5]
        high_titles = [f.get("title", "?") for f in findings if f.get("severity") == "high"][:5]

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
                    key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                        x.get("severity", "info"), 4
                    ),
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
            "model_used": getattr(get_settings(), "LITELLM_MODEL", "rule_based_fallback"),
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
        }


# Module-level singleton
_analyst_agent: Optional[AnalystAgent] = None


def get_analyst_agent() -> AnalystAgent:
    """Return singleton AnalystAgent instance."""
    global _analyst_agent
    if _analyst_agent is None:
        _analyst_agent = AnalystAgent()
    return _analyst_agent


async def analyze_findings(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Entry-point helper for Agent 2. Called by analyst_tasks.py."""
    agent = get_analyst_agent()
    return await agent.analyze(scan_results)
