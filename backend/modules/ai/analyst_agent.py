"""
SentinelX — Agent 2: Analyst Agent (LLM + RAG)
Controlled AI interpretation layer for security findings.

Role:
  This agent ONLY interprets and explains findings produced by the Tools Layer.
  It does NOT execute tools, modify scan pipelines, or make security decisions.

Input:   Structured findings JSON from the scan pipeline + RAG context
Output:  Risk summary, severity reasoning, attack context, top risks

Boundaries (hard-coded, not configurable by LLM):
  - Cannot trigger tool execution
  - Cannot modify finding data
  - Must return structured JSON output only
  - Has a strict token budget (3000 tokens context + 1000 tokens output)
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional

from backend.modules.ai.rag_engine import get_rag_engine

logger = logging.getLogger("sentinelx.analyst")

# Maximum findings to include in context (to keep prompts manageable)
_MAX_FINDINGS_IN_PROMPT = 15

# LLM call budget — protects against runaway costs
_MAX_CONTEXT_TOKENS = 3000
_MAX_OUTPUT_TOKENS = 1200


class AnalystAgent:
    """
    Agent 2 — LLM-powered finding interpreter.

    Uses LiteLLM for provider-agnostic LLM calls.
    Queries RAG for contextual knowledge before calling the LLM.
    Output is strictly bounded and structured.
    """

    def __init__(self):
        self._rag = get_rag_engine()

    async def analyze(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze scan findings and produce a structured AI interpretation.

        Args:
            scan_results: Full scan results dict from active_scan.py or passive_recon.py

        Returns:
            Structured analysis dict with risk_summary, top_risks, severity_reasoning
        """
        domain = scan_results.get("domain", "Unknown")
        all_findings = scan_results.get("all_findings", [])
        summary = scan_results.get("summary", {})

        logger.info(
            f"[Analyst] Analyzing {len(all_findings)} findings for {domain} "
            f"(risk score: {summary.get('risk_score', 0)}/100)"
        )

        if not all_findings:
            logger.info("[Analyst] No findings to analyze")
            return self._empty_analysis(domain)

        # 1. Retrieve RAG context for these findings
        critical_and_high = [
            f for f in all_findings
            if f.get("severity") in ("critical", "high")
        ][:_MAX_FINDINGS_IN_PROMPT]

        context = self._rag.query(critical_and_high or all_findings[:10])
        rag_context = self._rag.format_context_for_prompt(context, max_chars=2000)

        # 2. Build prompt (structured, LLM cannot deviate from output format)
        prompt = self._build_analysis_prompt(domain, all_findings, summary, rag_context)

        # 3. Call LLM
        raw_response = await self._call_llm(prompt)

        # 4. Parse and validate response
        analysis = self._parse_llm_response(raw_response, domain, summary)

        logger.info(f"[Analyst] Analysis complete for {domain}")
        return analysis

    def _build_analysis_prompt(
        self,
        domain: str,
        findings: List[Dict],
        summary: Dict,
        rag_context: str,
    ) -> str:
        """
        Construct a strictly-bounded analysis prompt.
        The output format is hard-coded — the LLM must follow it exactly.
        """
        # Truncate findings list for prompt
        findings_for_prompt = self._format_findings_for_prompt(
            findings[:_MAX_FINDINGS_IN_PROMPT]
        )

        severity_counts = summary.get("severity_counts", {})
        risk_score = summary.get("risk_score", 0)
        risk_level = summary.get("risk_level", "Unknown")

        prompt = f"""You are a senior cybersecurity analyst reviewing automated scan results.
Your role is STRICTLY LIMITED to interpreting and explaining the provided findings.
You must NOT suggest running additional tools or modifying the scan process.

TARGET: {domain}
RISK SCORE: {risk_score}/100 ({risk_level})
SEVERITY DISTRIBUTION: Critical={severity_counts.get('critical', 0)}, High={severity_counts.get('high', 0)}, Medium={severity_counts.get('medium', 0)}, Low={severity_counts.get('low', 0)}, Info={severity_counts.get('info', 0)}

SECURITY KNOWLEDGE CONTEXT:
{rag_context}

SCAN FINDINGS:
{findings_for_prompt}

Provide your analysis as valid JSON matching EXACTLY this structure:
{{
  "risk_summary": "2-3 sentence executive summary of the overall security posture",
  "top_risks": [
    {{
      "title": "finding title",
      "severity": "critical|high|medium|low",
      "attack_context": "how an attacker would exploit this (1-2 sentences)",
      "business_impact": "what business harm results if exploited (1 sentence)"
    }}
  ],
  "severity_reasoning": "Explain why this risk score was assessed at this level (2-3 sentences)",
  "attack_chain": "If multiple findings can be chained, describe the attack path (or null if not applicable)",
  "key_priorities": ["Priority action 1", "Priority action 2", "Priority action 3"]
}}

Rules:
- Include top 3 findings in top_risks (critical/high priority)
- Be specific and technical but clear to a non-security audience
- Do not include any text outside the JSON object
- Respond with valid JSON only"""

        return prompt

    def _format_findings_for_prompt(self, findings: List[Dict]) -> str:
        """Format findings list as compact text for prompt injection."""
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "info"), 4)
        )

        lines = []
        for i, f in enumerate(sorted_findings, 1):
            sev = f.get("severity", "info").upper()
            title = f.get("title", "Unknown")
            desc = (f.get("description") or "")[:150]
            target = f.get("target", "")
            lines.append(f"{i}. [{sev}] {title} | Target: {target} | {desc}")

        return "\n".join(lines)

    def _parse_llm_response(
        self,
        raw_response: str,
        domain: str,
        summary: Dict,
    ) -> Dict[str, Any]:
        """Parse and validate LLM JSON response. Falls back to structured default on error."""
        if not raw_response:
            return self._fallback_analysis(domain, summary)

        # Extract JSON from response (handles cases where LLM adds prose around it)
        json_str = raw_response.strip()
        if "```" in json_str:
            # Strip code blocks
            import re
            match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", json_str)
            if match:
                json_str = match.group(1)

        try:
            parsed = json.loads(json_str)

            # Validate required fields
            required = ["risk_summary", "top_risks", "severity_reasoning", "key_priorities"]
            for field in required:
                if field not in parsed:
                    logger.warning(f"[Analyst] LLM response missing field: {field}")
                    parsed[field] = self._default_value(field, summary)

            # Ensure top_risks is capped at 5
            if isinstance(parsed.get("top_risks"), list):
                parsed["top_risks"] = parsed["top_risks"][:5]

            parsed["domain"] = domain
            parsed["ai_generated"] = True
            return parsed

        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"[Analyst] Failed to parse LLM JSON response: {e}")
            return self._fallback_analysis(domain, summary)

    async def _call_llm(self, prompt: str) -> Optional[str]:
        """
        Call the configured LLM via LiteLLM.
        Returns raw string response or None on failure.
        """
        try:
            import litellm
            from backend.config import get_settings

            settings = get_settings()
            model = settings.LITELLM_MODEL

            logger.debug(f"[Analyst] Calling LLM: {model}")

            response = await litellm.acompletion(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=_MAX_OUTPUT_TOKENS,
                temperature=0.2,  # Low temperature for deterministic, factual output
            )

            return response.choices[0].message.content

        except ImportError:
            logger.warning("[Analyst] litellm not installed — using mock response")
            return self._mock_llm_response()
        except Exception as e:
            logger.error(f"[Analyst] LLM call failed: {e}")
            return None

    def _mock_llm_response(self) -> str:
        """Return a mock response for development environments without an LLM configured."""
        return json.dumps({
            "risk_summary": "This is a mock analysis response. Configure GROQ_API_KEY or another LLM provider in .env to enable real AI analysis. The scan has detected several security concerns that require attention.",
            "top_risks": [
                {
                    "title": "Mock: LLM Not Configured",
                    "severity": "info",
                    "attack_context": "Real AI analysis requires an LLM API key configured in the .env file.",
                    "business_impact": "Without AI analysis, findings are still reported but lack contextual interpretation."
                }
            ],
            "severity_reasoning": "Mock analysis mode. Set GROQ_API_KEY in .env and restart the server for real AI-powered analysis.",
            "attack_chain": None,
            "key_priorities": [
                "Configure GROQ_API_KEY in .env file",
                "Restart the backend server",
                "Re-run the scan for AI-powered analysis"
            ]
        })

    def _empty_analysis(self, domain: str) -> Dict[str, Any]:
        """Return structured empty analysis when no findings exist."""
        return {
            "domain": domain,
            "risk_summary": f"No vulnerabilities were detected for {domain} during this scan. The target appears to have a minimal attack surface based on the scan parameters used.",
            "top_risks": [],
            "severity_reasoning": "Risk score is minimal as no exploitable vulnerabilities were detected.",
            "attack_chain": None,
            "key_priorities": [
                "Continue regular scanning as the attack surface evolves",
                "Monitor for newly disclosed CVEs affecting detected technologies",
                "Consider expanding scan scope for more comprehensive coverage"
            ],
            "ai_generated": True,
        }

    def _fallback_analysis(self, domain: str, summary: Dict) -> Dict[str, Any]:
        """Rule-based fallback when LLM is unavailable or fails."""
        risk_score = summary.get("risk_score", 0)
        risk_level = summary.get("risk_level", "Unknown")
        counts = summary.get("severity_counts", {})

        return {
            "domain": domain,
            "risk_summary": (
                f"{domain} has an overall risk score of {risk_score}/100 ({risk_level}). "
                f"The scan identified {counts.get('critical', 0)} critical, "
                f"{counts.get('high', 0)} high, and {counts.get('medium', 0)} medium severity issues. "
                "AI narrative analysis was unavailable — see finding details for remediation guidance."
            ),
            "top_risks": [],
            "severity_reasoning": f"Risk score of {risk_score}/100 based on weighted severity counts: critical×25, high×15, medium×8, low×3.",
            "attack_chain": None,
            "key_priorities": [
                "Prioritize remediation of all critical findings immediately",
                "Address high severity findings within 7 days",
                "Review medium severity findings within 30 days"
            ],
            "ai_generated": False,
        }

    def _default_value(self, field: str, summary: Dict) -> Any:
        """Provide default values for missing LLM response fields."""
        defaults = {
            "risk_summary": "Analysis incomplete — see findings table for details.",
            "top_risks": [],
            "severity_reasoning": f"Risk score: {summary.get('risk_score', 0)}/100",
            "key_priorities": ["Review all critical and high findings immediately"],
            "attack_chain": None,
        }
        return defaults.get(field, None)


# Module-level singleton
_analyst_agent: Optional[AnalystAgent] = None


def get_analyst_agent() -> AnalystAgent:
    """Return singleton AnalystAgent instance."""
    global _analyst_agent
    if _analyst_agent is None:
        _analyst_agent = AnalystAgent()
    return _analyst_agent


async def analyze_findings(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Entry-point helper for Agent 2."""
    agent = get_analyst_agent()
    return await agent.analyze(scan_results)
