"""
SentinelX — Agent 3: Remediation Advisor
Generates prioritized, actionable remediation plans from scan findings.

Role:
  This agent produces step-by-step remediation guidance.
  It does NOT discover vulnerabilities or analyze their severity.
  It takes the findings + Agent 2 analysis as input and produces a fix plan.

Input:   Scan findings + Agent 2 analysis output
Output:  Prioritized remediation plan with immediate actions and fix steps

Boundaries:
  - Cannot trigger tool execution
  - Cannot modify finding severity or risk score
  - Output is structured JSON only
  - Uses RAG to retrieve known fix patterns before calling LLM
"""

import json
import logging
from typing import Any, Dict, List, Optional

from backend.modules.ai.rag_engine import get_rag_engine

logger = logging.getLogger("sentinelx.remediation")

_MAX_FINDINGS_FOR_REMEDIATION = 10
_MAX_OUTPUT_TOKENS = 1500


class RemediationAgent:
    """
    Agent 3 — Remediation Advisor.

    Combines RAG-retrieved fix patterns with LLM reasoning
    to produce structured, actionable remediation plans.
    """

    def __init__(self):
        self._rag = get_rag_engine()

    async def advise(
        self,
        scan_results: Dict[str, Any],
        analyst_output: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a prioritized remediation plan.

        Args:
            scan_results:    Full scan findings from the pipeline
            analyst_output:  Optional Agent 2 analysis for context enrichment

        Returns:
            Structured remediation plan dict
        """
        domain = scan_results.get("domain", "Unknown")
        all_findings = scan_results.get("all_findings", [])
        summary = scan_results.get("summary", {})

        logger.info(
            f"[Remediation] Generating remediation plan for {domain}: "
            f"{len(all_findings)} finding(s)"
        )

        if not all_findings:
            return self._empty_plan(domain)

        # Prioritize findings — critical and high first
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        prioritized = sorted(
            [f for f in all_findings if f.get("severity") != "info"],
            key=lambda f: severity_order.get(f.get("severity", "info"), 4)
        )[:_MAX_FINDINGS_FOR_REMEDIATION]

        # Retrieve RAG context for these findings
        context = self._rag.query(prioritized, top_k=4)
        rag_context = self._rag.format_context_for_prompt(context, max_chars=2500)

        # Build remediation prompt
        prompt = self._build_remediation_prompt(
            domain, prioritized, summary, rag_context, analyst_output
        )

        # Call LLM
        raw_response = await self._call_llm(prompt)

        # Parse and return
        plan = self._parse_response(raw_response, domain, prioritized)
        logger.info(f"[Remediation] Plan generated for {domain}")
        return plan

    def _build_remediation_prompt(
        self,
        domain: str,
        findings: List[Dict],
        summary: Dict,
        rag_context: str,
        analyst_output: Optional[Dict],
    ) -> str:
        """Build a structured remediation prompt."""

        findings_text = self._format_findings(findings)
        risk_level = summary.get("risk_level", "Unknown")
        risk_score = summary.get("risk_score", 0)

        # Include analyst top risks for context if available
        analyst_context = ""
        if analyst_output and analyst_output.get("top_risks"):
            analyst_context = "\nANALYST PRIORITY RISKS:\n"
            for risk in analyst_output["top_risks"][:3]:
                analyst_context += f"- {risk.get('title', '')}: {risk.get('business_impact', '')}\n"

        prompt = f"""You are a senior cybersecurity engineer creating a remediation plan.
Your role is STRICTLY LIMITED to providing fix guidance for the listed findings.
Do not suggest additional scans or tools. Focus only on how to fix what was found.

TARGET: {domain}
RISK LEVEL: {risk_level} ({risk_score}/100)
{analyst_context}

REMEDIATION KNOWLEDGE BASE:
{rag_context}

FINDINGS REQUIRING REMEDIATION:
{findings_text}

Generate a remediation plan as valid JSON matching EXACTLY this structure:
{{
  "immediate_actions": [
    {{
      "action": "Single sentence describing what to do RIGHT NOW",
      "reason": "Why this is urgent",
      "effort": "Minutes|Hours|Days"
    }}
  ],
  "remediation_plan": [
    {{
      "finding_title": "exact finding title from the list",
      "severity": "critical|high|medium|low",
      "priority": 1,
      "steps": ["Step 1", "Step 2", "Step 3"],
      "estimated_effort": "30 minutes|2 hours|1 day",
      "verification": "How to verify the fix was successful"
    }}
  ],
  "quick_wins": ["Simple fix 1 (< 15 min)", "Simple fix 2"],
  "long_term_recommendations": ["Strategic recommendation 1", "Strategic recommendation 2"]
}}

Rules:
- immediate_actions: max 3, for critical/high findings only
- remediation_plan: ordered by priority (1 = most urgent), max 8 entries
- quick_wins: fixes achievable in under 15 minutes
- long_term_recommendations: security posture improvements for the next 30-90 days
- Respond with valid JSON only — no prose outside the JSON"""

        return prompt

    def _format_findings(self, findings: List[Dict]) -> str:
        """Format findings for remediation prompt."""
        lines = []
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "info").upper()
            title = f.get("title", "Unknown")
            target = f.get("target", "")
            remediation = (f.get("remediation") or "")[:200]
            lines.append(
                f"{i}. [{sev}] {title}\n"
                f"   Target: {target}\n"
                f"   Existing guidance: {remediation}"
            )
        return "\n".join(lines)

    def _parse_response(
        self,
        raw_response: Optional[str],
        domain: str,
        findings: List[Dict],
    ) -> Dict[str, Any]:
        """Parse LLM JSON response with fallback to rule-based plan."""
        if not raw_response:
            return self._rule_based_plan(domain, findings)

        json_str = raw_response.strip()
        if "```" in json_str:
            import re
            match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", json_str)
            if match:
                json_str = match.group(1)

        try:
            parsed = json.loads(json_str)

            # Validate required keys
            required = ["immediate_actions", "remediation_plan", "quick_wins"]
            for key in required:
                if key not in parsed:
                    parsed[key] = []

            # Cap lengths
            parsed["immediate_actions"] = parsed["immediate_actions"][:3]
            parsed["remediation_plan"] = parsed["remediation_plan"][:8]
            parsed["quick_wins"] = parsed["quick_wins"][:5]

            parsed["domain"] = domain
            parsed["ai_generated"] = True
            return parsed

        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"[Remediation] Failed to parse LLM response: {e}")
            return self._rule_based_plan(domain, findings)

    async def _call_llm(self, prompt: str) -> Optional[str]:
        """Call the configured LLM via LiteLLM."""
        try:
            import litellm
            from backend.config import get_settings

            settings = get_settings()
            model = settings.LITELLM_MODEL

            logger.debug(f"[Remediation] Calling LLM: {model}")

            response = await litellm.acompletion(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=_MAX_OUTPUT_TOKENS,
                temperature=0.1,  # Very low temperature for consistent remediation steps
            )

            return response.choices[0].message.content

        except ImportError:
            logger.warning("[Remediation] litellm not installed — using rule-based plan")
            return None
        except Exception as e:
            logger.error(f"[Remediation] LLM call failed: {e}")
            return None

    def _rule_based_plan(self, domain: str, findings: List[Dict]) -> Dict[str, Any]:
        """
        Generate a purely rule-based remediation plan when LLM is unavailable.
        Uses the remediation field from each finding directly.
        """
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        immediate_actions = []
        remediation_plan = []
        quick_wins = []

        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "info")
            title = f.get("title", "Unknown")
            remediation = f.get("remediation", "Review and apply security best practices.")

            entry = {
                "finding_title": title,
                "severity": sev,
                "priority": i,
                "steps": [remediation],
                "estimated_effort": "Review required",
                "verification": f"Re-scan {f.get('target', domain)} after applying fix.",
            }
            remediation_plan.append(entry)

            if sev == "critical":
                immediate_actions.append({
                    "action": f"Address '{title}' immediately",
                    "reason": "Critical severity — high likelihood of exploitation",
                    "effort": "Hours",
                })

            if sev in ("critical", "high"):
                # Short remediations are quick wins
                if len(remediation) < 120:
                    quick_wins.append(remediation)

        return {
            "domain": domain,
            "immediate_actions": immediate_actions[:3],
            "remediation_plan": remediation_plan[:8],
            "quick_wins": quick_wins[:5],
            "long_term_recommendations": [
                "Implement continuous vulnerability scanning in your CI/CD pipeline",
                "Establish a patch management policy with defined SLAs by severity",
                "Conduct quarterly security reviews and penetration tests",
            ],
            "ai_generated": False,
        }

    def _empty_plan(self, domain: str) -> Dict[str, Any]:
        """Return an empty plan when no findings require remediation."""
        return {
            "domain": domain,
            "immediate_actions": [],
            "remediation_plan": [],
            "quick_wins": ["Maintain current security posture"],
            "long_term_recommendations": [
                "Continue regular security scanning",
                "Monitor for new CVEs affecting your technology stack",
                "Consider expanding scan scope for deeper coverage",
            ],
            "ai_generated": True,
        }


# Module-level singleton
_remediation_agent: Optional[RemediationAgent] = None


def get_remediation_agent() -> RemediationAgent:
    """Return singleton RemediationAgent instance."""
    global _remediation_agent
    if _remediation_agent is None:
        _remediation_agent = RemediationAgent()
    return _remediation_agent


async def generate_remediation_plan(
    scan_results: Dict[str, Any],
    analyst_output: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Entry-point helper for Agent 3."""
    agent = get_remediation_agent()
    return await agent.advise(scan_results, analyst_output)
