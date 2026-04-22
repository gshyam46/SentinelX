"""
SentinelX — AI Pipeline Orchestrator
Entry point for the complete AI analysis layer (Agents 2 + 3).

This module ties together:
  - RAG Engine (knowledge retrieval)
  - Agent 2: Analyst (LLM interpretation)
  - Agent 3: Remediation Advisor (fix planning)

Usage:
    from backend.modules.ai import run_ai_pipeline

    ai_output = await run_ai_pipeline(scan_results)
"""

import logging
from typing import Any, Dict

from backend.modules.ai.analyst_agent import analyze_findings
from backend.modules.ai.remediation_agent import generate_remediation_plan

logger = logging.getLogger("sentinelx.ai")


async def run_ai_pipeline(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run the complete AI interpretation pipeline (Agents 2 + 3).

    Agent 2 (Analyst) runs first, then its output is passed to
    Agent 3 (Remediation Advisor) for enriched fix guidance.

    Args:
        scan_results: Complete scan results from the tools layer

    Returns:
        Combined AI output with analysis + remediation plan
    """
    domain = scan_results.get("domain", "Unknown")
    logger.info(f"[AI Pipeline] Starting analysis for {domain}")

    # Agent 2: Interpret and explain findings
    try:
        analysis = await analyze_findings(scan_results)
        logger.info(f"[AI Pipeline] Analyst complete for {domain}")
    except Exception as e:
        logger.error(f"[AI Pipeline] Analyst failed: {e}", exc_info=True)
        analysis = {"error": str(e), "ai_generated": False}

    # Agent 3: Generate remediation plan (uses Agent 2 output for context)
    try:
        remediation = await generate_remediation_plan(scan_results, analysis)
        logger.info(f"[AI Pipeline] Remediation complete for {domain}")
    except Exception as e:
        logger.error(f"[AI Pipeline] Remediation failed: {e}", exc_info=True)
        remediation = {"error": str(e), "ai_generated": False}

    return {
        "analysis": analysis,
        "remediation": remediation,
        "pipeline_complete": True,
    }
