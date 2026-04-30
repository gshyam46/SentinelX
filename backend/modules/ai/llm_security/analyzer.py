"""
SentinelX Phase 3 — LLM Security Analyzer

Orchestrates all 10 OWASP LLM Top 10 checks concurrently, computes a
composite risk score, derives multi-step attack chains from detected
risk combinations, and produces a structured LLMSecurityReport.

Risk score formula:
  severity_weights = {critical: 3.0, high: 2.0, medium: 1.0, low: 0.3}
  raw = sum(confidence * severity_weight for detected risks)
  llm_risk_score = min(10.0, raw)

Attack chain correlation (detected risk combinations → escalated chain):
  LLM01 + LLM07 → RCE via prompt-triggered tool execution
  LLM01 + LLM06 → Credential/PII exfiltration via prompt injection
  LLM01 + LLM08 → Full system takeover via injection + agency
  LLM06 + LLM02 → Data leak amplified via unescaped output
  LLM07 + LLM08 → Unauthorized action via plugin + excessive agency
  LLM04 + LLM10 → Financial DoS + model extraction (dual-threat)
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

from backend.modules.ai.llm_security.base import LLMRiskItem, LLMSecurityReport
from backend.modules.ai.llm_security.checks import ALL_CHECKS

logger = logging.getLogger("sentinelx.llmsec.analyzer")

# ---------------------------------------------------------------------------
# Severity → weight mapping for risk score
# ---------------------------------------------------------------------------

_SEV_WEIGHT: dict[str, float] = {
    "critical": 3.0,
    "high": 2.0,
    "medium": 1.0,
    "low": 0.3,
    "info": 0.0,
}

# ---------------------------------------------------------------------------
# Attack chain correlation rules
# Each rule: (required_check_ids_set, chain_definition)
# Fires when ALL check_ids in the set are detected with confidence >= threshold
# ---------------------------------------------------------------------------

_CHAIN_RULES: list[dict[str, Any]] = [
    {
        "checks": {"LLM01", "LLM07"},
        "confidence_threshold": 0.50,
        "chain": {
            "name": "Prompt Injection → Tool RCE",
            "severity": "critical",
            "steps": [
                "LLM01: Attacker injects adversarial prompt into chat input",
                "LLM07: Injected instruction triggers tool/plugin call without confirmation",
                "Exploitation: Tool executes attacker-controlled command (SSRF, RCE, data exfil)",
            ],
            "impact": "Remote code execution or complete data exfiltration via LLM tool use",
            "mitre": "T1190 (Exploit Public-Facing Application) → T1059 (Command Execution)",
        },
    },
    {
        "checks": {"LLM01", "LLM06"},
        "confidence_threshold": 0.45,
        "chain": {
            "name": "Prompt Injection → Credential/PII Exfiltration",
            "severity": "critical",
            "steps": [
                "LLM01: Adversarial prompt overrides system instructions",
                "LLM06: Overridden model leaks API keys, credentials, or PII from context",
                "Exploitation: Attacker uses leaked credentials for account takeover",
            ],
            "impact": "Credential theft and PII exfiltration leading to account compromise",
            "mitre": "T1528 (Steal Application Access Token) → T1087 (Account Discovery)",
        },
    },
    {
        "checks": {"LLM01", "LLM08"},
        "confidence_threshold": 0.50,
        "chain": {
            "name": "Prompt Injection → Autonomous System Takeover",
            "severity": "critical",
            "steps": [
                "LLM01: Prompt injection bypasses system instructions",
                "LLM08: AI's excessive agency allows it to execute destructive autonomous actions",
                "Exploitation: Delete data, disable auth, create backdoor accounts",
            ],
            "impact": "Complete system takeover — data destruction or persistent backdoor installation",
            "mitre": "T1190 → T1098 (Account Manipulation) → T1485 (Data Destruction)",
        },
    },
    {
        "checks": {"LLM06", "LLM02"},
        "confidence_threshold": 0.45,
        "chain": {
            "name": "Data Leakage → XSS Amplification",
            "severity": "high",
            "steps": [
                "LLM06: Sensitive data (PII, credentials) appears in LLM response",
                "LLM02: Response rendered without sanitization in browser context",
                "Exploitation: Stored XSS exfiltrates leaked data to attacker-controlled server",
            ],
            "impact": "Sensitive data leaked via both LLM response and XSS exfiltration channel",
            "mitre": "T1059.007 (JS Execution) → T1567 (Exfiltration via Web Service)",
        },
    },
    {
        "checks": {"LLM07", "LLM08"},
        "confidence_threshold": 0.50,
        "chain": {
            "name": "Insecure Plugin + Excessive Agency → Unauthorized Action Cascade",
            "severity": "critical",
            "steps": [
                "LLM07: Attacker triggers tool via prompt (no confirmation required)",
                "LLM08: AI's excessive permissions allow tool to perform irreversible actions",
                "Exploitation: Chain of tool calls deletes data, sends emails, exfiltrates secrets",
            ],
            "impact": "Multi-stage irreversible damage through tool chain execution",
            "mitre": "T1071 (C2 via App Layer) → T1485 (Data Destruction)",
        },
    },
    {
        "checks": {"LLM04", "LLM10"},
        "confidence_threshold": 0.45,
        "chain": {
            "name": "No Rate Limiting → Financial DoS + Model Extraction",
            "severity": "high",
            "steps": [
                "LLM04: No rate limiting allows unlimited inference requests",
                "LLM10: Unlimited queries enable systematic model extraction / functional cloning",
                "Exploitation: Cost amplification (thousands of expensive requests) + IP theft",
            ],
            "impact": "Financial denial-of-service (cost exhaustion) combined with model IP theft",
            "mitre": "T1499 (Endpoint DoS) → T1565 (Data Manipulation)",
        },
    },
    {
        "checks": {"LLM01", "LLM03"},
        "confidence_threshold": 0.45,
        "chain": {
            "name": "Prompt Injection → Backdoor Trigger Activation",
            "severity": "high",
            "steps": [
                "LLM03: Backdoor trigger embedded in training data",
                "LLM01: Prompt injection delivers trigger token to the model",
                "Exploitation: Backdoor activates, bypassing all safety filters for injecting user",
            ],
            "impact": "Complete safety bypass for targeted users via trained backdoor trigger",
            "mitre": "T1195 (Supply Chain Compromise) → T1562 (Impair Defenses)",
        },
    },
    {
        "checks": {"LLM05", "LLM07"},
        "confidence_threshold": 0.45,
        "chain": {
            "name": "Supply Chain Compromise → Malicious Plugin Execution",
            "severity": "high",
            "steps": [
                "LLM05: Compromised third-party plugin/SDK in dependency chain",
                "LLM07: Plugin executes malicious code via tool invocation",
                "Exploitation: RCE or data exfiltration through poisoned plugin",
            ],
            "impact": "Code execution via supply chain without direct exploit of application",
            "mitre": "T1195.002 (Compromise Software Supply Chain) → T1059",
        },
    },
]


class LLMSecurityAnalyzer:
    """
    Orchestrates all OWASP LLM Top 10 checks concurrently and produces
    a comprehensive LLMSecurityReport with risk scoring and attack chains.
    """

    def __init__(self) -> None:
        self._checks = [cls() for cls in ALL_CHECKS]

    async def analyze(
        self,
        target: str,
        recon_result: dict[str, Any] | None = None,
        findings: list[dict[str, Any]] | None = None,
    ) -> LLMSecurityReport:
        """
        Run all 10 checks concurrently against the target.

        Args:
            target:       Domain or URL of the target application.
            recon_result: Passive recon data (headers, endpoints, etc.) from Phase 1.
            findings:     Existing vulnerability findings from prior scans.

        Returns:
            LLMSecurityReport — never raises. Failed checks return detected=False.
        """
        recon_result = recon_result or {}
        findings = findings or []

        logger.info("[LLMSec] Starting analysis of %s (%d checks)", target, len(self._checks))
        t_start = time.monotonic()

        # Run all checks concurrently — wrap each in error boundary
        tasks = [
            self._run_check_safe(check, target, recon_result, findings)
            for check in self._checks
        ]
        risk_items: list[LLMRiskItem] = await asyncio.gather(*tasks)

        scan_duration = round(time.monotonic() - t_start, 2)

        # Aggregate endpoint discovery
        all_endpoints: list[str] = []
        for item in risk_items:
            all_endpoints.extend(item.endpoints_tested)
        ai_endpoints_discovered = list(dict.fromkeys(all_endpoints))

        # Filter detected risks
        detected_risks = [r for r in risk_items if r.detected]
        issues_found = len(detected_risks)

        # Compute risk score
        llm_risk_score = _compute_risk_score(risk_items)

        # Derive attack chains
        attack_chains = _derive_attack_chains(risk_items)

        # Generate executive summary
        executive_summary = _build_summary(
            target, risk_items, detected_risks, llm_risk_score, attack_chains
        )

        logger.info(
            "[LLMSec] Analysis complete for %s — score=%.1f issues=%d chains=%d duration=%.1fs",
            target, llm_risk_score, issues_found, len(attack_chains), scan_duration,
        )

        return LLMSecurityReport(
            target=target,
            llm_risk_score=round(llm_risk_score, 2),
            checks_run=len(risk_items),
            issues_found=issues_found,
            risks=risk_items,
            scan_duration=scan_duration,
            ai_endpoints_discovered=ai_endpoints_discovered[:20],
            attack_chains=attack_chains,
            executive_summary=executive_summary,
        )

    @staticmethod
    async def _run_check_safe(
        check: Any,
        target: str,
        recon_result: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> LLMRiskItem:
        """
        Execute a single check with full error isolation.
        A failed check is logged and returns detected=False rather than crashing the pipeline.
        """
        try:
            result = await check.run(target, recon_result, findings)
            logger.debug(
                "[LLMSec] %s: detected=%s confidence=%.2f",
                check.check_id, result.detected, result.confidence,
            )
            return result
        except Exception as exc:
            logger.error("[LLMSec] %s check failed: %s", check.check_id, exc)
            return LLMRiskItem(
                check_id=check.check_id,
                title=check.title,
                detected=False,
                severity="info",
                confidence=0.0,
                evidence=[f"Check execution failed: {str(exc)[:200]}"],
                recommendation="Re-run this check after resolving the connection issue.",
            )


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def _compute_risk_score(risk_items: list[LLMRiskItem]) -> float:
    """
    Weighted score: sum(confidence × severity_weight) for detected risks, capped at 10.
    """
    raw = sum(
        item.confidence * _SEV_WEIGHT.get(item.severity, 0.0)
        for item in risk_items
        if item.detected
    )
    return min(10.0, raw)


# ---------------------------------------------------------------------------
# Attack chain derivation
# ---------------------------------------------------------------------------

def _derive_attack_chains(risk_items: list[LLMRiskItem]) -> list[dict[str, Any]]:
    """
    Correlate detected risks and produce multi-step attack chains.
    A chain fires when all required check IDs are detected above threshold.
    """
    detected_map: dict[str, LLMRiskItem] = {
        item.check_id: item for item in risk_items if item.detected
    }
    chains: list[dict[str, Any]] = []

    for rule in _CHAIN_RULES:
        required = rule["checks"]
        threshold = rule["confidence_threshold"]

        # All required checks must be detected with confidence >= threshold
        if not required.issubset(detected_map.keys()):
            continue

        if not all(
            detected_map[cid].confidence >= threshold for cid in required
        ):
            continue

        # Compute chain confidence as minimum of component confidences
        chain_confidence = min(detected_map[cid].confidence for cid in required)
        chain_def = rule["chain"].copy()
        chain_def["confidence"] = round(chain_confidence, 3)
        chain_def["component_checks"] = sorted(required)
        chains.append(chain_def)
        logger.info(
            "[LLMSec] Attack chain detected: %s (confidence=%.2f)",
            chain_def["name"], chain_confidence,
        )

    return chains


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------

def _build_summary(
    target: str,
    all_risks: list[LLMRiskItem],
    detected_risks: list[LLMRiskItem],
    score: float,
    chains: list[dict[str, Any]],
) -> str:
    if not detected_risks:
        return (
            f"LLM security assessment of {target} found no significant vulnerabilities "
            f"across all {len(all_risks)} OWASP LLM Top 10 checks. "
            "No AI endpoints were actively exploitable during the assessment window."
        )

    critical = [r for r in detected_risks if r.severity == "critical"]
    high = [r for r in detected_risks if r.severity == "high"]

    risk_label = _risk_label(score)
    top_risks = ", ".join(r.title for r in detected_risks[:3])
    chain_note = (
        f" {len(chains)} multi-step attack chain(s) identified"
        f" (e.g., {chains[0]['name']})."
        if chains else ""
    )

    return (
        f"LLM security assessment of {target} found {len(detected_risks)} risk(s) "
        f"across {len(all_risks)} OWASP LLM Top 10 checks. "
        f"Overall LLM Risk Score: {score:.1f}/10 ({risk_label}). "
        f"Critical: {len(critical)}, High: {len(high)}. "
        f"Top findings: {top_risks}.{chain_note} "
        "Immediate remediation recommended for critical and high severity findings."
    )


def _risk_label(score: float) -> str:
    if score >= 8.0:
        return "CRITICAL"
    if score >= 6.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 2.0:
        return "LOW"
    return "MINIMAL"


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_analyzer: Optional[LLMSecurityAnalyzer] = None


def get_llm_security_analyzer() -> LLMSecurityAnalyzer:
    """Return singleton LLMSecurityAnalyzer instance."""
    global _analyzer
    if _analyzer is None:
        _analyzer = LLMSecurityAnalyzer()
    return _analyzer
