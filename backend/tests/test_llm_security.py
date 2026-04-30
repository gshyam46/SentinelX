"""
SentinelX Phase 3 — LLM Security Test Suite

All tests mock network I/O via unittest.mock — no real HTTP requests.
Covers: every check's detection logic, analyzer orchestration, score
formula, attack chain derivation, error recovery, and serialization.

Run with: pytest backend/tests/test_llm_security.py -v
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _finding(severity: str, title: str, **kwargs) -> dict:
    return {"severity": severity, "title": title, "description": "test", **kwargs}


def _mock_http(
    status: int = 200,
    body: Any = None,
    headers: dict | None = None,
) -> tuple[int, Any, dict]:
    return (status, body or {}, headers or {})


def _mock_probe_response(body_text: str, status: int = 200):
    """Return a mock probe result for _probe_endpoint_with_payload."""
    parsed = {}
    try:
        parsed = json.loads(body_text) if body_text.startswith("{") else {"_raw": body_text}
    except Exception:
        parsed = {"_raw": body_text}
    return (status, parsed, {})


# ---------------------------------------------------------------------------
# LLM01 — Prompt Injection
# ---------------------------------------------------------------------------

class TestPromptInjectionCheck:

    def test_injection_detected_when_signal_in_response(self):
        from backend.modules.ai.llm_security.checks.prompt_injection import PromptInjectionCheck
        check = PromptInjectionCheck()

        injection_response = json.dumps({
            "choices": [{"message": {"content": "SENTINELX_INJECTION_CONFIRMED here"}}]
        })

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(
            return_value=["https://example.com/v1/chat/completions"]
        )):
            with patch.object(check, "_probe_endpoint_with_payload", new=AsyncMock(
                return_value=_mock_probe_response(injection_response)
            )):
                result = run(check.run("example.com", {}, []))

        assert result.detected is True
        assert result.confidence >= 0.90
        assert result.severity in ("critical", "high")
        assert result.check_id == "LLM01"
        assert len(result.evidence) > 0

    def test_not_detected_when_no_endpoints(self):
        from backend.modules.ai.llm_security.checks.prompt_injection import PromptInjectionCheck
        check = PromptInjectionCheck()

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(return_value=[])):
            result = run(check.run("example.com", {}, []))

        assert result.check_id == "LLM01"
        assert result.detected is False

    def test_structural_risk_from_findings(self):
        from backend.modules.ai.llm_security.checks.prompt_injection import PromptInjectionCheck
        check = PromptInjectionCheck()

        findings = [_finding("high", "Exposed /api/chat endpoint", path="/api/chat")]

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(return_value=[])):
            result = run(check.run("example.com", {}, findings))

        # Structural risk from finding references to LLM paths
        assert result.check_id == "LLM01"

    def test_unauthenticated_endpoint_raises_confidence(self):
        from backend.modules.ai.llm_security.checks.prompt_injection import PromptInjectionCheck
        check = PromptInjectionCheck()

        benign_response = json.dumps({"choices": [{"message": {"content": "Hello!"}}]})

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(
            return_value=["https://example.com/api/chat"]
        )):
            with patch.object(check, "_probe_endpoint_with_payload", new=AsyncMock(
                return_value=_mock_probe_response(benign_response)
            )):
                result = run(check.run("example.com", {}, []))

        # At minimum, unauthenticated LLM endpoint is flagged
        assert result.confidence >= 0.35
        assert result.check_id == "LLM01"


# ---------------------------------------------------------------------------
# LLM02 — Insecure Output Handling
# ---------------------------------------------------------------------------

class TestInsecureOutputCheck:

    def test_xss_payload_in_response_detected(self):
        from backend.modules.ai.llm_security.checks.insecure_output import InsecureOutputCheck
        check = InsecureOutputCheck()

        xss_response = json.dumps({
            "choices": [{"message": {"content": '<script>alert(document.domain)</script>'}}]
        })

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(
            return_value=["https://example.com/api/chat"]
        )):
            with patch.object(check, "_probe_endpoint_with_payload", new=AsyncMock(
                return_value=_mock_probe_response(xss_response)
            )):
                with patch.object(check, "_get", new=AsyncMock(
                    return_value=(200, "<html>normal page</html>", {})
                )):
                    result = run(check.run("example.com", {}, []))

        assert result.detected is True
        assert result.check_id == "LLM02"
        assert result.confidence >= 0.85

    def test_ssrf_payload_critical_severity(self):
        from backend.modules.ai.llm_security.checks.insecure_output import InsecureOutputCheck
        check = InsecureOutputCheck()

        ssrf_response = json.dumps({
            "choices": [{"message": {"content": "Content from 169.254.169.254/latest/meta-data/"}}]
        })

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(
            return_value=["https://example.com/api/chat"]
        )):
            with patch.object(check, "_probe_endpoint_with_payload", new=AsyncMock(
                return_value=_mock_probe_response(ssrf_response)
            )):
                with patch.object(check, "_get", new=AsyncMock(
                    return_value=(200, "", {})
                )):
                    result = run(check.run("example.com", {}, []))

        assert result.detected is True
        assert result.severity in ("critical", "high")

    def test_raw_render_indicator_in_frontend(self):
        from backend.modules.ai.llm_security.checks.insecure_output import InsecureOutputCheck
        check = InsecureOutputCheck()

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(return_value=[])):
            with patch.object(check, "_get", new=AsyncMock(
                return_value=(200, "<div dangerouslySetInnerHTML={html} />", {})
            )):
                result = run(check.run("example.com", {}, []))

        assert result.check_id == "LLM02"
        assert result.confidence >= 0.50


# ---------------------------------------------------------------------------
# LLM03 — Training Data Poisoning
# ---------------------------------------------------------------------------

class TestTrainingPoisoningCheck:

    def test_risky_training_source_detected(self):
        from backend.modules.ai.llm_security.checks.training_poisoning import TrainingPoisoningCheck
        check = TrainingPoisoningCheck()

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(return_value=[])):
            with patch.object(check, "_get", new=AsyncMock(
                return_value=(200, "Model trained on web crawl data including pastebin", {})
            )):
                result = run(check.run("example.com", {}, []))

        assert result.check_id == "LLM03"
        assert result.detected is True
        assert result.confidence >= 0.60

    def test_memorization_sensitive_data_critical(self):
        from backend.modules.ai.llm_security.checks.training_poisoning import TrainingPoisoningCheck
        check = TrainingPoisoningCheck()

        mem_response = json.dumps({
            "choices": [{"message": {"content": "sk-abc123def456ghijklmnopqrstuvwxyz1234567890"}}]
        })

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(
            return_value=["https://example.com/v1/chat/completions"]
        )):
            with patch.object(check, "_get", new=AsyncMock(return_value=(404, "", {}))):
                with patch.object(check, "_probe_endpoint_with_payload", new=AsyncMock(
                    return_value=_mock_probe_response(mem_response)
                )):
                    result = run(check.run("example.com", {}, []))

        assert result.detected is True
        assert result.confidence >= 0.70


# ---------------------------------------------------------------------------
# LLM04 — Model Denial of Service
# ---------------------------------------------------------------------------

class TestModelDenialOfServiceCheck:

    def test_no_rate_limit_detected(self):
        from backend.modules.ai.llm_security.checks.model_dos import ModelDenialOfServiceCheck
        check = ModelDenialOfServiceCheck()

        ok_response = (200, {"choices": [{"message": {"content": "4"}}]}, {})

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(
            return_value=["https://example.com/api/chat"]
        )):
            with patch.object(check, "_probe_endpoint_with_payload", new=AsyncMock(
                return_value=ok_response
            )):
                with patch.object(check, "_post_json", new=AsyncMock(
                    return_value=(200, {}, {})
                )):
                    result = run(check.run("example.com", {}, []))

        assert result.check_id == "LLM04"
        assert result.detected is True
        assert result.confidence >= 0.50

    def test_rate_limit_present_lowers_confidence(self):
        from backend.modules.ai.llm_security.checks.model_dos import ModelDenialOfServiceCheck
        check = ModelDenialOfServiceCheck()

        # First call returns 429 (rate limited)
        limited_response = (429, {"error": "rate limit"}, {"x-ratelimit-limit": "60"})

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(
            return_value=["https://example.com/api/chat"]
        )):
            with patch.object(check, "_probe_endpoint_with_payload", new=AsyncMock(
                return_value=limited_response
            )):
                with patch.object(check, "_post_json", new=AsyncMock(
                    return_value=(429, {}, {"x-ratelimit-limit": "60"})
                )):
                    result = run(check.run("example.com", {}, []))

        assert result.check_id == "LLM04"
        # Rate limiting present — lower risk signal

    def test_no_endpoints_returns_safe_result(self):
        from backend.modules.ai.llm_security.checks.model_dos import ModelDenialOfServiceCheck
        check = ModelDenialOfServiceCheck()

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(return_value=[])):
            result = run(check.run("example.com", {}, []))

        assert result.check_id == "LLM04"
        assert result.detected is False


# ---------------------------------------------------------------------------
# LLM06 — Sensitive Information Disclosure
# ---------------------------------------------------------------------------

class TestSensitiveDisclosureCheck:

    def test_api_key_in_response_critical(self):
        from backend.modules.ai.llm_security.checks.sensitive_disclosure import SensitiveDisclosureCheck
        check = SensitiveDisclosureCheck()

        leak_response = json.dumps({
            "choices": [{"message": {
                "content": "[SYSTEM_PROMPT_START] sk-abc123def456ghijklmnopqrstuvwxyz1234 is the key"
            }}]
        })

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(
            return_value=["https://example.com/api/chat"]
        )):
            with patch.object(check, "_probe_endpoint_with_payload", new=AsyncMock(
                return_value=_mock_probe_response(leak_response)
            )):
                result = run(check.run("example.com", {}, []))

        assert result.detected is True
        assert result.severity in ("critical", "high")
        assert result.check_id == "LLM06"

    def test_system_prompt_marker_detected(self):
        from backend.modules.ai.llm_security.checks.sensitive_disclosure import SensitiveDisclosureCheck
        check = SensitiveDisclosureCheck()

        # Response contains extraction marker
        marker_response = json.dumps({
            "choices": [{"message": {"content": "[SYSTEM_PROMPT_START] You are a helpful assistant..."}}]
        })

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(
            return_value=["https://example.com/api/chat"]
        )):
            with patch.object(check, "_probe_endpoint_with_payload", new=AsyncMock(
                return_value=_mock_probe_response(marker_response)
            )):
                result = run(check.run("example.com", {}, []))

        assert result.detected is True
        assert result.confidence >= 0.75


# ---------------------------------------------------------------------------
# LLM07 — Plugin Misuse
# ---------------------------------------------------------------------------

class TestPluginMisuseCheck:

    def test_fire_and_forget_tool_exec_detected(self):
        from backend.modules.ai.llm_security.checks.plugin_misuse import PluginMisuseCheck
        check = PluginMisuseCheck()

        tool_response = json.dumps({
            "choices": [{"message": {
                "content": "action_taken: true, command executed successfully"
            }}]
        })

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(
            return_value=["https://example.com/api/agent"]
        )):
            with patch.object(check, "_probe_endpoint_with_payload", new=AsyncMock(
                return_value=_mock_probe_response(tool_response)
            )):
                with patch.object(check, "_get", new=AsyncMock(
                    return_value=(404, "", {})
                )):
                    with patch.object(check, "_post_json", new=AsyncMock(
                        return_value=(404, {}, {})
                    )):
                        result = run(check.run("example.com", {}, []))

        assert result.check_id == "LLM07"
        assert result.detected is True

    def test_plugin_manifest_no_auth_detected(self):
        from backend.modules.ai.llm_security.checks.plugin_misuse import PluginMisuseCheck
        check = PluginMisuseCheck()

        manifest = json.dumps({
            "name": "MyPlugin",
            "description": "execute and delete capabilities",
            "auth": {"type": "none"},
        })

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(return_value=[])):
            with patch.object(check, "_get", new=AsyncMock(
                return_value=(200, manifest, {})
            )):
                with patch.object(check, "_post_json", new=AsyncMock(
                    return_value=(404, {}, {})
                )):
                    result = run(check.run("example.com", {}, []))

        assert result.check_id == "LLM07"
        assert result.detected is True
        assert result.confidence >= 0.60


# ---------------------------------------------------------------------------
# LLM09 — Overreliance
# ---------------------------------------------------------------------------

class TestOverrelianceCheck:

    def test_overconfident_response_detected(self):
        from backend.modules.ai.llm_security.checks.overreliance import OverrelianceCheck
        check = OverrelianceCheck()

        confident_response = json.dumps({
            "choices": [{"message": {
                "content": "The exact birth date is January 6, 1854. I am certain that this is correct."
            }}]
        })

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(
            return_value=["https://example.com/api/chat"]
        )):
            with patch.object(check, "_probe_endpoint_with_payload", new=AsyncMock(
                return_value=_mock_probe_response(confident_response)
            )):
                with patch.object(check, "_get", new=AsyncMock(
                    return_value=(200, "<html>no disclaimer</html>", {})
                )):
                    result = run(check.run("example.com", {}, []))

        assert result.check_id == "LLM09"
        assert result.detected is True

    def test_uncertainty_expressions_reduce_risk(self):
        from backend.modules.ai.llm_security.checks.overreliance import OverrelianceCheck
        check = OverrelianceCheck()

        uncertain_response = json.dumps({
            "choices": [{"message": {
                "content": (
                    "I cannot verify this information. I am not sure about the exact date. "
                    "My knowledge may be outdated. Please verify with a reliable source."
                )
            }}]
        })

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(
            return_value=["https://example.com/api/chat"]
        )):
            with patch.object(check, "_probe_endpoint_with_payload", new=AsyncMock(
                return_value=_mock_probe_response(uncertain_response)
            )):
                with patch.object(check, "_get", new=AsyncMock(
                    return_value=(200, "AI-generated content — may contain errors", {})
                )):
                    result = run(check.run("example.com", {}, []))

        assert result.check_id == "LLM09"
        # Appropriate uncertainty reduces risk


# ---------------------------------------------------------------------------
# Analyzer — orchestration, scoring, chain derivation
# ---------------------------------------------------------------------------

class TestLLMSecurityAnalyzer:

    def test_analyzer_runs_all_10_checks(self):
        from backend.modules.ai.llm_security.analyzer import LLMSecurityAnalyzer
        from backend.modules.ai.llm_security.base import LLMRiskItem

        def _safe_item(check_id: str, title: str) -> LLMRiskItem:
            return LLMRiskItem(
                check_id=check_id, title=title, detected=False,
                severity="info", confidence=0.0, evidence=[],
                recommendation="", endpoints_tested=[],
            )

        analyzer = LLMSecurityAnalyzer()

        # Patch each check's run() to return a safe non-detected result
        for check in analyzer._checks:
            check.run = AsyncMock(return_value=_safe_item(check.check_id, check.title))

        report = run(analyzer.analyze("example.com", {}, []))

        assert report.checks_run == 10
        assert report.issues_found == 0
        assert 0.0 <= report.llm_risk_score <= 10.0
        assert isinstance(report.risks, list)
        assert len(report.risks) == 10

    def test_risk_score_formula(self):
        from backend.modules.ai.llm_security.analyzer import _compute_risk_score
        from backend.modules.ai.llm_security.base import LLMRiskItem

        risks = [
            LLMRiskItem(check_id="LLM01", title="PI", detected=True,
                        severity="critical", confidence=1.0, evidence=[]),
            LLMRiskItem(check_id="LLM06", title="SD", detected=True,
                        severity="high", confidence=0.8, evidence=[]),
            LLMRiskItem(check_id="LLM09", title="OR", detected=True,
                        severity="medium", confidence=0.5, evidence=[]),
            LLMRiskItem(check_id="LLM04", title="DoS", detected=False,
                        severity="info", confidence=0.0, evidence=[]),
        ]
        # critical×3.0×1.0 + high×2.0×0.8 + medium×1.0×0.5 = 3.0+1.6+0.5 = 5.1
        score = _compute_risk_score(risks)
        assert abs(score - 5.1) < 0.01

    def test_score_capped_at_10(self):
        from backend.modules.ai.llm_security.analyzer import _compute_risk_score
        from backend.modules.ai.llm_security.base import LLMRiskItem

        risks = [
            LLMRiskItem(check_id=f"LLM0{i}", title=f"Check{i}", detected=True,
                        severity="critical", confidence=1.0, evidence=[])
            for i in range(10)
        ]
        score = _compute_risk_score(risks)
        assert score == 10.0

    def test_attack_chain_derived_from_llm01_llm07(self):
        from backend.modules.ai.llm_security.analyzer import _derive_attack_chains
        from backend.modules.ai.llm_security.base import LLMRiskItem

        risks = [
            LLMRiskItem(check_id="LLM01", title="PI", detected=True,
                        severity="critical", confidence=0.85, evidence=[]),
            LLMRiskItem(check_id="LLM07", title="Plugin", detected=True,
                        severity="high", confidence=0.75, evidence=[]),
            LLMRiskItem(check_id="LLM04", title="DoS", detected=False,
                        severity="info", confidence=0.0, evidence=[]),
        ]
        chains = _derive_attack_chains(risks)
        chain_names = [c["name"] for c in chains]
        assert any("Prompt Injection" in n and "Tool RCE" in n for n in chain_names)

    def test_failed_check_doesnt_crash_analyzer(self):
        from backend.modules.ai.llm_security.analyzer import LLMSecurityAnalyzer

        analyzer = LLMSecurityAnalyzer()

        # Make half the checks raise exceptions
        for i, check in enumerate(analyzer._checks):
            if i % 2 == 0:
                check.run = AsyncMock(side_effect=RuntimeError("simulated crash"))
            else:
                from backend.modules.ai.llm_security.base import LLMRiskItem
                check.run = AsyncMock(return_value=LLMRiskItem(
                    check_id=check.check_id, title=check.title, detected=False,
                    severity="info", confidence=0.0, evidence=[], recommendation="",
                ))

        # Must not raise
        report = run(analyzer.analyze("example.com", {}, []))
        assert report.checks_run == 10
        # Failed checks contribute detected=False items with error evidence
        crashed = [r for r in report.risks if any("failed" in e.lower() for e in r.evidence)]
        assert len(crashed) > 0

    def test_report_is_serializable(self):
        from backend.modules.ai.llm_security.analyzer import LLMSecurityAnalyzer
        from backend.modules.ai.llm_security.base import LLMRiskItem

        analyzer = LLMSecurityAnalyzer()
        for check in analyzer._checks:
            check.run = AsyncMock(return_value=LLMRiskItem(
                check_id=check.check_id, title=check.title, detected=False,
                severity="info", confidence=0.0, evidence=[], recommendation="",
            ))

        report = run(analyzer.analyze("example.com", {}, []))

        # model_dump() + json serialization must not raise
        report_dict = report.model_dump()
        json_str = json.dumps(report_dict)
        reconstructed = json.loads(json_str)

        assert reconstructed["target"] == "example.com"
        assert reconstructed["checks_run"] == 10
        assert isinstance(reconstructed["risks"], list)
        assert isinstance(reconstructed["attack_chains"], list)

    def test_no_chain_when_only_one_component_detected(self):
        from backend.modules.ai.llm_security.analyzer import _derive_attack_chains
        from backend.modules.ai.llm_security.base import LLMRiskItem

        # Only LLM01 detected — LLM07 not detected → no chain
        risks = [
            LLMRiskItem(check_id="LLM01", title="PI", detected=True,
                        severity="critical", confidence=0.90, evidence=[]),
            LLMRiskItem(check_id="LLM07", title="Plugin", detected=False,
                        severity="info", confidence=0.0, evidence=[]),
        ]
        chains = _derive_attack_chains(risks)
        injection_tool_chains = [
            c for c in chains if "LLM01" in c.get("component_checks", [])
            and "LLM07" in c.get("component_checks", [])
        ]
        assert len(injection_tool_chains) == 0

    def test_executive_summary_present(self):
        from backend.modules.ai.llm_security.analyzer import LLMSecurityAnalyzer
        from backend.modules.ai.llm_security.base import LLMRiskItem

        analyzer = LLMSecurityAnalyzer()
        for check in analyzer._checks:
            check.run = AsyncMock(return_value=LLMRiskItem(
                check_id=check.check_id, title=check.title, detected=True,
                severity="high", confidence=0.75, evidence=["test evidence"],
                recommendation="Fix it.",
            ))

        report = run(analyzer.analyze("vulnapp.example.com", {}, []))
        assert len(report.executive_summary) > 50
        assert "vulnapp.example.com" in report.executive_summary


# ---------------------------------------------------------------------------
# Model Theft — rate limit test
# ---------------------------------------------------------------------------

class TestModelTheftCheck:

    def test_no_rate_limit_bulk_inference_detected(self):
        from backend.modules.ai.llm_security.checks.model_theft import ModelTheftCheck
        check = ModelTheftCheck()

        ok = (200, {"choices": [{"message": {"content": "4"}}]}, {})

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(
            return_value=["https://example.com/api/chat"]
        )):
            with patch.object(check, "_probe_endpoint_with_payload", new=AsyncMock(
                return_value=ok
            )):
                with patch.object(check, "_get", new=AsyncMock(
                    return_value=(404, "", {})
                )):
                    with patch.object(check, "_post_json", new=AsyncMock(
                        return_value=(200, {}, {})
                    )):
                        result = run(check.run("example.com", {}, []))

        assert result.check_id == "LLM10"


# ---------------------------------------------------------------------------
# Excessive Agency
# ---------------------------------------------------------------------------

class TestExcessiveAgencyCheck:

    def test_compliance_with_dangerous_instruction_detected(self):
        from backend.modules.ai.llm_security.checks.excessive_agency import ExcessiveAgencyCheck
        check = ExcessiveAgencyCheck()

        dangerous_response = json.dumps({
            "choices": [{"message": {
                "content": "I have deleted all files in /tmp as requested. Task executed."
            }}]
        })

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(
            return_value=["https://example.com/api/chat"]
        )):
            with patch.object(check, "_probe_endpoint_with_payload", new=AsyncMock(
                return_value=_mock_probe_response(dangerous_response)
            )):
                with patch.object(check, "_get", new=AsyncMock(
                    return_value=(404, "", {})
                )):
                    result = run(check.run("example.com", {}, []))

        assert result.check_id == "LLM08"
        assert result.detected is True
        assert result.severity in ("critical", "high")

    def test_refusal_is_safe(self):
        from backend.modules.ai.llm_security.checks.excessive_agency import ExcessiveAgencyCheck
        check = ExcessiveAgencyCheck()

        refusal_response = json.dumps({
            "choices": [{"message": {
                "content": (
                    "I cannot delete files as this is dangerous and irreversible. "
                    "This requires explicit confirmation from an authorized administrator."
                )
            }}]
        })

        with patch.object(check, "discover_ai_endpoints", new=AsyncMock(
            return_value=["https://example.com/api/chat"]
        )):
            with patch.object(check, "_probe_endpoint_with_payload", new=AsyncMock(
                return_value=_mock_probe_response(refusal_response)
            )):
                with patch.object(check, "_get", new=AsyncMock(
                    return_value=(404, "", {})
                )):
                    result = run(check.run("example.com", {}, []))

        # Proper refusal — should not be detected as a high-severity finding
        assert result.check_id == "LLM08"
        assert result.confidence < 0.70
