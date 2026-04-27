"""
Unit tests for analyst_agent.py — KEV escalation and prompt engineering.

Loaded via importlib to avoid the backend.modules.ai __init__ eager-import
chain (rag_engine + litellm + DB config absent in CI).

Coverage:
  - analyze_findings() signature accepts kev_matches (backward compat)
  - _build_system_prompt() returns base prompt when kev_matches empty
  - _build_system_prompt() appends KEV block when kev_matches non-empty
  - analyze() appends KEV note to analyst_notes when kev_matches supplied
  - analyze() leaves analyst_notes unchanged when kev_matches empty
  - AnalysisReport schema NOT changed: no new fields added by KEV path
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import types
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Isolated module load — bypass backend.modules.ai package __init__ chain
# ---------------------------------------------------------------------------

_ANALYST_PATH = (
    Path(__file__).parent / "analyst_agent.py"
)


def _load_analyst_module():
    """Load analyst_agent.py without triggering package-level imports."""
    # Stub out backend.modules.ai.rag_engine so the module-level import
    # `from backend.modules.ai.rag_engine import get_rag_engine` succeeds.
    fake_rag = MagicMock()
    fake_rag.query.return_value = {
        "chunks": [], "kev_matches": [], "kev_alerts": [],
        "owasp": [], "headers": [], "remediation": [],
        "exploit_db": [], "cve_summaries": [], "kev_catalog": [],
    }
    fake_rag.format_context_for_prompt.return_value = ""
    fake_rag.get_retrieval_method.return_value = "keyword"
    fake_rag._kb = {"exploit_db": []}

    rag_module = types.ModuleType("backend.modules.ai.rag_engine")
    rag_module.get_rag_engine = lambda: fake_rag

    # Ensure parent package stubs exist in sys.modules
    for pkg in ("backend", "backend.modules", "backend.modules.ai"):
        if pkg not in sys.modules:
            sys.modules[pkg] = types.ModuleType(pkg)
    sys.modules["backend.modules.ai.rag_engine"] = rag_module

    spec = importlib.util.spec_from_file_location(
        "analyst_agent_isolated", str(_ANALYST_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod, fake_rag


_mod, _fake_rag = _load_analyst_module()
AnalystAgent = _mod.AnalystAgent
analyze_findings = _mod.analyze_findings
_KEV_BLOCK = _mod._KEV_SYSTEM_PROMPT_BLOCK


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAMPLE_FINDINGS = [
    {
        "title": "SQL Injection",
        "severity": "critical",
        "description": "Unsanitised user input in login form.",
        "target": "example.com/login",
        "owasp_categories": ["A03"],
    },
    {
        "title": "Missing HSTS Header",
        "severity": "medium",
        "description": "HTTP Strict-Transport-Security not set.",
        "target": "example.com",
        "owasp_categories": ["A05"],
    },
]

_SCAN_RESULTS = {
    "domain": "example.com",
    "all_findings": _SAMPLE_FINDINGS,
    "summary": {
        "risk_score": 75,
        "risk_level": "high",
        "total_findings": 2,
        "severity_counts": {"critical": 1, "high": 0, "medium": 1, "low": 0},
    },
}

_KEV_IDS = ["CVE-2021-44228", "CVE-2023-23397"]


def _make_agent() -> AnalystAgent:
    agent = AnalystAgent.__new__(AnalystAgent)
    agent._rag = _fake_rag
    return agent


def _mock_llm_response(notes: str = "Base analyst notes from LLM.") -> str:
    return json.dumps({
        "executive_summary": "Test summary.",
        "risk_score": 75,
        "attack_chains": [],
        "owasp_coverage": {f"A{i:02d}": "missing" for i in range(1, 11)},
        "critical_findings": ["SQL Injection"],
        "remediation_priorities": [],
        "analyst_notes": notes,
        "top_risks": [],
        "key_priorities": ["Fix SQL injection", "Add HSTS header", "Review configs"],
    })


# ---------------------------------------------------------------------------
# Tests: _build_system_prompt
# ---------------------------------------------------------------------------

class TestBuildSystemPrompt:
    def setup_method(self):
        self.agent = _make_agent()

    def test_returns_base_prompt_when_no_kev(self):
        result = self.agent._build_system_prompt([])
        assert result == self.agent._SYSTEM_PROMPT

    def test_appends_kev_block_when_matches_present(self):
        result = self.agent._build_system_prompt(_KEV_IDS)
        assert result.startswith(self.agent._SYSTEM_PROMPT)
        assert "CRITICAL INTELLIGENCE" in result
        assert "KNOWN EXPLOITATION IN THE WILD" in result
        assert "CVE-2021-44228" in result
        assert "CVE-2023-23397" in result

    def test_kev_block_contains_required_instructions(self):
        result = self.agent._build_system_prompt(["CVE-2021-44228"])
        assert "known exploited in wild" in result
        assert "IMMEDIATE" in result
        assert "CRITICAL" in result

    def test_base_prompt_unchanged_in_kev_result(self):
        """The original _SYSTEM_PROMPT content must be fully preserved."""
        result = self.agent._build_system_prompt(_KEV_IDS)
        assert self.agent._SYSTEM_PROMPT in result

    def test_each_cve_on_own_line_in_block(self):
        result = self.agent._build_system_prompt(_KEV_IDS)
        # Both CVEs must appear, separated by newline inside the block
        idx_first = result.index("CVE-2021-44228")
        idx_second = result.index("CVE-2023-23397")
        between = result[idx_first:idx_second]
        assert "\n" in between


# ---------------------------------------------------------------------------
# Tests: analyze() KEV annotation of analyst_notes
# ---------------------------------------------------------------------------

class TestAnalyzeKevNotes:
    def setup_method(self):
        self.agent = _make_agent()

    def _run(self, kev_matches, llm_notes="Base analyst notes."):
        async def _inner():
            with patch.object(
                self.agent,
                "_call_llm",
                return_value=_mock_llm_response(notes=llm_notes),
            ):
                return await self.agent.analyze(_SCAN_RESULTS, kev_matches=kev_matches)
        return asyncio.run(_inner())

    def test_no_kev_leaves_notes_unchanged(self):
        report = self._run([])
        assert "KEV matches detected" not in report["analyst_notes"]

    def test_kev_appended_to_existing_notes(self):
        report = self._run(_KEV_IDS)
        notes = report["analyst_notes"]
        assert "Base analyst notes." in notes
        assert "KEV matches detected" in notes
        assert "CVE-2021-44228" in notes
        assert "CVE-2023-23397" in notes
        assert "severity elevated per CISA KEV catalog" in notes

    def test_kev_note_comes_after_llm_notes(self):
        report = self._run(_KEV_IDS)
        idx_base = report["analyst_notes"].index("Base analyst notes.")
        idx_kev = report["analyst_notes"].index("KEV matches detected")
        assert idx_base < idx_kev

    def test_kev_appended_when_notes_empty_string(self):
        report = self._run(_KEV_IDS, llm_notes="")
        notes = report["analyst_notes"]
        # When LLM returns empty notes, KEV note becomes the full value
        assert "KEV matches detected" in notes

    def test_single_cve_kev_match(self):
        report = self._run(["CVE-2021-44228"])
        assert "CVE-2021-44228" in report["analyst_notes"]
        assert "CVE-2023-23397" not in report["analyst_notes"]


# ---------------------------------------------------------------------------
# Tests: analyze_findings() entry-point signature
# ---------------------------------------------------------------------------

class TestAnalyzeFindingsSignature:
    def test_accepts_no_kev_matches(self):
        """Existing callers with no kev_matches arg must not break."""
        import inspect
        sig = inspect.signature(analyze_findings)
        params = list(sig.parameters.keys())
        assert "scan_results" in params
        assert "kev_matches" in params

    def test_kev_matches_defaults_to_none(self):
        """kev_matches default is None (not []) to avoid the mutable default bug.
        The module resolves None to [] internally before use."""
        import inspect
        sig = inspect.signature(analyze_findings)
        default = sig.parameters["kev_matches"].default
        assert default is None


# ---------------------------------------------------------------------------
# Tests: AnalysisReport schema NOT changed by KEV path
# ---------------------------------------------------------------------------

class TestSchemaUnchanged:
    """Verify KEV changes are purely additive in prompting — no new schema fields
    are introduced that weren't already in the dict returned by analyze()."""

    # Fields that must be present (were present before KEV work)
    _REQUIRED_FIELDS = {
        "executive_summary",
        "risk_score",
        "attack_chains",
        "owasp_coverage",
        "critical_findings",
        "remediation_priorities",
        "analyst_notes",
        "top_risks",
        "key_priorities",
        "domain",
        "ai_generated",
        "rag_context_used",
        "retrieval_method",
    }

    def _run_with_kev(self):
        agent = _make_agent()
        async def _inner():
            with patch.object(
                agent,
                "_call_llm",
                return_value=_mock_llm_response(),
            ):
                return await agent.analyze(_SCAN_RESULTS, kev_matches=_KEV_IDS)
        return asyncio.run(_inner())

    def test_all_required_fields_present_with_kev(self):
        report = self._run_with_kev()
        for field in self._REQUIRED_FIELDS:
            assert field in report, f"Missing required field: {field}"

    def test_no_unexpected_new_top_level_fields(self):
        """Ensure no brand-new top-level keys appeared that aren't in the
        known schema. kev_matches was added in ADR-018; known_exploited,
        exploit_available, priority_reason were added in ADR-020."""
        report = self._run_with_kev()
        known_fields = self._REQUIRED_FIELDS | {
            "kev_matches",
            "model_used",
            # ADR-020 intelligence correlation fields
            "known_exploited",
            "exploit_available",
            "priority_reason",
        }
        unexpected = set(report.keys()) - known_fields
        assert not unexpected, f"Unexpected new fields in report: {unexpected}"

    def test_analyst_notes_is_still_a_string(self):
        """analyst_notes must remain a str after KEV annotation."""
        report = self._run_with_kev()
        assert isinstance(report["analyst_notes"], str)
