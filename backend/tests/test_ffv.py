"""
Tests for Phase 2 P2-03 — Find→Fix→Verify engine.
All tests run with MOCK_MODE=True.
Engine tests only — no HTTP client / no real DB required.
"""
from __future__ import annotations

import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("MOCK_MODE", "true")


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _finding(severity: str, title: str, **kwargs) -> dict:
    return {"severity": severity, "title": title, "description": "test finding", **kwargs}


# ---------------------------------------------------------------------------
# test_verify_finding_fixed
# Validator returns validated=False → fix_status="fixed"
# ---------------------------------------------------------------------------

def test_verify_finding_fixed():
    from backend.modules.pentest.ffv.engine import verify_finding
    from backend.modules.pentest.validation.base import ValidationResult

    mock_vresult = ValidationResult(
        finding_id="test", validated=False, confidence=0.1, method="mock_probe"
    )

    with patch(
        "backend.modules.pentest.validation.xss.XSSValidator.validate",
        new=AsyncMock(return_value=mock_vresult),
    ):
        result = run(verify_finding(_finding("high", "Reflected XSS on /search"), "example.com"))

    assert result.fix_status == "fixed"
    assert result.title == "Reflected XSS on /search"
    assert result.original_severity == "high"
    assert result.validation_method == "mock_probe"
    assert "fix appears effective" in result.note.lower()


# ---------------------------------------------------------------------------
# test_verify_finding_still_present
# Validator returns validated=True → fix_status="still_present"
# ---------------------------------------------------------------------------

def test_verify_finding_still_present():
    from backend.modules.pentest.ffv.engine import verify_finding
    from backend.modules.pentest.validation.base import ValidationResult

    mock_vresult = ValidationResult(
        finding_id="test", validated=True, confidence=0.9, method="boolean_delta"
    )

    with patch(
        "backend.modules.pentest.validation.sqli.SQLiValidator.validate",
        new=AsyncMock(return_value=mock_vresult),
    ):
        result = run(verify_finding(_finding("critical", "SQL Injection in login form"), "example.com"))

    assert result.fix_status == "still_present"
    assert result.confidence == pytest.approx(0.9)
    assert "still present" in result.note.lower()
    assert result.validation_method == "boolean_delta"


# ---------------------------------------------------------------------------
# test_verify_finding_no_validator
# Finding type with no validator → fix_status="unverifiable"
# ---------------------------------------------------------------------------

def test_verify_finding_no_validator():
    from backend.modules.pentest.ffv.engine import verify_finding

    result = run(verify_finding(
        _finding("high", "Outdated SSL/TLS version — unknown to validator"),
        "example.com",
    ))

    assert result.fix_status == "unverifiable"
    assert result.confidence == pytest.approx(0.0)
    assert result.validation_method is None
    assert "no validator" in result.note.lower()


# ---------------------------------------------------------------------------
# test_verify_finding_validator_error
# Validator raises an exception → fix_status="unverifiable", no crash
# ---------------------------------------------------------------------------

def test_verify_finding_validator_error():
    from backend.modules.pentest.ffv.engine import verify_finding

    with patch(
        "backend.modules.pentest.validation.cors.CORSValidator.validate",
        new=AsyncMock(side_effect=RuntimeError("simulated probe failure")),
    ):
        result = run(verify_finding(
            _finding("high", "CORS Misconfiguration on API endpoint"),
            "example.com",
        ))

    assert result.fix_status == "unverifiable"
    assert "simulated probe failure" in result.note
    assert result.confidence == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# test_verify_multiple_findings
# Batch: XSS (fixed) + SQLi (still_present) + unknown type (unverifiable)
# ---------------------------------------------------------------------------

def test_verify_multiple_findings():
    from backend.modules.pentest.ffv.engine import verify_findings
    from backend.modules.pentest.validation.base import ValidationResult

    fixed_result = ValidationResult(
        finding_id="xss", validated=False, confidence=0.05, method="reflection_probe"
    )
    present_result = ValidationResult(
        finding_id="sqli", validated=True, confidence=0.85, method="boolean_delta"
    )

    findings = [
        _finding("high", "Reflected XSS on /q"),
        _finding("critical", "SQL Injection in user search"),
        _finding("medium", "Directory listing enabled"),  # no validator
    ]

    with (
        patch("backend.modules.pentest.validation.xss.XSSValidator.validate",
              new=AsyncMock(return_value=fixed_result)),
        patch("backend.modules.pentest.validation.sqli.SQLiValidator.validate",
              new=AsyncMock(return_value=present_result)),
    ):
        results = run(verify_findings(findings, "example.com"))

    assert len(results) == 3
    assert results[0].fix_status == "fixed"
    assert results[1].fix_status == "still_present"
    assert results[2].fix_status == "unverifiable"   # medium severity, no validator match
    assert results[2].confidence == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# test_verify_result_is_pydantic_serializable
# VerifyResult must round-trip through JSON without error
# ---------------------------------------------------------------------------

def test_verify_result_is_pydantic_serializable():
    from backend.modules.pentest.ffv.engine import verify_finding

    result = run(verify_finding(
        _finding("high", "CORS Misconfiguration"),  # MOCK_MODE → validated=True
        "example.com",
    ))

    dumped = result.model_dump()
    serialised = json.dumps(dumped)
    restored = json.loads(serialised)

    assert restored["title"] == result.title
    assert restored["fix_status"] in ("fixed", "still_present", "unverifiable")
    assert isinstance(restored["confidence"], float)
    assert isinstance(restored["verified_at"], str)


# ---------------------------------------------------------------------------
# test_verify_note_content
# Notes must reference the method name for observability
# ---------------------------------------------------------------------------

def test_verify_note_content():
    from backend.modules.pentest.ffv.engine import verify_finding
    from backend.modules.pentest.validation.base import ValidationResult

    named_result = ValidationResult(
        finding_id="test", validated=True, confidence=0.75, method="acao_inspection"
    )

    with patch(
        "backend.modules.pentest.validation.cors.CORSValidator.validate",
        new=AsyncMock(return_value=named_result),
    ):
        result = run(verify_finding(
            _finding("high", "CORS Misconfiguration"),
            "example.com",
        ))

    # Note must name the method so operators can trace what probe ran
    assert "acao_inspection" in result.note
    assert result.fix_status == "still_present"
