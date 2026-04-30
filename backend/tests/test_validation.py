"""
Tests for Phase 2 validation layer.
All tests run with MOCK_MODE=True — no real HTTP requests.
"""
from __future__ import annotations

import asyncio
import os
import pytest

os.environ.setdefault("MOCK_MODE", "true")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _finding(severity: str, title: str, **kwargs) -> dict:
    return {"severity": severity, "title": title, "description": "test", **kwargs}


# ---------------------------------------------------------------------------
# Individual validators in MOCK_MODE
# ---------------------------------------------------------------------------

def test_xss_validator_mock():
    from backend.modules.pentest.validation.xss import XSSValidator
    v = XSSValidator()
    result = run(v.validate(_finding("high", "Reflected XSS"), "example.com"))
    assert result.validated is True
    assert result.confidence == pytest.approx(0.85)
    assert "mock" in result.method


def test_sqli_validator_mock():
    from backend.modules.pentest.validation.sqli import SQLiValidator
    v = SQLiValidator()
    result = run(v.validate(_finding("critical", "SQL Injection"), "example.com"))
    assert result.validated is True
    assert result.confidence == pytest.approx(0.80)
    assert "mock" in result.method


def test_idor_validator_mock():
    from backend.modules.pentest.validation.idor import IDORValidator
    v = IDORValidator()
    result = run(v.validate(_finding("high", "IDOR"), "example.com"))
    assert result.validated is False
    assert result.confidence == pytest.approx(0.0)
    assert "mock" in result.method


def test_cors_validator_mock():
    from backend.modules.pentest.validation.cors import CORSValidator
    v = CORSValidator()
    result = run(v.validate(_finding("high", "CORS Misconfiguration"), "example.com"))
    assert result.validated is True
    assert result.confidence == pytest.approx(0.90)
    assert "mock" in result.method


# ---------------------------------------------------------------------------
# run_validation with mixed finding types
# ---------------------------------------------------------------------------

def test_run_validation_mixed():
    from backend.modules.pentest.validation.engine import run_validation

    findings = [
        _finding("critical", "SQL Injection in login form"),
        _finding("high", "Reflected XSS on search page"),
        _finding("medium", "Outdated library"),          # skipped — not critical/high
        _finding("low", "Missing rate limiting"),         # skipped
        _finding("high", "CORS Misconfiguration"),
        _finding("info", "Open port 80"),                 # skipped
    ]

    result = run(run_validation(findings, "example.com"))

    assert len(result) == 6  # all findings returned

    sqli = next(f for f in result if "sql" in f["title"].lower())
    assert sqli["validated"] is True
    assert "confidence" in sqli
    assert "validation_method" in sqli

    xss = next(f for f in result if "xss" in f["title"].lower())
    assert xss["validated"] is True

    cors = next(f for f in result if "cors" in f["title"].lower())
    assert cors["validated"] is True

    medium = next(f for f in result if f["severity"] == "medium")
    assert "validated" not in medium  # not enriched — severity below threshold

    low = next(f for f in result if f["severity"] == "low")
    assert "validated" not in low


# ---------------------------------------------------------------------------
# Error path: validator raises → finding survives with validated=False
# ---------------------------------------------------------------------------

def test_run_validation_error_path(monkeypatch):
    from backend.modules.pentest.validation import engine
    from backend.modules.pentest.validation.xss import XSSValidator

    async def _exploding_validate(self, finding, target):
        raise RuntimeError("simulated validator crash")

    monkeypatch.setattr(XSSValidator, "validate", _exploding_validate)

    findings = [_finding("high", "Reflected XSS on search")]
    result = run(engine.run_validation(findings, "example.com"))

    assert len(result) == 1
    assert result[0]["validated"] is False
    assert result[0]["confidence"] == pytest.approx(0.0)
    assert result[0]["validation_method"] == "error"
    # Original fields preserved
    assert result[0]["title"] == "Reflected XSS on search"


# ---------------------------------------------------------------------------
# Only critical/high findings are validated
# ---------------------------------------------------------------------------

def test_only_critical_high_validated():
    from backend.modules.pentest.validation.engine import run_validation

    findings = [
        _finding("critical", "SQL Injection"),
        _finding("high", "XSS"),
        _finding("medium", "Info disclosure"),
        _finding("low", "Weak cipher"),
        _finding("info", "Banner grabbing"),
    ]
    result = run(run_validation(findings, "example.com"))

    validated_titles = {f["title"] for f in result if "validated" in f}
    assert "SQL Injection" in validated_titles
    assert "XSS" in validated_titles
    assert "Info disclosure" not in validated_titles
    assert "Weak cipher" not in validated_titles
    assert "Banner grabbing" not in validated_titles


# ---------------------------------------------------------------------------
# Findings with unrecognised titles pass through unmodified
# ---------------------------------------------------------------------------

def test_unrecognised_title_passthrough():
    from backend.modules.pentest.validation.engine import run_validation

    findings = [_finding("critical", "Some unknown vulnerability type")]
    result = run(run_validation(findings, "example.com"))
    assert len(result) == 1
    assert "validated" not in result[0]
