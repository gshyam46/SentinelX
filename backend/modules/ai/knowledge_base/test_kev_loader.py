"""
Tests for backend/modules/ai/knowledge_base/kev_loader.py

All HTTP calls are mocked — no real network traffic.
Run with:
    backend\\venv\\Scripts\\python.exe -m pytest backend/modules/ai/knowledge_base/test_kev_loader.py -v
"""

from __future__ import annotations

import importlib.util as _ilu
import json
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Load kev_loader directly from its file path.
#
# We do NOT do `from backend.modules.ai.knowledge_base.kev_loader import ...`
# because backend/modules/ai/__init__.py eagerly imports analyst_agent and
# rag_engine which in turn need LiteLLM/DB config that is absent in CI.
# Loading via importlib lets us test just this file in isolation.
# ---------------------------------------------------------------------------

_MOD_PATH = Path(__file__).parent / "kev_loader.py"
_spec = _ilu.spec_from_file_location("kev_loader_isolated", _MOD_PATH)
_kev_mod = _ilu.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_kev_mod)  # type: ignore[union-attr]

# Re-export names used in tests
KEVEntry = _kev_mod.KEVEntry
_cvss_to_severity = _kev_mod._cvss_to_severity
_normalise_entry = _kev_mod._normalise_entry
_read_cache = _kev_mod._read_cache
_write_cache = _kev_mod._write_cache
get_cached_kev = _kev_mod.get_cached_kev
load_kev_entries = _kev_mod.load_kev_entries
search_kev = _kev_mod.search_kev


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_RAW_ENTRY: dict[str, Any] = {
    "cveID": "CVE-2021-44228",
    "vendorProject": "Apache",
    "product": "Log4j",
    "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
    "dateAdded": "2021-12-10",
    "shortDescription": "Apache Log4j2 contains a remote code execution vulnerability.",
    "requiredAction": "Apply updates per vendor instructions.",
    "dueDate": "2021-12-24",
    "cvssV3BaseScore": "10.0",
}

SAMPLE_ENTRY = KEVEntry(
    cve_id="CVE-2021-44228",
    severity="critical",
    known_exploited=True,
    description="Apache Log4j2 contains a remote code execution vulnerability.",
    vendor_project="Apache",
    product="Log4j",
    date_added="2021-12-10",
)

SAMPLE_FEED_JSON: dict[str, Any] = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "vulnerabilities": [SAMPLE_RAW_ENTRY],
}


@pytest.fixture(autouse=True)
def _isolate_cache(tmp_path, monkeypatch):
    """
    Redirect _CACHE_PATH to a temp file for every test so tests never
    read/write the real cache on disk.  The monkeypatch targets the module
    object we loaded via importlib.
    """
    fake_cache = tmp_path / "kev_cache_test.json"
    monkeypatch.setattr(_kev_mod, "_CACHE_PATH", fake_cache)
    yield fake_cache


# ---------------------------------------------------------------------------
# 1. KEVEntry schema validation
# ---------------------------------------------------------------------------


class TestKEVEntrySchema:
    def test_valid_entry_roundtrip(self):
        entry = KEVEntry(
            cve_id="CVE-2023-1234",
            severity="high",
            known_exploited=True,
            description="Test vuln",
            vendor_project="Vendor",
            product="Widget",
            date_added="2023-06-01",
        )
        assert entry.cve_id == "CVE-2023-1234"
        assert entry.known_exploited is True

    def test_cve_id_normalised_to_uppercase(self):
        entry = KEVEntry(cve_id="cve-2021-44228")
        assert entry.cve_id == "CVE-2021-44228"

    def test_cve_id_whitespace_stripped(self):
        entry = KEVEntry(cve_id="  CVE-2021-44228  ")
        assert entry.cve_id == "CVE-2021-44228"

    def test_defaults_applied(self):
        entry = KEVEntry(cve_id="CVE-2020-0001")
        assert entry.severity == "unknown"
        assert entry.known_exploited is True
        assert entry.description == ""
        assert entry.vendor_project == ""
        assert entry.product == ""
        assert entry.date_added == ""

    def test_known_exploited_always_true(self):
        entry = KEVEntry(cve_id="CVE-2020-0001", known_exploited=True)
        assert entry.known_exploited is True

    def test_model_dump_roundtrip(self):
        entry = SAMPLE_ENTRY
        dumped = entry.model_dump()
        restored = KEVEntry(**dumped)
        assert restored == entry

    def test_cvss_to_severity_critical(self):
        assert _cvss_to_severity("10.0") == "critical"
        assert _cvss_to_severity("9.0") == "critical"

    def test_cvss_to_severity_high(self):
        assert _cvss_to_severity("7.5") == "high"

    def test_cvss_to_severity_medium(self):
        assert _cvss_to_severity("5.0") == "medium"

    def test_cvss_to_severity_low(self):
        assert _cvss_to_severity("2.0") == "low"

    def test_cvss_to_severity_unknown_on_none(self):
        assert _cvss_to_severity(None) == "unknown"

    def test_cvss_to_severity_unknown_on_garbage(self):
        assert _cvss_to_severity("n/a") == "unknown"

    def test_normalise_entry_valid(self):
        entry = _normalise_entry(SAMPLE_RAW_ENTRY)
        assert entry is not None
        assert entry.cve_id == "CVE-2021-44228"
        assert entry.severity == "critical"
        assert entry.vendor_project == "Apache"
        assert entry.product == "Log4j"

    def test_normalise_entry_missing_cve_id(self):
        bad = {**SAMPLE_RAW_ENTRY, "cveID": ""}
        assert _normalise_entry(bad) is None

    def test_normalise_entry_no_cvss_gives_unknown(self):
        raw = {**SAMPLE_RAW_ENTRY}
        raw.pop("cvssV3BaseScore", None)
        raw.pop("cvssScore", None)
        entry = _normalise_entry(raw)
        assert entry is not None
        assert entry.severity == "unknown"


# ---------------------------------------------------------------------------
# 2. Cache file write / read round-trip
# ---------------------------------------------------------------------------


class TestCacheRoundTrip:
    def test_write_then_read(self, _isolate_cache):
        entries = [SAMPLE_ENTRY]
        _write_cache(entries)
        assert _isolate_cache.exists()
        loaded = _read_cache()
        assert len(loaded) == 1
        assert loaded[0].cve_id == SAMPLE_ENTRY.cve_id
        assert loaded[0].severity == SAMPLE_ENTRY.severity

    def test_read_empty_when_no_cache(self, _isolate_cache):
        assert not _isolate_cache.exists()
        result = _read_cache()
        assert result == []

    def test_write_multiple_entries(self, _isolate_cache):
        entries = [
            KEVEntry(cve_id="CVE-2021-44228", severity="critical"),
            KEVEntry(cve_id="CVE-2022-0001", severity="high"),
        ]
        _write_cache(entries)
        loaded = _read_cache()
        ids = {e.cve_id for e in loaded}
        assert "CVE-2021-44228" in ids
        assert "CVE-2022-0001" in ids

    def test_read_corrupt_cache_returns_empty(self, _isolate_cache):
        _isolate_cache.write_text("NOT VALID JSON", encoding="utf-8")
        result = _read_cache()
        assert result == []

    def test_get_cached_kev_returns_empty_when_no_cache(self, _isolate_cache):
        assert get_cached_kev() == []

    def test_get_cached_kev_reads_written_cache(self, _isolate_cache):
        _write_cache([SAMPLE_ENTRY])
        result = get_cached_kev()
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2021-44228"


# ---------------------------------------------------------------------------
# 3. search_kev
# ---------------------------------------------------------------------------


class TestSearchKev:
    def test_finds_known_cve(self):
        entries = [SAMPLE_ENTRY]
        result = search_kev("CVE-2021-44228", entries)
        assert result is not None
        assert result.cve_id == "CVE-2021-44228"

    def test_returns_none_for_unknown_cve(self):
        entries = [SAMPLE_ENTRY]
        result = search_kev("CVE-9999-9999", entries)
        assert result is None

    def test_case_insensitive_match(self):
        entries = [SAMPLE_ENTRY]
        result = search_kev("cve-2021-44228", entries)
        assert result is not None
        assert result.cve_id == "CVE-2021-44228"

    def test_whitespace_trimmed_in_query(self):
        entries = [SAMPLE_ENTRY]
        result = search_kev("  CVE-2021-44228  ", entries)
        assert result is not None

    def test_empty_list_returns_none(self):
        assert search_kev("CVE-2021-44228", []) is None

    def test_multiple_entries_correct_match(self):
        entries = [
            KEVEntry(cve_id="CVE-2022-0001", severity="high"),
            SAMPLE_ENTRY,
            KEVEntry(cve_id="CVE-2023-9999", severity="medium"),
        ]
        result = search_kev("CVE-2021-44228", entries)
        assert result is not None
        assert result.cve_id == "CVE-2021-44228"


# ---------------------------------------------------------------------------
# 4. load_kev_entries — network failure falls back to stale cache
# ---------------------------------------------------------------------------


class TestLoadKevEntriesNetworkFailure:
    @pytest.mark.asyncio
    async def test_falls_back_to_stale_cache_on_network_error(self, _isolate_cache):
        """
        When the network fetch fails and a stale cache exists, load_kev_entries
        must return the stale cached data and not raise.
        """
        # Write stale data to the (isolated) cache
        _write_cache([SAMPLE_ENTRY])

        # Patch directly on the loaded module object
        _kev_mod._is_cache_fresh = lambda: False
        _kev_mod._fetch_kev_feed = AsyncMock(
            side_effect=ConnectionError("network unavailable")
        )
        try:
            result = await load_kev_entries()
        finally:
            # Restore originals from module source
            del _kev_mod._is_cache_fresh
            del _kev_mod._fetch_kev_feed

        assert len(result) == 1
        assert result[0].cve_id == "CVE-2021-44228"

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_cache_and_network_fails(
        self, _isolate_cache
    ):
        """
        When the network fetch fails AND no cache exists, load_kev_entries
        must return [] with a warning rather than raising.
        """
        _kev_mod._is_cache_fresh = lambda: False
        _kev_mod._fetch_kev_feed = AsyncMock(
            side_effect=ConnectionError("network unavailable")
        )
        try:
            result = await load_kev_entries()
        finally:
            del _kev_mod._is_cache_fresh
            del _kev_mod._fetch_kev_feed

        assert result == []


# ---------------------------------------------------------------------------
# 5. load_kev_entries — returns list when cache is fresh
# ---------------------------------------------------------------------------


class TestLoadKevEntriesFreshCache:
    @pytest.mark.asyncio
    async def test_returns_cached_entries_when_cache_is_fresh(self, _isolate_cache):
        """
        When the cache is fresh, load_kev_entries must return cached data
        without making any network call.
        """
        _write_cache([SAMPLE_ENTRY])

        fetch_mock = AsyncMock(side_effect=AssertionError("should not fetch"))
        _kev_mod._is_cache_fresh = lambda: True
        _kev_mod._fetch_kev_feed = fetch_mock
        try:
            result = await load_kev_entries()
        finally:
            del _kev_mod._is_cache_fresh
            del _kev_mod._fetch_kev_feed

        assert len(result) == 1
        assert result[0].cve_id == "CVE-2021-44228"

    @pytest.mark.asyncio
    async def test_fetches_and_writes_cache_when_stale(self, _isolate_cache):
        """
        When cache is stale, load_kev_entries fetches fresh data and writes
        the updated cache.
        """
        fresh_entry = KEVEntry(
            cve_id="CVE-2023-5678",
            severity="high",
            known_exploited=True,
            description="Fresh entry",
            vendor_project="Acme",
            product="Widget",
            date_added="2023-01-01",
        )

        _kev_mod._is_cache_fresh = lambda: False
        _kev_mod._fetch_kev_feed = AsyncMock(return_value=[fresh_entry])
        try:
            result = await load_kev_entries()
        finally:
            del _kev_mod._is_cache_fresh
            del _kev_mod._fetch_kev_feed

        assert len(result) == 1
        assert result[0].cve_id == "CVE-2023-5678"

        # Cache must have been written to the isolated tmp path
        assert _isolate_cache.exists()
        on_disk = _read_cache()
        assert len(on_disk) == 1
        assert on_disk[0].cve_id == "CVE-2023-5678"
