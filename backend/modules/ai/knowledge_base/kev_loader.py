"""
SentinelX — CISA KEV Loader
backend/modules/ai/knowledge_base/kev_loader.py

Fetches the CISA Known Exploited Vulnerabilities (KEV) catalog and exposes it
for injection into RAG prompts.

Public surface:
    async def load_kev_entries() -> list[KEVEntry]
        Fetch fresh feed (or serve from valid cache).  Writes cache file on success.
        Falls back to stale cache on network failure.  Returns [] with warning if
        neither succeeds.

    def get_cached_kev() -> list[KEVEntry]
        Synchronous — reads the cache file only, no network.  Returns [] if missing.

    def search_kev(cve_id: str, entries: list[KEVEntry]) -> KEVEntry | None
        Case-insensitive exact match on cve_id.

Cache: backend/modules/ai/knowledge_base/kev_cache.json
TTL  : 24 hours  (checked via file mtime)
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("sentinelx.kev")

_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CACHE_PATH = Path(__file__).parent / "kev_cache.json"
_CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class KEVEntry(BaseModel):
    """One entry from the CISA Known Exploited Vulnerabilities catalog."""

    cve_id: str = Field(..., description="CVE identifier, e.g. CVE-2021-44228")
    severity: str = Field(
        "unknown",
        description="Severity derived from CVSS score, or 'unknown' when absent",
    )
    known_exploited: bool = Field(
        True,
        description="Always True for KEV entries — present in schema for clarity",
    )
    description: str = Field("", description="Short vulnerability description")
    vendor_project: str = Field("", description="Affected vendor or project name")
    product: str = Field("", description="Affected product name")
    date_added: str = Field("", description="ISO date the entry was added to KEV")

    @field_validator("cve_id")
    @classmethod
    def normalise_cve_id(cls, v: str) -> str:
        return v.strip().upper()


# ---------------------------------------------------------------------------
# CVSS → severity helper
# ---------------------------------------------------------------------------

def _cvss_to_severity(cvss_v3: Optional[str]) -> str:
    """
    Map a CVSS v3 base score string to a human severity label.
    Returns 'unknown' when the score is absent or unparseable.
    """
    if not cvss_v3:
        return "unknown"
    try:
        score = float(cvss_v3)
    except (ValueError, TypeError):
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Normalise raw CISA JSON → KEVEntry
# ---------------------------------------------------------------------------

def _normalise_entry(raw: dict) -> Optional[KEVEntry]:
    """
    Convert one raw CISA KEV catalog entry into a KEVEntry.
    Returns None (and logs a warning) if the entry lacks a cve_id.
    """
    cve_id = raw.get("cveID", "").strip()
    if not cve_id:
        logger.warning("KEV: skipping entry with missing cveID: %s", raw)
        return None

    # CISA feed may carry cvssV3BaseScore as a string or number
    cvss_raw = raw.get("cvssV3BaseScore") or raw.get("cvssScore")
    severity = _cvss_to_severity(str(cvss_raw) if cvss_raw is not None else None)

    return KEVEntry(
        cve_id=cve_id,
        severity=severity,
        known_exploited=True,
        description=raw.get("shortDescription", "").strip(),
        vendor_project=raw.get("vendorProject", "").strip(),
        product=raw.get("product", "").strip(),
        date_added=raw.get("dateAdded", "").strip(),
    )


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _is_cache_fresh() -> bool:
    """Return True if the cache file exists and is younger than the TTL."""
    if not _CACHE_PATH.exists():
        return False
    age = time.time() - _CACHE_PATH.stat().st_mtime
    return age < _CACHE_TTL_SECONDS


def _write_cache(entries: list[KEVEntry]) -> None:
    """Serialise entries to the cache file."""
    try:
        payload = [e.model_dump() for e in entries]
        _CACHE_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info("KEV: Cache written — %d entries → %s", len(entries), _CACHE_PATH)
    except OSError as exc:
        logger.error("KEV: Failed to write cache file: %s", exc)


def _read_cache() -> list[KEVEntry]:
    """Load entries from the cache file. Returns [] on any error."""
    if not _CACHE_PATH.exists():
        return []
    try:
        raw_list = json.loads(_CACHE_PATH.read_text(encoding="utf-8"))
        entries = []
        for item in raw_list:
            try:
                entries.append(KEVEntry(**item))
            except Exception as exc:
                logger.debug("KEV: Skipping malformed cache entry: %s", exc)
        logger.info("KEV: Loaded %d entries from cache (%s)", len(entries), _CACHE_PATH)
        return entries
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("KEV: Failed to read cache: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Fetch from CISA
# ---------------------------------------------------------------------------

async def _fetch_kev_feed() -> list[KEVEntry]:
    """
    Async fetch of the CISA KEV JSON feed.
    Prefers 'httpx' (async); falls back to 'urllib.request' in a thread executor
    so the event loop is never blocked.
    """
    import asyncio

    loop = asyncio.get_event_loop()

    async def _fetch_httpx() -> bytes:
        import httpx  # type: ignore
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(_FEED_URL)
            response.raise_for_status()
            return response.content

    async def _fetch_urllib() -> bytes:
        import urllib.request
        def _blocking_get() -> bytes:
            with urllib.request.urlopen(_FEED_URL, timeout=30) as resp:
                return resp.read()
        return await loop.run_in_executor(None, _blocking_get)

    # Try httpx first (non-blocking); fall back to urllib
    try:
        content = await _fetch_httpx()
    except ImportError:
        logger.debug("KEV: httpx not installed, falling back to urllib")
        content = await _fetch_urllib()

    data = json.loads(content)
    raw_entries = data.get("vulnerabilities", [])
    logger.info("KEV: Feed returned %d raw entries", len(raw_entries))

    entries: list[KEVEntry] = []
    for raw in raw_entries:
        entry = _normalise_entry(raw)
        if entry:
            entries.append(entry)

    logger.info("KEV: Normalised %d valid entries", len(entries))
    return entries


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

async def load_kev_entries() -> list[KEVEntry]:
    """
    Return the current KEV catalog as a list of KEVEntry objects.

    Strategy:
      1. If cache is fresh (< 24 h), return cached data.
      2. Otherwise fetch from CISA; write cache on success.
      3. On network/parse failure, fall back to stale cache with a warning.
      4. If no cache exists either, log a warning and return [].
    """
    if _is_cache_fresh():
        logger.info("KEV: Cache is fresh — skipping network fetch")
        return _read_cache()

    logger.info("KEV: Fetching fresh data from CISA feed: %s", _FEED_URL)
    try:
        entries = await _fetch_kev_feed()
        _write_cache(entries)
        return entries
    except Exception as exc:
        logger.error("KEV: Feed fetch failed: %s", exc)
        if _CACHE_PATH.exists():
            logger.warning("KEV: Using stale cache as fallback")
            return _read_cache()
        logger.warning("KEV: No cache available — returning empty KEV list")
        return []


def get_cached_kev() -> list[KEVEntry]:
    """
    Synchronous helper — reads only from the local cache file; never touches
    the network.  Intended for use from synchronous contexts (e.g. RAG engine
    startup).  Returns [] if no cache exists.
    """
    return _read_cache()


def search_kev(cve_id: str, entries: list[KEVEntry]) -> Optional[KEVEntry]:
    """
    Return the KEVEntry whose cve_id matches `cve_id` (case-insensitive),
    or None if not found.
    """
    needle = cve_id.strip().upper()
    for entry in entries:
        if entry.cve_id == needle:
            return entry
    return None
