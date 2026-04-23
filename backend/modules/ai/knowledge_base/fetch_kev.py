"""
SentinelX — CISA KEV Catalog Fetcher
backend/modules/ai/knowledge_base/fetch_kev.py

Downloads the official CISA Known Exploited Vulnerabilities JSON feed and
saves a normalised, full-fidelity copy to kev_catalog.json in this directory.

Fields retained per entry (nothing trimmed that has signal):
    cve_id              — canonical CVE identifier (e.g. CVE-2021-44228)
    vulnerability_name  — human-readable name from CISA
    vendor              — vendor / project affected
    product             — specific product affected
    severity            — derived from cvssV3BaseScore (critical/high/medium/low/unknown)
    cvss_score          — raw CVSS v3 base score string (preserve for downstream sorting)
    date_added          — ISO date entry was added to KEV
    due_date            — CISA remediation due date
    description         — shortDescription from CISA feed
    required_action     — CISA mandated remediation action (high-value for RAG)
    notes               — additional CISA notes / references (when present)
    known_exploited     — always True; kept for schema clarity when merged with other sources

Usage (one-shot manual refresh):
    python -m backend.modules.ai.knowledge_base.fetch_kev
    -- or --
    python backend/modules/ai/knowledge_base/fetch_kev.py

Writes:
    backend/modules/ai/knowledge_base/kev_catalog.json
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinelx.fetch_kev")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_OUTPUT_PATH = Path(__file__).parent / "kev_catalog.json"


# ---------------------------------------------------------------------------
# CVSS → severity
# ---------------------------------------------------------------------------

def _cvss_to_severity(cvss_raw: Optional[str]) -> str:
    """Map a CVSS v3 base score string to a severity label."""
    if not cvss_raw:
        return "unknown"
    try:
        score = float(cvss_raw)
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
# Normalise one raw CISA JSON entry → dict
# ---------------------------------------------------------------------------

def _normalise(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Convert one raw CISA entry into a clean dict.
    Returns None if cveID is missing or empty (skip corrupt entries).
    All string fields are stripped; empty strings retained to preserve schema shape.
    """
    cve_id = raw.get("cveID", "").strip().upper()
    if not cve_id:
        logger.warning("KEV fetch: skipping entry with missing cveID: %s", raw)
        return None

    cvss_raw_val = raw.get("cvssV3BaseScore") or raw.get("cvssScore")
    cvss_str = str(cvss_raw_val).strip() if cvss_raw_val is not None else ""

    return {
        "cve_id": cve_id,
        "vulnerability_name": raw.get("vulnerabilityName", "").strip(),
        "vendor": raw.get("vendorProject", "").strip(),
        "product": raw.get("product", "").strip(),
        "severity": _cvss_to_severity(cvss_str if cvss_str else None),
        "cvss_score": cvss_str,                          # raw score — don't discard
        "date_added": raw.get("dateAdded", "").strip(),
        "due_date": raw.get("dueDate", "").strip(),
        "description": raw.get("shortDescription", "").strip(),
        "required_action": raw.get("requiredAction", "").strip(),  # CISA mandated action
        "notes": raw.get("notes", "").strip(),
        "known_exploited": True,
    }


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

def _fetch_raw() -> bytes:
    """
    Download KEV feed.  Tries 'requests' first (likely installed); falls back
    to stdlib urllib.request so this script works in minimal environments.
    """
    try:
        import requests  # type: ignore
        logger.info("KEV: fetching via requests from %s", KEV_URL)
        resp = requests.get(KEV_URL, timeout=30)
        resp.raise_for_status()
        return resp.content
    except ImportError:
        pass

    import urllib.request
    logger.info("KEV: fetching via urllib from %s", KEV_URL)
    with urllib.request.urlopen(KEV_URL, timeout=30) as resp:
        return resp.read()


def fetch_kev(output_path: Path = _OUTPUT_PATH) -> List[Dict[str, Any]]:
    """
    Fetch CISA KEV feed, normalise all entries, write to output_path.

    Returns the list of normalised entries (useful when called from other modules).
    Raises on unrecoverable network or JSON parse errors.
    """
    raw_bytes = _fetch_raw()
    data = json.loads(raw_bytes)

    raw_entries: List[Dict[str, Any]] = data.get("vulnerabilities", [])
    logger.info("KEV: raw feed contains %d entries", len(raw_entries))

    normalised: List[Dict[str, Any]] = []
    skipped = 0
    for item in raw_entries:
        entry = _normalise(item)
        if entry:
            normalised.append(entry)
        else:
            skipped += 1

    logger.info(
        "KEV: normalised %d entries (%d skipped) → writing %s",
        len(normalised),
        skipped,
        output_path,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(normalised, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("KEV: kev_catalog.json written (%d bytes)", output_path.stat().st_size)

    return normalised


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        entries = fetch_kev()
        print(f"[OK] kev_catalog.json written — {len(entries)} KEV entries saved to {_OUTPUT_PATH}")
        sys.exit(0)
    except Exception as exc:
        logger.error("KEV fetch failed: %s", exc, exc_info=True)
        print(f"[FAIL] {exc}", file=sys.stderr)
        sys.exit(1)
