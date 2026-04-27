"""
SentinelX — NVD CVE Summaries Fetcher
backend/modules/ai/knowledge_base/fetch_cve.py

Downloads CVEs from the NIST NVD REST API v2, filtered to:
    - Published in the last 3 years
    - CVSS v3 base score ≥ 7.0 (High and Critical only)

Saves to: backend/modules/ai/knowledge_base/cve_summaries.json

Fields retained per CVE (no over-trimming — all have RAG value):
    cve_id              — canonical CVE ID (e.g. CVE-2023-12345)
    description         — English description from NVD (primary RAG text)
    cvss_score          — CVSS v3.1 or v3.0 base score (float as string)
    severity            — critical | high (based on score)
    cvss_vector         — attack vector string (e.g. AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
    attack_vector       — extracted AV component (NETWORK | ADJACENT | LOCAL | PHYSICAL)
    attack_complexity   — extracted AC component (LOW | HIGH)
    privileges_required — extracted PR component (NONE | LOW | HIGH)
    user_interaction    — extracted UI component (NONE | REQUIRED)
    scope               — extracted S component (UNCHANGED | CHANGED)
    confidentiality     — extracted C component (NONE | LOW | HIGH)
    integrity           — extracted I component (NONE | LOW | HIGH)
    availability        — extracted A component (NONE | LOW | HIGH)
    cwe_ids             — list of CWE IDs (weakness types — key for OWASP mapping)
    cpe_affected        — list of CPE URIs (affected products — key for tech fingerprint match)
    published_date      — ISO datetime when CVE was published
    last_modified       — ISO datetime of last NVD update
    references          — list of {url, source, tags[]} — advisory/patch/PoC links
    vendor_comments     — vendor statements (when present)
    known_exploited     — True if also present in CISA KEV (enriched separately)

NVD API:
    https://services.nvd.nist.gov/rest/json/cves/2.0
    Rate limit: 5 requests / 30 s without API key; 50 requests / 30 s with key.
    Set env var NVD_API_KEY to use authenticated rate.

Usage:
    python -m backend.modules.ai.knowledge_base.fetch_cve
    -- or --
    python backend/modules/ai/knowledge_base/fetch_cve.py
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinelx.fetch_cve")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_OUTPUT_PATH = Path(__file__).parent / "cve_summaries.json"

_MIN_CVSS = 7.0          # High and Critical only
_YEARS_BACK = 3          # last 3 years
_PAGE_SIZE = 1000        # NVD API max per request (2000 causes 404)
_WINDOW_DAYS = 120       # NVD API max date-range window per request
_UNAUTHENTICATED_SLEEP = 6.0   # seconds between requests without API key
_AUTHENTICATED_SLEEP = 0.6     # seconds between requests with API key


# ---------------------------------------------------------------------------
# CVSS helpers
# ---------------------------------------------------------------------------

def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _parse_cvss_vector(vector: str) -> Dict[str, str]:
    """
    Parse a CVSS v3 vector string into component fields.
    Returns empty strings for missing components (graceful — vectors vary).
    Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    """
    mapping = {
        "AV": "attack_vector",
        "AC": "attack_complexity",
        "PR": "privileges_required",
        "UI": "user_interaction",
        "S": "scope",
        "C": "confidentiality",
        "I": "integrity",
        "A": "availability",
    }
    human_readable = {
        "N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL",
        "H": "HIGH", "M": "MEDIUM", "R": "REQUIRED", "U": "UNCHANGED",
        "C": "CHANGED", "NONE": "NONE",
    }
    result = {v: "" for v in mapping.values()}
    for part in vector.split("/"):
        if ":" not in part:
            continue
        key, val = part.split(":", 1)
        field = mapping.get(key)
        if field:
            result[field] = human_readable.get(val, val)
    return result


# ---------------------------------------------------------------------------
# NVD API normalisation
# ---------------------------------------------------------------------------

def _normalise_cve(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Convert one NVD API v2 CVE item into our schema.
    Returns None if the CVE doesn't meet the CVSS threshold.
    """
    cve = item.get("cve", {})
    cve_id = cve.get("id", "").strip()
    if not cve_id:
        return None

    # -- Description (English preferred) -----------------------------------
    descriptions = cve.get("descriptions", [])
    description = ""
    for d in descriptions:
        if d.get("lang") == "en":
            description = d.get("value", "").strip()
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "").strip()

    # -- CVSS v3 metrics ----------------------------------------------------
    metrics = cve.get("metrics", {})
    cvss_data: Dict[str, Any] = {}

    # Prefer v3.1 > v3.0 > v2
    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(version_key, [])
        if metric_list:
            # Take the primary source (type == "Primary") if available
            for m in metric_list:
                if m.get("type") == "Primary":
                    cvss_data = m.get("cvssData", {})
                    break
            if not cvss_data:
                cvss_data = metric_list[0].get("cvssData", {})
            break

    base_score = cvss_data.get("baseScore")
    if base_score is None:
        return None  # no score — skip

    try:
        score_float = float(base_score)
    except (ValueError, TypeError):
        return None

    if score_float < _MIN_CVSS:
        return None  # below threshold

    cvss_vector = cvss_data.get("vectorString", "")
    vector_components = _parse_cvss_vector(cvss_vector)

    # -- CWE IDs -----------------------------------------------------------
    weaknesses = cve.get("weaknesses", [])
    cwe_ids: List[str] = []
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "").strip()
            if val and val.upper() != "NVD-CWE-NOINFO" and val.upper() != "NVD-CWE-OTHER":
                cwe_ids.append(val)

    # -- CPE affected products ----------------------------------------------
    configurations = cve.get("configurations", [])
    cpe_affected: List[str] = []
    seen_cpes: set[str] = set()
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable", False):
                    uri = cpe_match.get("criteria", "").strip()
                    if uri and uri not in seen_cpes:
                        seen_cpes.add(uri)
                        cpe_affected.append(uri)

    # -- References --------------------------------------------------------
    raw_refs = cve.get("references", [])
    references: List[Dict[str, Any]] = []
    for ref in raw_refs:
        url = ref.get("url", "").strip()
        if url:
            references.append({
                "url": url,
                "source": ref.get("source", "").strip(),
                "tags": ref.get("tags", []),
            })

    # -- Vendor comments ---------------------------------------------------
    vendor_comments_raw = cve.get("vendorComments", [])
    vendor_comments: List[str] = []
    for vc in vendor_comments_raw:
        comment = vc.get("comment", "").strip()
        if comment:
            vendor_comments.append(comment)

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": str(base_score),
        "severity": _cvss_to_severity(score_float),
        "cvss_vector": cvss_vector,
        **vector_components,                 # attack_vector, complexity, etc.
        "cwe_ids": cwe_ids,
        "cpe_affected": cpe_affected[:50],   # cap at 50 CPEs to avoid huge entries
        "published_date": cve.get("published", "").strip(),
        "last_modified": cve.get("lastModified", "").strip(),
        "references": references[:20],        # cap at 20 refs — advisories/patches
        "vendor_comments": vendor_comments,
        "known_exploited": False,             # enriched separately via KEV cross-ref
    }


# ---------------------------------------------------------------------------
# NVD paginated fetch
# ---------------------------------------------------------------------------

def _build_headers(api_key: Optional[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    return headers


def _fetch_page(
    session: Any,
    start_index: int,
    pub_start: str,
    pub_end: str,
    api_key: Optional[str],
    retries: int = 3,
) -> Dict[str, Any]:
    """
    Fetch one page from NVD API v2 with retry + exponential backoff.

    Constraints:
      - Max date range: 120 days per request.
      - Max resultsPerPage: 1000 (2000 causes 404).
      - Timestamp format: YYYY-MM-DDTHH:MM:SS.000Z
      - cvssV3Severity cannot be combined with date filters (causes 404).
        Filter by CVSS score client-side after fetch.
    """
    import time as _time
    params = {
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
        "resultsPerPage": _PAGE_SIZE,
        "startIndex": start_index,
    }
    headers = _build_headers(api_key)
    last_exc: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        try:
            resp = session.get(NVD_API_BASE, params=params, headers=headers, timeout=90)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            last_exc = exc
            wait = 10 * attempt
            logger.warning(
                "CVE: page fetch attempt %d/%d failed (%s) — retrying in %ds",
                attempt, retries, exc, wait,
            )
            _time.sleep(wait)
    raise last_exc  # type: ignore[misc]


def fetch_cve(
    output_path: Path = _OUTPUT_PATH,
    years_back: int = _YEARS_BACK,
    min_cvss: float = _MIN_CVSS,
    api_key: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Fetch NVD CVEs for the last `years_back` years with CVSS ≥ `min_cvss`.
    Writes normalised results to output_path.  Returns the entries list.

    Note: NVD API paginates in pages of up to 2000 results.
    Without an API key, requests are rate-limited to 5 req / 30 s.
    Set env var NVD_API_KEY to use authenticated rate (50 req / 30 s).
    """
    try:
        import requests  # type: ignore
    except ImportError:
        raise RuntimeError(
            "The 'requests' library is required to fetch CVE data. "
            "Install it: pip install requests"
        )

    if api_key is None:
        api_key = os.environ.get("NVD_API_KEY")

    sleep_secs = _AUTHENTICATED_SLEEP if api_key else _UNAUTHENTICATED_SLEEP

    now = datetime.now(tz=timezone.utc)
    start_dt = now - timedelta(days=365 * years_back)

    # NVD API v2: max 120-day window per request; timestamp must end with Z
    # Build list of (window_start, window_end) 120-day chunks
    windows: List[tuple] = []
    chunk_start = start_dt
    while chunk_start < now:
        chunk_end = min(chunk_start + timedelta(days=_WINDOW_DAYS), now)
        windows.append((
            chunk_start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            chunk_end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        ))
        chunk_start = chunk_end

    logger.info(
        "CVE: fetching NVD (CVSS >= %.1f, last %d years, %d x 120-day windows, page_size=%d)",
        min_cvss,
        years_back,
        len(windows),
        _PAGE_SIZE,
    )

    session = requests.Session()
    all_entries: List[Dict[str, Any]] = []

    for win_idx, (pub_start, pub_end) in enumerate(windows, 1):
        logger.info(
            "CVE: window %d/%d  %s → %s",
            win_idx, len(windows), pub_start[:10], pub_end[:10],
        )
        start_index = 0
        total_results = None
        page_num = 0

        while True:
            page_num += 1
            logger.info(
                "CVE: page %d (startIndex=%d, window_total=%s)",
                page_num,
                start_index,
                total_results if total_results is not None else "?",
            )

            try:
                data = _fetch_page(session, start_index, pub_start, pub_end, api_key)
            except Exception as exc:
                logger.error(
                    "CVE: NVD request failed at window %d startIndex=%d: %s",
                    win_idx, start_index, exc,
                )
                raise

            if total_results is None:
                total_results = data.get("totalResults", 0)
                logger.info(
                    "CVE: window %d reports %d total results",
                    win_idx, total_results,
                )

            vulnerabilities = data.get("vulnerabilities", [])
            logger.info(
                "CVE: window %d page %d returned %d raw items",
                win_idx, page_num, len(vulnerabilities),
            )

            for item in vulnerabilities:
                entry = _normalise_cve(item)
                if entry:
                    all_entries.append(entry)

            start_index += len(vulnerabilities)

            if not vulnerabilities or start_index >= total_results:
                break

            logger.debug("CVE: sleeping %.1fs before next page", sleep_secs)
            time.sleep(sleep_secs)

        # Sleep between windows too
        if win_idx < len(windows):
            time.sleep(sleep_secs)

    logger.info(
        "CVE: done — %d entries pass CVSS >= %.1f threshold across all windows",
        len(all_entries),
        min_cvss,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(all_entries, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.info(
        "CVE: cve_summaries.json written — %d entries, %d bytes",
        len(all_entries),
        output_path.stat().st_size,
    )

    return all_entries


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        entries = fetch_cve()
        print(
            f"[OK] cve_summaries.json written — {len(entries)} CVEs (CVSS ≥ {_MIN_CVSS}) "
            f"saved to {_OUTPUT_PATH}"
        )
        sys.exit(0)
    except Exception as exc:
        logger.error("CVE fetch failed: %s", exc, exc_info=True)
        print(f"[FAIL] {exc}", file=sys.stderr)
        sys.exit(1)
