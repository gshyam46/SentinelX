#!/usr/bin/env python3
"""
SentinelX E2E Smoke Test
Validates the full pipeline end-to-end using real tools.

Run on the target system (Linux, real binaries) — not Windows dev.
Exit 0 on success, exit 1 on any assertion failure.

Usage:
    python backend/tests/e2e_smoke.py

Environment variables:
    BASE_URL            API root          default: http://localhost:8000
    SMOKE_EMAIL         account email     default: smoke@sentinelx.test
    SMOKE_PASSWORD      account password  default: SmokeTest1!
    DEV_BYPASS_SECRET   X-Dev-Bypass header value for pro-tier access (required for active scan)
    POLL_TIMEOUT        scan poll ceiling default: 300 (seconds)
"""

import os
import sys
import time
import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BASE_URL        = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
SMOKE_EMAIL     = os.environ.get("SMOKE_EMAIL", "smoke@sentinelx.test")
SMOKE_PASSWORD  = os.environ.get("SMOKE_PASSWORD", "SmokeTest1!")
BYPASS_SECRET   = os.environ.get("DEV_BYPASS_SECRET", "")
POLL_TIMEOUT    = int(os.environ.get("POLL_TIMEOUT", "300"))
POLL_INTERVAL   = 5

TARGET    = "scanme.nmap.org"
SCAN_TYPE = "active"
SCAN_MODE = "deterministic"

# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

http = requests.Session()
http.headers["Content-Type"] = "application/json"
if BYPASS_SECRET:
    http.headers["X-Dev-Bypass"] = BYPASS_SECRET

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fail(step: str, reason: str) -> None:
    print(f"\nFAIL [{step}]: {reason}", file=sys.stderr)
    sys.exit(1)


def check(step: str, condition: bool, reason: str) -> None:
    if not condition:
        fail(step, reason)


def _url(path: str) -> str:
    return f"{BASE_URL}{path}"


def _get(path: str) -> requests.Response:
    return http.get(_url(path))


def _post(path: str, body: dict) -> requests.Response:
    return http.post(_url(path), json=body)


# ---------------------------------------------------------------------------
# Step 1 — Register
# ---------------------------------------------------------------------------

print("[1/7] Register...")
r = _post("/api/v1/auth/register", {
    "email": SMOKE_EMAIL,
    "password": SMOKE_PASSWORD,
    "full_name": "Smoke Test",
})
if r.status_code not in (201, 409):
    fail("register", f"HTTP {r.status_code}: {r.text[:300]}")
print(f"      {'registered' if r.status_code == 201 else 'already exists, will login'}")

# ---------------------------------------------------------------------------
# Step 2 — Login
# ---------------------------------------------------------------------------

print("[2/7] Login...")
r = _post("/api/v1/auth/login", {
    "email": SMOKE_EMAIL,
    "password": SMOKE_PASSWORD,
})
check("login", r.status_code == 200, f"HTTP {r.status_code}: {r.text[:300]}")
http.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
print("      ok — JWT stored")

# ---------------------------------------------------------------------------
# Step 3 — Health check
# ---------------------------------------------------------------------------

print("[3/7] Health check...")
r = _get("/api/v1/health")
check("health", r.status_code == 200, f"HTTP {r.status_code}: {r.text[:300]}")
tools = r.json().get("tools", {})
check("health.nmap",    tools.get("nmap") is not None,      "nmap not found — install nmap or set NMAP_PATH")
check("health.nuclei",  tools.get("nuclei") is not None,    "nuclei not found — install nuclei or set NUCLEI_PATH")
check("health.zap",     tools.get("zap") == "reachable",    "ZAP unreachable — verify Docker service at :8090")
print(f"      nmap={tools['nmap']}  nuclei={tools['nuclei']}  zap={tools['zap']}")

# ---------------------------------------------------------------------------
# Step 4 — Start scan
# ---------------------------------------------------------------------------

print(f"[4/7] Start scan ({SCAN_TYPE}/{SCAN_MODE}) on {TARGET}...")
r = _post("/api/v1/scans", {
    "domain": TARGET,
    "scan_type": SCAN_TYPE,
    "scan_mode": SCAN_MODE,
    "authorization_confirmed": True,
})
if r.status_code == 403:
    fail(
        "create_scan",
        "403 Forbidden — active scan requires a pro account. "
        "Set DEV_BYPASS_SECRET env var (and DEV_BYPASS_TIER=true in .env) or use a pro account.",
    )
check("create_scan", r.status_code == 201, f"HTTP {r.status_code}: {r.text[:300]}")
scan_id = r.json()["id"]
print(f"      scan_id = {scan_id}")

# ---------------------------------------------------------------------------
# Step 5 — Poll until complete
# ---------------------------------------------------------------------------

print(f"[5/7] Polling scan (timeout={POLL_TIMEOUT}s)...")
deadline = time.time() + POLL_TIMEOUT
scan_data: dict = {}

while time.time() < deadline:
    r = _get(f"/api/v1/scans/{scan_id}")
    check("poll", r.status_code == 200, f"HTTP {r.status_code}: {r.text[:300]}")
    scan_data = r.json()
    scan_status = scan_data.get("status", "unknown")
    progress    = scan_data.get("progress", 0)
    step_label  = scan_data.get("current_step") or ""
    print(f"      {scan_status} {progress}% {step_label}")

    if scan_status == "complete":
        break
    if scan_status == "failed":
        fail("poll", f"Scan failed: {scan_data.get('error_message') or 'no error_message'}")
    time.sleep(POLL_INTERVAL)
else:
    fail("poll", f"Timed out after {POLL_TIMEOUT}s — last status: {scan_data.get('status', 'unknown')}")

# ---------------------------------------------------------------------------
# Step 6 — Validate results
# ---------------------------------------------------------------------------

print("[6/7] Validate results...")
results      = scan_data.get("results") or {}
findings     = results.get("findings") or results.get("scan_findings") or []
exec_graph   = scan_data.get("execution_graph")
ai_report    = results.get("ai_report") or {}
exec_summary = ai_report.get("executive_summary", "")

check("results.findings_count",    len(findings) > 0,       f"findings is empty — tools may have all failed")
check("results.severity_present",  any(f.get("severity") for f in findings),
                                                              "no finding has a severity field")
check("results.execution_graph",   exec_graph is not None,  "execution_graph missing from response")
check("results.ai_report",         bool(ai_report),         "ai_report missing — analyst task may not have run")
check("results.executive_summary", bool(exec_summary),      "executive_summary empty in ai_report")

print(f"      findings={len(findings)}  severities={sorted({f.get('severity') for f in findings} - {None})}")
print(f"      execution_graph=present  ai_report=present")

# ---------------------------------------------------------------------------
# Step 7 — LLM security report
# ---------------------------------------------------------------------------

print("[7/7] LLM security report...")
r = _get(f"/api/v1/scans/{scan_id}/llm-security-report")
if r.status_code == 403:
    fail(
        "llm_security",
        "403 Forbidden — LLM security requires a pro account. "
        "Set DEV_BYPASS_SECRET env var or use a pro account.",
    )
check("llm_security", r.status_code == 200, f"HTTP {r.status_code}: {r.text[:300]}")
llm = r.json()
ai_endpoints = llm.get("ai_endpoints_discovered", [])
check(
    "llm_security.llm_surface_detected",
    len(ai_endpoints) == 0,
    f"LLM endpoints unexpectedly found on {TARGET}: {ai_endpoints}",
)
print(f"      score={llm.get('llm_risk_score', 0):.1f}  issues={llm.get('issues_found', 0)}"
      f"  ai_endpoints=none")

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

print()
print("ALL CHECKS PASSED")
sys.exit(0)
