"""
SentinelX - Full API End-to-End Test
Tests: Register -> Login -> Create Scan -> Poll Results -> Tier Gating
"""
import sys
import io
import time
import requests
import json

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

BASE = "http://localhost:8000/api/v1"

def test_full_flow():
    print("\n" + "="*60)
    print("  SentinelX API End-to-End Test")
    print("="*60)

    # 1. Health check
    print("\n[1] Health check...")
    r = requests.get(f"{BASE}/health")
    assert r.status_code == 200, f"Health check failed: {r.status_code}"
    print(f"    OK: {r.json()}")

    # 2. Register
    print("\n[2] Register new user...")
    r = requests.post(f"{BASE}/auth/register", json={
        "email": "test@sentinelx.io",
        "password": "TestPass123!",
        "full_name": "Test User"
    })
    if r.status_code == 409:
        print("    User exists, logging in instead...")
        r = requests.post(f"{BASE}/auth/login", json={
            "email": "test@sentinelx.io",
            "password": "TestPass123!"
        })
    assert r.status_code in (200, 201), f"Auth failed: {r.status_code} {r.text}"
    data = r.json()
    token = data["access_token"]
    user = data["user"]
    print(f"    OK: User {user['email']} (tier: {user['tier']})")
    print(f"    Token: {token[:40]}...")

    headers = {"Authorization": f"Bearer {token}"}

    # 3. Get profile
    print("\n[3] Get profile (GET /auth/me)...")
    r = requests.get(f"{BASE}/auth/me", headers=headers)
    assert r.status_code == 200, f"Profile failed: {r.status_code} {r.text}"
    print(f"    OK: {r.json()['email']}")

    # 4. Create passive scan
    print("\n[4] Create passive scan (POST /scans)...")
    r = requests.post(f"{BASE}/scans", headers=headers, json={
        "domain": "example.com",
        "scan_type": "passive"
    })
    assert r.status_code == 201, f"Scan create failed: {r.status_code} {r.text}"
    scan = r.json()
    scan_id = scan["id"]
    print(f"    OK: Scan {scan_id[:8]}... created (status: {scan['status']})")

    # 5. Poll scan until complete
    print("\n[5] Polling scan status...")
    max_polls = 30
    final_status = "pending"
    for i in range(max_polls):
        time.sleep(3)
        r = requests.get(f"{BASE}/scans/{scan_id}", headers=headers)
        assert r.status_code == 200
        scan = r.json()
        final_status = scan["status"]
        progress = scan["progress"]
        step = scan.get("current_step") or ""
        print(f"    [{i+1:2d}] {final_status} | {progress}% | {step}")
        if final_status in ("complete", "failed"):
            break

    if final_status == "complete":
        print(f"\n    --- SCAN COMPLETE ---")
        print(f"    Findings: {scan['findings_count']}")
        print(f"    Critical: {scan['critical_count']}  High: {scan['high_count']}  "
              f"Medium: {scan['medium_count']}  Low: {scan['low_count']}  Info: {scan['info_count']}")
        print(f"    Risk Score: {scan['risk_score']}")

        results = scan.get("results") or {}
        findings = results.get("all_findings", [])
        if findings:
            print(f"\n    Sample findings:")
            for f in findings[:3]:
                print(f"      [{f.get('severity','?').upper()}] {f.get('title','N/A')}")

        if results.get("gated"):
            print(f"\n    FREE TIER GATING: {results.get('hidden_findings_count',0)} findings hidden")
            print(f"    Upgrade: {results.get('upgrade_message','')[:80]}...")
    elif final_status == "failed":
        print(f"    FAILED: {scan.get('error_message', 'Unknown')}")

    # 6. List scans
    print("\n[6] List scan history...")
    r = requests.get(f"{BASE}/scans", headers=headers)
    assert r.status_code == 200
    print(f"    OK: {r.json()['total']} scan(s) in history")

    # 7. Active scan blocked for free tier
    print("\n[7] Test tier gating (active scan blocked)...")
    r = requests.post(f"{BASE}/scans", headers=headers, json={
        "domain": "example.com",
        "scan_type": "active",
        "authorization_confirmed": True
    })
    assert r.status_code == 403, f"Expected 403, got {r.status_code}"
    print(f"    OK: Correctly blocked - {r.json()['detail'][:60]}...")

    print("\n" + "="*60)
    print("  ALL TESTS PASSED")
    print("="*60 + "\n")

if __name__ == "__main__":
    test_full_flow()
