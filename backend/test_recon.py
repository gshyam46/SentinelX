"""
SentinelX - Standalone Recon Test Runner
Run this directly to test passive recon without Django/FastAPI/DB.
Usage: python test_recon.py example.com
"""

import asyncio
import json
import sys
import os
import io

# Fix Windows console encoding
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Add project root to path so imports work from backend/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


async def main():
    # Import after path fix
    from backend.modules.recon.dns_intel import analyze_dns
    from backend.modules.recon.ssl_analyzer import analyze_ssl
    from backend.modules.recon.header_checker import check_headers
    from backend.modules.recon.tech_fingerprint import fingerprint_technologies

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"

    print(f"\n{'='*60}")
    print(f"  SentinelX Passive Recon -- {target}")
    print(f"{'='*60}")

    all_findings = []

    # Step 1: DNS
    print(f"\n  [1/4] DNS Intelligence...")
    try:
        dns_results = await analyze_dns(target)
        dns_findings = dns_results.get("findings", [])
        all_findings.extend(dns_findings)
        records = dns_results.get("records", {})
        subdomains = dns_results.get("subdomains", [])
        print(f"        Records: {sum(len(v) for v in records.values())} found")
        print(f"        Subdomains: {len(subdomains)} discovered")
        print(f"        Findings: {len(dns_findings)}")
        if subdomains:
            print(f"        Sample: {', '.join(subdomains[:5])}")
    except Exception as e:
        print(f"        [ERROR] {e}")

    # Step 2: SSL/TLS
    print(f"\n  [2/4] SSL/TLS Analysis...")
    try:
        ssl_results = await analyze_ssl(target)
        ssl_findings = ssl_results.get("findings", [])
        all_findings.extend(ssl_findings)
        cert = ssl_results.get("certificate", {})
        if cert.get("days_until_expiry"):
            print(f"        Certificate expires in: {cert['days_until_expiry']} days")
        if cert.get("issuer"):
            print(f"        Issuer: {cert['issuer']}")
        print(f"        Protocol: {ssl_results.get('protocol', {}).get('version', 'N/A')}")
        cipher = ssl_results.get("cipher", {})
        if cipher.get("name"):
            print(f"        Cipher: {cipher['name']} ({cipher.get('bits', '?')}-bit)")
        print(f"        Findings: {len(ssl_findings)}")
    except Exception as e:
        print(f"        [ERROR] {e}")

    # Step 3: HTTP Headers
    print(f"\n  [3/4] HTTP Security Headers...")
    try:
        header_results = await check_headers(target)
        header_findings = header_results.get("findings", [])
        all_findings.extend(header_findings)
        missing = header_results.get("headers_missing", [])
        print(f"        Missing headers: {len(missing)}")
        if missing:
            for h in missing[:7]:
                print(f"          - {h}")
        print(f"        Findings: {len(header_findings)}")
    except Exception as e:
        print(f"        [ERROR] {e}")

    # Step 4: Tech Fingerprinting
    print(f"\n  [4/4] Technology Fingerprinting...")
    try:
        tech_results = await fingerprint_technologies(target)
        tech_findings = tech_results.get("findings", [])
        all_findings.extend(tech_findings)
        detected = tech_results.get("detected", [])
        if detected:
            for t in detected:
                ver = f" v{t['version']}" if t.get('version') else ""
                print(f"          - {t['name']}{ver} ({t['category']})")
        else:
            print(f"        No technologies fingerprinted")
        print(f"        Findings: {len(tech_findings)}")
    except Exception as e:
        print(f"        [ERROR] {e}")

    # Summary
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    risk_score = min(100, (
        severity_counts["critical"] * 25 +
        severity_counts["high"] * 15 +
        severity_counts["medium"] * 8 +
        severity_counts["low"] * 3
    ))

    if risk_score >= 75:
        risk_level = "CRITICAL"
    elif risk_score >= 50:
        risk_level = "HIGH"
    elif risk_score >= 25:
        risk_level = "MEDIUM"
    elif risk_score > 0:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"

    print(f"\n{'='*60}")
    print(f"  RESULTS SUMMARY")
    print(f"{'='*60}")
    print(f"  Total Findings: {len(all_findings)}")
    print(f"  Risk Score:     {risk_score}/100 ({risk_level})")
    print(f"")
    print(f"  [CRIT] Critical: {severity_counts['critical']}")
    print(f"  [HIGH] High:     {severity_counts['high']}")
    print(f"  [MED]  Medium:   {severity_counts['medium']}")
    print(f"  [LOW]  Low:      {severity_counts['low']}")
    print(f"  [INFO] Info:     {severity_counts['info']}")

    # Show top findings
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        all_findings,
        key=lambda f: severity_order.get(f.get("severity", "info"), 5)
    )

    print(f"\n{'='*60}")
    print(f"  TOP FINDINGS")
    print(f"{'='*60}")
    for finding in sorted_findings[:12]:
        sev = finding.get("severity", "info").upper()
        print(f"\n  [{sev}] {finding['title']}")
        desc = finding.get('description', '')
        # Wrap long descriptions
        if len(desc) > 120:
            desc = desc[:120] + "..."
        print(f"     {desc}")
        remediation = finding.get('remediation', '')
        if remediation:
            rem_short = remediation.split('\n')[0]
            if len(rem_short) > 100:
                rem_short = rem_short[:100] + "..."
            print(f"     Fix: {rem_short}")

    # Save full results
    output = {
        "domain": target,
        "findings": all_findings,
        "summary": {
            "total": len(all_findings),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "severity_counts": severity_counts,
        },
    }
    output_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        f"scan_{target.replace('.', '_')}.json"
    )
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\n  Full results saved: {output_file}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    asyncio.run(main())
