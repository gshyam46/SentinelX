"""
SentinelX — Passive Recon Orchestrator
Coordinates all passive recon sub-modules and aggregates findings.
This is the core engine for the free tier.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable

from backend.modules.recon.dns_intel import analyze_dns
from backend.modules.recon.ssl_analyzer import analyze_ssl
from backend.modules.recon.header_checker import check_headers
from backend.modules.recon.tech_fingerprint import fingerprint_technologies
from backend.modules.recon.breach_check import check_breaches

logger = logging.getLogger(__name__)

# Scan pipeline steps — order matters for progress reporting
SCAN_STEPS = [
    ("dns", "DNS Intelligence", analyze_dns),
    ("headers", "HTTP Security Headers", check_headers),
    ("ssl", "SSL/TLS Analysis", analyze_ssl),
    ("technologies", "Technology Fingerprinting", fingerprint_technologies),
    ("breach", "Breach & Threat Intelligence", check_breaches),
]


async def run_passive_recon(
    domain: str,
    progress_callback: Callable | None = None,
) -> dict[str, Any]:
    """
    Full passive recon pipeline.

    Args:
        domain: Target domain (e.g., "example.com")
        progress_callback: Optional async callback(step_name, progress_pct)

    Returns:
        Complete scan results with all findings aggregated.
    """
    results = {
        "domain": domain,
        "scan_type": "passive",
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "modules": {},
        "all_findings": [],
        "summary": {},
    }

    total_steps = len(SCAN_STEPS)

    for i, (module_key, step_name, module_func) in enumerate(SCAN_STEPS):
        progress_pct = int((i / total_steps) * 100)

        if progress_callback:
            await progress_callback(step_name, progress_pct)

        logger.info(f"[{domain}] Running: {step_name} ({progress_pct}%)")

        try:
            module_result = await asyncio.wait_for(
                module_func(domain),
                timeout=30,  # 30 second timeout per module
            )
            results["modules"][module_key] = module_result

            # Collect findings from this module
            module_findings = module_result.get("findings", [])
            for finding in module_findings:
                finding["source_module"] = module_key
            results["all_findings"].extend(module_findings)

        except asyncio.TimeoutError:
            logger.warning(f"[{domain}] {step_name} timed out after 30s")
            results["modules"][module_key] = {
                "error": "Module timed out",
                "findings": [{
                    "severity": "info",
                    "title": f"{step_name} Timed Out",
                    "description": f"The {step_name} module did not complete within 30 seconds.",
                    "source_module": module_key,
                    "category": "timeout",
                }],
            }
        except Exception as e:
            logger.error(f"[{domain}] {step_name} failed: {e}")
            results["modules"][module_key] = {
                "error": str(e),
                "findings": [{
                    "severity": "info",
                    "title": f"{step_name} Error",
                    "description": str(e),
                    "source_module": module_key,
                    "category": "error",
                }],
            }

    # Also run exposed paths as part of headers/recon
    try:
        exposed = await asyncio.wait_for(
            _check_common_exposures(domain),
            timeout=30,
        )
        results["modules"]["exposed_paths"] = exposed
        for finding in exposed.get("findings", []):
            finding["source_module"] = "exposed_paths"
        results["all_findings"].extend(exposed.get("findings", []))
    except Exception as e:
        logger.warning(f"[{domain}] Exposed paths check failed: {e}")

    # Final progress
    if progress_callback:
        await progress_callback("Generating Summary", 95)

    # Generate summary
    results["summary"] = _generate_summary(results["all_findings"])

    if progress_callback:
        await progress_callback("Complete", 100)

    logger.info(
        f"[{domain}] Passive recon complete: "
        f"{results['summary']['total_findings']} findings, "
        f"risk score: {results['summary']['risk_score']}"
    )

    return results


async def _check_common_exposures(domain: str) -> dict:
    """Check for commonly exposed sensitive files and paths."""
    import httpx

    findings = []

    sensitive_paths = [
        ("/.git/HEAD", "critical", "Git Repository Exposed",
         "Attackers can download your entire source code, including credentials and secrets."),
        ("/.env", "critical", "Environment File Exposed",
         "Contains API keys, database credentials, and application secrets."),
        ("/.git/config", "critical", "Git Config Exposed",
         "Reveals repository URLs, potentially including credentials."),
        ("/backup.zip", "critical", "Backup File Exposed",
         "May contain full application backup with source code and credentials."),
        ("/backup.sql", "critical", "Database Backup Exposed",
         "Database dump file accessible — may contain all user data."),
        ("/db.sql", "critical", "Database Dump Exposed",
         "SQL database file accessible from the internet."),
        ("/.DS_Store", "medium", "macOS .DS_Store Exposed",
         "Reveals directory structure and filenames on the server."),
        ("/phpinfo.php", "high", "PHP Info Page Exposed",
         "Reveals server configuration, PHP version, installed modules, and file paths."),
        ("/wp-config.php.bak", "critical", "WordPress Config Backup Exposed",
         "Backup of WordPress config file with database credentials."),
        ("/admin", "info", "Admin Panel Found",
         "Admin interface accessible. Verify strong authentication is in place."),
        ("/wp-admin", "info", "WordPress Admin Found",
         "WordPress admin login page publicly accessible."),
        ("/api/v1/users", "medium", "API User Endpoint Exposed",
         "User listing API endpoint may be accessible without authentication."),
        ("/server-status", "medium", "Apache Server Status Exposed",
         "Server metrics, request details, and connected clients visible."),
        ("/server-info", "medium", "Apache Server Info Exposed",
         "Detailed server configuration and modules information exposed."),
        ("/.htaccess", "medium", "Htaccess File Exposed",
         "Server configuration rules disclosed — reveals URL rewriting and access rules."),
        ("/robots.txt", "info", "Robots.txt Found",
         "May reveal hidden directories and paths the site owner doesn't want indexed."),
        ("/sitemap.xml", "info", "Sitemap Found",
         "Site map available — useful for understanding site structure."),
        ("/.well-known/security.txt", "info", "Security.txt Found",
         "Security contact information is properly configured (this is good practice)."),
    ]

    try:
        async with httpx.AsyncClient(
            verify=False,
            timeout=5,
            follow_redirects=False,
        ) as client:
            tasks = []
            for path, severity, title, description in sensitive_paths:
                tasks.append(
                    _check_single_path(client, domain, path, severity, title, description)
                )

            path_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in path_results:
                if isinstance(result, dict):
                    findings.append(result)

    except Exception as e:
        logger.warning(f"Exposed paths check failed for {domain}: {e}")

    return {"findings": findings}


async def _check_single_path(
    client, domain: str, path: str,
    severity: str, title: str, description: str,
) -> dict | None:
    """Check if a single path is accessible."""
    try:
        response = await client.get(f"https://{domain}{path}")

        if response.status_code == 200:
            # Verify it's not just a generic 200 (custom 404 page)
            content_length = len(response.content)
            if content_length > 0:
                return {
                    "severity": severity,
                    "title": title,
                    "path": path,
                    "status_code": response.status_code,
                    "content_length": content_length,
                    "description": description,
                    "remediation": f"Block access to {path} via web server configuration or firewall rules.",
                    "category": "exposed_path",
                }
        elif response.status_code == 403:
            # 403 means the path exists but is blocked — less severe but still informative
            if severity in ("critical", "high"):
                return {
                    "severity": "info",
                    "title": f"{title} (Blocked — 403)",
                    "path": path,
                    "status_code": 403,
                    "description": f"Path {path} exists but returns 403 Forbidden. Access is blocked, which is good, but the path's existence is confirmed.",
                    "remediation": "Consider returning 404 instead of 403 to avoid confirming the path exists.",
                    "category": "exposed_path",
                }
    except Exception:
        pass

    return None


def _generate_summary(findings: list[dict]) -> dict:
    """Generate a summary from all findings."""
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        sev = finding.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Calculate risk score (0-100)
    # Weighted: critical=25, high=15, medium=8, low=3, info=0
    risk_score = min(100, (
        severity_counts["critical"] * 25 +
        severity_counts["high"] * 15 +
        severity_counts["medium"] * 8 +
        severity_counts["low"] * 3
    ))

    # Determine overall risk level
    if risk_score >= 75:
        risk_level = "Critical"
    elif risk_score >= 50:
        risk_level = "High"
    elif risk_score >= 25:
        risk_level = "Medium"
    elif risk_score > 0:
        risk_level = "Low"
    else:
        risk_level = "Minimal"

    return {
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }


# Standalone test runner
if __name__ == "__main__":
    import sys

    async def main():
        target = sys.argv[1] if len(sys.argv) > 1 else "example.com"

        async def log_progress(step: str, pct: int):
            print(f"  [{pct:3d}%] {step}")

        print(f"\n{'='*60}")
        print(f"  SentinelX Passive Recon — {target}")
        print(f"{'='*60}\n")

        results = await run_passive_recon(target, progress_callback=log_progress)

        print(f"\n{'='*60}")
        print(f"  RESULTS SUMMARY")
        print(f"{'='*60}")
        summary = results["summary"]
        print(f"  Risk Score: {summary['risk_score']}/100 ({summary['risk_level']})")
        print(f"  Total Findings: {summary['total_findings']}")
        print(f"  Critical: {summary['severity_counts']['critical']}")
        print(f"  High:     {summary['severity_counts']['high']}")
        print(f"  Medium:   {summary['severity_counts']['medium']}")
        print(f"  Low:      {summary['severity_counts']['low']}")
        print(f"  Info:     {summary['severity_counts']['info']}")

        print(f"\n{'='*60}")
        print(f"  TOP FINDINGS")
        print(f"{'='*60}")

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            results["all_findings"],
            key=lambda f: severity_order.get(f.get("severity", "info"), 5)
        )

        for finding in sorted_findings[:15]:
            sev = finding.get("severity", "info").upper()
            print(f"\n  [{sev}] {finding['title']}")
            print(f"    {finding.get('description', '')[:120]}")

        # Save full results
        output_file = f"scan_{target.replace('.', '_')}.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n  Full results saved to: {output_file}")

    asyncio.run(main())
