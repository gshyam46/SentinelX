"""
SentinelX — Breach & Threat Intelligence Check
Integration with HIBP, AlienVault OTX, and Shodan for passive threat intel.
"""

import logging
from typing import Any

import httpx

from backend.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


async def check_breaches(domain: str) -> dict[str, Any]:
    """
    Check domain against breach databases and threat intel feeds.
    All passive lookups — no active scanning.
    """
    results = {
        "breaches": [],
        "threat_intel": [],
        "shodan": {},
        "findings": [],
    }

    # 1. HaveIBeenPwned domain search
    if settings.HIBP_API_KEY:
        hibp_data = await _check_hibp(domain)
        results["breaches"] = hibp_data.get("breaches", [])
        results["findings"].extend(hibp_data.get("findings", []))

    # 2. AlienVault OTX threat intel
    if settings.OTX_API_KEY:
        otx_data = await _check_otx(domain)
        results["threat_intel"] = otx_data.get("pulses", [])
        results["findings"].extend(otx_data.get("findings", []))

    # 3. Shodan passive lookup
    if settings.SHODAN_API_KEY:
        shodan_data = await _check_shodan(domain)
        results["shodan"] = shodan_data.get("data", {})
        results["findings"].extend(shodan_data.get("findings", []))

    # If no API keys configured, note it
    if not any([settings.HIBP_API_KEY, settings.OTX_API_KEY, settings.SHODAN_API_KEY]):
        results["findings"].append({
            "severity": "info",
            "title": "Breach Intelligence Skipped",
            "description": (
                "No API keys configured for breach/threat intelligence services. "
                "Configure HIBP_API_KEY, OTX_API_KEY, and/or SHODAN_API_KEY in .env "
                "to enable breach and threat intelligence checking."
            ),
            "category": "configuration",
        })

    return results


async def _check_hibp(domain: str) -> dict:
    """Check domain against HaveIBeenPwned breach database."""
    findings = []
    breaches = []

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}",
                headers={
                    "hibp-api-key": settings.HIBP_API_KEY,
                    "User-Agent": "SentinelX-Security-Scanner",
                },
            )

            if response.status_code == 200:
                data = response.json()
                if data:
                    breaches = [
                        {
                            "name": b.get("Name"),
                            "title": b.get("Title"),
                            "breach_date": b.get("BreachDate"),
                            "pwn_count": b.get("PwnCount"),
                            "data_classes": b.get("DataClasses", []),
                            "description": b.get("Description", ""),
                        }
                        for b in data
                    ]

                    total_records = sum(b.get("PwnCount", 0) for b in data)
                    severity = "critical" if total_records > 100000 else "high" if total_records > 1000 else "medium"

                    findings.append({
                        "severity": severity,
                        "title": f"Domain Found in {len(data)} Data Breach(es)",
                        "description": (
                            f"The domain {domain} appears in {len(data)} known data breaches "
                            f"affecting approximately {total_records:,} records total. "
                            f"Breached data includes: {', '.join(set(dc for b in data for dc in b.get('DataClasses', [])))}."
                        ),
                        "remediation": (
                            "1. Notify affected users and require password resets.\n"
                            "2. Enable multi-factor authentication for all accounts.\n"
                            "3. Monitor for credential stuffing attacks.\n"
                            "4. Check if exposed credentials are reused on other services."
                        ),
                        "category": "breach",
                    })

            elif response.status_code == 404:
                findings.append({
                    "severity": "info",
                    "title": "No Known Breaches Found",
                    "description": f"Domain {domain} was not found in the HaveIBeenPwned database.",
                    "category": "breach",
                })

    except Exception as e:
        logger.warning(f"HIBP check failed for {domain}: {e}")

    return {"breaches": breaches, "findings": findings}


async def _check_otx(domain: str) -> dict:
    """Check domain against AlienVault OTX threat intelligence."""
    findings = []
    pulses = []

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                headers={"X-OTX-API-KEY": settings.OTX_API_KEY},
            )

            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get("pulse_info", {})
                pulse_count = pulse_info.get("count", 0)

                if pulse_count > 0:
                    pulses = [
                        {
                            "name": p.get("name"),
                            "description": p.get("description", ""),
                            "created": p.get("created"),
                            "tags": p.get("tags", []),
                        }
                        for p in pulse_info.get("pulses", [])[:10]  # Limit to 10
                    ]

                    severity = "high" if pulse_count > 5 else "medium" if pulse_count > 0 else "info"
                    findings.append({
                        "severity": severity,
                        "title": f"Domain Mentioned in {pulse_count} Threat Intelligence Report(s)",
                        "description": (
                            f"AlienVault OTX has {pulse_count} threat intelligence pulses "
                            f"mentioning {domain}. This indicates the domain has been "
                            "associated with malicious activity or security incidents."
                        ),
                        "remediation": (
                            "Review the threat intelligence reports for context.\n"
                            "Check if the domain's IP has been compromised.\n"
                            "Monitor network logs for indicators of compromise."
                        ),
                        "category": "threat_intel",
                    })

                # Check reputation
                reputation = data.get("reputation", 0)
                if reputation and reputation < 0:
                    findings.append({
                        "severity": "medium",
                        "title": f"Negative Domain Reputation Score: {reputation}",
                        "description": "The domain has a negative reputation in threat intelligence databases.",
                        "remediation": "Investigate potential compromise and check if IP is on blacklists.",
                        "category": "threat_intel",
                    })

    except Exception as e:
        logger.warning(f"OTX check failed for {domain}: {e}")

    return {"pulses": pulses, "findings": findings}


async def _check_shodan(domain: str) -> dict:
    """Passive Shodan lookup — check what's visible from the internet."""
    findings = []
    data = {}

    try:
        # First resolve domain to IP
        import socket
        ip = await _resolve_domain(domain)
        if not ip:
            return {"data": {}, "findings": []}

        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}?key={settings.SHODAN_API_KEY}"
            )

            if response.status_code == 200:
                shodan_data = response.json()
                data = {
                    "ip": ip,
                    "country": shodan_data.get("country_name"),
                    "org": shodan_data.get("org"),
                    "isp": shodan_data.get("isp"),
                    "os": shodan_data.get("os"),
                    "ports": shodan_data.get("ports", []),
                    "vulns": shodan_data.get("vulns", []),
                    "last_update": shodan_data.get("last_update"),
                }

                # Report open ports
                ports = shodan_data.get("ports", [])
                if ports:
                    risky_ports = {
                        21: "FTP",
                        22: "SSH",
                        23: "Telnet",
                        25: "SMTP",
                        3306: "MySQL",
                        5432: "PostgreSQL",
                        6379: "Redis",
                        27017: "MongoDB",
                        9200: "Elasticsearch",
                        11211: "Memcached",
                    }

                    exposed_services = []
                    for port in ports:
                        if port in risky_ports:
                            exposed_services.append(f"{risky_ports[port]} (port {port})")

                    if exposed_services:
                        findings.append({
                            "severity": "high",
                            "title": f"{len(exposed_services)} Sensitive Service(s) Exposed to Internet",
                            "description": (
                                f"Shodan detected the following services accessible from the internet: "
                                f"{', '.join(exposed_services)}. "
                                "These services should not be directly accessible and may be targets "
                                "for brute-force attacks or exploitation."
                            ),
                            "remediation": (
                                "1. Place services behind a firewall — only allow necessary ports.\n"
                                "2. Use VPN or SSH tunnels for remote database access.\n"
                                "3. Never expose databases (MySQL, PostgreSQL, Redis, MongoDB) to the public internet."
                            ),
                            "category": "exposure",
                        })

                # Report known vulnerabilities
                vulns = shodan_data.get("vulns", [])
                if vulns:
                    findings.append({
                        "severity": "critical",
                        "title": f"{len(vulns)} Known Vulnerability(ies) Detected by Shodan",
                        "description": (
                            f"Shodan has identified {len(vulns)} known CVEs associated with "
                            f"services running on this host: {', '.join(vulns[:10])}"
                            f"{'...' if len(vulns) > 10 else ''}"
                        ),
                        "remediation": (
                            "Patch or update the affected services immediately.\n"
                            "Check each CVE at nvd.nist.gov for severity and patch information."
                        ),
                        "category": "vulnerability",
                    })

    except Exception as e:
        logger.warning(f"Shodan check failed for {domain}: {e}")

    return {"data": data, "findings": findings}


async def _resolve_domain(domain: str) -> str | None:
    """Resolve domain to IP address."""
    import asyncio
    try:
        result = await asyncio.to_thread(
            lambda: __import__("socket").gethostbyname(domain)
        )
        return result
    except Exception:
        return None
