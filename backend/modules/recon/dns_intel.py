"""
SentinelX — DNS Intelligence Module
Deep DNS analysis: record enumeration, email security (SPF/DKIM/DMARC),
subdomain discovery via certificate transparency logs.
"""

import asyncio
import logging
from typing import Any

import dns.resolver
import httpx

logger = logging.getLogger(__name__)


async def analyze_dns(domain: str) -> dict[str, Any]:
    """
    Full DNS intelligence gathering.
    Returns structured DNS records and security findings.
    """
    results = {
        "records": {},
        "email_security": {},
        "subdomains": [],
        "findings": [],
    }

    # 1. Enumerate all record types
    results["records"] = await _get_all_records(domain)

    # 2. Check email security (SPF, DKIM, DMARC)
    results["email_security"] = _check_email_security(domain, results["records"])
    results["findings"].extend(results["email_security"].get("findings", []))

    # 3. Subdomain enumeration via crt.sh
    results["subdomains"] = await _enumerate_subdomains_crtsh(domain)

    # 4. Check for zone transfer vulnerability
    zone_finding = await _check_zone_transfer(domain)
    if zone_finding:
        results["findings"].append(zone_finding)

    return results


async def _get_all_records(domain: str) -> dict[str, list[str]]:
    """Enumerate DNS records across all common types."""
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
    records = {}

    for rtype in record_types:
        try:
            # Run blocking DNS resolver in thread pool
            answers = await asyncio.to_thread(
                dns.resolver.resolve, domain, rtype
            )
            records[rtype] = [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            records[rtype] = []
        except Exception as e:
            logger.debug(f"DNS {rtype} lookup failed for {domain}: {e}")
            records[rtype] = []

    return records


def _check_email_security(domain: str, records: dict) -> dict[str, Any]:
    """Analyze SPF, DKIM, and DMARC configuration."""
    findings = []
    email_sec = {"spf": None, "dmarc": None, "dkim_selector_hint": None}

    txt_records = records.get("TXT", [])
    all_txt = " ".join(txt_records)

    # --- SPF Check ---
    spf_records = [r for r in txt_records if "v=spf1" in r]
    if not spf_records:
        findings.append({
            "severity": "medium",
            "title": "Missing SPF Record",
            "description": (
                "No SPF (Sender Policy Framework) record found. "
                "Attackers can spoof emails appearing to come from your domain, "
                "which can be used for phishing attacks against your employees or customers."
            ),
            "remediation": (
                "Add a TXT record: v=spf1 include:_spf.yourmailprovider.com ~all\n"
                "Replace 'yourmailprovider' with your actual email service (e.g., google.com for Gmail)."
            ),
            "category": "email_security",
        })
    else:
        email_sec["spf"] = spf_records[0]
        # Check for overly permissive SPF
        if "+all" in spf_records[0]:
            findings.append({
                "severity": "high",
                "title": "Overly Permissive SPF Record",
                "description": (
                    "SPF record uses '+all' which allows ANY server to send email "
                    "as your domain. This completely defeats the purpose of SPF."
                ),
                "remediation": "Change '+all' to '~all' (softfail) or '-all' (hardfail).",
                "category": "email_security",
            })

    # --- DMARC Check ---
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_records = [str(r) for r in dmarc_answers]
        dmarc_txt = " ".join(dmarc_records)

        if "v=DMARC1" in dmarc_txt:
            email_sec["dmarc"] = dmarc_txt
            # Check for p=none (monitoring only, no enforcement)
            if "p=none" in dmarc_txt:
                findings.append({
                    "severity": "low",
                    "title": "DMARC Policy Set to None (Monitor Only)",
                    "description": (
                        "DMARC is configured but set to 'p=none', meaning spoofed emails "
                        "are not blocked — only reported. This is a valid starting point "
                        "but should be upgraded to 'quarantine' or 'reject' after monitoring."
                    ),
                    "remediation": "After reviewing DMARC reports, upgrade to p=quarantine then p=reject.",
                    "category": "email_security",
                })
        else:
            findings.append({
                "severity": "medium",
                "title": "Invalid DMARC Record",
                "description": "A TXT record exists at _dmarc but does not contain a valid DMARC policy.",
                "remediation": "Add a valid DMARC record: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com",
                "category": "email_security",
            })
    except Exception:
        findings.append({
            "severity": "medium",
            "title": "Missing DMARC Record",
            "description": (
                "No DMARC (Domain-based Message Authentication) policy found. "
                "Without DMARC, there is no policy to handle emails that fail SPF/DKIM checks, "
                "making email spoofing attacks easier."
            ),
            "remediation": (
                "Add a TXT record for _dmarc.yourdomain.com:\n"
                "v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com"
            ),
            "category": "email_security",
        })

    return {"findings": findings, **email_sec}


async def _enumerate_subdomains_crtsh(domain: str) -> list[str]:
    """
    Discover subdomains via Certificate Transparency logs (crt.sh).
    This is entirely passive — queries public certificate databases.
    """
    subdomains = set()

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                follow_redirects=True,
            )
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    # crt.sh can return wildcard and multi-line entries
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub and not sub.startswith("*") and sub.endswith(domain):
                            subdomains.add(sub)
    except Exception as e:
        logger.warning(f"crt.sh subdomain enumeration failed for {domain}: {e}")

    return sorted(subdomains)


async def _check_zone_transfer(domain: str) -> dict | None:
    """
    Check if any nameservers allow zone transfers (AXFR).
    A successful zone transfer is a critical finding — it leaks ALL DNS records.
    """
    try:
        ns_records = await asyncio.to_thread(dns.resolver.resolve, domain, "NS")
        for ns in ns_records:
            ns_host = str(ns).rstrip(".")
            try:
                # Attempt zone transfer
                import dns.zone
                import dns.query

                zone = await asyncio.to_thread(
                    dns.zone.from_xfr,
                    dns.query.xfr(ns_host, domain, timeout=5),
                )
                if zone:
                    return {
                        "severity": "critical",
                        "title": "DNS Zone Transfer Allowed (AXFR)",
                        "description": (
                            f"Nameserver {ns_host} allows zone transfers. "
                            "An attacker can download ALL DNS records for this domain, "
                            "revealing internal hostnames, IP addresses, and infrastructure."
                        ),
                        "remediation": (
                            "Restrict zone transfers to authorized secondary nameservers only. "
                            "Configure 'allow-transfer' in BIND or equivalent in your DNS server."
                        ),
                        "category": "dns_security",
                    }
            except Exception:
                continue  # Zone transfer failed (expected — this is good)
    except Exception:
        pass

    return None
