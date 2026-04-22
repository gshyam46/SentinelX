"""
SentinelX — SSL/TLS Analyzer
Certificate analysis, protocol version checks, cipher strength assessment.
"""

import asyncio
import logging
import ssl
import socket
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


async def analyze_ssl(domain: str) -> dict[str, Any]:
    """
    Full SSL/TLS analysis for a domain.
    Checks certificate details, protocol versions, and cipher strength.
    """
    results = {
        "certificate": {},
        "protocol": {},
        "cipher": {},
        "findings": [],
    }

    # Run blocking SSL operations in thread pool
    try:
        cert_info, protocol_info, cipher_info, findings = await asyncio.to_thread(
            _perform_ssl_check, domain
        )
        results["certificate"] = cert_info
        results["protocol"] = protocol_info
        results["cipher"] = cipher_info
        results["findings"] = findings
    except Exception as e:
        logger.error(f"SSL analysis failed for {domain}: {e}")
        results["findings"].append({
            "severity": "high",
            "title": "SSL/TLS Connection Failed",
            "description": f"Could not establish SSL/TLS connection to {domain}: {str(e)}",
            "remediation": "Ensure the server has a valid SSL certificate and TLS is properly configured.",
            "category": "ssl_tls",
        })

    return results


def _perform_ssl_check(domain: str) -> tuple[dict, dict, dict, list]:
    """Synchronous SSL check (runs in thread pool)."""
    findings = []
    cert_info = {}
    protocol_info = {}
    cipher_info = {}

    try:
        # Create SSL context that accepts all certificates for analysis
        context = ssl.create_default_context()
        conn = socket.create_connection((domain, 443), timeout=10)
        ssock = context.wrap_socket(conn, server_hostname=domain)

        # --- Certificate Details ---
        cert = ssock.getpeercert()
        cert_info = _parse_certificate(cert, domain)
        findings.extend(cert_info.pop("_findings", []))

        # --- Protocol Version ---
        version = ssock.version()
        protocol_info = {"version": version}

        if version in ("SSLv3", "TLSv1", "TLSv1.1"):
            findings.append({
                "severity": "high",
                "title": f"Deprecated Protocol: {version}",
                "description": (
                    f"Server supports {version}, which has known vulnerabilities. "
                    "Attackers can exploit protocol weaknesses to decrypt traffic "
                    "(POODLE, BEAST attacks)."
                ),
                "remediation": "Disable SSLv3, TLS 1.0, and TLS 1.1. Only allow TLS 1.2 and TLS 1.3.",
                "category": "ssl_tls",
            })

        # --- Cipher Suite ---
        cipher = ssock.cipher()
        if cipher:
            cipher_info = {
                "name": cipher[0],
                "protocol": cipher[1],
                "bits": cipher[2],
            }

            if cipher[2] and cipher[2] < 128:
                findings.append({
                    "severity": "high",
                    "title": f"Weak Cipher: {cipher[0]} ({cipher[2]}-bit)",
                    "description": (
                        f"Using {cipher[2]}-bit encryption, which is below the "
                        "recommended 128-bit minimum. Brute-force decryption is feasible."
                    ),
                    "remediation": "Configure server to use only strong cipher suites (AES-128 or higher).",
                    "category": "ssl_tls",
                })

            # Check for known weak ciphers
            weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"]
            for weak in weak_ciphers:
                if weak.lower() in cipher[0].lower():
                    findings.append({
                        "severity": "high",
                        "title": f"Weak Cipher Suite: {cipher[0]}",
                        "description": (
                            f"Cipher suite contains {weak}, which is cryptographically weak. "
                            "This makes encrypted traffic vulnerable to decryption."
                        ),
                        "remediation": f"Remove all cipher suites containing {weak}. Use AEAD ciphers (AES-GCM, ChaCha20).",
                        "category": "ssl_tls",
                    })
                    break

        ssock.close()

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "severity": "critical",
            "title": "SSL Certificate Verification Failed",
            "description": (
                f"Certificate validation error: {str(e)}. "
                "This could indicate an expired, self-signed, or incorrectly configured certificate. "
                "Users will see browser warnings."
            ),
            "remediation": "Install a valid SSL certificate from a trusted Certificate Authority (e.g., Let's Encrypt — free).",
            "category": "ssl_tls",
        })
    except ssl.SSLError as e:
        findings.append({
            "severity": "high",
            "title": "SSL/TLS Configuration Error",
            "description": str(e),
            "remediation": "Review and fix SSL/TLS server configuration.",
            "category": "ssl_tls",
        })

    return cert_info, protocol_info, cipher_info, findings


def _parse_certificate(cert: dict, domain: str) -> dict:
    """Extract and analyze certificate details."""
    findings = []
    info = {}

    if not cert:
        return {"_findings": findings}

    # Subject
    subject = dict(x[0] for x in cert.get("subject", []))
    info["subject"] = subject
    info["common_name"] = subject.get("commonName", "")

    # Issuer
    issuer = dict(x[0] for x in cert.get("issuer", []))
    info["issuer"] = issuer.get("organizationName", issuer.get("commonName", "Unknown"))

    # Validity
    not_before = cert.get("notBefore", "")
    not_after = cert.get("notAfter", "")
    info["not_before"] = not_before
    info["not_after"] = not_after

    # Check expiry
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=timezone.utc)
            days_remaining = (expiry - datetime.now(timezone.utc)).days
            info["days_until_expiry"] = days_remaining

            if days_remaining < 0:
                findings.append({
                    "severity": "critical",
                    "title": "SSL Certificate Expired",
                    "description": (
                        f"Certificate expired {abs(days_remaining)} days ago. "
                        "Browsers will show security warnings and users cannot access the site securely."
                    ),
                    "remediation": "Renew the SSL certificate immediately. Use Let's Encrypt for free certificates.",
                    "category": "ssl_tls",
                })
            elif days_remaining < 30:
                findings.append({
                    "severity": "medium",
                    "title": f"SSL Certificate Expiring Soon ({days_remaining} days)",
                    "description": (
                        f"Certificate expires in {days_remaining} days. "
                        "If not renewed, the site will become inaccessible over HTTPS."
                    ),
                    "remediation": "Renew the SSL certificate. Consider automated renewal with certbot.",
                    "category": "ssl_tls",
                })
        except ValueError:
            pass

    # Subject Alternative Names
    sans = [entry[1] for entry in cert.get("subjectAltName", [])]
    info["san"] = sans

    # Check if domain is in SANs
    if domain not in sans and f"*.{'.'.join(domain.split('.')[1:])}" not in sans:
        findings.append({
            "severity": "medium",
            "title": "Domain Not in Certificate SANs",
            "description": (
                f"The domain {domain} is not listed in the certificate's "
                "Subject Alternative Names. This may cause certificate mismatch warnings."
            ),
            "remediation": "Request a new certificate that includes this domain in the SAN field.",
            "category": "ssl_tls",
        })

    # Self-signed check
    if info.get("issuer") == info.get("common_name"):
        findings.append({
            "severity": "high",
            "title": "Self-Signed Certificate Detected",
            "description": (
                "The certificate appears to be self-signed. "
                "Browsers will display security warnings, and this provides no chain of trust."
            ),
            "remediation": "Replace with a certificate from a trusted CA. Let's Encrypt is free.",
            "category": "ssl_tls",
        })

    info["_findings"] = findings
    return info
