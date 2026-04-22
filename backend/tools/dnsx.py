"""SentinelX — DnsxTool: DNS resolution and zone enumeration."""

from __future__ import annotations
import json
import time
import logging
from backend.tools.base import SecurityTool, Finding, ToolResult, ToolNotFoundError

logger = logging.getLogger("sentinelx.tools.dnsx")

# DNS record types that signal security issues
_DANGEROUS_RECORDS = {
    "AXFR": ("critical", "DNS Zone Transfer Allowed — Full Zone Data Exposed",
              "Restrict AXFR to authorized secondary nameservers only."),
    "SPF_MISSING": ("high", "Missing SPF Record — Email Spoofing Possible",
                    "Add a TXT record: v=spf1 include:_spf.your-provider.com ~all"),
    "DMARC_MISSING": ("high", "Missing DMARC Record — Domain Spoofing Unprotected",
                      "Add _dmarc TXT record: v=DMARC1; p=quarantine; rua=mailto:dmarc@your-domain.com"),
}


class DnsxTool(SecurityTool):
    name = "dnsx"
    owasp_coverage = ["A05"]
    requires_pro = False
    timeout_seconds = 90
    _install_cmd = "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"

    async def run(self, target: str, params: dict, scan_id: str) -> ToolResult:
        start = time.monotonic()
        host = target.replace("https://", "").replace("http://", "").rstrip("/")
        await self._publish_progress(scan_id, f"DNS resolution and analysis for {host}")

        findings: list[Finding] = []

        # ── A/AAAA/MX/TXT/NS records ─────────────────────────────────────
        cmd = [
            "dnsx",
            "-d", host,
            "-a", "-aaaa", "-mx", "-txt", "-ns", "-cname",
            "-json",
            "-silent",
            "-retry", "2",
        ]

        try:
            stdout, stderr, rc = await self._exec(cmd)
        except ToolNotFoundError:
            raise
        except Exception as exc:
            return self._timed_result(start, [], error=str(exc))

        has_spf = False
        has_dmarc = False

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            resolved_host: str = obj.get("host", host)
            a_records: list[str] = obj.get("a", [])
            txt_records: list[str] = obj.get("txt", [])

            # Check SPF
            for txt in txt_records:
                if txt.lower().startswith("v=spf1"):
                    has_spf = True
                if "v=dmarc1" in txt.lower():
                    has_dmarc = True

            # Flag wildcard DNS (can indicate takeover risk)
            if "*" in resolved_host:
                findings.append(Finding(
                    title=f"Wildcard DNS Detected: {resolved_host}",
                    description=(
                        f"A wildcard DNS record (*) resolves all subdomains of {host}. "
                        "This can mask subdomain takeover vulnerabilities and confuse security audits."
                    ),
                    affected_url=f"https://{host}",
                    tool_source=self.name,
                    owasp_category="A05",
                    severity="medium",
                    evidence=str(a_records[:5]),
                    remediation_hint=(
                        "Remove wildcard DNS unless explicitly required. "
                        "Enumerate all actual subdomain records explicitly."
                    ),
                ))

        # ── SPF / DMARC checks ────────────────────────────────────────────
        if not has_spf:
            findings.append(Finding(
                title="Missing SPF Record — Email Spoofing Risk",
                description=(
                    f"No SPF TXT record found for {host}. "
                    "Attackers can send emails impersonating @{host} addresses."
                ),
                affected_url=f"https://{host}",
                tool_source=self.name,
                owasp_category="A05",
                severity="high",
                evidence="dig TXT {host} returned no v=spf1 record",
                remediation_hint="Add TXT record: v=spf1 include:_spf.your-provider.com ~all",
            ))

        if not has_dmarc:
            findings.append(Finding(
                title="Missing DMARC Record — Domain Spoofing Unprotected",
                description=(
                    f"No DMARC record found at _dmarc.{host}. "
                    "Without DMARC, email receivers cannot act on SPF/DKIM failures."
                ),
                affected_url=f"https://{host}",
                tool_source=self.name,
                owasp_category="A05",
                severity="high",
                evidence=f"No TXT record at _dmarc.{host}",
                remediation_hint=(
                    "Add TXT record at _dmarc.{host}: "
                    "v=DMARC1; p=quarantine; rua=mailto:dmarc@{host}"
                ),
            ))

        # ── Zone transfer test ────────────────────────────────────────────
        axfr_cmd = ["dig", "AXFR", f"@{host}", host]
        try:
            axfr_stdout, _, axfr_rc = await self._exec(axfr_cmd, timeout=10)
            if "Transfer failed" not in axfr_stdout and len(axfr_stdout) > 200:
                findings.append(Finding(
                    title="DNS Zone Transfer (AXFR) Allowed — Full Zone Exposed",
                    description=(
                        f"The DNS server for {host} allows full zone transfers. "
                        "An attacker can enumerate ALL DNS records for the domain."
                    ),
                    affected_url=f"https://{host}",
                    tool_source=self.name,
                    owasp_category="A05",
                    severity="critical",
                    evidence=axfr_stdout[:400],
                    remediation_hint=(
                        "Restrict AXFR to authorized secondary nameservers only "
                        "(allow-transfer in BIND configuration)."
                    ),
                ))
        except Exception:
            pass

        logger.info(f"[{scan_id}] dnsx: {len(findings)} DNS findings for {host}")
        return self._timed_result(start, findings, stdout, triggered=["httpx_probe"])


async def run(params: dict) -> list[Finding]:
    tool = DnsxTool()
    result = await tool.run(
        target=params.get("target", ""),
        params=params,
        scan_id=params.get("scan_id", ""),
    )
    return result.findings
