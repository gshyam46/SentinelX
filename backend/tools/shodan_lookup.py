"""SentinelX — ShodanTool: passive host intelligence (Shodan Python API)."""

from __future__ import annotations
import time
import logging
import socket
from backend.tools.base import SecurityTool, Finding, ToolResult

logger = logging.getLogger("sentinelx.tools.shodan_lookup")

# Ports that are always high-risk when externally exposed
_CRITICAL_PORTS = {23, 445, 3389, 3306, 5432, 6379, 27017, 2375, 9200}
_HIGH_PORTS = {21, 25, 1433, 5900, 111}


class ShodanTool(SecurityTool):
    name = "shodan_lookup"
    owasp_coverage = ["A05", "A06"]
    requires_pro = False
    timeout_seconds = 30
    _install_cmd = "pip install shodan"

    async def run(self, target: str, params: dict, scan_id: str) -> ToolResult:
        start = time.monotonic()
        host = target.replace("https://", "").replace("http://", "").rstrip("/")
        await self._publish_progress(scan_id, f"Shodan passive lookup for {host}")

        try:
            import shodan
            from backend.config import get_settings
            api_key = get_settings().SHODAN_API_KEY
            if not api_key:
                return self._timed_result(
                    start, [], error="SHODAN_API_KEY not configured in .env"
                )
            api = shodan.Shodan(api_key)
        except ImportError:
            return self._timed_result(
                start, [], error="shodan package not installed: pip install shodan"
            )

        # Resolve hostname to IP for Shodan lookup
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return self._timed_result(start, [], error=f"Cannot resolve hostname: {host}")

        findings: list[Finding] = []
        raw_output = ""

        try:
            # Shodan API is synchronous — run in executor to avoid blocking
            import asyncio
            loop = asyncio.get_event_loop()
            info = await loop.run_in_executor(None, api.host, ip)
            raw_output = str(info)[:2000]
        except Exception as exc:
            # Shodan API errors (not found, rate limit, etc.)
            logger.warning(f"Shodan lookup failed for {ip}: {exc}")
            return self._timed_result(start, [], error=str(exc))

        open_ports: list[int] = info.get("ports", [])
        hostnames: list[str] = info.get("hostnames", [])
        org: str = info.get("org", "")
        country: str = info.get("country_name", "")
        os_name: str = info.get("os", "") or ""
        vulns: list[str] = list((info.get("vulns") or {}).keys())
        last_update: str = info.get("last_update", "")

        # ── Open port findings ───────────────────────────────────────────
        for port in open_ports:
            if port in _CRITICAL_PORTS:
                sev = "critical"
            elif port in _HIGH_PORTS:
                sev = "high"
            else:
                sev = "info"

            findings.append(Finding(
                title=f"Shodan: Port {port} Exposed — {host} ({ip})",
                description=(
                    f"Shodan passive data shows port {port} exposed on {ip} ({org}, {country}). "
                    f"Last indexed: {last_update}."
                ),
                affected_url=f"{ip}:{port}",
                tool_source=self.name,
                owasp_category="A05",
                severity=sev,  # type: ignore[arg-type]
                evidence=f"org={org} | country={country} | os={os_name}",
                remediation_hint=f"Verify port {port} is intentionally exposed. Apply firewall rules if not needed.",
            ))

        # ── Known CVEs from Shodan ────────────────────────────────────────
        for cve in vulns[:10]:  # cap at 10
            findings.append(Finding(
                title=f"Shodan: Known Vulnerability on Host — {cve}",
                description=(
                    f"Shodan's data indicates {ip} ({host}) is affected by {cve}. "
                    "This is based on passive banner analysis — verify with active scanning."
                ),
                affected_url=f"https://{host}",
                tool_source=self.name,
                owasp_category="A06",
                severity="high",
                evidence=f"CVE: {cve} | Source: Shodan passive data",
                cve_id=cve,
                remediation_hint=f"Patch {cve}. Refer to the NVD entry for specific remediation steps.",
            ))

        # ── Hostname enumeration ──────────────────────────────────────────
        if hostnames:
            findings.append(Finding(
                title=f"Shodan: {len(hostnames)} Associated Hostname(s) Found",
                description=(
                    f"Shodan identified the following hostnames for {ip}: {hostnames[:10]}. "
                    "These may reveal additional attack surface."
                ),
                affected_url=f"https://{host}",
                tool_source=self.name,
                owasp_category="A05",
                severity="info",
                evidence=str(hostnames[:10]),
                remediation_hint="Audit all associated hostnames for security misconfigurations.",
            ))

        logger.info(
            f"[{scan_id}] shodan: {len(open_ports)} ports, "
            f"{len(vulns)} CVEs for {host} ({ip})"
        )
        return self._timed_result(start, findings, raw_output)


async def run(params: dict) -> list[Finding]:
    tool = ShodanTool()
    result = await tool.run(
        target=params.get("target", ""),
        params=params,
        scan_id=params.get("scan_id", ""),
    )
    return result.findings
