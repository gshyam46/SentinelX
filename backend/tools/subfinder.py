"""SentinelX — SubfinderTool: passive subdomain enumeration."""

from __future__ import annotations
import json
import time
import logging
from backend.tools.base import SecurityTool, Finding, ToolResult, ToolNotFoundError

logger = logging.getLogger("sentinelx.tools.subfinder")


class SubfinderTool(SecurityTool):
    name = "subfinder"
    owasp_coverage = ["A01"]
    requires_pro = False
    timeout_seconds = 120
    _install_cmd = "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"

    async def run(self, target: str, params: dict, scan_id: str) -> ToolResult:
        start = time.monotonic()
        await self._publish_progress(scan_id, f"Enumerating subdomains for {target}")

        cmd = [
            "subfinder",
            "-d", target,
            "-silent",
            "-json",
            "-all",            # use all sources
            "-timeout", "30",  # per-source timeout
        ]

        try:
            stdout, stderr, rc = await self._exec(cmd)
        except ToolNotFoundError:
            raise
        except Exception as exc:
            return self._timed_result(start, [], error=str(exc))

        findings: list[Finding] = []
        triggered: list[str] = []
        seen: set[str] = set()

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # subfinder sometimes outputs plain hostnames when -json fails
                host = line
                obj = {"host": host}

            host: str = obj.get("host", "").strip()
            if not host or host in seen:
                continue
            seen.add(host)

            source: str = obj.get("source", "unknown")
            ip: str = obj.get("ip", "")

            findings.append(Finding(
                title=f"Subdomain Discovered: {host}",
                description=(
                    f"Passive DNS enumeration found subdomain '{host}' "
                    f"(source: {source}" + (f", IP: {ip}" if ip else "") + "). "
                    "Each subdomain expands the attack surface."
                ),
                affected_url=f"https://{host}",
                tool_source=self.name,
                owasp_category="A01",
                severity="info",
                evidence=line[:300],
                remediation_hint=(
                    "Audit all live subdomains. Decommission unused ones. "
                    "Ensure all subdomains enforce HTTPS and have valid certificates."
                ),
            ))

            # Every live subdomain should be probed and resolved
            triggered += [f"httpx_probe:{host}", f"dnsx:{host}"]

        # Deduplicate triggered tools list
        triggered = list(dict.fromkeys(triggered))

        logger.info(
            f"[{scan_id}] subfinder: {len(findings)} subdomains found for {target}"
        )
        return self._timed_result(start, findings, stdout, triggered=triggered)


async def run(params: dict) -> list[Finding]:
    """Orchestrator entry point."""
    tool = SubfinderTool()
    result = await tool.run(
        target=params.get("target", ""),
        params=params,
        scan_id=params.get("scan_id", ""),
    )
    return result.findings
