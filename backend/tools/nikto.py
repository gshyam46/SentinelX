"""SentinelX — NiktoTool: web server misconfiguration scanner."""

from __future__ import annotations
import json
import os
import tempfile
import time
import logging
from backend.tools.base import SecurityTool, Finding, ToolResult, ToolNotFoundError

logger = logging.getLogger("sentinelx.tools.nikto")

# Nikto OSVDB IDs that map to critical/high findings
_HIGH_OSVDB = {
    "0", "877", "3092", "3093", "3268", "3269",  # Apache, IIS misconfigs
}


class NiktoTool(SecurityTool):
    name = "nikto"
    owasp_coverage = ["A05", "A06"]
    requires_pro = False
    timeout_seconds = 300
    _install_cmd = "apt-get install nikto  OR  brew install nikto"

    async def run(self, target: str, params: dict, scan_id: str) -> ToolResult:
        start = time.monotonic()
        url = target if target.startswith("http") else f"https://{target}"
        out_file = os.path.join(tempfile.gettempdir(), f"nikto_{scan_id}.json")

        await self._publish_progress(scan_id, f"Web server scan on {url}")

        cmd = [
            "nikto",
            "-h", url,
            "-Format", "json",
            "-output", out_file,
            "-nointeractive",
            "-maxtime", "240",   # 4-minute cap per scan
            "-Tuning", "x",     # all tests except DoS
        ]

        try:
            stdout, stderr, rc = await self._exec(cmd)
        except ToolNotFoundError:
            raise
        except Exception as exc:
            return self._timed_result(start, [], error=str(exc))

        findings: list[Finding] = []

        if os.path.exists(out_file):
            try:
                with open(out_file, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)

                vulnerabilities = data.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    msg: str = vuln.get("msg", "")
                    osvdb: str = str(vuln.get("OSVDBID", ""))
                    method: str = vuln.get("method", "GET")
                    vuln_url: str = vuln.get("url", url)

                    if not msg:
                        continue

                    sev = "high" if osvdb in _HIGH_OSVDB else "medium"
                    if any(kw in msg.lower() for kw in ("critical", "remote code", "rce", "shell")):
                        sev = "critical"
                    elif any(kw in msg.lower() for kw in ("information disclosure", "default", "admin")):
                        sev = "medium"

                    findings.append(Finding(
                        title=f"Nikto: {msg[:80]}",
                        description=msg,
                        affected_url=vuln_url,
                        tool_source=self.name,
                        owasp_category="A05",
                        severity=sev,  # type: ignore[arg-type]
                        evidence=f"Method: {method} | OSVDB: {osvdb}",
                        remediation_hint=(
                            "Review and remediate the identified misconfiguration. "
                            "Apply web server hardening guidelines (CIS Benchmark)."
                        ),
                    ))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning(f"nikto JSON parse failed: {exc} — parsing stdout")
                # Fallback: parse plain-text stdout
                for line in stdout.splitlines():
                    if line.startswith("+") and len(line) > 5:
                        findings.append(Finding(
                            title=f"Nikto Finding",
                            description=line.lstrip("+ ").strip(),
                            affected_url=url,
                            tool_source=self.name,
                            owasp_category="A05",
                            severity="medium",
                            evidence=line[:400],
                            remediation_hint="Review web server configuration and apply hardening.",
                        ))
            finally:
                try:
                    os.remove(out_file)
                except OSError:
                    pass

        logger.info(f"[{scan_id}] nikto: {len(findings)} findings for {target}")
        return self._timed_result(start, findings, stdout)


async def run(params: dict) -> list[Finding]:
    tool = NiktoTool()
    result = await tool.run(
        target=params.get("target", ""),
        params=params,
        scan_id=params.get("scan_id", ""),
    )
    return result.findings
