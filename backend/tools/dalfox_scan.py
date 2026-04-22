"""SentinelX — DalfoxTool: XSS parameter analysis. PRO ONLY."""

from __future__ import annotations
import json
import time
import logging
from backend.tools.base import SecurityTool, Finding, ToolResult, ToolNotFoundError

logger = logging.getLogger("sentinelx.tools.dalfox_scan")


class DalfoxTool(SecurityTool):
    name = "dalfox_scan"
    owasp_coverage = ["A03"]
    requires_pro = True
    timeout_seconds = 300
    _install_cmd = "go install github.com/hahwul/dalfox/v2@latest"

    async def run(self, target: str, params: dict, scan_id: str) -> ToolResult:
        start = time.monotonic()
        url = params.get("url", target)
        if not url.startswith("http"):
            url = f"https://{url}"

        await self._publish_progress(scan_id, f"XSS scanning {url}")

        cmd = [
            "dalfox",
            "url", url,
            "--format", "json",
            "--silence",
            "--no-color",
            "--timeout", "10",
            "--worker", "20",
        ]

        # Include discovered params from arjun if provided
        extra_params = params.get("parameters", [])
        if extra_params:
            cmd += ["--custom-payload-file", "/dev/null"]  # placeholder
            cmd += ["--data", "&".join(f"{p}=FUZZ" for p in extra_params)]

        try:
            stdout, stderr, rc = await self._exec(cmd)
        except ToolNotFoundError:
            raise
        except Exception as exc:
            return self._timed_result(start, [], error=str(exc))

        findings: list[Finding] = []

        # dalfox outputs one JSON object per line
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # Some dalfox versions print plain-text POC lines
                if "PoC:" in line or "XSS" in line:
                    findings.append(Finding(
                        title="Cross-Site Scripting (XSS) Detected",
                        description=f"dalfox found an XSS vulnerability. PoC: {line[:300]}",
                        affected_url=url,
                        tool_source=self.name,
                        owasp_category="A03",
                        severity="high",
                        evidence=line[:400],
                        cvss_score=6.1,
                        remediation_hint=(
                            "HTML-encode all user input before rendering. "
                            "Implement a strict Content-Security-Policy."
                        ),
                    ))
                continue

            vuln_type: str = obj.get("type", "XSS")
            param: str = obj.get("param", "unknown")
            poc: str = obj.get("poc", "")
            cwe: str = obj.get("cwe", "")

            findings.append(Finding(
                title=f"{vuln_type} Vulnerability — Parameter: {param}",
                description=(
                    f"dalfox confirmed {vuln_type} in parameter '{param}' on {url}. "
                    "Attacker can execute arbitrary JavaScript in the victim's browser."
                ),
                affected_url=url,
                tool_source=self.name,
                owasp_category="A03",
                severity="high",
                evidence=poc[:400],
                cvss_score=6.1,
                remediation_hint=(
                    "HTML-encode all user-controlled data before output. "
                    "Implement CSP with script-src 'self'. "
                    "Use HttpOnly + Secure flags on session cookies."
                ),
            ))

        logger.info(f"[{scan_id}] dalfox: {len(findings)} XSS findings for {url}")
        return self._timed_result(start, findings, stdout)


async def run(params: dict) -> list[Finding]:
    tool = DalfoxTool()
    result = await tool.run(
        target=params.get("target", ""),
        params=params,
        scan_id=params.get("scan_id", ""),
    )
    return result.findings
