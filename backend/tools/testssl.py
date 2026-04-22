"""SentinelX — TestsslTool: TLS/SSL analysis."""

from __future__ import annotations
import json
import os
import time
import tempfile
import logging
from backend.tools.base import SecurityTool, Finding, ToolResult, ToolNotFoundError

logger = logging.getLogger("sentinelx.tools.testssl")

# Mapping of testssl finding IDs to severity
_SEVERITY_MAP = {
    "OK": "info",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
    "WARN": "medium",
    "NOT OK": "high",
}

# testssl finding IDs that map to known OWASP issues
_HIGH_RISK_IDS = {
    "POODLE", "BEAST", "LUCKY13", "SWEET32", "DROWN", "LOGJAM",
    "FREAK", "HEARTBLEED", "ROBOT", "CCS", "TICKETBLEED",
    "expired", "self_signed", "RC4", "NULL_CIPHER", "EXPORT_CIPHER",
}


class TestsslTool(SecurityTool):
    name = "testssl"
    owasp_coverage = ["A02"]
    requires_pro = False
    timeout_seconds = 180
    _install_cmd = "apt-get install testssl.sh  OR  git clone https://github.com/drwetter/testssl.sh"

    async def run(self, target: str, params: dict, scan_id: str) -> ToolResult:
        start = time.monotonic()
        host = target.replace("https://", "").replace("http://", "").rstrip("/")
        port = params.get("port", 443)
        await self._publish_progress(scan_id, f"Analyzing TLS/SSL on {host}:{port}")

        json_out = os.path.join(tempfile.gettempdir(), f"ssl_{scan_id}.json")

        cmd = [
            "testssl.sh",
            "--jsonfile", json_out,
            "--quiet",
            "--fast",          # skip time-expensive checks for speed
            "--color", "0",    # no ANSI escape codes
            f"{host}:{port}",
        ]

        try:
            stdout, stderr, rc = await self._exec(cmd)
        except ToolNotFoundError:
            raise
        except Exception as exc:
            return self._timed_result(start, [], error=str(exc))

        findings: list[Finding] = []

        # Parse the JSON output file
        if os.path.exists(json_out):
            try:
                with open(json_out, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                results = data if isinstance(data, list) else data.get("scanResult", [])
                if isinstance(results, dict):
                    results = results.get("scanResult", [])

                for entry in results:
                    if not isinstance(entry, dict):
                        continue
                    finding_id: str = entry.get("id", "")
                    severity_str: str = entry.get("severity", "OK").upper()
                    finding_str: str = entry.get("finding", "")

                    if severity_str in ("OK", "INFO") and finding_id not in _HIGH_RISK_IDS:
                        continue  # skip informational pass entries

                    sev = _SEVERITY_MAP.get(severity_str, "info")

                    # Promote known critical vulns
                    if any(risk in finding_id.upper() for risk in _HIGH_RISK_IDS):
                        sev = "critical" if severity_str in ("CRITICAL", "HIGH", "NOT OK") else sev

                    findings.append(Finding(
                        title=f"TLS Issue: {finding_id}",
                        description=finding_str or f"testssl detected issue '{finding_id}' on {host}:{port}.",
                        affected_url=f"https://{host}:{port}",
                        tool_source=self.name,
                        owasp_category="A02",
                        severity=sev,  # type: ignore[arg-type]
                        evidence=json.dumps(entry)[:400],
                        remediation_hint=(
                            "Disable deprecated TLS versions (TLS 1.0, 1.1). "
                            "Remove weak cipher suites. Use TLS 1.2+ only. "
                            "Verify certificate chain and expiry."
                        ),
                    ))
            except (json.JSONDecodeError, KeyError) as exc:
                logger.warning(f"testssl JSON parse failed: {exc}")
            finally:
                try:
                    os.remove(json_out)
                except OSError:
                    pass
        else:
            # Fall back to stdout parsing if JSON file wasn't created
            for line in stdout.splitlines():
                if "CRITICAL" in line or "HIGH" in line or "NOT OK" in line:
                    sev = "critical" if "CRITICAL" in line else "high"
                    findings.append(Finding(
                        title=f"TLS Issue Detected",
                        description=line.strip(),
                        affected_url=f"https://{host}",
                        tool_source=self.name,
                        owasp_category="A02",
                        severity=sev,  # type: ignore[arg-type]
                        evidence=line.strip()[:400],
                        remediation_hint="Review TLS configuration and apply recommended hardening.",
                    ))

        logger.info(f"[{scan_id}] testssl: {len(findings)} TLS issues on {host}:{port}")
        return self._timed_result(start, findings, stdout, triggered=[])


async def run(params: dict) -> list[Finding]:
    tool = TestsslTool()
    result = await tool.run(
        target=params.get("target", ""),
        params=params,
        scan_id=params.get("scan_id", ""),
    )
    return result.findings
