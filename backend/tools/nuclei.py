"""SentinelX — NucleiTool: CVE and misconfiguration scanning."""

from __future__ import annotations
import json
import os
import tempfile
import time
import logging
from backend.tools.base import SecurityTool, Finding, ToolResult, ToolNotFoundError

logger = logging.getLogger("sentinelx.tools.nuclei")

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}

# Template tags that should trigger follow-up tools
_SQLI_TAGS = {"sqli", "sql-injection", "sql", "blind-sqli"}
_XSS_TAGS  = {"xss", "reflected-xss", "stored-xss", "blind-xss"}


class NucleiTool(SecurityTool):
    name = "nuclei"
    owasp_coverage = ["A01", "A03", "A05", "A06", "A07", "A09"]
    requires_pro = False
    timeout_seconds = 1200
    _install_cmd = "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

    async def run(self, target: str, params: dict, scan_id: str) -> ToolResult:
        start = time.monotonic()
        url = target if target.startswith("http") else f"https://{target}"
        await self._publish_progress(scan_id, f"Running Nuclei templates on {target}")

        out_file = os.path.join(tempfile.gettempdir(), f"nuclei_{scan_id}.jsonl")

        cmd = [
            "nuclei",
            "-target", url,
            "-json-export", out_file,
            "-severity", "critical,high,medium,low",
            "-t", "cves",
            "-t", "exposed-panels",
            "-t", "misconfiguration",
            "-t", "takeovers",
            "-t", "default-logins",
            "-t", "ssrf",
            "-t", "xss",
            "-no-color",
            "-silent",
            "-rate-limit", "150",
            "-bulk-size", "25",
            "-concurrency", "10",
        ]

        try:
            stdout, stderr, rc = await self._exec(cmd)
        except ToolNotFoundError:
            raise
        except Exception as exc:
            return self._timed_result(start, [], error=str(exc))

        findings: list[Finding] = []
        triggered: list[str] = []

        # Parse JSONL export file
        lines_src = []
        if os.path.exists(out_file):
            try:
                with open(out_file, "r", encoding="utf-8", errors="replace") as f:
                    lines_src = f.readlines()
            finally:
                try:
                    os.remove(out_file)
                except OSError:
                    pass
        else:
            lines_src = stdout.splitlines()

        for line in lines_src:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            info: dict = obj.get("info", {})
            classification: dict = info.get("classification", {})
            tags: list[str] = [t.lower() for t in (info.get("tags") or [])]
            cve_ids: list[str] = classification.get("cve-id") or []
            cvss: float | None = classification.get("cvss-score")
            owasp_tags: list[str] = [
                t.upper() for t in (classification.get("owasp-id") or [])
                if t.upper().startswith("A")
            ]
            owasp_cat = owasp_tags[0] if owasp_tags else "A05"

            sev_raw = info.get("severity", "info").lower()
            sev = _SEVERITY_MAP.get(sev_raw, "info")

            finding = Finding(
                title=info.get("name", "Nuclei Finding"),
                description=info.get("description", "No description."),
                affected_url=obj.get("matched-at", url),
                tool_source=self.name,
                owasp_category=owasp_cat,
                severity=sev,  # type: ignore[arg-type]
                evidence=(obj.get("extracted-results") or [obj.get("curl-command", "")])[:1].__repr__()[:400],
                cvss_score=cvss,
                cve_id=cve_ids[0] if cve_ids else None,
                remediation_hint=info.get("remediation") or "Apply vendor patch or recommended configuration.",
            )
            findings.append(finding)

            # Trigger follow-ups based on finding tags
            if any(t in _SQLI_TAGS for t in tags):
                triggered.append("sqlmap_scan")
            if any(t in _XSS_TAGS for t in tags):
                triggered.append("dalfox_scan")

        triggered = list(dict.fromkeys(triggered))
        logger.info(f"[{scan_id}] nuclei: {len(findings)} findings for {target}")
        return self._timed_result(start, findings, stdout, triggered=triggered)


async def run(params: dict) -> list[Finding]:
    tool = NucleiTool()
    result = await tool.run(
        target=params.get("target", ""),
        params=params,
        scan_id=params.get("scan_id", ""),
    )
    return result.findings
