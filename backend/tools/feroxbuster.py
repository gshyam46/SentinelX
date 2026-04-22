"""SentinelX — FeroxbusterTool: recursive directory brute-forcing. PRO ONLY."""

from __future__ import annotations
import json
import os
import tempfile
import time
import logging
from backend.tools.base import SecurityTool, Finding, ToolResult, ToolNotFoundError

logger = logging.getLogger("sentinelx.tools.feroxbuster")

_DEFAULT_WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"


class FeroxbusterTool(SecurityTool):
    name = "feroxbuster"
    owasp_coverage = ["A01", "A05"]
    requires_pro = True
    timeout_seconds = 600
    _install_cmd = "cargo install feroxbuster  OR  apt-get install feroxbuster"

    async def run(self, target: str, params: dict, scan_id: str) -> ToolResult:
        start = time.monotonic()
        url = target if target.startswith("http") else f"https://{target}"
        out_file = os.path.join(tempfile.gettempdir(), f"ferox_{scan_id}.json")

        wordlist = params.get("wordlist", _DEFAULT_WORDLIST)
        if not os.path.exists(wordlist):
            return self._timed_result(
                start, [],
                error=f"Wordlist not found: {wordlist}. Install: apt-get install wordlists",
            )

        await self._publish_progress(scan_id, f"Recursive directory brute-force on {url}")

        cmd = [
            "feroxbuster",
            "--url", url,
            "--wordlist", wordlist,
            "--output", out_file,
            "--json",
            "--quiet",
            "--auto-tune",           # adaptive rate limiting
            "--no-recursion",        # controlled depth — orchestrator decides
            "--depth", "3",
            "--threads", "50",
            "--timeout", "10",
            "--filter-status", "404",
            "--status-codes", "200,201,204,301,302,403,405",
        ]

        try:
            stdout, stderr, rc = await self._exec(cmd)
        except ToolNotFoundError:
            raise
        except Exception as exc:
            return self._timed_result(start, [], error=str(exc))

        findings: list[Finding] = []
        results: list[dict] = []

        if os.path.exists(out_file):
            try:
                with open(out_file, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            if obj.get("type") == "response":
                                results.append(obj)
                        except json.JSONDecodeError:
                            continue
            finally:
                try:
                    os.remove(out_file)
                except OSError:
                    pass

        for r in results:
            status: int = r.get("status", 0)
            found_url: str = r.get("url", url)
            content_length: int = r.get("content_length", 0)

            # Skip obvious false-positives
            if content_length == 0 and status not in (301, 302):
                continue

            if status == 200:
                sev = "medium"
            elif status == 403:
                sev = "low"
            elif status in (301, 302):
                sev = "info"
            else:
                sev = "info"

            findings.append(Finding(
                title=f"Directory Found (recursive): {found_url}",
                description=(
                    f"feroxbuster found {found_url} returning HTTP {status} "
                    f"({content_length} bytes). Recursive enumeration may reveal "
                    "hidden admin panels, APIs, or sensitive files."
                ),
                affected_url=found_url,
                tool_source=self.name,
                owasp_category="A01",
                severity=sev,  # type: ignore[arg-type]
                evidence=f"HTTP {status} — {content_length} bytes",
                remediation_hint=(
                    "Review all exposed paths. Restrict access to sensitive directories. "
                    "Implement authentication on admin interfaces."
                ),
            ))

        logger.info(f"[{scan_id}] feroxbuster: {len(findings)} paths for {target}")
        return self._timed_result(start, findings, stdout)


async def run(params: dict) -> list[Finding]:
    tool = FeroxbusterTool()
    result = await tool.run(
        target=params.get("target", ""),
        params=params,
        scan_id=params.get("scan_id", ""),
    )
    return result.findings
