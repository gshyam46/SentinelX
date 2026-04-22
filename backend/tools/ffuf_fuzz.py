"""SentinelX — FfufTool: directory and endpoint fuzzing."""

from __future__ import annotations
import json
import os
import tempfile
import time
import logging
from backend.tools.base import SecurityTool, Finding, ToolResult, ToolNotFoundError

logger = logging.getLogger("sentinelx.tools.ffuf_fuzz")

_DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
_FALLBACK_WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"


class FfufTool(SecurityTool):
    name = "ffuf_fuzz"
    owasp_coverage = ["A01", "A05"]
    requires_pro = False
    timeout_seconds = 300
    _install_cmd = "go install github.com/ffuf/ffuf/v2@latest"

    async def run(self, target: str, params: dict, scan_id: str) -> ToolResult:
        start = time.monotonic()
        base_url = target if target.startswith("http") else f"https://{target}"
        out_file = os.path.join(tempfile.gettempdir(), f"ffuf_{scan_id}.json")

        wordlist = (
            params.get("wordlist")
            or (_DEFAULT_WORDLIST if os.path.exists(_DEFAULT_WORDLIST) else _FALLBACK_WORDLIST)
        )

        await self._publish_progress(scan_id, f"Directory fuzzing {base_url}")

        cmd = [
            "ffuf",
            "-u", f"{base_url}/FUZZ",
            "-w", wordlist,
            "-o", out_file,
            "-of", "json",
            "-ac",                          # auto-calibrate (removes false positives)
            "-mc", "200,201,204,301,302,403",
            "-t", "40",                     # 40 concurrent threads
            "-timeout", "10",
            "-noninteractive",
            "-s",                           # silent (no banner)
        ]

        try:
            stdout, stderr, rc = await self._exec(cmd)
        except ToolNotFoundError:
            raise
        except Exception as exc:
            return self._timed_result(start, [], error=str(exc))

        findings: list[Finding] = []
        triggered: list[str] = []
        api_paths: list[str] = []
        dir_count = 0

        if os.path.exists(out_file):
            try:
                with open(out_file, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                results: list[dict] = data.get("results", [])
            except (json.JSONDecodeError, OSError):
                results = []
            finally:
                try:
                    os.remove(out_file)
                except OSError:
                    pass

            for r in results:
                path: str = r.get("input", {}).get("FUZZ", r.get("url", ""))
                status: int = r.get("status", 0)
                length: int = r.get("length", 0)
                full_url = f"{base_url}/{path}".rstrip("/")

                # Severity based on status
                if status == 200:
                    sev = "medium"
                elif status in (301, 302):
                    sev = "info"
                elif status == 403:
                    sev = "low"
                else:
                    sev = "info"

                findings.append(Finding(
                    title=f"Directory/Path Found: /{path}",
                    description=(
                        f"HTTP {status} response for {full_url} "
                        f"(content length: {length} bytes). "
                        "Exposed paths may reveal sensitive functionality."
                    ),
                    affected_url=full_url,
                    tool_source=self.name,
                    owasp_category="A01",
                    severity=sev,  # type: ignore[arg-type]
                    evidence=f"HTTP {status} — {length} bytes",
                    remediation_hint=(
                        "Restrict access to sensitive directories. "
                        "Return 404 rather than 403 to avoid confirming path existence."
                    ),
                ))

                if "/api" in path.lower():
                    api_paths.append(full_url)

                dir_count += 1

        # Trigger arjun for each API path found
        for api_path in api_paths:
            triggered.append(f"arjun:{api_path}")

        # Trigger feroxbuster for recursive enumeration if >5 dirs found (pro)
        if dir_count > 5:
            triggered.append("feroxbuster")

        triggered = list(dict.fromkeys(triggered))
        logger.info(f"[{scan_id}] ffuf: {dir_count} paths, {len(api_paths)} API paths for {target}")
        return self._timed_result(start, findings, stdout, triggered=triggered)


async def run(params: dict) -> list[Finding]:
    tool = FfufTool()
    result = await tool.run(
        target=params.get("target", ""),
        params=params,
        scan_id=params.get("scan_id", ""),
    )
    return result.findings
