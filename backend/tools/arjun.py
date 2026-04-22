"""SentinelX — ArjunTool: hidden HTTP parameter discovery."""

from __future__ import annotations
import json
import os
import tempfile
import time
import logging
from backend.tools.base import SecurityTool, Finding, ToolResult, ToolNotFoundError

logger = logging.getLogger("sentinelx.tools.arjun")


class ArjunTool(SecurityTool):
    name = "arjun"
    owasp_coverage = ["A01", "A03"]
    requires_pro = False
    timeout_seconds = 180
    _install_cmd = "pip install arjun"

    async def run(self, target: str, params: dict, scan_id: str) -> ToolResult:
        start = time.monotonic()
        url = params.get("url", target)
        if not url.startswith("http"):
            url = f"https://{url}"

        out_file = os.path.join(tempfile.gettempdir(), f"arjun_{scan_id}.json")
        await self._publish_progress(scan_id, f"Discovering hidden parameters on {url}")

        cmd = [
            "arjun",
            "-u", url,
            "--json",
            "-oJ", out_file,
            "-t", "20",      # threads
            "--stable",      # stable/safe mode
        ]

        try:
            stdout, stderr, rc = await self._exec(cmd)
        except ToolNotFoundError:
            raise
        except Exception as exc:
            return self._timed_result(start, [], error=str(exc))

        findings: list[Finding] = []
        triggered: list[str] = []
        discovered_params: list[str] = []

        if os.path.exists(out_file):
            try:
                with open(out_file, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                # arjun JSON: {url: [param1, param2, ...]}
                for endpoint_url, params_list in data.items():
                    if isinstance(params_list, list) and params_list:
                        discovered_params.extend(params_list)
                        findings.append(Finding(
                            title=f"Hidden Parameters Discovered: {', '.join(params_list[:8])}",
                            description=(
                                f"arjun found {len(params_list)} hidden HTTP parameter(s) on {endpoint_url}: "
                                f"{params_list}. Hidden parameters are often untested and vulnerable."
                            ),
                            affected_url=endpoint_url,
                            tool_source=self.name,
                            owasp_category="A01",
                            severity="medium",
                            evidence=str(params_list[:20]),
                            remediation_hint=(
                                "Test all discovered parameters for injection, IDOR, and mass assignment. "
                                "Implement strict server-side input validation."
                            ),
                        ))
            except (json.JSONDecodeError, OSError):
                pass
            finally:
                try:
                    os.remove(out_file)
                except OSError:
                    pass

        # If parameters found, trigger dalfox and sqlmap with the params
        if discovered_params:
            triggered += ["dalfox_scan", "sqlmap_scan"]

        triggered = list(dict.fromkeys(triggered))
        logger.info(f"[{scan_id}] arjun: {len(discovered_params)} params found on {url}")
        return self._timed_result(start, findings, stdout, triggered=triggered)


async def run(params: dict) -> list[Finding]:
    tool = ArjunTool()
    result = await tool.run(
        target=params.get("target", ""),
        params=params,
        scan_id=params.get("scan_id", ""),
    )
    return result.findings
