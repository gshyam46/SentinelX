"""SentinelX — SqlmapTool: automated SQL injection detection. PRO ONLY."""

from __future__ import annotations
import json
import os
import shutil
import tempfile
import time
import logging
from backend.tools.base import SecurityTool, Finding, ToolResult, ToolNotFoundError

logger = logging.getLogger("sentinelx.tools.sqlmap_scan")


class SqlmapTool(SecurityTool):
    name = "sqlmap_scan"
    owasp_coverage = ["A03"]
    requires_pro = True
    timeout_seconds = 600
    _install_cmd = "pip install sqlmap  OR  apt-get install sqlmap"

    async def run(self, target: str, params: dict, scan_id: str) -> ToolResult:
        start = time.monotonic()
        url = target if target.startswith("http") else f"https://{target}"
        output_dir = os.path.join(tempfile.gettempdir(), f"sqlmap_{scan_id}")
        os.makedirs(output_dir, exist_ok=True)

        await self._publish_progress(scan_id, f"Testing SQL injection on {target}")

        # Additional params from orchestrator (e.g. specific endpoint, form data)
        extra_url = params.get("url", url)
        dbms = params.get("dbms")

        cmd = [
            "sqlmap",
            "-u", extra_url,
            "--batch",               # non-interactive
            "--random-agent",
            "--level", "2",
            "--risk", "1",           # safe: no dangerous payloads
            "--forms",               # test form fields
            "--crawl", "2",
            "--output-dir", output_dir,
            "--flush-session",
        ]
        if dbms:
            cmd += ["--dbms", dbms]

        try:
            stdout, stderr, rc = await self._exec(cmd)
        except ToolNotFoundError:
            raise
        except Exception as exc:
            shutil.rmtree(output_dir, ignore_errors=True)
            return self._timed_result(start, [], error=str(exc))

        findings: list[Finding] = []

        # sqlmap stores results per-target in subdirectories
        for root_dir, dirs, files in os.walk(output_dir):
            for fname in files:
                if fname != "log":
                    continue
                try:
                    with open(os.path.join(root_dir, fname), "r", errors="replace") as f:
                        log_content = f.read()
                    if "is vulnerable" in log_content or "sqlmap identified" in log_content:
                        # Extract injectable param name from log
                        param = "unknown"
                        for line in log_content.splitlines():
                            if "Parameter:" in line:
                                param = line.split("Parameter:")[-1].strip()
                                break
                        findings.append(Finding(
                            title=f"SQL Injection Vulnerability — Parameter: {param}",
                            description=(
                                f"sqlmap confirmed SQL injection in parameter '{param}' on {extra_url}. "
                                "An attacker can read, modify, or delete database contents."
                            ),
                            affected_url=extra_url,
                            tool_source=self.name,
                            owasp_category="A03",
                            severity="critical",
                            evidence=log_content[:600],
                            cvss_score=9.8,
                            remediation_hint=(
                                "Use parameterized queries / prepared statements. "
                                "Never concatenate user input into SQL strings. "
                                "Apply least-privilege database accounts."
                            ),
                        ))
                except OSError:
                    continue

        # If no confirmed findings but suspicious output
        if not findings and ("might be injectable" in stdout or "heuristic" in stdout):
            findings.append(Finding(
                title="Potential SQL Injection Point Detected (Unconfirmed)",
                description=(
                    f"sqlmap heuristics suggest a possible injection point on {extra_url}. "
                    "Manual verification is recommended."
                ),
                affected_url=extra_url,
                tool_source=self.name,
                owasp_category="A03",
                severity="medium",
                evidence=stdout[:400],
                remediation_hint="Review all user-controlled parameters for proper parameterization.",
            ))

        shutil.rmtree(output_dir, ignore_errors=True)
        logger.info(f"[{scan_id}] sqlmap: {len(findings)} findings for {target}")
        return self._timed_result(start, findings, stdout)


async def run(params: dict) -> list[Finding]:
    tool = SqlmapTool()
    result = await tool.run(
        target=params.get("target", ""),
        params=params,
        scan_id=params.get("scan_id", ""),
    )
    return result.findings
