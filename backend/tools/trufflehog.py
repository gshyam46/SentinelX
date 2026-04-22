"""SentinelX — TrufflehogTool: secret/credential scanning."""

from __future__ import annotations
import json
import os
import shutil
import subprocess
import tempfile
import time
import logging
from backend.tools.base import SecurityTool, Finding, ToolResult, ToolNotFoundError

logger = logging.getLogger("sentinelx.tools.trufflehog")


class TrufflehogTool(SecurityTool):
    name = "trufflehog"
    owasp_coverage = ["A02"]
    requires_pro = False
    timeout_seconds = 180
    _install_cmd = "go install github.com/trufflesecurity/trufflehog/v3@latest"

    async def run(self, target: str, params: dict, scan_id: str) -> ToolResult:
        start = time.monotonic()
        await self._publish_progress(scan_id, f"Scanning for exposed secrets on {target}")

        clone_dir = os.path.join(tempfile.gettempdir(), f"clone_{scan_id}")
        findings: list[Finding] = []
        raw_output = ""

        # Determine scan mode: git repo or HTTP target
        is_git_url = (
            target.startswith("https://github.com")
            or target.startswith("https://gitlab.com")
            or target.startswith("git@")
        )

        if is_git_url:
            # Clone repo then scan filesystem
            try:
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", target, clone_dir],
                    capture_output=True, timeout=60
                )
                if result.returncode != 0:
                    return self._timed_result(
                        start, [], error=f"git clone failed: {result.stderr.decode()[:200]}"
                    )
            except FileNotFoundError:
                return self._timed_result(start, [], error="git not installed")
            except subprocess.TimeoutExpired:
                return self._timed_result(start, [], error="git clone timed out")

            cmd = [
                "trufflehog",
                "filesystem",
                "--directory", clone_dir,
                "--json",
                "--no-update",
            ]
        else:
            # Scan HTTP target directly
            url = target if target.startswith("http") else f"https://{target}"
            cmd = [
                "trufflehog",
                "http",
                "--url", url,
                "--json",
                "--no-update",
            ]

        try:
            stdout, stderr, rc = await self._exec(cmd)
            raw_output = stdout
        except ToolNotFoundError:
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise
        except Exception as exc:
            shutil.rmtree(clone_dir, ignore_errors=True)
            return self._timed_result(start, [], error=str(exc))

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            detector: str = obj.get("DetectorName", obj.get("detector_name", "Unknown"))
            raw_val: str = obj.get("Raw", obj.get("raw", ""))[:200]
            source_meta: dict = obj.get("SourceMetadata", {}) or {}
            source_data: dict = source_meta.get("Data", {}) or {}
            file_path: str = (
                source_data.get("Filesystem", {}).get("file", "")
                or source_data.get("Git", {}).get("file", "")
                or ""
            )
            verified: bool = obj.get("Verified", False)

            sev = "critical" if verified else "high"
            findings.append(Finding(
                title=f"Secret Exposed: {detector}",
                description=(
                    f"{'Verified' if verified else 'Potential'} secret of type '{detector}' "
                    f"found{' in ' + file_path if file_path else ''}. "
                    "Exposed credentials allow unauthorized access to third-party services."
                ),
                affected_url=target if not file_path else f"{target}/{file_path}",
                tool_source=self.name,
                owasp_category="A02",
                severity=sev,  # type: ignore[arg-type]
                evidence=raw_val,
                cvss_score=9.8 if verified else 7.5,
                remediation_hint=(
                    "Rotate the exposed credential immediately. "
                    "Remove from repository history using git-filter-repo. "
                    "Add pre-commit hooks (trufflehog / gitleaks) to prevent future leaks."
                ),
            ))

        shutil.rmtree(clone_dir, ignore_errors=True)
        logger.info(f"[{scan_id}] trufflehog: {len(findings)} secrets found for {target}")
        return self._timed_result(start, findings, raw_output)


async def run(params: dict) -> list[Finding]:
    tool = TrufflehogTool()
    result = await tool.run(
        target=params.get("target", ""),
        params=params,
        scan_id=params.get("scan_id", ""),
    )
    return result.findings
