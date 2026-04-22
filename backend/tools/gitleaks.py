"""SentinelX — GitleaksTool: git secret scanning (triggered on .git exposure)."""

from __future__ import annotations
import json
import os
import shutil
import subprocess
import tempfile
import time
import logging
from backend.tools.base import SecurityTool, Finding, ToolResult, ToolNotFoundError

logger = logging.getLogger("sentinelx.tools.gitleaks")


class GitleaksTool(SecurityTool):
    name = "gitleaks"
    owasp_coverage = ["A02"]
    requires_pro = False
    timeout_seconds = 180
    _install_cmd = "go install github.com/gitleaks/gitleaks/v8@latest  OR  brew install gitleaks"

    async def run(self, target: str, params: dict, scan_id: str) -> ToolResult:
        start = time.monotonic()
        await self._publish_progress(scan_id, f"Scanning exposed .git for secrets on {target}")

        clone_dir = os.path.join(tempfile.gettempdir(), f"clone_{scan_id}")
        report_file = os.path.join(tempfile.gettempdir(), f"gitleaks_{scan_id}.json")
        findings: list[Finding] = []

        # Construct the repo URL — if .git is exposed, we can clone it
        base = target.replace("https://", "").replace("http://", "").rstrip("/")
        git_url = f"https://{base}"

        try:
            clone_result = subprocess.run(
                ["git", "clone", "--depth", "50", git_url, clone_dir],
                capture_output=True,
                timeout=90,
            )
            cloned = clone_result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            cloned = False

        if not cloned:
            # git-dumper fallback — dump .git over HTTP
            try:
                dump_result = subprocess.run(
                    ["git-dumper", f"https://{base}/.git", clone_dir],
                    capture_output=True,
                    timeout=120,
                )
                cloned = dump_result.returncode == 0
            except FileNotFoundError:
                pass

        if not cloned:
            return self._timed_result(
                start, [],
                error="Could not clone or dump the repository. Ensure git or git-dumper is installed.",
            )

        cmd = [
            "gitleaks",
            "detect",
            "--source", clone_dir,
            "--report-format", "json",
            "--report-path", report_file,
            "--redact",     # redact secret values in report
            "--exit-code", "0",  # don't fail on findings
        ]

        try:
            stdout, stderr, rc = await self._exec(cmd)
        except ToolNotFoundError:
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise
        except Exception as exc:
            shutil.rmtree(clone_dir, ignore_errors=True)
            return self._timed_result(start, [], error=str(exc))

        # Parse JSON report
        if os.path.exists(report_file):
            try:
                with open(report_file, "r", encoding="utf-8", errors="replace") as f:
                    leaks = json.load(f)
                if not isinstance(leaks, list):
                    leaks = []
            except (json.JSONDecodeError, OSError):
                leaks = []
            finally:
                try:
                    os.remove(report_file)
                except OSError:
                    pass

            for leak in leaks:
                rule_id: str = leak.get("RuleID", "unknown")
                secret: str = "[REDACTED]"  # never log actual secrets
                file_path: str = leak.get("File", "")
                commit: str = leak.get("Commit", "")[:12]
                line_num: int = leak.get("StartLine", 0)
                author: str = leak.get("Author", "")
                date: str = leak.get("Date", "")

                findings.append(Finding(
                    title=f"Secret Leaked in Git History: {rule_id}",
                    description=(
                        f"gitleaks found a '{rule_id}' secret in {file_path}:{line_num} "
                        f"(commit: {commit}, author: {author}, date: {date}). "
                        "Exposed via publicly accessible .git directory."
                    ),
                    affected_url=f"https://{base}/.git/{file_path}",
                    tool_source=self.name,
                    owasp_category="A02",
                    severity="critical",
                    evidence=f"File: {file_path}:{line_num} | Commit: {commit}",
                    cvss_score=9.8,
                    remediation_hint=(
                        "1. Rotate the exposed credential IMMEDIATELY. "
                        "2. Block public access to /.git via web server config. "
                        "3. Purge secret from git history: git filter-repo --path <file> --invert-paths. "
                        "4. Add gitleaks pre-commit hook to prevent future leaks."
                    ),
                ))

        shutil.rmtree(clone_dir, ignore_errors=True)
        logger.info(f"[{scan_id}] gitleaks: {len(findings)} secrets for {target}")
        return self._timed_result(start, findings, stdout)


async def run(params: dict) -> list[Finding]:
    tool = GitleaksTool()
    result = await tool.run(
        target=params.get("target", ""),
        params=params,
        scan_id=params.get("scan_id", ""),
    )
    return result.findings
