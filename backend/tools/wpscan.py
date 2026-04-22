"""SentinelX — WpscanTool: WordPress vulnerability scanning (triggered only)."""

from __future__ import annotations
import json
import time
import logging
from backend.tools.base import SecurityTool, Finding, ToolResult, ToolNotFoundError

logger = logging.getLogger("sentinelx.tools.wpscan")


class WpscanTool(SecurityTool):
    name = "wpscan"
    owasp_coverage = ["A06"]
    requires_pro = False
    timeout_seconds = 300
    _install_cmd = "gem install wpscan  OR  docker run wpscanteam/wpscan"

    async def run(self, target: str, params: dict, scan_id: str) -> ToolResult:
        start = time.monotonic()
        url = target if target.startswith("http") else f"https://{target}"
        await self._publish_progress(scan_id, f"WordPress scanning {url}")

        cmd = [
            "wpscan",
            "--url", url,
            "--format", "json",
            "--no-banner",
            "--random-user-agent",
            "--enumerate", "vp,vt,u",   # vulnerable plugins, themes, users
            "--plugins-detection", "passive",
        ]

        api_token = params.get("wpscan_api_token")
        if api_token:
            cmd += ["--api-token", api_token]

        try:
            stdout, stderr, rc = await self._exec(cmd)
        except ToolNotFoundError:
            raise
        except Exception as exc:
            return self._timed_result(start, [], error=str(exc))

        findings: list[Finding] = []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            logger.warning(f"wpscan: failed to parse JSON for {target}")
            return self._timed_result(start, [], stdout, error="JSON parse failed")

        # ── WordPress version ─────────────────────────────────────────────
        wp_version: dict = data.get("version", {})
        if wp_version:
            ver = wp_version.get("number", "unknown")
            vulns: list[dict] = wp_version.get("vulnerabilities", [])
            if vulns:
                for v in vulns:
                    cve_ids = v.get("references", {}).get("cve", [])
                    findings.append(Finding(
                        title=f"WordPress {ver} — Known Vulnerability: {v.get('title', 'Unknown')}",
                        description=v.get("title", ""),
                        affected_url=url,
                        tool_source=self.name,
                        owasp_category="A06",
                        severity="high",
                        evidence=json.dumps(v)[:400],
                        cve_id=f"CVE-{cve_ids[0]}" if cve_ids else None,
                        remediation_hint=f"Update WordPress to the latest version (current: {ver}).",
                    ))

        # ── Plugins ───────────────────────────────────────────────────────
        plugins: dict = data.get("plugins", {})
        for plugin_slug, plugin_data in plugins.items():
            vulns = plugin_data.get("vulnerabilities", [])
            for v in vulns:
                cve_ids = v.get("references", {}).get("cve", [])
                findings.append(Finding(
                    title=f"Vulnerable WordPress Plugin: {plugin_slug}",
                    description=v.get("title", f"Vulnerability in plugin {plugin_slug}"),
                    affected_url=url,
                    tool_source=self.name,
                    owasp_category="A06",
                    severity="high",
                    evidence=json.dumps(v)[:400],
                    cve_id=f"CVE-{cve_ids[0]}" if cve_ids else None,
                    remediation_hint=f"Update or remove the '{plugin_slug}' plugin.",
                ))

        # ── User enumeration ──────────────────────────────────────────────
        users: dict = data.get("users", {})
        if users:
            usernames = list(users.keys())
            findings.append(Finding(
                title=f"WordPress User Enumeration: {', '.join(usernames[:5])}",
                description=(
                    f"wpscan enumerated {len(usernames)} WordPress user(s): {usernames}. "
                    "These usernames can be used in brute-force attacks."
                ),
                affected_url=url,
                tool_source=self.name,
                owasp_category="A07",
                severity="medium",
                evidence=str(usernames[:10]),
                remediation_hint=(
                    "Disable user enumeration via REST API. "
                    "Use a security plugin (e.g. Wordfence) to block enumeration."
                ),
            ))

        logger.info(f"[{scan_id}] wpscan: {len(findings)} findings for {target}")
        return self._timed_result(start, findings, stdout)


async def run(params: dict) -> list[Finding]:
    tool = WpscanTool()
    result = await tool.run(
        target=params.get("target", ""),
        params=params,
        scan_id=params.get("scan_id", ""),
    )
    return result.findings
