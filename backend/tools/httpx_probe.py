"""SentinelX — HttpxProbeTool: live host probing and tech fingerprinting."""

from __future__ import annotations
import json
import time
import logging
from backend.tools.base import SecurityTool, Finding, ToolResult, ToolNotFoundError

logger = logging.getLogger("sentinelx.tools.httpx_probe")

# Headers that indicate weak security posture
_MISSING_HEADER_FINDINGS = [
    ("strict-transport-security", "Missing HSTS Header", "A02", "high",
     "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("content-security-policy", "Missing Content-Security-Policy Header", "A05", "high",
     "Implement a strict CSP: default-src 'self'; script-src 'self'"),
    ("x-frame-options", "Missing X-Frame-Options Header", "A05", "medium",
     "Add: X-Frame-Options: DENY"),
    ("x-content-type-options", "Missing X-Content-Type-Options Header", "A05", "medium",
     "Add: X-Content-Type-Options: nosniff"),
]


class HttpxProbeTool(SecurityTool):
    name = "httpx_probe"
    owasp_coverage = ["A02", "A05", "A06"]
    requires_pro = False
    timeout_seconds = 90
    _install_cmd = "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"

    async def run(self, target: str, params: dict, scan_id: str) -> ToolResult:
        start = time.monotonic()
        await self._publish_progress(scan_id, f"Probing {target} for live services")

        url = target if target.startswith("http") else f"https://{target}"

        cmd = [
            "httpx",
            "-u", url,
            "-json",
            "-tech-detect",
            "-status-code",
            "-title",
            "-server",
            "-content-length",
            "-follow-redirects",
            "-response-in-json",
            "-silent",
            "-timeout", "15",
        ]

        try:
            stdout, stderr, rc = await self._exec(cmd)
        except ToolNotFoundError:
            raise
        except Exception as exc:
            return self._timed_result(start, [], error=str(exc))

        findings: list[Finding] = []
        triggered: list[str] = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            live_url: str = obj.get("url", url)
            status: int = obj.get("status-code", 0)
            server: str = obj.get("server", "")
            title: str = obj.get("title", "")
            technologies: list[str] = obj.get("technologies", []) or []
            headers_raw: dict = obj.get("headers", {}) or {}
            response_body: str = (obj.get("response", "") or "")[:2000]

            # ── Technology disclosure ───────────────────────────────────────
            if server:
                findings.append(Finding(
                    title=f"Server Banner Disclosed: {server}",
                    description=(
                        f"The server responded with a Server header value of '{server}'. "
                        "This reveals software version details useful for targeted attacks."
                    ),
                    affected_url=live_url,
                    tool_source=self.name,
                    owasp_category="A05",
                    severity="info",
                    evidence=f"Server: {server}",
                    remediation_hint="Remove or obfuscate the Server header in web server config.",
                ))

            # ── Detected technologies ────────────────────────────────────────
            tech_str = ", ".join(technologies) if technologies else ""
            if tech_str:
                findings.append(Finding(
                    title=f"Technology Stack Identified: {tech_str}",
                    description=(
                        f"httpx fingerprinted the following technologies on {live_url}: {tech_str}. "
                        "Known CVEs for these versions should be checked."
                    ),
                    affected_url=live_url,
                    tool_source=self.name,
                    owasp_category="A06",
                    severity="info",
                    evidence=tech_str,
                    remediation_hint="Keep all frameworks and libraries up to date.",
                ))

            # ── Trigger wpscan if WordPress detected ────────────────────────
            if any("wordpress" in t.lower() for t in technologies):
                triggered.append("wpscan")
                findings.append(Finding(
                    title="WordPress CMS Detected",
                    description=(
                        f"WordPress was identified on {live_url}. "
                        "WordPress installations require dedicated vulnerability scanning."
                    ),
                    affected_url=live_url,
                    tool_source=self.name,
                    owasp_category="A06",
                    severity="medium",
                    evidence=tech_str,
                    remediation_hint="Run wpscan to enumerate plugins, themes, and known CVEs.",
                ))

            # ── Trigger jwt_tool if auth header in response ─────────────────
            auth_header = headers_raw.get("www-authenticate", "") or headers_raw.get("authorization", "")
            if "bearer" in auth_header.lower() or "bearer" in response_body.lower()[:500]:
                triggered.append("jwt_tool")

            # ── Check for missing security headers ──────────────────────────
            headers_lower = {k.lower(): v for k, v in headers_raw.items()}
            for header_name, title, owasp, sev, hint in _MISSING_HEADER_FINDINGS:
                if header_name not in headers_lower:
                    findings.append(Finding(
                        title=title,
                        description=f"The response from {live_url} is missing the '{header_name}' security header.",
                        affected_url=live_url,
                        tool_source=self.name,
                        owasp_category=owasp,
                        severity=sev,  # type: ignore[arg-type]
                        evidence=f"HTTP {status} — header absent",
                        remediation_hint=hint,
                    ))

            # ── HTTP (non-HTTPS) ────────────────────────────────────────────
            if live_url.startswith("http://") and status < 400:
                findings.append(Finding(
                    title="Plaintext HTTP Service Active",
                    description=(
                        f"{live_url} responds over plain HTTP. "
                        "Credentials and session tokens transmitted in cleartext."
                    ),
                    affected_url=live_url,
                    tool_source=self.name,
                    owasp_category="A02",
                    severity="high",
                    evidence=f"HTTP {status} on non-TLS URL",
                    remediation_hint="Force HTTPS redirect and enable HSTS.",
                ))

        triggered = list(dict.fromkeys(triggered))
        logger.info(f"[{scan_id}] httpx_probe: {len(findings)} findings for {target}")
        return self._timed_result(start, findings, stdout, triggered=triggered)


async def run(params: dict) -> list[Finding]:
    tool = HttpxProbeTool()
    result = await tool.run(
        target=params.get("target", ""),
        params=params,
        scan_id=params.get("scan_id", ""),
    )
    return result.findings
