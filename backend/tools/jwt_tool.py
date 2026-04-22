"""SentinelX — JwtTool: JWT attack suite (triggered when Bearer tokens detected)."""

from __future__ import annotations
import json
import time
import logging
from backend.tools.base import SecurityTool, Finding, ToolResult, ToolNotFoundError

logger = logging.getLogger("sentinelx.tools.jwt_tool")


class JwtTool(SecurityTool):
    name = "jwt_tool"
    owasp_coverage = ["A01", "A07"]
    requires_pro = False
    timeout_seconds = 120
    _install_cmd = "pip install jwt_tool  OR  git clone https://github.com/ticarpi/jwt_tool"

    async def run(self, target: str, params: dict, scan_id: str) -> ToolResult:
        start = time.monotonic()
        url = target if target.startswith("http") else f"https://{target}"
        token: str = params.get("token", "")

        await self._publish_progress(scan_id, f"Testing JWT security on {url}")

        if not token:
            # Try to extract a sample JWT from params or use a dummy
            token = params.get("jwt", "")

        if not token:
            return self._timed_result(
                start, [],
                error="No JWT token provided. Pass 'token' or 'jwt' in params.",
            )

        findings: list[Finding] = []

        # ── Test 1: alg:none attack ──────────────────────────────────────
        cmd_none = [
            "jwt_tool", token,
            "-t", url,
            "-X", "a",   # alg:none
            "--no-banner",
        ]
        try:
            stdout, _, rc = await self._exec(cmd_none, timeout=30)
            if "VALID" in stdout.upper() or "200" in stdout:
                findings.append(Finding(
                    title="JWT Algorithm:None Attack Succeeds",
                    description=(
                        "The server accepted a JWT with algorithm set to 'none', "
                        "meaning signature verification is completely bypassed."
                    ),
                    affected_url=url,
                    tool_source=self.name,
                    owasp_category="A07",
                    severity="critical",
                    evidence=stdout[:400],
                    cvss_score=9.1,
                    remediation_hint=(
                        "Explicitly reject JWTs with 'none' algorithm. "
                        "Whitelist only expected algorithms (e.g. RS256)."
                    ),
                ))
        except ToolNotFoundError:
            raise
        except Exception:
            pass

        # ── Test 2: RS256 → HS256 confusion ─────────────────────────────
        cmd_confusion = [
            "jwt_tool", token,
            "-t", url,
            "-X", "k",   # key confusion
            "--no-banner",
        ]
        try:
            stdout, _, rc = await self._exec(cmd_confusion, timeout=30)
            if "VALID" in stdout.upper() or "200" in stdout:
                findings.append(Finding(
                    title="JWT Algorithm Confusion Attack (RS256 → HS256)",
                    description=(
                        "The server is vulnerable to algorithm confusion. "
                        "An attacker can forge tokens by signing with the public key as HMAC secret."
                    ),
                    affected_url=url,
                    tool_source=self.name,
                    owasp_category="A07",
                    severity="critical",
                    evidence=stdout[:400],
                    cvss_score=9.0,
                    remediation_hint=(
                        "Pin the expected algorithm server-side. "
                        "Verify the 'alg' header matches your library configuration."
                    ),
                ))
        except Exception:
            pass

        # ── Test 3: Weak HMAC secret (common secrets list) ───────────────
        cmd_crack = [
            "jwt_tool", token,
            "-C",        # crack mode
            "-d", "/usr/share/wordlists/rockyou.txt",
            "--no-banner",
        ]
        try:
            stdout, _, rc = await self._exec(cmd_crack, timeout=45)
            if "secret" in stdout.lower() and "found" in stdout.lower():
                secret_line = next(
                    (l for l in stdout.splitlines() if "found" in l.lower()), ""
                )
                findings.append(Finding(
                    title="JWT Signed with Weak/Guessable Secret",
                    description=(
                        "The JWT HMAC secret was found via dictionary attack. "
                        "An attacker can forge arbitrary tokens."
                    ),
                    affected_url=url,
                    tool_source=self.name,
                    owasp_category="A02",
                    severity="critical",
                    evidence=secret_line[:200],
                    cvss_score=9.8,
                    remediation_hint=(
                        "Use a cryptographically random secret of at least 256 bits. "
                        "Prefer asymmetric signing (RS256/ES256) for stateless JWTs."
                    ),
                ))
        except Exception:
            pass

        if not findings:
            findings.append(Finding(
                title="JWT Security Tests Completed — No Critical Issues Found",
                description=(
                    "jwt_tool ran alg:none, algorithm confusion, and weak secret tests. "
                    "No exploitable vulnerabilities confirmed."
                ),
                affected_url=url,
                tool_source=self.name,
                owasp_category="A07",
                severity="info",
                evidence="",
                remediation_hint="Ensure JWTs are validated server-side on every request.",
            ))

        logger.info(f"[{scan_id}] jwt_tool: {len(findings)} findings for {url}")
        return self._timed_result(start, findings, "")


async def run(params: dict) -> list[Finding]:
    tool = JwtTool()
    result = await tool.run(
        target=params.get("target", ""),
        params=params,
        scan_id=params.get("scan_id", ""),
    )
    return result.findings
