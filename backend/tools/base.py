"""
SentinelX — Tool Base Layer
Shared types and base class for every security tool wrapper.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal, Optional

logger = logging.getLogger("sentinelx.tools")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ToolNotFoundError(Exception):
    """Raised when the tool binary is not installed on the system."""
    def __init__(self, tool_name: str, install_cmd: str):
        self.tool_name = tool_name
        self.install_cmd = install_cmd
        super().__init__(
            f"Tool '{tool_name}' not found. Install with: {install_cmd}"
        )


# ---------------------------------------------------------------------------
# Shared data models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    title: str
    description: str
    affected_url: str
    tool_source: str
    owasp_category: str                        # "A01" … "A10"
    severity: Literal["critical", "high", "medium", "low", "info"]
    evidence: str = ""                          # raw proof: banner, snippet, header
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    remediation_hint: Optional[str] = None
    is_new: bool = True
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "tool_source": self.tool_source,
            "owasp_category": self.owasp_category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "affected_url": self.affected_url,
            "evidence": self.evidence[:500] if self.evidence else "",
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id,
            "remediation_hint": self.remediation_hint,
            "is_new": self.is_new,
            "discovered_at": self.discovered_at,
        }


@dataclass
class ToolResult:
    tool_name: str
    findings: list[Finding]
    raw_output: str
    duration_seconds: float
    error: Optional[str] = None
    triggered_tools: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.error is None

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "findings": [f.to_dict() for f in self.findings],
            "duration_seconds": round(self.duration_seconds, 2),
            "error": self.error,
            "triggered_tools": self.triggered_tools,
            "finding_count": len(self.findings),
        }


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class SecurityTool(ABC):
    name: str = "base"
    owasp_coverage: list[str] = []
    requires_pro: bool = False
    timeout_seconds: int = 300
    _install_cmd: str = "see documentation"

    @abstractmethod
    async def run(
        self,
        target: str,
        params: dict,
        scan_id: str,
    ) -> ToolResult:
        """Execute the tool and return structured findings."""

    async def _exec(
        self,
        cmd: list[str],
        timeout: Optional[int] = None,
    ) -> tuple[str, str, int]:
        """
        Safe async subprocess executor.
        - Never uses shell=True
        - Enforces timeout (falls back to self.timeout_seconds)
        - Returns (stdout, stderr, returncode)
        """
        _timeout = timeout or self.timeout_seconds
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=_timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                raise asyncio.TimeoutError(
                    f"Tool '{self.name}' timed out after {_timeout}s"
                )

            return (
                stdout_bytes.decode("utf-8", errors="replace"),
                stderr_bytes.decode("utf-8", errors="replace"),
                proc.returncode or 0,
            )
        except FileNotFoundError:
            raise ToolNotFoundError(self.name, self._install_cmd)

    async def _check_binary(self, binary: str) -> bool:
        """Return True if `binary` is on PATH."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "which", binary,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            return proc.returncode == 0
        except Exception:
            return False

    async def _publish_progress(self, scan_id: str, message: str) -> None:
        """Publish a progress event to Redis scan:{scan_id}:events."""
        try:
            import redis.asyncio as aioredis
            from backend.config import get_settings
            r = aioredis.from_url(get_settings().REDIS_URL, decode_responses=True)
            payload = json.dumps({
                "type": "tool_progress",
                "tool": self.name,
                "message": message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            await r.publish(f"scan:{scan_id}:events", payload)
            await r.aclose()
        except Exception:
            pass  # Redis unavailable — not fatal

    def _timed_result(
        self,
        start: float,
        findings: list[Finding],
        raw: str = "",
        error: Optional[str] = None,
        triggered: Optional[list[str]] = None,
    ) -> ToolResult:
        import time
        return ToolResult(
            tool_name=self.name,
            findings=findings,
            raw_output=raw[:4096],
            duration_seconds=time.monotonic() - start,
            error=error,
            triggered_tools=triggered or [],
        )
