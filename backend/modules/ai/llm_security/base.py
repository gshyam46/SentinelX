"""
SentinelX Phase 3 — LLM Security Base Layer

Foundation models and abstract base class for all OWASP LLM Top 10 checks.
Every check subclasses BaseCheck, uses its HTTP helpers, and returns a LLMRiskItem.
No mock data — all checks perform real active probing against live targets.
"""

from __future__ import annotations

import asyncio
import logging
import re
from abc import ABC, abstractmethod
from typing import Any, Optional

import aiohttp
from pydantic import BaseModel, Field

logger = logging.getLogger("sentinelx.llmsec")

# ---------------------------------------------------------------------------
# Common AI endpoint path patterns (OpenAI-compat, Anthropic, generic)
# ---------------------------------------------------------------------------

KNOWN_AI_PATHS: list[str] = [
    # OpenAI-compatible
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/messages",
    "/v1/models",
    # Versioned API
    "/api/v1/chat",
    "/api/v1/completions",
    "/api/v1/messages",
    "/api/v1/chat/completions",
    # Generic AI endpoints
    "/api/chat",
    "/api/complete",
    "/api/generate",
    "/api/ask",
    "/api/ai/chat",
    "/api/ai/ask",
    "/api/llm/chat",
    "/api/llm/complete",
    "/api/openai/chat",
    "/api/gpt",
    "/api/claude",
    "/api/copilot",
    "/api/assistant",
    "/api/bot/message",
    "/api/agent/run",
    "/api/agent/chat",
    # Short paths
    "/chat",
    "/chatbot",
    "/assistant",
    "/complete",
    "/generate",
    # Tool/plugin endpoints
    "/api/tools",
    "/api/plugins",
    "/api/functions",
    "/api/actions",
    # Info/model endpoints
    "/model",
    "/info",
    "/health",
    "/.well-known/ai-plugin.json",
    "/openapi.yaml",
    "/openapi.json",
]

# Response headers indicating AI backend presence
AI_RESPONSE_HEADER_PATTERNS: list[str] = [
    "x-model-name",
    "x-ai-model",
    "x-openai-model",
    "x-openai-organization",
    "x-anthropic-",
    "x-groq-",
    "x-llm-",
    "x-chat-model",
    "x-request-id",       # common in OpenAI
    "openai-processing-ms",
    "openai-version",
    "anthropic-version",
]

# ---------------------------------------------------------------------------
# Regex patterns for sensitive data in LLM responses
# ---------------------------------------------------------------------------

SENSITIVE_PATTERNS: dict[str, re.Pattern[str]] = {
    "openai_api_key":     re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    "anthropic_api_key":  re.compile(r"sk-ant-[a-zA-Z0-9\-_]{20,}"),
    "aws_access_key":     re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key":     re.compile(
        r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"
    ),
    "generic_api_key":    re.compile(
        r"(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[=:]\s*['\"]?[a-zA-Z0-9\-_]{20,}['\"]?"
    ),
    "password_field":     re.compile(
        r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]?"
    ),
    "private_key":        re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    "jwt_token":          re.compile(
        r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
    ),
    "database_conn_str":  re.compile(
        r"(?i)(?:postgresql|mysql|mongodb|redis)://[^\s'\"<>]{10,}"
    ),
    "internal_path_unix": re.compile(
        r"/(?:etc|home|var|root|opt|usr|tmp)/[a-zA-Z0-9/._-]{5,}"
    ),
    "internal_path_win":  re.compile(
        r"[Cc]:\\(?:Users|Windows|Program Files|ProgramData)[\\a-zA-Z0-9 ._-]{5,}"
    ),
    "ipv4_internal":      re.compile(
        r"(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}"
    ),
    "system_prompt_leak": re.compile(
        r"(?i)\b(you are (?:a |an )?(?:helpful|assistant|AI|bot)|"
        r"your (?:instructions|task|role|job) (?:is|are)|"
        r"act as (?:a |an )?|"
        r"you must (?:always|never|not)|"
        r"respond (?:only|always) (?:in|with|as))\b"
    ),
    "embedding_vector":   re.compile(
        r"\[(?:\s*-?\d+(?:\.\d+)?(?:e[+-]?\d+)?\s*,\s*){50,}-?\d+(?:\.\d+)?(?:e[+-]?\d+)?\s*\]"
    ),
    "ssn_pattern":        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card":        re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"
    ),
    "env_file_leak":      re.compile(r"(?m)^[A-Z_]{3,}=.{5,}$"),
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class LLMRiskItem(BaseModel):
    check_id: str                                    # "LLM01" … "LLM10"
    title: str
    detected: bool
    severity: str = "info"                           # critical|high|medium|low|info
    confidence: float = 0.0                          # 0.0–1.0
    evidence: list[str] = Field(default_factory=list)
    recommendation: str = ""
    attack_vector: Optional[str] = None              # exploitation narrative
    endpoints_tested: list[str] = Field(default_factory=list)
    payload_used: Optional[str] = None               # redacted sample payload


class LLMSecurityReport(BaseModel):
    target: str
    llm_risk_score: float                            # 0–10
    checks_run: int
    issues_found: int
    risks: list[LLMRiskItem]
    scan_duration: float                             # seconds
    ai_endpoints_discovered: list[str] = Field(default_factory=list)
    attack_chains: list[dict] = Field(default_factory=list)
    executive_summary: str = ""


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------

class BaseCheck(ABC):
    check_id: str = "LLM00"
    title: str = "Base Check"
    timeout: int = 20            # per-request timeout in seconds
    max_endpoints: int = 10      # cap active endpoint discovery

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    async def run(
        self,
        target: str,
        recon_result: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> LLMRiskItem:
        """
        Execute the check against the target.
        Must never raise — catch all exceptions and return detected=False.
        """
        ...

    # ------------------------------------------------------------------
    # URL helpers
    # ------------------------------------------------------------------

    def _base_url(self, target: str) -> str:
        if target.startswith(("http://", "https://")):
            return target.rstrip("/")
        return f"https://{target}"

    def _also_http(self, url: str) -> str:
        """Return HTTP variant of an HTTPS URL for fallback probes."""
        return url.replace("https://", "http://", 1)

    # ------------------------------------------------------------------
    # AI endpoint discovery
    # ------------------------------------------------------------------

    async def discover_ai_endpoints(
        self,
        target: str,
        recon_result: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> list[str]:
        """
        Discover AI-related endpoints from three sources:
        1. Recon response headers (AI provider header presence)
        2. Existing scan findings referencing AI/LLM paths
        3. Active HEAD probing of known AI endpoint patterns
        Returns deduplicated list capped at max_endpoints.
        """
        base = self._base_url(target)
        candidates: list[str] = []

        # Source 1: recon headers
        headers_info: dict = recon_result.get("headers", {})
        for hdr_name in headers_info:
            if any(pat in hdr_name.lower() for pat in AI_RESPONSE_HEADER_PATTERNS):
                candidates.append(base)
                break

        # Source 2: findings with AI-related paths
        ai_keywords = {"chat", "llm", "gpt", "claude", "openai", "copilot",
                       "assistant", "ai/", "complete", "generate", "agent"}
        for f in findings:
            path: str = f.get("path") or f.get("target") or ""
            if any(kw in path.lower() for kw in ai_keywords):
                full = path if path.startswith("http") else f"{base}{path}"
                candidates.append(full)

        # Source 3: active HEAD probe of known paths
        probe_urls = [f"{base}{path}" for path in KNOWN_AI_PATHS]
        probe_results = await self._bulk_head(probe_urls, cap=30)
        for url, status in probe_results.items():
            if status not in (0, 404, 410):
                candidates.append(url)

        deduped = list(dict.fromkeys(candidates))
        return deduped[: self.max_endpoints]

    async def _bulk_head(
        self,
        urls: list[str],
        cap: int = 30,
    ) -> dict[str, int]:
        """
        HEAD probe multiple URLs concurrently.
        Returns {url: status_code} — 0 on connection failure.
        """
        connector = aiohttp.TCPConnector(ssl=False, limit=20)
        timeout = aiohttp.ClientTimeout(total=5, connect=3)
        results: dict[str, int] = {}

        async def _probe(session: aiohttp.ClientSession, url: str) -> None:
            try:
                async with session.head(
                    url,
                    headers={"User-Agent": "SentinelX-LLMSec/1.0"},
                    allow_redirects=False,
                ) as resp:
                    results[url] = resp.status
            except Exception:
                results[url] = 0

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            await asyncio.gather(*[_probe(session, u) for u in urls[:cap]])

        return results

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _post_json(
        self,
        url: str,
        payload: dict[str, Any],
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any] | str, dict[str, str]]:
        """
        POST JSON. Returns (status, body_dict_or_str, response_headers).
        Never raises.
        """
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SentinelX-LLMSec/1.0",
            "Accept": "application/json, */*",
        }
        if extra_headers:
            headers.update(extra_headers)

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=self.timeout, connect=5),
            ) as session:
                async with session.post(url, json=payload, headers=headers) as resp:
                    resp_headers = dict(resp.headers)
                    try:
                        body: dict[str, Any] | str = await resp.json(content_type=None)
                    except Exception:
                        body = await resp.text(errors="replace")
                    return resp.status, body, resp_headers
        except asyncio.TimeoutError:
            return 0, {"error": "connection_timeout"}, {}
        except aiohttp.ClientConnectorError as exc:
            return 0, {"error": f"connection_refused: {exc}"}, {}
        except Exception as exc:
            return 0, {"error": str(exc)[:300]}, {}

    async def _get(
        self,
        url: str,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, str, dict[str, str]]:
        """
        GET request. Returns (status, body_text, response_headers). Never raises.
        """
        headers = {"User-Agent": "SentinelX-LLMSec/1.0"}
        if extra_headers:
            headers.update(extra_headers)

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=self.timeout, connect=5),
            ) as session:
                async with session.get(
                    url, headers=headers, allow_redirects=True
                ) as resp:
                    resp_headers = dict(resp.headers)
                    text = await resp.text(errors="replace")
                    return resp.status, text, resp_headers
        except asyncio.TimeoutError:
            return 0, "timeout", {}
        except Exception as exc:
            return 0, str(exc)[:300], {}

    # ------------------------------------------------------------------
    # Payload formats for probing LLM chat endpoints
    # ------------------------------------------------------------------

    @staticmethod
    def _build_chat_payloads(prompt: str) -> list[dict[str, Any]]:
        """
        Return multiple payload formats for the same prompt text,
        covering OpenAI-compat, Anthropic-style, and generic API patterns.
        """
        return [
            # OpenAI chat completions format
            {
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 200,
                "temperature": 0.0,
            },
            # Anthropic messages format
            {
                "model": "claude-3-haiku-20240307",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 200,
            },
            # Generic message field
            {"message": prompt, "max_tokens": 200},
            # Generic prompt field
            {"prompt": prompt, "max_tokens": 200},
            # Generic query field
            {"query": prompt},
            # Generic input field
            {"input": prompt},
        ]

    # ------------------------------------------------------------------
    # Multi-format endpoint probe
    # ------------------------------------------------------------------

    async def _probe_endpoint_with_payload(
        self,
        url: str,
        prompt: str,
    ) -> tuple[int, dict[str, Any] | str, dict[str, str]]:
        """
        Try all payload formats against an endpoint, return first non-error response.
        Falls through to the last attempt if all fail.
        """
        for payload in self._build_chat_payloads(prompt):
            status, body, headers = await self._post_json(url, payload)
            if status not in (0, 404, 410):
                return status, body, headers
        return 0, {"error": "all_formats_rejected"}, {}

    # ------------------------------------------------------------------
    # Sensitive data scanner
    # ------------------------------------------------------------------

    def _scan_for_sensitive_data(self, text: str) -> list[str]:
        """
        Scan response text for sensitive data pattern matches.
        Returns evidence strings with redacted sample (never full secret).
        """
        evidence: list[str] = []
        haystack = text[:15_000]  # cap to prevent pathological input
        for pattern_name, pattern in SENSITIVE_PATTERNS.items():
            match = pattern.search(haystack)
            if match:
                raw = match.group(0)
                # Redact: show first 6 chars and last 4 chars only
                if len(raw) > 12:
                    redacted = raw[:6] + "..." + raw[-4:]
                else:
                    redacted = raw[:4] + "..."
                evidence.append(f"Pattern [{pattern_name}] matched: {redacted}")
        return evidence

    # ------------------------------------------------------------------
    # LLM response text extractor
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_response_text(body: dict[str, Any] | str) -> str:
        """
        Extract the assistant's response text from various API response formats.
        Returns empty string if not parseable.
        """
        if isinstance(body, str):
            return body[:5000]

        # OpenAI chat completions
        choices = body.get("choices")
        if choices and isinstance(choices, list) and choices:
            msg = choices[0].get("message") or {}
            if isinstance(msg, dict):
                return str(msg.get("content") or "")[:5000]
            # completions format
            text = choices[0].get("text")
            if text:
                return str(text)[:5000]

        # Anthropic messages
        content = body.get("content")
        if isinstance(content, list) and content:
            item = content[0]
            if isinstance(item, dict):
                return str(item.get("text") or "")[:5000]

        # Generic fields
        for key in ("response", "message", "text", "output", "answer", "result", "data"):
            val = body.get(key)
            if val and isinstance(val, str):
                return val[:5000]

        # _raw from failed JSON parse
        raw = body.get("_raw")
        if raw:
            return str(raw)[:5000]

        return ""

    # ------------------------------------------------------------------
    # Helper: check if headers reveal AI provider
    # ------------------------------------------------------------------

    @staticmethod
    def _headers_reveal_ai_provider(headers: dict[str, str]) -> list[str]:
        evidence: list[str] = []
        for hdr_name, hdr_val in headers.items():
            lower = hdr_name.lower()
            if any(pat in lower for pat in AI_RESPONSE_HEADER_PATTERNS):
                evidence.append(f"AI provider header: {hdr_name}: {hdr_val[:100]}")
        return evidence
