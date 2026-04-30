"""
LLM05 — Supply Chain Vulnerabilities

Assesses risks from third-party model dependencies, plugin sources, and
external tool integrations that may introduce untrusted code or data:
  - Model provenance disclosure via info/health endpoints
  - Outdated or end-of-life model versions with known CVEs
  - Plugin/tool registry pointing to external untrusted domains
  - Unsigned or unverified model weights indicators
  - Third-party AI SDK version disclosure (OpenAI, LangChain, etc.)
  - Dependency confusion via package name squatting indicators
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from backend.modules.ai.llm_security.base import BaseCheck, LLMRiskItem

logger = logging.getLogger("sentinelx.llmsec.llm05")

# Endpoints likely to reveal model provenance or supply chain info
_SUPPLY_INFO_PATHS = [
    "/v1/models",
    "/api/models",
    "/api/v1/models",
    "/model",
    "/info",
    "/health",
    "/status",
    "/api/info",
    "/.well-known/ai-plugin.json",
    "/openapi.json",
    "/openapi.yaml",
    "/api/plugins",
    "/api/tools",
    "/api/functions",
    "/api/extensions",
    "/api/version",
    "/version",
    "/meta",
    "/api/meta",
    "/model-card",
    "/api/model-card",
]

# Known end-of-life / vulnerable model versions
_DEPRECATED_MODELS = {
    "gpt-3.5-turbo-0301": "Deprecated 2024-06-13",
    "gpt-4-0314": "Deprecated 2024-06-13",
    "text-davinci-003": "Deprecated 2024-01-04",
    "text-davinci-002": "Deprecated 2024-01-04",
    "gpt-3.5-turbo-0613": "Deprecated 2024-09-13",
    "claude-instant-1": "Deprecated — use claude-3-haiku",
    "claude-2.0": "Legacy — limited support",
}

# Third-party plugin/tool domains that indicate supply chain risk
_RISKY_EXTERNAL_DOMAINS_RE = re.compile(
    r"https?://(?!(?:api\.openai\.com|api\.anthropic\.com|api\.groq\.com|"
    r"[a-z0-9\-]+\.azure\.com|[a-z0-9\-]+\.amazonaws\.com))"
    r"([a-z0-9\-]+\.(?:ngrok\.io|localhost|127\.0\.0\.|0\.0\.0\.|"
    r"github\.io|githubusercontent\.com|pastebin\.com|pastie\.org|"
    r"transfer\.sh|hastebin\.com|rentry\.co))"
    , re.IGNORECASE
)

# Signs of unverified model loading
_UNVERIFIED_MODEL_RE = re.compile(
    r"(?i)(load_from_url|from_pretrained\s*\(\s*['\"]http|"
    r"wget|curl.*model|download.*weight|huggingface.*untrusted|"
    r"trust_remote_code\s*=\s*True)",
)

# LangChain / OpenAI SDK version patterns
_SDK_VERSION_RE = re.compile(
    r"(?i)(langchain[/_-]([0-9]+\.[0-9]+)|openai[/_-]([0-9]+\.[0-9]+)|"
    r"transformers[/_-]([0-9]+\.[0-9]+)|llama.index[/_-]([0-9]+\.[0-9]+))"
)

# Known vulnerable SDK versions (below these are risky)
_RISKY_SDK_VERSIONS = {
    "langchain": (0, 1, 0),    # before 0.1.0 had prompt injection via output parsers
    "openai": (1, 0, 0),       # before 1.0 had insecure proxy patterns
}


class SupplyChainCheck(BaseCheck):
    check_id = "LLM05"
    title = "Supply Chain Vulnerabilities"
    timeout = 15

    async def run(
        self,
        target: str,
        recon_result: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> LLMRiskItem:
        evidence: list[str] = []
        endpoints_tested: list[str] = []
        best_confidence = 0.0

        try:
            base = self._base_url(target)

            # -- Check 1: Probe info/model endpoints --
            for path in _SUPPLY_INFO_PATHS:
                url = f"{base}{path}"
                status, body_text, resp_headers = await self._get(url)
                if status not in (200, 206):
                    continue

                endpoints_tested.append(url)
                body_lower = body_text.lower()

                # Check for deprecated model versions
                for model_id, reason in _DEPRECATED_MODELS.items():
                    if model_id.lower() in body_lower:
                        if best_confidence < 0.70:
                            best_confidence = 0.70
                        evidence.append(
                            f"Deprecated model '{model_id}' referenced at {path}: {reason}"
                        )

                # Check for risky external plugin/tool domains
                risky_matches = _RISKY_EXTERNAL_DOMAINS_RE.findall(body_text)
                for domain in risky_matches[:3]:
                    if best_confidence < 0.75:
                        best_confidence = 0.75
                    evidence.append(
                        f"Plugin/tool points to untrusted external domain: {domain} at {path}"
                    )

                # Check for unverified model loading
                if _UNVERIFIED_MODEL_RE.search(body_text):
                    if best_confidence < 0.65:
                        best_confidence = 0.65
                    evidence.append(
                        f"Unverified model loading pattern detected at {path} "
                        f"(trust_remote_code=True or dynamic URL loading)"
                    )

                # Check for SDK version disclosure
                sdk_matches = _SDK_VERSION_RE.findall(body_text)
                for match in sdk_matches[:5]:
                    sdk_str = match[0]
                    evidence.append(f"AI SDK version disclosed: {sdk_str} at {path}")
                    if best_confidence < 0.40:
                        best_confidence = 0.40

                # Check for model cards / provenance
                if re.search(r"(?i)(model.card|base.model|fine.tun|checkpoint|weights)", body_text):
                    evidence.append(f"Model provenance information exposed at {path}")
                    if best_confidence < 0.45:
                        best_confidence = 0.45

                # Try to parse as JSON for structured analysis
                try:
                    obj = json.loads(body_text)
                    _analyse_json_supply_chain(obj, path, evidence)
                    if evidence and best_confidence < 0.50:
                        best_confidence = 0.50
                except json.JSONDecodeError:
                    pass

            # -- Check 2: Recon headers for SDK/framework disclosure --
            resp_headers = recon_result.get("headers", {})
            server_header = resp_headers.get("server", "") or resp_headers.get("x-powered-by", "")
            if re.search(r"(?i)(langchain|llamaindex|haystack|openai|anthropic)", server_header):
                evidence.append(f"AI framework disclosed in server header: {server_header[:100]}")
                if best_confidence < 0.45:
                    best_confidence = 0.45

            # -- Check 3: Existing findings mentioning supply chain risks --
            for f in findings:
                desc = str(f.get("description", "") + f.get("title", "")).lower()
                if any(kw in desc for kw in ("outdated", "vulnerable dependency", "supply chain",
                                              "untrusted plugin", "third.party")):
                    if best_confidence < 0.50:
                        best_confidence = 0.50
                    evidence.append(
                        f"Existing finding suggests supply chain risk: '{f.get('title', '')}'"
                    )

        except Exception as exc:
            logger.warning("[LLM05] Error for %s: %s", target, exc)
            return LLMRiskItem(
                check_id=self.check_id,
                title=self.title,
                detected=False,
                severity="info",
                confidence=0.0,
                evidence=[f"Check error: {exc}"],
                recommendation=_RECOMMENDATION,
            )

        detected = best_confidence >= 0.35
        return LLMRiskItem(
            check_id=self.check_id,
            title=self.title,
            detected=detected,
            severity=_severity(best_confidence),
            confidence=round(best_confidence, 3),
            evidence=evidence[:10],
            recommendation=_RECOMMENDATION,
            attack_vector=_ATTACK_VECTOR,
            endpoints_tested=endpoints_tested[:5],
        )


def _analyse_json_supply_chain(
    obj: Any,
    path: str,
    evidence: list[str],
) -> None:
    """Recursively scan JSON object for supply chain risk indicators."""
    if isinstance(obj, dict):
        # Check model IDs
        for key in ("model", "base_model", "model_id", "model_name"):
            val = obj.get(key, "")
            if isinstance(val, str) and val in _DEPRECATED_MODELS:
                evidence.append(
                    f"JSON response at {path} references deprecated model: {val}"
                )
        # Check for external URLs in plugin/tool definitions
        for key in ("url", "api_url", "server_url", "endpoint", "base_url"):
            val = obj.get(key, "")
            if isinstance(val, str) and _RISKY_EXTERNAL_DOMAINS_RE.search(val):
                evidence.append(
                    f"JSON plugin definition at {path} references untrusted URL: {val[:80]}"
                )
        for v in obj.values():
            _analyse_json_supply_chain(v, path, evidence)
    elif isinstance(obj, list):
        for item in obj[:20]:
            _analyse_json_supply_chain(item, path, evidence)


def _severity(confidence: float) -> str:
    if confidence >= 0.70:
        return "high"
    if confidence >= 0.45:
        return "medium"
    return "info"


_RECOMMENDATION = (
    "1. Pin model versions and AI SDK dependencies — never use floating 'latest' tags. "
    "2. Audit all third-party plugins and tool integrations; allowlist approved vendor domains. "
    "3. Disable trust_remote_code=True in Hugging Face transformers; use verified model sources. "
    "4. Implement SBOMs (Software Bill of Materials) for all AI components. "
    "5. Monitor CVE feeds for AI framework vulnerabilities (LangChain, LlamaIndex, OpenAI SDK). "
    "6. Sign and verify model weights before deployment using content hashing."
)

_ATTACK_VECTOR = (
    "Adversary compromises a third-party plugin, tool, or AI SDK dependency used by the "
    "application. Via malicious model weights, poisoned fine-tuning data, or backdoored SDK "
    "code, arbitrary code execution or data exfiltration is achieved without direct access "
    "to the target application's own codebase."
)
