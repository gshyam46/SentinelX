"""
SentinelX — RAG Engine (Retrieval-Augmented Generation)
Lightweight keyword + semantic retrieval from the local knowledge base.

Strategy:
  Phase 1 (current): Keyword/TF-IDF based retrieval — zero external dependencies,
                     fast, deterministic, works offline.
  Phase 2 (future):  Replace with FAISS + sentence-transformers for semantic search
                     when production scaling requires it.

The RAG engine is NOT an agent. It is a pure information retrieval module.
It does not make decisions — it surfaces relevant knowledge for LLM prompts.
"""

import json
import logging
import re
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sentinelx.rag")

# Absolute path to knowledge base directory
_KB_DIR = Path(__file__).parent / "knowledge_base"

# Knowledge base files to load
_KB_FILES = {
    "owasp_top10": "owasp_top10.json",
    "security_headers": "security_headers.json",
    "remediation_guides": "remediation_guides.json",
}


class RAGEngine:
    """
    Keyword-based retrieval engine over the SentinelX knowledge base.

    Extracts relevant context documents based on finding titles and descriptions,
    then formats them for injection into LLM prompts.
    """

    def __init__(self):
        self._kb: Dict[str, List[Dict]] = {}
        self._loaded = False

    def load(self) -> None:
        """Load all knowledge base files into memory."""
        if self._loaded:
            return

        for kb_name, filename in _KB_FILES.items():
            filepath = _KB_DIR / filename
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                # Flatten to list of records
                if isinstance(data, dict):
                    # Extract the first top-level list value
                    for v in data.values():
                        if isinstance(v, list):
                            self._kb[kb_name] = v
                            break
                elif isinstance(data, list):
                    self._kb[kb_name] = data
                logger.info(f"RAG: Loaded {kb_name} ({len(self._kb.get(kb_name, []))} entries)")
            except FileNotFoundError:
                logger.warning(f"RAG: Knowledge base file not found: {filepath}")
                self._kb[kb_name] = []
            except json.JSONDecodeError as e:
                logger.error(f"RAG: Failed to parse {filename}: {e}")
                self._kb[kb_name] = []

        self._loaded = True
        total = sum(len(v) for v in self._kb.values())
        logger.info(f"RAG: Knowledge base loaded — {total} total entries")

    def query(
        self,
        findings: List[Dict[str, Any]],
        top_k: int = 3,
    ) -> Dict[str, List[Dict]]:
        """
        Retrieve relevant knowledge base entries for a list of findings.

        Args:
            findings: List of finding dicts from the scan pipeline
            top_k:    Max number of results per finding (default 3)

        Returns:
            Dict with 'owasp', 'headers', 'remediation' lists of relevant entries
        """
        if not self._loaded:
            self.load()

        # Extract all text from findings for matching
        finding_texts = []
        for f in findings:
            text_parts = [
                f.get("title", ""),
                f.get("description", ""),
                f.get("component", ""),
                str(f.get("cve_id") or ""),
            ]
            finding_texts.append(" ".join(text_parts).lower())

        combined_text = " ".join(finding_texts)

        return {
            "owasp": self._match_owasp(combined_text, top_k),
            "headers": self._match_headers(combined_text, top_k),
            "remediation": self._match_remediation(finding_texts, top_k),
        }

    def query_single(
        self,
        finding: Dict[str, Any],
        top_k: int = 2,
    ) -> Dict[str, List[Dict]]:
        """Query knowledge base for a single finding."""
        return self.query([finding], top_k=top_k)

    def format_context_for_prompt(
        self,
        context: Dict[str, List[Dict]],
        max_chars: int = 3000,
    ) -> str:
        """
        Format retrieved knowledge into a compact string for LLM prompt injection.

        Args:
            context:   Output from query()
            max_chars: Maximum character budget for the context block

        Returns:
            Formatted context string ready for prompt injection
        """
        sections = []

        if context.get("owasp"):
            owasp_lines = ["=== OWASP CONTEXT ==="]
            for entry in context["owasp"][:2]:
                owasp_lines.append(
                    f"[{entry.get('id', '')}] {entry.get('name', '')}: "
                    f"{entry.get('description', '')[:200]} | "
                    f"Fix: {entry.get('fix', '')[:200]}"
                )
            sections.append("\n".join(owasp_lines))

        if context.get("headers"):
            header_lines = ["=== HEADER CONTEXT ==="]
            for entry in context["headers"][:2]:
                header_lines.append(
                    f"{entry.get('name', '')}: {entry.get('impact_if_missing', '')[:200]} | "
                    f"Fix: {entry.get('fix', '')[:200]}"
                )
            sections.append("\n".join(header_lines))

        if context.get("remediation"):
            remed_lines = ["=== REMEDIATION CONTEXT ==="]
            for entry in context["remediation"][:2]:
                steps = entry.get("fix_steps", [])[:4]
                remed_lines.append(
                    f"{entry.get('vulnerability_type', '')}: "
                    + " | ".join(steps)
                )
            sections.append("\n".join(remed_lines))

        full_context = "\n\n".join(sections)

        # Truncate to max_chars budget
        if len(full_context) > max_chars:
            full_context = full_context[:max_chars] + "\n[...context truncated for length...]"

        return full_context

    # ------------------------------------------------------------------
    # Private matching methods
    # ------------------------------------------------------------------

    def _match_owasp(self, text: str, top_k: int) -> List[Dict]:
        """Match findings text against OWASP Top 10 entries."""
        scored = []
        for entry in self._kb.get("owasp_top10", []):
            score = self._keyword_score(text, [
                entry.get("name", ""),
                entry.get("description", ""),
                " ".join(entry.get("examples", [])),
            ])
            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [e for _, e in scored[:top_k]]

    def _match_headers(self, text: str, top_k: int) -> List[Dict]:
        """Match findings text against security headers knowledge."""
        scored = []
        for entry in self._kb.get("security_headers", []):
            score = self._keyword_score(text, [
                entry.get("name", ""),
                entry.get("alias", ""),
                " ".join(entry.get("keywords", [])),
                entry.get("impact_if_missing", ""),
            ])
            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [e for _, e in scored[:top_k]]

    def _match_remediation(self, finding_texts: List[str], top_k: int) -> List[Dict]:
        """Match each finding against remediation guides."""
        # Track best score per guide to avoid duplicates
        guide_best: Dict[str, Tuple[float, Dict]] = {}

        for text in finding_texts:
            for guide in self._kb.get("remediation_guides", []):
                score = self._keyword_score(text, [
                    guide.get("vulnerability_type", ""),
                    " ".join(guide.get("keywords", [])),
                ])
                key = guide.get("vulnerability_type", "")
                if score > 0:
                    if key not in guide_best or score > guide_best[key][0]:
                        guide_best[key] = (score, guide)

        # Sort by score and return top_k
        sorted_guides = sorted(guide_best.values(), key=lambda x: x[0], reverse=True)
        return [g for _, g in sorted_guides[:top_k]]

    @staticmethod
    def _keyword_score(text: str, corpus: List[str]) -> float:
        """
        Simple keyword frequency scoring.
        Tokenizes corpus and counts term overlap with finding text.
        """
        text_lower = text.lower()
        score = 0.0
        for c in corpus:
            words = re.findall(r"\b\w+\b", c.lower())
            for word in words:
                if len(word) > 3 and word in text_lower:
                    score += 1.0
        return score


# Module-level singleton
_rag_engine: Optional[RAGEngine] = None


def get_rag_engine() -> RAGEngine:
    """Return the loaded RAG engine singleton."""
    global _rag_engine
    if _rag_engine is None:
        _rag_engine = RAGEngine()
        _rag_engine.load()
    return _rag_engine
