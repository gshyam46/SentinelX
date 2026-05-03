"""
SentinelX — RAG Engine (Retrieval-Augmented Generation)

Retrieval strategy (with automatic fallback):

  Primary (FAISS):  FAISS IndexFlatIP + sentence-transformers/all-MiniLM-L6-v2.
                    L2-normalized vectors → inner product = cosine similarity.
                    Deterministic, exact search. Pre-computed at startup.
                    retrieval_method = "faiss"

  Fallback (TF-IDF): Keyword frequency scoring when FAISS/sentence-transformers
                    are unavailable (Windows dev without conda, CI without GPU).
                    retrieval_method = "keyword"

The RAG engine is NOT an agent. It is pure information retrieval — it surfaces
relevant knowledge for LLM prompts and records which method was used.
"""

import json
import logging
import re
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from backend.modules.ai.knowledge_base.kev_loader import KEVEntry, get_cached_kev, search_kev
except ImportError:
    from modules.ai.knowledge_base.kev_loader import KEVEntry, get_cached_kev, search_kev  # type: ignore

logger = logging.getLogger("sentinelx.rag")

_KB_DIR = Path(__file__).parent / "knowledge_base"
_KB_FILES = {
    "owasp_top10": "owasp_top10.json",
    "security_headers": "security_headers.json",
    "remediation_guides": "remediation_guides.json",
    # New high-signal sources — loaded when present; skipped gracefully if absent
    "kev_catalog": "kev_catalog.json",
    "exploit_db": "exploit_db.json",
    "cve_summaries": "cve_summaries.json",
}


def _kb_entry_to_text(entry: dict, source: str) -> str:
    """Build a searchable text representation of a knowledge base entry."""
    parts: list[str] = []
    if source == "owasp_top10":
        parts = [
            entry.get("id", ""),
            entry.get("name", ""),
            entry.get("description", ""),
            " ".join(entry.get("examples", [])),
            entry.get("fix", ""),
        ]
    elif source == "security_headers":
        parts = [
            entry.get("name", ""),
            entry.get("alias", ""),
            " ".join(entry.get("keywords", [])),
            entry.get("impact_if_missing", ""),
            entry.get("fix", ""),
        ]
    elif source == "remediation_guides":
        parts = [
            entry.get("vulnerability_type", ""),
            " ".join(entry.get("keywords", [])),
            " ".join(entry.get("fix_steps", [])),
        ]
    elif source == "kev_catalog":
        parts = [
            entry.get("cve_id", ""),
            entry.get("vulnerability_name", ""),
            entry.get("vendor", ""),
            entry.get("product", ""),
            entry.get("description", ""),
            entry.get("required_action", ""),
            entry.get("notes", ""),
        ]
    elif source == "exploit_db":
        parts = [
            entry.get("description", ""),
            entry.get("type", ""),
            entry.get("platform", ""),
            entry.get("author", ""),
            " ".join(entry.get("codes", [])),
            " ".join(entry.get("tags", [])),
        ]
    elif source == "cve_summaries":
        parts = [
            entry.get("cve_id", ""),
            entry.get("description", ""),
            entry.get("severity", ""),
            entry.get("attack_vector", ""),
            " ".join(entry.get("cwe_ids", [])),
        ]
    return " ".join(p for p in parts if p)


class RAGEngine:
    """
    Retrieval engine over the SentinelX knowledge base.

    Public interface (stable — do not change signatures):
      load()                         → None
      query(findings, top_k=3)       → {owasp, headers, remediation}
      query_single(finding, top_k=2) → {owasp, headers, remediation}
      format_context_for_prompt(ctx) → str
      get_retrieval_method()         → "faiss" | "keyword" | "not_loaded"
    """

    def __init__(self):
        self._kb: Dict[str, List[Dict]] = {}
        self._loaded = False
        self._use_faiss = False
        self._retrieval_method = "not_loaded"

        # FAISS state
        self._model = None          # SentenceTransformer
        self._index = None          # faiss.Index
        self._index_docs: list[dict] = []      # parallel to index rows
        self._index_sources: list[str] = []    # source key per indexed doc

        # KEV catalog — loaded from cache at startup (sync, no network)
        self._kev_entries: List[KEVEntry] = []

        # kev_catalog.json entries (richer, persisted file — separate from kev_cache)
        self._kev_catalog: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Load
    # ------------------------------------------------------------------

    def load(self) -> None:
        if self._loaded:
            return

        # 1. Load KB files
        for kb_name, filename in _KB_FILES.items():
            filepath = _KB_DIR / filename
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    for v in data.values():
                        if isinstance(v, list):
                            self._kb[kb_name] = v
                            break
                elif isinstance(data, list):
                    self._kb[kb_name] = data
                logger.info("RAG: Loaded %s (%d entries)", kb_name, len(self._kb.get(kb_name, [])))
            except FileNotFoundError:
                logger.warning("RAG: KB file not found: %s", filepath)
                self._kb[kb_name] = []
            except json.JSONDecodeError as exc:
                logger.error("RAG: Failed to parse %s: %s", filename, exc)
                self._kb[kb_name] = []

        total = sum(len(v) for v in self._kb.values())
        logger.info("RAG: Knowledge base loaded — %d total entries", total)

        # 2. Attempt FAISS index (skipped when DISABLE_FAISS=1 — prevents post-fork OpenMP deadlock in Celery prefork workers)
        import os
        _disable_faiss = os.getenv("DISABLE_FAISS", "").lower() in ("1", "true", "yes")

        if _disable_faiss:
            logger.info("RAG: FAISS disabled via DISABLE_FAISS env var — using keyword fallback (Celery-safe)")
            self._retrieval_method = "keyword"
        else:
            try:
                import faiss  # type: ignore
                import numpy as np
                from sentence_transformers import SentenceTransformer  # type: ignore

                self._model = SentenceTransformer("all-MiniLM-L6-v2")
                self._build_faiss_index(faiss, np)
                self._use_faiss = True
                self._retrieval_method = "faiss"
                logger.info(
                    "RAG: FAISS index built (%d vectors, dim=384, all-MiniLM-L6-v2)",
                    len(self._index_docs),
                )
            except ImportError as exc:
                logger.warning("RAG: FAISS/sentence-transformers not available (%s) — using keyword fallback", exc)
                self._retrieval_method = "keyword"
            except Exception as exc:
                logger.error("RAG: FAISS index build failed (%s) — using keyword fallback", exc)
                self._retrieval_method = "keyword"

        # 3. Load KEV catalog from local cache (sync — no network at startup)
        try:
            self._kev_entries = get_cached_kev()
            logger.info("RAG: KEV cache loaded — %d entries", len(self._kev_entries))
        except Exception as exc:
            logger.warning("RAG: KEV cache load failed (%s) — KEV enrichment disabled", exc)
            self._kev_entries = []

        # 4. Mirror kev_catalog from _kb if the file was loaded
        self._kev_catalog = self._kb.get("kev_catalog", [])
        logger.info("RAG: kev_catalog.json — %d entries", len(self._kev_catalog))

        self._loaded = True

    def _build_faiss_index(self, faiss, np) -> None:
        """Build a flat inner-product FAISS index over all KB entries."""
        texts: list[str] = []
        docs: list[dict] = []
        sources: list[str] = []

        for source, entries in self._kb.items():
            for entry in entries:
                text = _kb_entry_to_text(entry, source)
                if text.strip():
                    texts.append(text)
                    docs.append(entry)
                    sources.append(source)

        if not texts:
            return

        embeddings = self._model.encode(texts, convert_to_numpy=True, show_progress_bar=False)
        embeddings = embeddings.astype(np.float32)
        faiss.normalize_L2(embeddings)  # enables cosine similarity via inner product

        dim = embeddings.shape[1]
        index = faiss.IndexFlatIP(dim)
        index.add(embeddings)

        self._index = index
        self._index_docs = docs
        self._index_sources = sources

    # ------------------------------------------------------------------
    # Public query interface
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # KEV enrichment helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_cve_ids(findings: List[Dict[str, Any]]) -> List[str]:
        """
        Extract all CVE identifiers mentioned anywhere in the findings list.
        Searches every string value in each finding dict using the canonical
        CVE regex pattern.  Preserves order; deduplicates.
        """
        _CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
        seen: set[str] = set()
        ordered: list[str] = []
        for finding in findings:
            # Gather all string-like values from the finding dict
            texts: list[str] = []
            for val in finding.values():
                if isinstance(val, str):
                    texts.append(val)
                elif isinstance(val, (list, tuple)):
                    texts.extend(str(v) for v in val if v)
            combined = " ".join(texts)
            for match in _CVE_PATTERN.finditer(combined):
                cve = match.group(0).upper()
                if cve not in seen:
                    seen.add(cve)
                    ordered.append(cve)
        return ordered

    def _build_kev_alerts(
        self, cve_ids: List[str]
    ) -> tuple[list[str], list[str]]:
        """
        For each CVE in cve_ids, check the KEV catalog.
        Returns:
            kev_matches  — list of CVE IDs that matched KEV
            kev_context  — list of formatted alert strings for prompt injection
        """
        kev_matches: list[str] = []
        kev_context: list[str] = []
        for cve_id in cve_ids:
            hit = search_kev(cve_id, self._kev_entries)
            if hit:
                kev_matches.append(hit.cve_id)
                kev_context.append(
                    f"[KEV ALERT] {hit.cve_id} is in CISA's Known Exploited Vulnerabilities catalog. "
                    f"Product: {hit.vendor_project} {hit.product}. "
                    f"This vulnerability has been actively exploited in the wild."
                )
                logger.info("RAG: KEV match — %s (%s %s)", hit.cve_id, hit.vendor_project, hit.product)
        return kev_matches, kev_context

    # ------------------------------------------------------------------
    # Public query interface
    # ------------------------------------------------------------------

    def query(
        self,
        findings: List[Dict[str, Any]],
        top_k: int = 3,
    ) -> Dict[str, Any]:
        """
        Retrieve relevant KB entries for a list of findings.

        Priority routing:
          1. KEV hits (CISA known-exploited) — prepended first, highest urgency.
          2. Normal RAG retrieval (OWASP / headers / remediation / exploit_db / cve_summaries).

        Returns:
            {
                "owasp":        list[dict],
                "headers":      list[dict],
                "remediation":  list[dict],
                "exploit_db":   list[dict],   # Exploit-DB matches (additive)
                "cve_summaries":list[dict],   # NVD CVE matches (additive)
                "kev_matches":  list[str],    # CVE IDs found in CISA KEV
                "kev_alerts":   list[str],    # pre-formatted KEV alert strings
            }
        """
        if not self._loaded:
            self.load()

        # -- Step 1: KEV CVE ID enrichment (highest priority) --
        cve_ids = self._extract_cve_ids(findings)
        kev_matches, kev_alerts = self._build_kev_alerts(cve_ids)

        # -- Step 2: normal RAG retrieval --
        if self._use_faiss:
            base = self._faiss_query(findings, top_k)
        else:
            base = self._keyword_query(findings, top_k)

        # If KEV hits found, also surface matching kev_catalog entries
        kev_catalog_hits = self._match_kev_catalog(cve_ids, top_k)
        if kev_catalog_hits:
            # Prepend KEV catalog entries before normal retrieval results
            base["kev_catalog"] = kev_catalog_hits
        else:
            base["kev_catalog"] = []

        base["kev_matches"] = kev_matches
        base["kev_alerts"] = kev_alerts
        return base

    def _match_kev_catalog(
        self, cve_ids: List[str], top_k: int
    ) -> List[Dict[str, Any]]:
        """Return kev_catalog.json entries that match any CVE in cve_ids."""
        if not cve_ids or not self._kev_catalog:
            return []
        needle_set = {c.upper() for c in cve_ids}
        hits: List[Dict[str, Any]] = []
        for entry in self._kev_catalog:
            if entry.get("cve_id", "").upper() in needle_set:
                hits.append(entry)
                if len(hits) >= top_k:
                    break
        return hits

    def query_single(
        self,
        finding: Dict[str, Any],
        top_k: int = 2,
    ) -> Dict[str, List[Dict]]:
        return self.query([finding], top_k=top_k)

    def get_retrieval_method(self) -> str:
        """Return "faiss", "keyword", or "not_loaded"."""
        return self._retrieval_method

    # ------------------------------------------------------------------
    # FAISS retrieval
    # ------------------------------------------------------------------

    def _faiss_query(
        self, findings: List[Dict[str, Any]], top_k: int
    ) -> Dict[str, List[Dict]]:
        import numpy as np
        import faiss  # type: ignore

        if self._index is None or not self._index_docs:
            return {"owasp": [], "headers": [], "remediation": []}

        # Build query text from findings
        query_parts = []
        for f in findings:
            query_parts.extend([
                f.get("title", ""),
                f.get("description", "")[:200],
                " ".join(f.get("owasp_categories", [])),
                str(f.get("cve_id") or ""),
            ])
        query_text = " ".join(p for p in query_parts if p)
        if not query_text.strip():
            return {"owasp": [], "headers": [], "remediation": []}

        query_vec = self._model.encode([query_text], convert_to_numpy=True).astype(np.float32)
        faiss.normalize_L2(query_vec)

        k = min(top_k * 4, len(self._index_docs))
        scores, indices = self._index.search(query_vec, k)

        # Group by source, deduplicate, cap at top_k each
        result: Dict[str, List[Dict]] = {
            "owasp": [], "headers": [], "remediation": [],
            "exploit_db": [], "cve_summaries": [],
        }
        source_map = {
            "owasp_top10": "owasp",
            "security_headers": "headers",
            "remediation_guides": "remediation",
            "kev_catalog": "owasp",       # KEV catalog enriches OWASP bucket
            "exploit_db": "exploit_db",
            "cve_summaries": "cve_summaries",
        }
        seen_per_source: Dict[str, int] = {
            "owasp": 0, "headers": 0, "remediation": 0,
            "exploit_db": 0, "cve_summaries": 0,
        }

        for idx in indices[0]:
            if idx < 0 or idx >= len(self._index_docs):
                continue
            source = self._index_sources[idx]
            bucket = source_map.get(source)
            if bucket is None:
                continue
            if seen_per_source[bucket] >= top_k:
                continue
            result[bucket].append(self._index_docs[idx])
            seen_per_source[bucket] += 1

        return result

    # ------------------------------------------------------------------
    # Keyword (TF-IDF) retrieval — fallback
    # ------------------------------------------------------------------

    def _keyword_query(
        self, findings: List[Dict[str, Any]], top_k: int
    ) -> Dict[str, List[Dict]]:
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
            "owasp": self._kw_match_owasp(combined_text, top_k),
            "headers": self._kw_match_headers(combined_text, top_k),
            "remediation": self._kw_match_remediation(finding_texts, top_k),
            "exploit_db": self._kw_match_exploitdb(combined_text, top_k),
            "cve_summaries": self._kw_match_cve(combined_text, top_k),
        }

    def _kw_match_owasp(self, text: str, top_k: int) -> List[Dict]:
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

    def _kw_match_headers(self, text: str, top_k: int) -> List[Dict]:
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

    def _kw_match_remediation(self, finding_texts: List[str], top_k: int) -> List[Dict]:
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
        sorted_guides = sorted(guide_best.values(), key=lambda x: x[0], reverse=True)
        return [g for _, g in sorted_guides[:top_k]]

    def _kw_match_exploitdb(self, text: str, top_k: int) -> List[Dict]:
        scored = []
        for entry in self._kb.get("exploit_db", []):
            score = self._keyword_score(text, [
                entry.get("description", ""),
                entry.get("type", ""),
                entry.get("platform", ""),
                " ".join(entry.get("codes", [])),
                " ".join(entry.get("tags", [])),
            ])
            if score > 0:
                scored.append((score, entry))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [e for _, e in scored[:top_k]]

    def _kw_match_cve(self, text: str, top_k: int) -> List[Dict]:
        scored = []
        for entry in self._kb.get("cve_summaries", []):
            score = self._keyword_score(text, [
                entry.get("cve_id", ""),
                entry.get("description", ""),
                " ".join(entry.get("cwe_ids", [])),
            ])
            if score > 0:
                scored.append((score, entry))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [e for _, e in scored[:top_k]]

    @staticmethod
    def _keyword_score(text: str, corpus: List[str]) -> float:
        text_lower = text.lower()
        score = 0.0
        for c in corpus:
            words = re.findall(r"\b\w+\b", c.lower())
            for word in words:
                if len(word) > 3 and word in text_lower:
                    score += 1.0
        return score

    # ------------------------------------------------------------------
    # Prompt formatting
    # ------------------------------------------------------------------

    def format_context_for_prompt(
        self,
        context: Dict[str, Any],
        max_chars: int = 3000,
    ) -> str:
        """
        Format retrieved knowledge into a compact string for LLM prompt injection.

        KEV alerts (if any) are prepended at highest priority before all other
        KB sections.  Callers that do not pass kev_alerts simply get the same
        output as before — fully backward-compatible.
        """
        sections = []

        # KEV alerts — highest priority, prepended first
        kev_alerts: list[str] = context.get("kev_alerts", [])
        if kev_alerts:
            kev_lines = ["=== CISA KEV ALERTS (ACTIVE EXPLOITATION) ==="]
            kev_lines.extend(kev_alerts)
            sections.append("\n".join(kev_lines))

        # KEV catalog detail block (if catalog hits exist)
        kev_catalog: list[dict] = context.get("kev_catalog", [])
        if kev_catalog:
            kcat_lines = ["=== KEV CATALOG DETAIL ==="]
            for entry in kev_catalog[:3]:
                kcat_lines.append(
                    f"{entry.get('cve_id', '')} | {entry.get('vulnerability_name', '')} | "
                    f"{entry.get('vendor', '')} {entry.get('product', '')} | "
                    f"Action: {entry.get('required_action', '')[:200]}"
                )
            sections.append("\n".join(kcat_lines))

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

        if context.get("exploit_db"):
            edb_lines = ["=== EXPLOIT-DB MATCHES ==="]
            for entry in context["exploit_db"][:2]:
                codes = ", ".join(entry.get("codes", [])[:3])
                edb_lines.append(
                    f"EDB-{entry.get('id', '')} [{entry.get('type', '')}|{entry.get('platform', '')}] "
                    f"{entry.get('description', '')[:200]} "
                    f"| CVE refs: {codes or 'none'} | Verified: {entry.get('verified', '0')}"
                )
            sections.append("\n".join(edb_lines))

        if context.get("cve_summaries"):
            cve_lines = ["=== CVE SUMMARIES ==="]
            for entry in context["cve_summaries"][:2]:
                cve_lines.append(
                    f"{entry.get('cve_id', '')} [{entry.get('severity', '').upper()}] "
                    f"CVSS {entry.get('cvss_score', '?')} AV:{entry.get('attack_vector', '?')} "
                    f"— {entry.get('description', '')[:200]}"
                )
            sections.append("\n".join(cve_lines))

        full_context = "\n\n".join(sections)
        if len(full_context) > max_chars:
            full_context = full_context[:max_chars] + "\n[...context truncated...]"
        return full_context


# Module-level singleton
_rag_engine: Optional[RAGEngine] = None


def get_rag_engine() -> RAGEngine:
    """Return the loaded RAG engine singleton."""
    global _rag_engine
    if _rag_engine is None:
        _rag_engine = RAGEngine()
        _rag_engine.load()
    return _rag_engine
