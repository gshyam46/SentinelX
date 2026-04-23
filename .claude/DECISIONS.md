# SentinelX — Architecture Decisions Log
> Record every significant architectural decision here with rationale.
> This prevents re-litigating decisions in future sessions.

---

## ADR-001: Two-Layer Architecture (Tools + AI) — UPDATED 2026-04-23
**Date:** Week 1
**Original decision:** Security tools perform all discovery. AI only interprets outputs. Agent 1 = pure Python, zero LLM involvement.
**Updated decision (2026-04-23):** CONSTRAINED ADAPTIVE orchestrator. LLM recommends which tool to run next from a code-enforced ALLOWED_TOOLS list. LLM cannot execute tools, skip tools, add tools outside the list, or request additional scans. Every LLM selection is validated against the allowlist and logged. Rule-based fallback fires if LLM selects an invalid tool.
**What changed:** Agent 1 is no longer "zero LLM" — it uses LLM for adaptive tool selection, but with hard Python enforcement. The deterministic constraint now lives in the allowlist + validation layer, not in avoiding LLM entirely.
**Consequence:** All LLM tool selections are auditable (logged with reasoning). Impossible for LLM to hallucinate a tool outside TOOL_REGISTRY. The Analyst (Agent 2) can no longer request follow-up tool runs — that path was removed.

## ADR-002: LiteLLM as AI Interface
**Decision:** Use LiteLLM instead of direct SDK (OpenAI/Anthropic)
**Rationale:** Single abstraction layer allows switching between Groq (fast/cheap), OpenAI, Anthropic without code changes. Critical for cost optimization in production.
**Consequence:** All AI calls go through `litellm.completion()`, not direct SDKs.

## ADR-003: RAG Strategy — UPDATED 2026-04-23
**Original decision:** FAISS + sentence-transformers local vector store.
**V1 implementation (2026-04-23):** Keyword/TF-IDF matching in `modules/ai/rag_engine.py`. FAISS and sentence-transformers commented out in requirements.txt.
**Rationale:** Keyword RAG is fast, zero GPU dependency, sufficient for V1 demo scope. Knowledge base is small and static.
**V2 plan:** Upgrade to FAISS + all-MiniLM-L6-v2 (sentence-transformers) when knowledge base grows beyond ~500 entries or semantic retrieval quality becomes a demo differentiator.
**Consequence:** Knowledge base entries must have good keyword coverage in their text fields.

## ADR-004: BackgroundTasks → Celery Migration Path — UPDATED 2026-04-23
**Original decision:** Start with FastAPI BackgroundTasks, design for Celery migration.
**Actual state (2026-04-23):** Full Celery pipeline already implemented (scan_tasks.py, analyst_tasks.py). BackgroundTasks were skipped. ADR-004 is moot — Celery is the live architecture.
**Consequence:** Redis is now a hard runtime dependency, not optional. docker-compose.dev.yml includes it.

## ADR-005: Mock Mode for Windows Dev
**Decision:** All security tool wrappers must support mock mode
**Rationale:** Nuclei/Nmap/Gobuster are Linux binaries. Dev happens on Windows.
**Consequence:** Each scanner checks `settings.MOCK_MODE` flag. Mock returns valid JSON matching real output schema exactly. `MOCK_MODE: bool = False` added to config.py (2026-04-23).

## ADR-006: Freemium Tier Split
**Decision:** Free = passive recon (DNS, SSL, headers, fingerprint, breach). Paid = active scan + AI report.
**Rationale:** Passive recon has zero legal risk (no active probing). Active scanning requires explicit authorization — paid tier implies accountability.
**Consequence:** Tier check happens in API deps, not inside modules. The orchestrator receives `budget: int` and `allowed_tools: list[str]` (not tier string) — it is tier-agnostic. Tier-to-params computation lives in `workers/scan_tasks.py`.

## ADR-007: Follow-ups are prohibited from LLM.Future follow-ups will be orchestrator-driven via PTT state transitions. (2026-04-23)
**Decision:** Removed the `follow_up_tools` / `orchestrate_mini_scan` path from the pipeline.
**Rationale:** This path allowed Agent 2 (Analyst LLM) to indirectly trigger additional tool executions by populating `follow_up_tools` in its output. This violates ADR-001's constraint that LLM cannot control tool execution flow, even indirectly. The iteration loop added complexity without clear demo value.
**Consequence:** `orchestrate_mini_scan` Celery task deleted. `run_analyst` always chains directly to `generate_report`. Analyst prompt no longer contains `follow_up_tools` field.

## ADR-008: PyJWT over python-jose (2026-04-23)
**Decision:** Replace `python-jose` with `PyJWT>=2.8.0` in all JWT operations.
**Rationale:** `python-jose` is effectively unmaintained, has known CVEs including algorithm confusion vulnerabilities. For a security product this is unacceptable and would be flagged in any professional audit.
**Consequence:** `api/deps.py` uses `import jwt` + `jwt.PyJWTError` exception class. API is identical. No behavior change.

## ADR-009: Deterministic vs Adaptive Scan Modes (2026-04-23)
**Decision:** `active_scan.py` dispatches to two modes — `deterministic` (fixed profile order, no LLM) and `adaptive` (OrchestratorAgent with LLM + rule fallback). Mode is stored in DB and emitted in `scan_complete` event metadata.
**Rationale:** This split is the primary research contribution for benchmarking. Both modes use identical tool implementations and output schemas — only the selection strategy differs. Enables the research question: "Does adaptive LLM-guided selection improve finding coverage vs fixed sequential pipeline?"
**Research data captured:** execution_mode, per-tool timing, tools_selected_by (llm|rule_fallback|fixed), rag_context_used, retrieval_method — all in scan_complete metadata and ai_report.
**Consequence:** scan_tasks.py must pass `mode` param to active_scan. Scan DB record should eventually store mode. The deterministic mode is the research baseline.

## ADR-010: Operational Tool Registry (2026-04-23)
**Decision:** `modules/pentest/tool_registry.py` holds OPERATIONAL_REGISTRY (tool_name → executor callable) and SCAN_PROFILES. The orchestrator's TOOL_REGISTRY (in agents/orchestrator.py) remains the catalogue (metadata, descriptions, OWASP tags for the LLM prompt). `_execute_tool()` dispatches through operational registry.
**Rationale:** The catalogue is tightly coupled to the LLM system prompt (it must list all potential tools). The operational registry only contains tools with working implementations. Separating them prevents hallucinated tools from being dispatched and makes the implementation boundary explicit.
**Consequence:** Adding a new tool requires entries in BOTH registries. The operational registry is the authority on what can actually run.

## ADR-011: FAISS RAG — Soft Dependency (2026-04-23)
**Decision:** FAISS + sentence-transformers is the primary retrieval method. If import fails, silently fall back to TF-IDF keyword matching. `retrieval_method: "faiss" | "keyword"` is stored in ai_report metadata.
**Rationale:** FAISS/sentence-transformers can fail on Windows dev environments without MSVC/conda. The keyword fallback keeps the pipeline functional. The `retrieval_method` field in reports is itself a research data point — which retrieval method correlates with better remediation quality?
**Consequence:** requirements.txt must list faiss-cpu and sentence-transformers as optional (with comment). The test suite must pass with both retrieval methods.

## ADR-012: Analyst Schema Unification (2026-04-23)
**Decision:** `analyst_agent.py` is the single source of truth for AnalysisReport schema. It produces the full schema: executive_summary, risk_score, attack_chains, owasp_coverage, critical_findings, remediation_priorities, analyst_notes, top_risks, key_priorities, rag_context_used, retrieval_method, model_used. `analyst_tasks.py` calls `analyze_findings()` and stores the result — no inline LLM code.
**Rationale:** analyst_tasks.py had a duplicate LLM path with NO RAG context injection. analyst_agent.py had RAG but a weaker schema. Unifying removes the duplication, adds RAG to the persisted report, and adds research metadata fields.
**Consequence:** The inline `_ANALYST_SYSTEM_PROMPT`, `_llm_analyze()`, and `_rule_based_report()` in analyst_tasks.py are deleted. All LLM analysis goes through analyst_agent.py.

## ADR-013: ZAP Scanner — CLI-first with Daemon Option (2026-04-23)
**Decision:** ZAP scanner defaults to CLI mode (`zaproxy -cmd`). Daemon mode (persistent REST API on :8090) is optional, activated by `ZAP_DAEMON_MODE=true` env var. MOCK_MODE returns realistic mock findings with OWASP categories.
**Rationale:** CLI mode is simpler, stateless, and works reliably for one-shot scans. Daemon mode adds complexity but enables real-time progress and parallel scans — appropriate for production but not V1 demo.
**Consequence:** ZAP is in the deep and web_vapt scan profiles. Active scan is paid-tier only (it probes the target). Passive scan (spider only) could be free tier in future.

## ADR-014: Scan Task Boundary Carries Scan Type + Scan Mode (2026-04-24)
**Decision:** `workers/scan_tasks.py` is the execution boundary that receives both `scan_type` and `scan_mode`. Passive scans route through `modules/recon/passive_recon.py`. Active and full scans route through `modules/pentest/active_scan.py` with `scan_mode="deterministic" | "adaptive"`.
**Rationale:** Passing only `tier` into the worker blurred the free/passive legal boundary and left the research mode architecture unwired in the live Celery path. Making the worker aware of both scan type and scan mode preserves safety while enabling the deterministic-vs-adaptive experiment in production code.
**Consequence:** `api/v1/scans.py` and `schemas/scan.py` must carry `scan_mode` explicitly. Worker tests must assert that `scan_metadata.execution_mode` matches the requested mode. Passive scans are now guaranteed to avoid active tooling even if the caller is paid.

## ADR-015: Execution Graph (implemented 2026-04-24)
**Decision:** `modules/pentest/execution_graph.py` is a pure Python DAG that records every tool execution and finding as nodes, with directed "triggered_by" edges. `export_graph()` emits a JSON-serialisable dict that is embedded in the `scan_complete` event metadata under key `"execution_graph"`.
**Rationale:** Transforms linear scan logs into verifiable causal attack paths — a prerequisite for NodeZero-style evidence graphs and for the deterministic-vs-adaptive research comparison.
**Constraints:** Graph is write-only during execution (active_scan.py writes, nothing reads mid-pipeline). LLM can read the exported graph but cannot mutate graph state. No external graph library — pure Python dataclasses + dicts.
**Consequence:** `active_scan.py` `_deterministic_scan` calls init_graph/add_tool_execution/add_finding/link_nodes/export_graph as additive instrumentation around existing tool execution — zero existing logic changed. `scan_complete` metadata now always includes `execution_graph`. Future: store execution_graph JSON in DB scan record JSONB column.


## ADR-016: CISA KEV as High-Priority RAG Context (implemented 2026-04-24)
**Decision:** `kev_loader.py` fetches the CISA KEV catalog (JSON feed), caches locally at
`knowledge_base/kev_cache.json` (24h TTL), and exposes `get_cached_kev()` / `search_kev()`.
`rag_engine.py` extracts CVE IDs from findings (regex), runs KEV lookups, and PREPENDS
`[KEV ALERT]` strings into the context block before all other RAG sections.
The query return dict gains two additive keys: `kev_matches: list[str]` and `kev_alerts: list[str]`.

**Rationale:** A CVE that is in CISA's KEV catalog means active exploitation has been confirmed.
That signal must outrank all other knowledge-base context in the LLM prompt — an
actively-exploited RCE in Log4j is categorically more urgent than a generic OWASP A06 entry.
Prepending KEV alerts gives the LLM the correct priority ordering before it reads OWASP/header context.

**Constraints:** KEV data is analysis-layer only — it never influences tool selection or execution.
`kev_cache.json` is in `.gitignore` (auto-refreshed at runtime). Network failure degrades
gracefully to stale cache (or empty list with warning) — the rest of the pipeline proceeds.

**Import resolution:** `rag_engine.py` uses a `try/except ImportError` dual-import pattern
(`backend.modules.ai...` first, `modules.ai...` fallback) because `backend/modules/ai/__init__.py`
uses the `backend.` prefix convention while isolated test loading uses the bare `modules.` path.

**Consequence:** `RAGEngine.query()` return type broadened from `Dict[str,List[Dict]]` to
`Dict[str,Any]` to accommodate the new string-list fields. `format_context_for_prompt()` now
accepts the same wider type — callers that don't pass `kev_alerts` see no change.
`kev_cache.json` added to root `.gitignore`. `knowledge_base/__init__.py` created.
Future: wire `await load_kev_entries()` into FastAPI lifespan for eager cache warm-up.
## ADR-017: Knowledge Base Expansion — KEV Catalog + Exploit-DB + NVD CVE (2026-04-24)
**Decision:** Three new knowledge sources added to `modules/ai/knowledge_base/`:
1. `kev_catalog.json` — full CISA KEV feed (1,579+ entries) with richer schema than `kev_cache.json`:
   adds `vulnerability_name`, `cvss_score`, `due_date`, `required_action`, `notes`.
   Fetched by `fetch_kev.py`. Permanent file (not a TTL cache).
2. `exploit_db.json` — Exploit-DB full catalog (46,993 exploits + 1,065 shellcodes = 48,058 entries)
   from official GitLab CSVs. Fields: id, description, date_published, author, type, platform,
   port, verified, codes (CVE/BID links), tags, source. Fetched by `fetch_exploitdb.py`.
3. `cve_summaries.json` — NVD API v2 CVEs, last 3 years, CVSS ≥ 7.0. Full schema including
   cvss_vector, attack_vector/complexity/PR/UI/scope, CWE IDs, CPE affected products,
   references (advisory/PoC/patch links), vendor_comments. Fetched by `fetch_cve.py`.

**RAG wiring (rag_engine.py):**
- `_KB_FILES` extended with all three new sources (graceful skip if file absent).
- `_kb_entry_to_text()` extended with text extractors for each source (FAISS indexing).
- `query()` now: (1) extract CVE IDs → KEV lookup (highest priority) → `kev_matches` + `kev_alerts`;
  (2) also match kev_catalog.json entries by CVE ID → `kev_catalog` key in result;
  (3) FAISS / keyword retrieval now also returns `exploit_db` + `cve_summaries` buckets.
- `format_context_for_prompt()` now renders KEV ALERT → KEV CATALOG DETAIL → OWASP → HEADER
  → REMEDIATION → EXPLOIT-DB → CVE SUMMARIES (priority order).

**Fetch scripts (one-shot, not at server startup):**
- `fetch_kev.py` — direct CISA feed; uses `requests` or `urllib` fallback.
- `fetch_exploitdb.py` — GitLab raw CSV for exploits + shellcodes; UTF-8/latin-1 fallback.
- `fetch_cve.py` — NVD API v2 with 120-day window chunking (API limit), 1000/page,
  Z-suffix timestamps, client-side CVSS filtering. Respects 6s rate limit (unauthenticated).

**Constraints:**
- Large files (`exploit_db.json` ~18 MB, `cve_summaries.json` ~100–300 MB) are gitignored.
- RAG engine loads all files at startup — exploit_db is large; FAISS indexing of 48k entries
  is one-time cost at first load. Consider lazy loading or separate index for exploit_db in V2.
- `kev_catalog` bucket in FAISS is routed into the `owasp` result bucket (shares slot);
  standalone `kev_catalog` key carries the direct CVE-ID matches.

## ADR-018: Additive Scan Result Metadata — execution_graph_present + kev_matches (2026-04-24)
**Decision:** Two metadata fields added to the scan results pipeline, additive-only with safe defaults:

1. `execution_graph_present: bool` — derived inside `_db_complete_scan()` from `bool(metadata.get("execution_graph"))`.
   Stored as a key inside `scan.results["scan_metadata"]`. Does NOT mutate the caller's metadata dict (new dict is built via spread).

2. `kev_matches: list[str]` — extracted from `rag_engine.query()` return value inside `AnalystAgent.analyze()`.
   Stamped onto the AnalysisReport dict (available to downstream LLM prompt readers via `report["kev_matches"]`).
   Also promoted to `scan.results["kev_matches"]` (top-level) by `_db_save_ai_report()` so any reader of scan
   results can access it without parsing `ai_report`.
   Also emitted in the `analyst_complete` Redis SSE event.

**Schema:** `ScanResultResponse` in `schemas/scan.py` gains both fields with default values
(`execution_graph_present: bool = False`, `kev_matches: list[str] = []`). Old DB records that lack these
keys deserialize correctly.

**Constraints:** Zero breaking changes — no existing field renamed or removed. No existing function
signatures changed. `analyze_findings()` signature unchanged. Test assertion for `result` dict in
`test_orchestrate_scan_pipeline_runs_requested_mode_end_to_date` unaffected because `execution_graph_present`
is added to the persisted copy (`persisted_metadata`) not to the `result` dict returned by the worker.

**Consequence:** Downstream consumers (frontend, report generator, reviewer) can now reliably check
`scan.results["kev_matches"]` and `scan.results["scan_metadata"]["execution_graph_present"]` on any
completed scan record.

## ADR-019: KEV Escalation in Analyst System Prompt (2026-04-24)
**Decision:** When `kev_matches` is non-empty, `AnalystAgent._build_system_prompt()` appends
`_KEV_SYSTEM_PROMPT_BLOCK` to the base `_SYSTEM_PROMPT` (never replaces it). The block
instructs the LLM to treat KEV CVEs as CRITICAL regardless of CVSS score, include the phrase
"known exploited in wild", and elevate remediation priority to IMMEDIATE.

After the LLM call, `analyze()` appends a human-readable KEV note to `analyst_notes`
(additive: `existing_notes + "\n" + kev_note`). Empty existing notes use `kev_note` directly.

`analyze()` and `analyze_findings()` both gain `kev_matches: List[str] = []` with
empty-list default — all existing callers continue to work without change.

`_call_llm()` gains an optional `system_prompt` parameter (defaults to `_SYSTEM_PROMPT`)
so the augmented prompt is passed per-call, not stored as mutable class state.

**Rationale:** KEV-confirmed CVEs represent the highest-urgency signal in the analysis.
The LLM must treat them as CRITICAL at the prompt level, not just because the RAG context
mentions them. Appending (not replacing) the system prompt preserves all existing output schema
instructions — the LLM still knows it must emit the full JSON schema. Annotating `analyst_notes`
gives downstream consumers (report generator, frontend) a human-readable KEV summary without
requiring a schema field change.

**Constraints:** `AnalysisReport` schema fields NOT changed — no new top-level field added
by the KEV escalation path. `kev_matches` was already present from ADR-018.
The `_SYSTEM_PROMPT` class attribute itself is never mutated — `_build_system_prompt()` builds
a new string and returns it, leaving the class-level constant intact for callers that use it directly.

**Consequence:** Backend-engineer Step 3 must call `analyze_findings(scan_results, kev_matches=kev_ids)`
where `kev_ids` comes from `context["kev_matches"]` returned by `rag_engine.query()` in `analyst_tasks.py`.
15 new unit tests added in `backend/modules/ai/test_analyst_agent.py` — all passing.

---
_Add new ADRs as decisions are made during build_
