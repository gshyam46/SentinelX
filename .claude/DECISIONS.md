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

## ADR-007: No Follow-Up Mini-Scans (2026-04-23)
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

---
_Add new ADRs as decisions are made during build_
