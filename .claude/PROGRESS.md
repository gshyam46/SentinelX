# SentinelX - Session Progress Tracker
> Read this at the start of every Claude Code session. Update it at the end.

---

## Current Sprint: Week 2 - VAPT Coverage + RAG Upgrade + Pipeline Stabilization

### Last Session Summary (2026-04-23)
- Completed pentest track foundation: `tool_registry.py`, `active_scan.py`, `zap_scanner.py`
- Fixed `orchestrator._execute_tool()` to dispatch through `OPERATIONAL_REGISTRY`
- Added `owasp_categories` coverage to Nuclei and Nmap findings
- Upgraded AI layer with FAISS-backed RAG fallback and unified analyst schema
- Replaced duplicate analyst task logic with `analyze_findings()`

### Session Summary (2026-04-24 — KB Expansion)
- Fetched CISA KEV full catalog → `kev_catalog.json` (1,579 entries, richer schema with requiredAction, dueDate, notes)
- Fetched Exploit-DB full catalog → `exploit_db.json` (48,058 entries: 46,993 exploits + 1,065 shellcodes)
- Fetching NVD CVEs → `cve_summaries.json` (last 3 years, CVSS ≥ 7.0, ~10 × 120-day windows in progress)
- Expanded `rag_engine.py`: added kev_catalog / exploit_db / cve_summaries to KB + FAISS index; KEV-priority routing; prompt context blocks for exploit_db and cve_summaries
- Added `fetch_kev.py`, `fetch_exploitdb.py`, `fetch_cve.py` as one-shot refresh scripts
- Updated `.gitignore` to exclude large generated files; `kev_catalog.json` (~1.2 MB) is committed
- Logged ADR-017 in DECISIONS.md
- Wired `scan_type` and `scan_mode` through the Celery scan boundary
- `workers/scan_tasks.py` now uses the dedicated passive recon engine for passive scans
- Active and full scans now flow through `modules/pentest/active_scan.py` with validated deterministic/adaptive mode selection
- Added isolated pytest coverage in `backend/test_api.py` for:
  - API dispatch carrying `scan_type` + `scan_mode`
  - free-tier active-scan blocking
  - worker-boundary pipeline execution and metadata persistence
- Verified the targeted tests pass with:
  - `backend\venv\Scripts\python.exe -m pytest backend/test_api.py`
- Built `modules/pentest/execution_graph.py` — pure Python causal DAG (no external libs)
  - `init_graph`, `add_tool_execution`, `add_finding`, `link_nodes`, `export_graph` public API
  - node types: `tool_execution`, `finding`; edge type: `triggered_by`; UUID4 node IDs
- Wired execution graph into `_deterministic_scan` in `active_scan.py` (additive only, zero existing logic changed)
  - graph initialised at scan start; each tool execution + its findings are recorded and linked
  - `scan_complete` metadata now always includes `execution_graph` key
- 36/36 tests passing: `backend\venv\Scripts\python.exe -m pytest backend/modules/pentest/test_execution_graph.py -v`

### Active Tasks
- [x] `tool_registry.py` - operational registry + scan profiles
- [x] `zap_scanner.py` - CLI + daemon mode + MOCK_MODE support
- [x] `active_scan.py` - deterministic + adaptive dispatcher
- [x] `orchestrator._execute_tool` - dispatches through `OPERATIONAL_REGISTRY`
- [x] `nuclei_scanner.py` - MOCK_MODE + `owasp_categories`
- [x] `nmap_scanner.py` - MOCK_MODE + `owasp_categories`
- [x] `rag_engine.py` - FAISS primary path with keyword fallback; KEV-enriched query; kev_catalog/exploit_db/cve_summaries KB sources wired
- [x] `analyst_agent.py` - unified `AnalysisReport` schema + research metadata; `kev_matches` stamped onto report; KEV prompt escalation + analyst_notes annotation wired (Step 2 of KEV pipeline complete)
- [x] `analyst_tasks.py` - calls `analyze_findings()` as single source of truth; persists `kev_matches` as top-level `scan.results` key; emits `kev_matches` in `analyst_complete` Redis event
- [x] `workers/scan_tasks.py` - `scan_type` + `scan_mode` boundary wiring complete; `execution_graph_present` derived and persisted in `scan_metadata` on scan completion
- [x] `schemas/scan.py` - `execution_graph_present: bool = False` and `kev_matches: list[str] = []` added to `ScanResultResponse` (backward-compatible defaults)
- [x] `backend/test_api.py` - isolated integration coverage added and passing (3/3)
- [x] `execution_graph.py` - causal DAG for tool chaining (36/36 tests passing)
- [x] `kev_loader.py` - CISA KEV feed loader with 24h cache, fallback, Pydantic schema (31/31 tests passing)
- [x] `kev_catalog.json` - full CISA KEV catalog (1,579 entries, fetch_kev.py)
- [x] `exploit_db.json` - Exploit-DB full catalog (48,058 entries, fetch_exploitdb.py)
- [x] `ARCHITECTURE.md` - synced to live adaptive orchestrator + Celery pipeline + execution graph + KEV/RAG architecture
- [x] `CLAUDE.md` - build status updated to reflect Week 2 completion state
- [ ] `cve_summaries.json` - NVD CVE fetch in progress (fetch_cve.py, ~10 min)
- [ ] KEV lifespan pre-warm - wire `await load_kev_entries()` into FastAPI lifespan (`@backend-engineer`)
- [ ] `@reviewer` audit - full audit of pentest + worker pipeline

---

## Feature Status

### COMPLETE
| Feature | File | Notes |
|---|---|---|
| Async PostgreSQL setup | `db/session.py` | asyncpg, auto-init |
| JWT Auth | `api/v1/auth.py` | register, login, token refresh |
| Tier-gating middleware | `api/deps.py` | `require_paid_tier` DI |
| Scan job management | `api/v1/scans.py` | Celery dispatch, WebSocket, rate limiting |
| DNS Intelligence | `modules/recon/dns_intel.py` | A/MX/NS/TXT, SPF/DKIM/DMARC, crt.sh, AXFR |
| SSL/TLS Analyzer | `modules/recon/ssl_analyzer.py` | x509, cipher suites, expiry |
| HTTP Header Checker | `modules/recon/header_checker.py` | OWASP headers, exposed paths |
| Tech Fingerprinting | `modules/recon/tech_fingerprint.py` | 25+ signatures, CVE version patterns |
| Breach Intelligence | `modules/recon/breach_check.py` | AlienVault OTX, Shodan |
| Passive Recon Orchestrator | `modules/recon/passive_recon.py` | Dedicated passive worker path now wired |
| Nuclei Scanner | `modules/pentest/nuclei_scanner.py` | MOCK_MODE + OWASP categories |
| Nmap Scanner | `modules/pentest/nmap_scanner.py` | MOCK_MODE + OWASP categories |
| ZAP Scanner | `modules/pentest/zap_scanner.py` | CLI + daemon, passive + active, MOCK_MODE |
| Active Scan Dispatcher | `modules/pentest/active_scan.py` | deterministic + adaptive execution + execution graph wiring |
| Operational Tool Registry | `modules/pentest/tool_registry.py` | runnable tools + scan profiles |
| Execution Graph | `modules/pentest/execution_graph.py` | causal DAG — tool→finding edges, UUID4 nodes, JSON export |
| RAG Engine | `modules/ai/rag_engine.py` | FAISS + sentence-transformers fallback; KEV-enriched query with kev_matches + kev_alerts; kev_catalog/exploit_db/cve_summaries KB sources wired |
| KEV Loader | `modules/ai/knowledge_base/kev_loader.py` | CISA KEV feed, 24h cache, Pydantic KEVEntry, graceful fallback |
| KEV Catalog | `modules/ai/knowledge_base/kev_catalog.json` | 1,579 entries, full schema (vulnerability_name, requiredAction, dueDate, notes) |
| Exploit-DB Catalog | `modules/ai/knowledge_base/exploit_db.json` | 48,058 entries (exploits + shellcodes), gitignored, refresh via fetch_exploitdb.py |
| CVE Summaries | `modules/ai/knowledge_base/cve_summaries.json` | NVD CVEs last 3y CVSS ≥7, gitignored, refresh via fetch_cve.py |
| KEV Loader | `modules/ai/knowledge_base/kev_loader.py` | CISA KEV feed, 24h cache, Pydantic KEVEntry, graceful fallback |
| Analyst Agent | `modules/ai/analyst_agent.py` | full `AnalysisReport` schema + research metadata; KEV escalation in system prompt + analyst_notes annotation |
| Analyst Task | `workers/analyst_tasks.py` | wired to analyst agent, no duplicate LLM path |
| Celery Pipeline | `workers/scan_tasks.py`, `workers/analyst_tasks.py` | scan -> analyst -> report |
| Remediation Agent | `modules/ai/remediation_agent.py` | wired into report generation |

### IN PROGRESS
| Feature | File | Status |
|---|---|---|
| Reviewer audit | `backend/` | Run focused review on pentest + worker changes |
| Doc sync | `CLAUDE.md`, `ARCHITECTURE.md`, `DOCUMENTATION.md` | Still contains pre-adaptive architecture text in places |
| Broader integration coverage | `backend/test_api.py` | Add `full` scan path and report-ready chain coverage |

### QUEUED (Week 3+)
- React frontend (Dashboard, FindingsTable, AIInsightsPanel)
- PDF report generator (ReportLab)
- Alembic migrations (replace dev auto-create)
- Docker production image
- Nginx + SSL
- - Pentest Task Tree (PTT) for orchestrator-driven follow-ups
- Attack path chaining using execution graph
- Continuous verification (Find → Fix → Verify loop)
- LLM security module (prompt injection, tool shadowing detection)
---

## Architecture Decisions Log
> For detailed decisions see `.claude/DECISIONS.md`

| Decision | Rationale |
|---|---|
| LiteLLM over direct OpenAI SDK | Switchable between Groq/OpenAI/Anthropic |
| FAISS over Pinecone/Weaviate | Local and fast for V1, with keyword fallback for dev resilience |
| Celery over BackgroundTasks | Redis/Celery is already the live architecture |
| Mock mode on Windows | Real tools only run on Linux production target |
| Constrained adaptive orchestrator | LLM recommends only from code-enforced allowlists |
| Passive worker path for free scans | Preserves the freemium/legal boundary |
| No follow-up mini-scans | LLM cannot request additional tool runs mid-pipeline |

---

## Known Issues / Blockers
- [ ] `SYNC_DATABASE_URL` in `config.py` is still unused unless Alembic needs it.
- [ ] Adaptive event metadata is still thinner than deterministic metadata (`tools_selected_by` is not yet present on every adaptive scan event).
- [x] `execution_graph_present` now derived and persisted in `scan_metadata` JSONB on scan completion (2026-04-24).
- [ ] Full `execution_graph` payload (the entire node/edge dict) is not yet stored as its own top-level key in `scan.results` — only `execution_graph_present: bool` is stored in `scan_metadata`. If the full graph needs to be queryable, add it as `scan.results["execution_graph"]` in a follow-up.
- [ ] KEV cache is not pre-warmed at startup — first scan may call network; `await load_kev_entries()` not yet in FastAPI lifespan.

---

## Next 3 Tasks (ordered)
1. `@backend-engineer` — Step 3: pass `kev_matches` from `rag_engine.query()` result through `analyst_tasks.py` → `analyze_findings(kev_matches=...)` (KEV pipeline final wiring)
2. `@backend-engineer` — wire `await load_kev_entries()` into FastAPI lifespan for KEV pre-warm (first-scan network latency fix)
3. `@reviewer` — full audit of pentest + worker pipeline (active_scan, execution_graph, scan_tasks, analyst_tasks, rag_engine)

---
_Last updated: 2026-04-24 by Codex_
