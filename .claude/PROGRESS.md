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

### Session Summary (2026-04-24)
- Wired `scan_type` and `scan_mode` through the Celery scan boundary
- `workers/scan_tasks.py` now uses the dedicated passive recon engine for passive scans
- Active and full scans now flow through `modules/pentest/active_scan.py` with validated deterministic/adaptive mode selection
- Added isolated pytest coverage in `backend/test_api.py` for:
  - API dispatch carrying `scan_type` + `scan_mode`
  - free-tier active-scan blocking
  - worker-boundary pipeline execution and metadata persistence
- Verified the targeted tests pass with:
  - `backend\venv\Scripts\python.exe -m pytest backend/test_api.py`

### Active Tasks
- [x] `tool_registry.py` - operational registry + scan profiles
- [x] `zap_scanner.py` - CLI + daemon mode + MOCK_MODE support
- [x] `active_scan.py` - deterministic + adaptive dispatcher
- [x] `orchestrator._execute_tool` - dispatches through `OPERATIONAL_REGISTRY`
- [x] `nuclei_scanner.py` - MOCK_MODE + `owasp_categories`
- [x] `nmap_scanner.py` - MOCK_MODE + `owasp_categories`
- [x] `rag_engine.py` - FAISS primary path with keyword fallback
- [x] `analyst_agent.py` - unified `AnalysisReport` schema + research metadata
- [x] `analyst_tasks.py` - calls `analyze_findings()` as single source of truth
- [x] `workers/scan_tasks.py` - `scan_type` + `scan_mode` boundary wiring complete
- [x] `backend/test_api.py` - isolated integration coverage added and passing
- [ ] `@reviewer` audit - next priority

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
| Active Scan Dispatcher | `modules/pentest/active_scan.py` | deterministic + adaptive execution |
| Operational Tool Registry | `modules/pentest/tool_registry.py` | runnable tools + scan profiles |
| RAG Engine | `modules/ai/rag_engine.py` | FAISS + sentence-transformers fallback strategy |
| Analyst Agent | `modules/ai/analyst_agent.py` | full `AnalysisReport` schema + research metadata |
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
- [ ] `CLAUDE.md` and `ARCHITECTURE.md` still describe the older fixed/zero-LLM orchestrator in several sections.
- [ ] `SYNC_DATABASE_URL` in `config.py` is still unused unless Alembic needs it.
- [ ] Adaptive event metadata is still thinner than deterministic metadata (`tools_selected_by` is not yet present on every adaptive event).

---

## Next 3 Tasks (ordered)
1. Run `@reviewer` audit on the pentest + worker pipeline changes
2. Sync `CLAUDE.md` and `ARCHITECTURE.md` to the live adaptive/passive-worker architecture
3. Extend isolated tests to cover the `full` scan path and report-ready chain

---
_Last updated: 2026-04-24 by Codex_
