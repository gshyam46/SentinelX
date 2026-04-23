# SentinelX — Session Progress Tracker
> Read this at the start of every Claude Code session. Update it at the end.

---

## Current Sprint: Week 2 — VAPT Coverage + RAG Upgrade + Pipeline Stabilization

### Last Session Summary (2026-04-23, session 1)
- Completed full architectural review + triage pass
- Fixed python-jose → PyJWT (security vulnerability)
- Added MOCK_MODE to config.py
- Refactored orchestrator: tier removed, budget+allowed_tools added (ADR-001 updated)
- Removed follow_up_tools path from analyst pipeline (LLM no longer controls tool execution)
- Wired Agent 3 (RemediationAgent) into generate_report task
- Deleted dead code: scan_worker.py, modules/pentest/active_scan.py

### Session 2 (2026-04-23) — Bugs found + Work dispatched
**Critical bugs discovered this session:**
- `_execute_tool` in orchestrator.py imports from `backend.tools.*` (DOES NOT EXIST) — loop can't execute any tools
- `analyst_tasks.py` calls litellm directly without RAG context — quality gap + duplicate LLM path
- Schema mismatch: `analyst_agent.analyze()` returns different keys than analyst_tasks.py expects
- `owasp_categories` missing from nuclei/nmap findings — orchestrator coverage tracking broken

**Work dispatched (agents running):**
- pentest-engineer: tool_registry.py, SCAN_PROFILES, zap_scanner.py, active_scan.py (det+adaptive), fix _execute_tool, add owasp_categories to nuclei/nmap
- ai-architect: FAISS RAG upgrade (soft dep), analyst schema unification, fix analyst_tasks to use analyst_agent

### Active Tasks
- [x] tool_registry.py — OPERATIONAL_REGISTRY + SCAN_PROFILES (done)
- [x] zap_scanner.py — CLI + daemon, passive + active, MOCK_MODE (done)
- [x] active_scan.py — deterministic + adaptive dispatcher (done)
- [x] Fix orchestrator._execute_tool — now dispatches via OPERATIONAL_REGISTRY (done)
- [x] Add ZAP + gobuster to orchestrator catalogue TOOL_REGISTRY (done)
- [x] nuclei_scanner.py — MOCK_MODE check + owasp_categories on all findings (done)
- [x] nmap_scanner.py — MOCK_MODE check + owasp_categories on all findings (done)
- [x] rag_engine.py — FAISS + sentence-transformers (soft dep, keyword fallback) (done)
- [x] analyst_agent.py — unified to full AnalysisReport schema + research metadata (done)
- [x] analyst_tasks.py — replaced inline LLM with analyze_findings() call (done)
- [x] requirements.txt — added faiss-cpu, sentence-transformers, numpy (done)
- [ ] scan_tasks.py — add mode param (deterministic/adaptive) — small, unblocked
- [ ] E2E integration test — next priority
- [ ] reviewer — full audit (after E2E passes)

---

## Feature Status

### ✅ COMPLETE
| Feature | File | Notes |
|---|---|---|
| Async PostgreSQL setup | `db/session.py` | asyncpg, auto-init |
| JWT Auth | `api/v1/auth.py` | register, login, token refresh |
| Tier-gating middleware | `api/deps.py` | `require_paid_tier` DI |
| Scan job management | `api/v1/scans.py` | Celery dispatch, WebSocket, rate limiting |
| DNS Intelligence | `modules/recon/dns_intel.py` | A/MX/NS/TXT, SPF/DKIM/DMARC, crt.sh, AXFR |
| SSL/TLS Analyzer | `modules/recon/ssl_analyzer.py` | x509, cipher suites, expiry |
| HTTP Header Checker | `modules/recon/header_checker.py` | OWASP headers, exposed paths |
| Tech Fingerprinting | `modules/recon/tech_fingerprint.py` | 25+ sigs, CVE version patterns |
| Breach Intelligence | `modules/recon/breach_check.py` | AlienVault OTX, Shodan |
| Passive Recon Orchestrator | `modules/recon/passive_recon.py` | Full pipeline |
| Nuclei Scanner | `modules/pentest/nuclei_scanner.py` | MOCK_MODE + owasp_categories ✅ |
| Nmap Scanner | `modules/pentest/nmap_scanner.py` | MOCK_MODE + owasp_categories ✅ |
| ZAP Scanner | `modules/pentest/zap_scanner.py` | CLI+daemon, passive+active, MOCK_MODE ✅ |
| active_scan.py | `modules/pentest/active_scan.py` | deterministic + adaptive dispatcher ✅ |
| Operational Tool Registry | `modules/pentest/tool_registry.py` | OPERATIONAL_REGISTRY + SCAN_PROFILES ✅ |
| RAG Engine (FAISS) | `modules/ai/rag_engine.py` | FAISS + sentence-transformers (soft dep) ✅ |
| Analyst Agent | `modules/ai/analyst_agent.py` | Full AnalysisReport schema + research metadata ✅ |
| Analyst Task | `workers/analyst_tasks.py` | Wired to analyst_agent, no duplicate LLM ✅ |
| Constrained Adaptive Orchestrator | `agents/orchestrator.py` | budget+allowed_tools, LLM-guided, rule fallback |
| Celery pipeline (scan → analyst → report) | `workers/scan_tasks.py`, `analyst_tasks.py` | Full chain wired |
| Remediation Agent (Agent 3) | `modules/ai/remediation_agent.py` | Wired into generate_report task |
| Knowledge Base JSONs | `modules/ai/knowledge_base/` | owasp_top10, remediation_guides, security_headers |

### 🔧 IN PROGRESS
| Feature | File | Status |
|---|---|---|
| scan_tasks.py mode param | `workers/scan_tasks.py` | Add `mode` (deterministic/adaptive) — small |
| E2E pipeline test | `tests/test_pipeline.py` | Next up — POST /scans → report_ready |

### ⬜ QUEUED (Week 3+)
- React frontend (Dashboard, FindingsTable, AIInsightsPanel)
- PDF report generator (ReportLab)
- Alembic migrations (replace dev auto-create)
- Docker production image
- Nginx + SSL
- scan_tasks.py: add `mode` param (deterministic/adaptive) — small addition, unblocked after session 2
- E2E integration test — unblocked after session 2 agents complete

---

## Architecture Decisions Log
> For detailed decisions see `.claude/DECISIONS.md`

| Decision | Rationale |
|---|---|
| LiteLLM over direct OpenAI SDK | Switchable between Groq/OpenAI/Anthropic |
| FAISS over Pinecone/Weaviate | Local, fast — keyword RAG for V1, FAISS for v2 |
| BackgroundTasks → Celery | Celery already in place; BackgroundTasks migration skipped |
| Mock mode on Windows | Real tools only run on Linux prod target |
| Constrained adaptive orchestrator | LLM recommends from ALLOWED_TOOLS only (code-enforced) |
| PyJWT over python-jose | python-jose unmaintained/CVE; replaced 2026-04-23 |
| No follow-up mini-scans | LLM cannot request additional tool runs mid-pipeline |

---

## Known Issues / Blockers
- [ ] `modules/ai/analyst_agent.py` exists but `analyst_tasks.py` calls litellm directly — duplication. Decide which path to standardize before frontend integration.
- [ ] `SYNC_DATABASE_URL` in config.py — unused. Safe to remove unless Alembic needs it.

---

## Next 3 Tasks (ordered)
1. Verify nmap_scanner.py mock mode works (add MOCK_MODE check if missing)
2. Run `test_api.py` end-to-end and confirm pipeline wires correctly
3. Build knowledge base content (owasp_top10.json, remediation_guides.json with real data)

---
_Last updated: 2026-04-23 by Claude_
