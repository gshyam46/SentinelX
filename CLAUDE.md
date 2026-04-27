# SentinelX — Claude Code Master Config

## Project Identity
AI-driven security decision engine: external black-box pentesting + LLM security analysis + internal VAPT+SOC.
**Stack:** FastAPI (Python 3.11+) · PostgreSQL 16 (asyncpg) · Redis 7 + Celery · React + Vite + React Flow · Docker
**Deploy target:** Ubuntu 22.04 — Nmap, Nuclei, ZAP as system binaries
**Dev environment:** Windows — MOCK_MODE=true for all tool wrappers

---

## Session Startup (mandatory every session)

1. Read `PROGRESS.md` — restore active phase and task state
2. Confirm which Phase 1.5 task you are on before writing any code
3. Delegate to correct agent (see table below)
4. On session end: update `PROGRESS.md` and `DECISIONS.md`

---

## Phase Status

| Phase | Scope | Status |
|---|---|---|
| 1 | Backend core, passive recon, active scan, AI analyst, execution graph, KEV/RAG | ✅ COMPLETE |
| 1.5 | Docker prod, Alembic, W2/W5/W6 fixes, React UI, PDF report, Linux E2E validation | 🔧 ACTIVE |
| 2 | Validation layer, PTT, chained attack paths, Find→Fix→Verify, authenticated scan | ⬜ QUEUED |
| 3 | LLM security module (OWASP LLM Top 10) | ⬜ QUEUED |
| 4 | SIEM module | ⬜ QUEUED |
| 5 | VAPT+SOC with code access | ⬜ QUEUED |

**ADR-026 gate:** Do not start Phase 2 until Phase 1.5 end condition is met (see PROGRESS.md).

---

## Critical Architecture Rules (Never Violate)

1. LLM recommends tools only from code-enforced `ALLOWED_TOOLS` — never executes tools directly
2. All tool dispatch via `_execute_tool()` → `OPERATIONAL_REGISTRY` in `tool_registry.py`
3. LLM only interprets structured JSON tool output — never discovers vulnerabilities
4. All LLM outputs validated via Pydantic before use or storage
5. Passive scans never touch active tooling — enforced in `scan_tasks.py` worker boundary (not just API)
6. KEV data is analysis-layer only — never influences tool selection or execution
7. Phase 2 follow-ups: PTT state-transition model only (orchestrator acts on PTT state; LLM updates state)
8. Validation layer (Phase 2): confirms findings only, never performs destructive exploitation
9. Attack chains derived from execution graph DAG edges only — no inference from finding text
10. `_KEV_SYSTEM_PROMPT_BLOCK` appended to base prompt only when kev_matches non-empty — never replaces base prompt

---

## Agent Delegation (strict — never load multiple large files in main context)

| Task involves | Delegate to |
|---|---|
| api/, models/, schemas/, workers/, Docker, Alembic, Redis/aioredis | @backend-engineer |
| modules/pentest/, tool_registry, active_scan, execution_graph, validation/ (Ph2) | @pentest-engineer |
| modules/ai/, RAG, analyst_agent, remediation_agent, llm_security/ (Ph3) | @ai-architect |
| modules/recon/ | @recon-engineer |
| frontend/, React, React Flow, PDF report | @frontend-engineer |
| KEV/ExploitDB/NVD KB ingestion, fetch scripts | @knowledge-engineer |
| ADR-009 benchmark data, research metadata logging | @research-analyst |
| All audits, E2E validation | @reviewer |

**Rule:** Task touches more than one file → delegate.

---

## Directory Map

```
sentinelX/
├── CLAUDE.md                    ← YOU ARE HERE
├── ARCHITECTURE.md              ← System design + data flows + phase roadmap
├── PROGRESS.md                  ← Task board, phase status, known issues, session log
├── DECISIONS.md                 ← ADR log (ADR-001 through ADR-026+)
├── backend/
│   ├── main.py                  # FastAPI factory + lifespan (KEV pre-warm)
│   ├── config.py                # MOCK_MODE, SYNC_DATABASE_URL, API keys
│   ├── api/v1/                  # auth.py, scans.py (+/report Ph1.5), health.py
│   ├── db/session.py            # Async SQLAlchemy engine
│   ├── models/                  # user.py, scan.py (ORM)
│   ├── schemas/                 # user.py, scan.py (Pydantic I/O)
│   ├── modules/
│   │   ├── recon/               # ✅ DNS, SSL, headers, fingerprint, breach
│   │   ├── pentest/             # ✅ active_scan, tool_registry, execution_graph, nuclei, nmap, zap
│   │   │   └── validation/      # ⬜ Phase 2: XSS/SQLi/IDOR/CORS validators
│   │   ├── ai/                  # ✅ analyst_agent, remediation_agent, rag_engine, knowledge_base/
│   │   │   └── llm_security/    # ⬜ Phase 3: OWASP LLM Top 10
│   │   ├── detection/           # ⬜ Phase 4: SIEM
│   │   └── report/              # ⬜ Phase 1.5: PDF generator
│   └── workers/
│       ├── scan_tasks.py        # Celery scan boundary (scan_type + scan_mode)
│       └── analyst_tasks.py     # analyze_findings() single LLM path
├── agents/
│   └── orchestrator.py          # OrchestratorAgent (adaptive mode)
├── docker/
│   ├── docker-compose.dev.yml
│   └── docker-compose.prod.yml  # ⬜ Phase 1.5
└── frontend/                    # ⬜ Phase 1.5
    └── src/
```

---

## Coding Standards

- Async-first: all DB calls and I/O use `async/await`
- Full type hints on all functions
- Pydantic models for all API inputs and outputs
- Tool subprocesses: `asyncio.wait_for` with timeout (Phase 1.5 fix)
- MOCK_MODE on Windows: returns structured fake JSON matching real tool output schema exactly
- Never use `print()` — use Python `logging` module
- All errors → structured JSON response, never crash the pipeline
- Every new module requires `test_*.py` before marked complete
- Adding a new tool: register in both `TOOL_REGISTRY` (catalogue/LLM prompt) AND `OPERATIONAL_REGISTRY` (callable dispatch)

---

## Standing Order — Docs After Every Task

Without being asked, after every completed task:
1. Update `PROGRESS.md` — mark task done, update session log, note any blockers
2. Update `DECISIONS.md` — add ADR if architectural decision was made
3. Update this file (`CLAUDE.md`) only if phase status changes or a new directory is added
