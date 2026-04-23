# SentinelX — Claude Code Master Config

## Project Identity

Full-stack AI-powered cybersecurity assessment platform.
**Stack:** FastAPI (Python 3.11+) · PostgreSQL 16 (asyncpg) · Redis + Celery · React/Vite · Docker
**Target Deploy:** Ubuntu 22.04 Linux (all security tools pre-installed as system binaries)
**Dev Env:** Windows (mock mode for native tools like Nuclei/Nmap/Gobuster)
**Build Phase:** V1 Demo — production-grade quality, no shortcuts

## Critical Architecture Rules (Never Violate)

1. AI (LLM) NEVER decides which tools to execute — all flow is deterministic Python code
2. LLM ONLY interprets structured JSON tool outputs — it never discovers vulnerabilities
3. Agent 1 (Orchestrator) = pure Python, zero LLM involvement
4. Agent 2 (Analyst) + Agent 3 (Remediation) = LLM + RAG, strict prompt boundaries
5. All LLM outputs validated via Pydantic before use
6. Tier-gating enforced at API layer: free = passive recon only, paid = active scan + AI report

## Directory Map

```
sentinelX/
├── CLAUDE.md                    ← YOU ARE HERE
├── .claude/
│   ├── PROGRESS.md              ← Session state tracker (read this every session)
│   ├── agents/                  ← Sub-agent definitions
│   └── DECISIONS.md             ← Architecture decisions log
├── backend/
│   ├── main.py                  ← FastAPI factory + lifespan
│   ├── config.py                ← Pydantic-settings config
│   ├── api/v1/                  ← auth.py, scans.py, health.py
│   ├── models/                  ← SQLAlchemy ORM (user.py, scan.py)
│   ├── schemas/                 ← Pydantic I/O models
│   ├── modules/
│   │   ├── recon/               ← ✅ COMPLETE passive recon engine
│   │   ├── pentest/             ← 🔧 Active scanning (in progress)
│   │   ├── ai/                  ← 🔧 AI agent layer (in progress)
│   │   └── report/              ← PDF generator
│   └── workers/celery_worker.py
└── frontend/src/
```

## Build Status (update in PROGRESS.md, not here)

- ✅ Week 1 DONE: DB, JWT auth, tier-gating, scan management, full passive recon engine
- 🔧 Week 2 ACTIVE: nmap_scanner, active_scan orchestrator, RAG engine, AI agents
- ⬜ Week 3: Celery migration, React frontend, PDF reports, Alembic migrations

## Coding Standards

- Async-first: all DB calls use `asyncpg`, all I/O uses `async/await`
- Type hints everywhere — all functions fully typed
- Pydantic models for all API inputs/outputs
- Tools (Nuclei/Nmap/Gobuster) run as async subprocesses with timeouts
- Mock mode in Windows: return structured fake JSON matching real tool output schema
- Never use `print()` — use Python `logging` module
- All errors caught and returned as structured JSON, never crash the pipeline

## Session Startup Ritual (do this every session)

1. Read `.claude/PROGRESS.md` to restore state
2. Read the relevant module's `CONTEXT.md` if working on a specific module
3. Confirm current task before writing any code
4. On session end: update `PROGRESS.md` with what was done and what's next

## Test Before Done

- Every module must have a `test_*.py` — use pytest + pytest-asyncio
- Run tests before marking any task complete
- Mock external APIs (OTX, Shodan, HaveIBeenPwned) in tests

## Agent Delegation Rules

- Use @recon-engineer for anything in modules/recon/
- Use @pentest-engineer for anything in modules/pentest/
- Use @ai-architect for anything in modules/ai/ and RAG design
- Use @backend-engineer for API routes, DB models, auth, Celery
- Use @reviewer for code review before any module is marked complete
- Delegate when a task would generate large file reads or logs (keep main context clean)

## Standing Order — Always Keep Docs Current

After EVERY task, fix, or decision — without being asked — you must:

1. Update .claude/PROGRESS.md
   - Mark completed items ✅
   - Update "Active Task"
   - Update "Next 3 Tasks"
   - Note any blockers discovered

2. Update .claude/DECISIONS.md
   - Log any new architectural decision made this session
   - If an existing ADR was changed, update it with the new decision
     and note what changed and why

3. Update CLAUDE.md itself if:
   - Build status section changes
   - A new module is added to the directory map
   - A core architectural rule changes

4. If a module gets complex enough — create or update
   modules/[name]/CONTEXT.md with current state of that module

This is not optional. Stale docs = broken context next session =
wasted time re-discovering what was already decided.

## Mandatory Agent Delegation

For EVERY task involving file reads or code changes, delegate to the
correct specialist agent. Never read multiple large files in the main
context window.

| Task involves...        | Delegate to       |
| ----------------------- | ----------------- |
| api/, models/, schemas/ | @backend-engineer |
| modules/pentest/        | @pentest-engineer |
| modules/ai/             | @ai-architect     |
| modules/recon/          | @recon-engineer   |
| Any review/audit        | @reviewer         |

Default behavior: if the task touches more than one file,
delegate it. Do not read files into main context directly.
