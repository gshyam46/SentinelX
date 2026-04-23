# SentinelX: Comprehensive Architecture & Progress Documentation

## 1. Project Overview & Vision
**SentinelX** is a full-stack, AI-powered cybersecurity assessment platform. It combines deterministic security tooling with a controlled AI interpretation layer to deliver explainable vulnerability intelligence and actionable remediation guidance.

**Freemium Model:**
- **Free Tier:** Automated passive reconnaissance (DNS, SSL, HTTP headers, technology fingerprinting, breach intelligence). Limited to 3 scans/day.
- **Paid/Pro Tier:** Active vulnerability scanning (Nuclei, Nmap, directory fuzzing) + full AI-generated reports.

---

## 2. Revised Architecture Principles (Linux-First Deployment)

> **Development Environment:** Windows (local dev, mock mode for native tools)
> **Production Target:** Linux (Ubuntu 22.04 / Debian-based), where all security tools (Nuclei, Nmap, Gobuster) are pre-installed as system binaries.

The platform follows a **two-layer controlled architecture** with a constrained adaptive orchestrator at the core:

### Layer 1 — Tools Layer (Deterministic + Constrained Adaptive Execution)
Security tools perform all vulnerability detection. AI is never allowed to discover vulnerabilities or introduce tools outside the enforced allowlist.

Agent 1 (Orchestrator) operates in two mutually exclusive modes:

**Deterministic mode** — fixed scan profile, no LLM involvement whatsoever. Tools run in the order defined by `SCAN_PROFILES` in `modules/pentest/tool_registry.py`.

**Adaptive mode** — LLM recommends which tool to run next, but only from the Python-enforced `ALLOWED_TOOLS` allowlist derived from `TOOL_REGISTRY` (in `agents/orchestrator.py`). Every LLM recommendation is validated against `OPERATIONAL_REGISTRY` (in `tool_registry.py`) before dispatch. Invalid selections trigger a deterministic rule-based fallback — execution never halts. LLM cannot execute tools, skip steps, add tools outside the registry, or trigger additional scan runs.

All tool execution dispatches through `OPERATIONAL_REGISTRY` in `modules/pentest/tool_registry.py`. No follow-up mini-scans: the LLM has no mechanism to request additional tool runs mid-pipeline.

### Layer 2 — AI Layer (Controlled Intelligence)
The AI does **not** discover vulnerabilities. It strictly:
- Interprets structured tool outputs
- Prioritizes risks with reasoning enriched by KEV and RAG context
- Generates remediation guidance
- Provides executive-level summaries

### Layer 3 — Execution Intelligence (Operational)

SentinelX incrementally builds a causal DAG during every active scan via `modules/pentest/execution_graph.py`:

tool_execution → (triggered_by) → finding

This transforms linear scan logs into verifiable attack paths. See Section 9 for full details.

This layer enables:
- attack chain reconstruction
- audit-grade evidence trails
- future automated verification loops (Find → Fix → Verify)

The graph is write-only during execution — additive instrumentation around existing tool calls, no existing logic changed. LLM may read the exported graph but cannot mutate it.

---

## 3. Architecture & Technology Stack

### Backend Stack
| Component | Technology |
|---|---|
| Framework | FastAPI (Python 3.11+), async |
| Database | PostgreSQL 16 via `sqlalchemy[asyncio]` + `asyncpg` |
| Cache/Broker | Redis 7 (Docker) → Celery workers |
| Auth | JWT + `bcrypt` password hashing |
| AI Interface | LiteLLM (Groq/OpenAI/Anthropic switchable) |
| RAG Engine | FAISS vector store + sentence-transformers |
| Containerization | Docker Compose (dev) → Docker (prod on Linux) |

### External Integrations
| Service | Purpose |
|---|---|
| Groq API (LiteLLM) | Fast LLM inference for AI agents |
| AlienVault OTX | Threat intelligence |
| Shodan | Passive host data |
| HaveIBeenPwned | Credential breach data |
| crt.sh | Subdomain enumeration |

---

## 4. Directory Structure (Full Target Layout)

```text
sentinelX/
├── .env / .env.example
├── docker/
│   └── docker-compose.dev.yml
├── ARCHITECTURE.md
├── DOCUMENTATION.md
├── README.md
├── backend/
│   ├── main.py                    # FastAPI factory + lifespan
│   ├── config.py                  # Pydantic-settings config manager
│   ├── requirements.txt
│   ├── api/
│   │   ├── deps.py                # Auth, DB, tier-gating DI
│   │   ├── router.py              # Main router aggregator
│   │   └── v1/
│   │       ├── auth.py            # /register, /login
│   │       ├── scans.py           # /scans CRUD + trigger
│   │       └── health.py          # /health
│   ├── db/
│   │   └── session.py             # Async SQLAlchemy engine
│   ├── models/                    # SQLAlchemy ORM
│   │   ├── user.py
│   │   └── scan.py
│   ├── schemas/                   # Pydantic I/O models
│   │   ├── user.py
│   │   └── scan.py
│   ├── modules/
│   │   ├── recon/                 # ✅ COMPLETE — Passive Recon Engine
│   │   │   ├── passive_recon.py   # Orchestrator
│   │   │   ├── dns_intel.py
│   │   │   ├── ssl_analyzer.py
│   │   │   ├── header_checker.py
│   │   │   ├── tech_fingerprint.py
│   │   │   └── breach_check.py
│   │   ├── pentest/               # 🔧 IN PROGRESS — Active Scanning
│   │   │   ├── active_scan.py     # Orchestrator (Agent 1 pipeline)
│   │   │   ├── nuclei_scanner.py  # ✅ Nuclei wrapper
│   │   │   └── nmap_scanner.py    # 🔧 Nmap wrapper (new)
│   │   ├── ai/                    # 🔧 NEW — AI Agent Layer
│   │   │   ├── analyst_agent.py   # Agent 2: LLM + RAG interpretation
│   │   │   ├── remediation_agent.py # Agent 3: Remediation advisor
│   │   │   ├── rag_engine.py      # FAISS + knowledge base loader
│   │   │   └── knowledge_base/    # RAG knowledge documents
│   │   │       ├── owasp_top10.json
│   │   │       ├── security_headers.json
│   │   │       ├── cve_summaries.json
│   │   │       └── remediation_guides.json
│   │   └── report/
│   │       └── report_generator.py # PDF report generator
│   └── workers/
│       └── celery_worker.py       # Celery task orchestrator
└── frontend/
    └── src/
        ├── components/
        │   ├── Dashboard.jsx
        │   ├── FindingsTable.jsx
        │   ├── AIInsightsPanel.jsx
        │   └── SeverityBadge.jsx
        └── App.jsx
```

---

## 5. Agent Roles and Celery Pipeline (Strictly Defined)

### Celery Pipeline (Live Architecture)

Celery is the live scan execution pipeline — not a future migration. The full chain:

```
POST /api/v1/scans
    → scan record created (status=pending)
    → scan_tasks.orchestrate_scan.delay(scan_id, scan_type, scan_mode)
        → scan_type="passive"  → modules/recon/passive_recon.py   (free tier)
        → scan_type="active"|"full"
             scan_mode="deterministic" → modules/pentest/active_scan._deterministic_scan
             scan_mode="adaptive"     → modules/pentest/active_scan._adaptive_scan
    → workers/analyst_tasks.run_analyst (analyze_findings)
    → generate_report
    → scan record updated (status=complete, results=JSON)
```

`workers/scan_tasks.py` is the Celery boundary that carries both `scan_type` and `scan_mode` across the task boundary. Passive scans are guaranteed to avoid active tooling regardless of tier (enforced at the worker, not just the API).

### Agent 1 — Orchestrator (Deterministic + Constrained Adaptive Controller)

**File:** `modules/pentest/active_scan.py` + `agents/orchestrator.py`

- **Deterministic mode:** fixed scan profile sequence from `SCAN_PROFILES`, zero LLM involvement. Execution graph populated as instrumentation.
- **Adaptive mode:** `OrchestratorAgent` prompts LLM for next-tool recommendation from `TOOL_REGISTRY` catalogue. Every selection validated against `OPERATIONAL_REGISTRY` before dispatch. Rule-based fallback fires on invalid selection. LLM cannot add tools, skip steps, or request additional scans.
- `scan_complete` event metadata always includes: `execution_mode`, `tool_timings`, `tools_selected_by` (llm | rule_fallback | fixed), `execution_graph`.

### Agent 2 — Analyst (LLM + RAG)

**File:** `modules/ai/analyst_agent.py`

- Sole source of `AnalysisReport` — no duplicate LLM paths exist.
- Input: structured findings JSON + RAG query result (including `kev_matches`)
- RAG result always injected before LLM call. `kev_matches` boosts severity reasoning: analyst flags "known exploited in wild" when the list is non-empty.
- Output schema (`AnalysisReport`): `executive_summary`, `risk_score`, `attack_chains`, `owasp_coverage`, `critical_findings`, `remediation_priorities`, `analyst_notes`, `top_risks`, `key_priorities`, `rag_context_used`, `retrieval_method`, `model_used`
- Prompt is fully structured — LLM cannot modify flow.

### Agent 3 — Remediation Advisor

**File:** `modules/ai/remediation_agent.py`

- Input: processed findings from Agent 2
- Output: step-by-step remediation, prioritized fix list
- Uses RAG to retrieve known remediation patterns

---

## 6. RAG Strategy

The system uses a lightweight FAISS-based RAG for local, fast retrieval.

### Knowledge Base Contents
| File | Contents |
|---|---|
| `owasp_top10.json` | OWASP Top 10 explanations + impacts |
| `security_headers.json` | Header best practices and fix patterns |
| `cve_summaries.json` | Common CVE descriptions and severity |
| `remediation_guides.json` | Step-by-step fix guides per vuln type |
| `kev_catalog.json` | CISA Known Exploited Vulnerabilities (auto-synced) |
| `exploit_db.json` | Public exploit references for validation and prioritization |
### RAG Flow
```
Finding → Embed with sentence-transformers → FAISS similarity search
→ Top-3 context chunks → Injected into LLM prompt → Structured response
RAG prioritizes:
1. Known exploited vulnerabilities (KEV)
2. Matching CVEs from findings
3. OWASP and remediation patterns
```

---

## 7. AI Processing Flow

```python
def analyze_findings(findings: dict) -> dict:
    # 1. Retrieve RAG context for top findings
    context = rag_engine.query(findings["all_findings"])
    
    # 2. Agent 2: Analyst — interpret and prioritize
    analysis = analyst_agent.run(findings, context)
    
    # 3. Agent 3: Remediation — generate fix guidance
    remediation = remediation_agent.run(findings, analysis)
    
    # 4. Return combined AI report
    return {
        "risk_summary": analysis["risk_summary"],
        "top_risks": analysis["top_risks"],
        "severity_reasoning": analysis["severity_reasoning"],
        "remediation_plan": remediation["steps"],
        "immediate_actions": remediation["immediate_actions"]
    }
```

---

## 8. Completed Features (Week 1 — ✅ Done)

### Core Platform (100%)
1. Async PostgreSQL database with auto-init
2. JWT authentication (register, login, token refresh)
3. Tier-gating middleware (`require_paid_tier`)
4. Scan job management with BackgroundTasks
5. Daily scan rate limiting per user

### Passive Reconnaissance Engine (100%)
1. **DNS Intelligence** — A/MX/NS/TXT, SPF/DKIM/DMARC, crt.sh subdomains, AXFR
2. **SSL/TLS Analyzer** — x509 parsing, cipher suite evaluation, expiry
3. **HTTP Security Headers** — OWASP headers, exposed paths
4. **Technology Fingerprinting** — 25+ signatures, CVE version patterns
5. **Breach Intelligence** — AlienVault OTX, Shodan passive lookup

---

## 9. Execution Graph (`modules/pentest/execution_graph.py`)

The execution graph is a pure Python directed acyclic graph (DAG) built during every active scan. It requires no external graph library — implemented with dataclasses and dicts.

### Node Types
| Type | Fields |
|---|---|
| `tool_execution` | node_id (UUID4), tool_name, target, status, duration_ms, finding_count, timestamp |
| `finding` | node_id (UUID4), severity, title, cve_ids, owasp_categories, tool_source |

### Edge Type
| Type | Meaning |
|---|---|
| `triggered_by` | A finding node points back to the tool_execution node that produced it |

### Public API
```python
graph = init_graph(scan_id)
exec_node = add_tool_execution(graph, tool_name, target, ...)
finding_node = add_finding(graph, severity, title, ...)
link_nodes(graph, finding_node.node_id, exec_node.node_id, "triggered_by")
payload = export_graph(graph)  # JSON-serialisable dict
```

### Integration with `active_scan.py`
- `init_graph()` called once at scan start in `_deterministic_scan`
- `add_tool_execution()` + `add_finding()` + `link_nodes()` called after each tool completes
- `export_graph()` output embedded in `scan_complete` event metadata under key `"execution_graph"`
- Additive instrumentation only — zero existing `active_scan.py` logic was changed
- `_adaptive_scan` is not yet instrumented (future task)

### Future
- Store `execution_graph` JSON in DB scan record as JSONB column for persistence beyond Celery event stream
- Use graph for attack path visualization in frontend
- Enable Find → Fix → Verify loop via graph-driven re-scan targeting

---

## 10. RAG Engine and Knowledge Base (`modules/ai/rag_engine.py`)

### Retrieval Strategy

FAISS + sentence-transformers (`all-MiniLM-L6-v2`) is the **primary** retrieval path. If FAISS or sentence-transformers fails to import (common on Windows dev without MSVC/conda), the engine silently falls back to TF-IDF keyword matching. The `retrieval_method` field in every `AnalysisReport` records which path was used — this is itself a research data point.

| Mode | Trigger | Notes |
|---|---|---|
| `faiss` | FAISS + sentence-transformers available | Semantic similarity, preferred |
| `keyword` | FAISS/sentence-transformers unavailable | TF-IDF, dev resilience fallback |

### Knowledge Base Sources

| File | Contents | Notes |
|---|---|---|
| `owasp_top10.json` | OWASP Top 10 explanations + impacts | Local, static |
| `security_headers.json` | Header best practices and fix patterns | Local, static |
| `remediation_guides.json` | Step-by-step fix guides per vuln type | Local, static |
| `cve_summaries.json` | NVD CVEs last 3y, CVSS ≥ 7.0 | Gitignored, refresh via `fetch_cve.py` |
| `exploit_db.json` | Exploit-DB full catalog (48,058 entries) | Gitignored, refresh via `fetch_exploitdb.py` |
| `kev_catalog.json` | CISA KEV full catalog (1,579+ entries) | Committed (~1.2 MB), refresh via `fetch_kev.py` |

All files are loaded at RAG engine startup. Missing files are skipped gracefully — the pipeline continues with whatever sources are available.

### CISA KEV Integration (`knowledge_base/kev_loader.py`)

KEV lookup runs at query time as a high-priority enrichment step before FAISS/keyword retrieval:

1. `rag_engine.query()` extracts CVE IDs from findings text using regex
2. `kev_loader.search_kev()` matches extracted CVE IDs against the cached KEV catalog
3. Matches are prepended as `[KEV ALERT]` blocks in the context string — highest priority position
4. `kev_matches: list[str]` and `kev_alerts: list[str]` are returned as additive keys in the query result dict

`kev_loader.py` details:
- `load_kev_entries()` — async, fetches CISA KEV JSON feed, normalises to `KEVEntry` Pydantic schema, writes `kev_cache.json` (24hr TTL)
- `get_cached_kev()` — sync, reads local cache; safe to call at startup without network I/O
- `kev_cache.json` is gitignored (auto-refreshed at runtime). `kev_catalog.json` is the committed full catalog used by the RAG FAISS index.
- Network failure degrades gracefully: stale cache used if present, empty list with warning logged if absent.
- Future: wire `await load_kev_entries()` into FastAPI lifespan for eager pre-warm before first scan.

### RAG Query Context Priority Order

```
[KEV ALERT blocks]          ← actively exploited CVEs (highest priority)
[KEV CATALOG DETAIL]        ← full KEV entry for matched CVEs
[OWASP guidance]            ← category-matched OWASP Top 10
[Header best practices]     ← if header findings present
[Remediation guides]        ← vuln-type matched fix patterns
[Exploit-DB references]     ← public exploit evidence
[CVE Summaries]             ← NVD detail for matched CVEs
```

### `rag_engine.query()` Return Schema

```python
{
    "owasp": List[Dict],           # OWASP/KEV-catalog FAISS results
    "headers": List[Dict],         # header KB results
    "exploits": List[Dict],        # exploit_db results
    "cve_summaries": List[Dict],   # NVD CVE results
    "kev_matches": List[str],      # CVE IDs matched in KEV catalog
    "kev_alerts": List[str],       # formatted [KEV ALERT] strings
    "kev_catalog": List[Dict],     # full KEV entries for matched CVEs
}
```

---

## 11. Control Constraints (Critical Safety Rules)

| Rule | Status | Implementation |
|---|---|---|
| LLM may recommend tools only from code-enforced allowlist | ✅ | `TOOL_REGISTRY` + `OPERATIONAL_REGISTRY` validation in `orchestrator.py` |
| LLM cannot execute tools directly | ✅ | All dispatch goes through `_execute_tool()` → `OPERATIONAL_REGISTRY` |
| LLM cannot introduce tools outside the registry | ✅ | Invalid selection triggers deterministic rule-based fallback, never halts |
| LLM cannot request additional scans mid-pipeline | ✅ | `follow_up_tools` / `orchestrate_mini_scan` path removed (ADR-007) |
| AI ONLY interprets structured tool output JSON | ✅ | Strict prompt boundaries in `analyst_agent.py` and `remediation_agent.py` |
| All LLM outputs validated before use | ✅ | Pydantic `AnalysisReport` schema enforced in `analyst_agent.py` |
| KEV data never influences tool selection or execution | ✅ | KEV enrichment is analysis-layer only (`rag_engine.py` / `analyst_agent.py`) |
| Passive scans always avoid active tooling | ✅ | Enforced in `scan_tasks.py` worker boundary, not just API tier check |
| Tier-gating enforced at API layer | ✅ | `Depends(require_paid_tier)` in route handlers |
| All LLM tool selections are logged with reasoning | ✅ | `tools_selected_by` field in `scan_complete` metadata |

---

## 12. Scan Event Metadata Schema

The `scan_complete` Celery event and the persisted scan record include the following metadata fields. These are the canonical research data capture points.

### `scan_complete` event metadata

| Field | Type | Source | Notes |
|---|---|---|---|
| `execution_mode` | `"deterministic"` \| `"adaptive"` | `active_scan.py` | Which orchestrator mode ran |
| `tool_timings` | `Dict[str, float]` | `active_scan.py` | Per-tool wall-clock seconds |
| `tools_selected_by` | `Dict[str, str]` | `active_scan.py` (adaptive) | `"llm"` \| `"rule_fallback"` \| `"fixed"` per tool |
| `execution_graph` | `Dict` (JSON DAG) | `execution_graph.export_graph()` | Full causal DAG; always present for active/full scans |

### `ai_report` metadata (stored in scan record)

| Field | Type | Source | Notes |
|---|---|---|---|
| `rag_context_used` | `bool` | `analyst_agent.py` | Whether RAG context was injected |
| `retrieval_method` | `"faiss"` \| `"keyword"` | `rag_engine.py` | Which retrieval path was active |
| `kev_matches` | `List[str]` | `rag_engine.query()` | CVE IDs matched in CISA KEV; non-empty triggers "known exploited in wild" flag |
| `model_used` | `str` | `analyst_agent.py` | LiteLLM model string (e.g. `"groq/llama-3..."`) |

---

## 13. Data Flow: Complete Scan Pipeline

```
POST /api/v1/scans
        │
        ▼
  [Auth + Tier Check] → require_paid_tier for active/full scan types
        │
        ▼
  [Scan Record: PostgreSQL status=pending]
        │
        ▼
  [Celery: scan_tasks.orchestrate_scan(scan_id, scan_type, scan_mode)]
        │
        ├──► scan_type="passive" ─────► modules/recon/passive_recon.py
        │         ├── DNS Intel                   (free tier)
        │         ├── SSL Analyzer
        │         ├── Header Checker
        │         ├── Tech Fingerprint
        │         └── Breach Check
        │
        └──► scan_type="active"|"full" ─► modules/pentest/active_scan.py
                  │                              (paid tier only)
                  ├── scan_mode="deterministic"
                  │     └── _deterministic_scan (SCAN_PROFILES fixed order)
                  │           + execution_graph instrumentation
                  │
                  └── scan_mode="adaptive"
                        └── _adaptive_scan (OrchestratorAgent LLM + allowlist)
        │
        ▼
  [Celery chain: analyst_tasks.run_analyst]
        └── RAG query (KEV enrichment + FAISS/keyword retrieval)
        └── analyst_agent.analyze_findings() → AnalysisReport
        └── remediation_agent.run()
        │
        ▼
  [PostgreSQL: status=complete, results=JSON, ai_report=JSON]

GET /api/v1/scans/{id}
  └── Free: top 3 findings shown, remainder gated
  └── Paid: full findings + AI report (AnalysisReport)
```

---

## 14. Roadmap

### Immediate (Next Tasks)
1. Store `execution_graph` JSON in DB scan record (JSONB column) — `@backend-engineer`
2. Wire analyst KEV boost: `kev_matches` from RAG result passed into analyst severity reasoning — `@ai-architect`
3. Wire `await load_kev_entries()` into FastAPI lifespan for KEV cache pre-warm — `@backend-engineer`
4. `@reviewer` full audit of pentest + worker pipeline changes

### Week 3
5. React frontend (Dashboard, FindingsTable, AIInsightsPanel)
6. PDF report generation (ReportLab)
7. Alembic database migrations (replace dev auto-create)
8. Broader integration test coverage (full scan path + report chain)
9. `cve_summaries.json` fetch completion verification

### Production (Linux Deploy)
10. Docker production image with pre-installed tools
11. Nginx reverse proxy + SSL termination
12. Environment variable management (secrets)
13. Monitoring + alerting
14. Pentest Task Tree (PTT) for orchestrator-driven follow-up scans
15. Attack path chaining visualization using execution graph
16. Continuous verification loop (Find → Fix → Verify)
