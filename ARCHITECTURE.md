# SentinelX — Architecture Reference
> Describes live architecture + phased roadmap. Update when ADRs change the system.

---

## 1. Vision

SentinelX is an explainable, AI-driven security decision engine. It combines:
- External black-box attack testing (no source code required)
- Validated findings (confirmation, not just detection)
- Intelligence-enriched AI analysis (KEV, ExploitDB, NVD)
- LLM security analysis and defense (Phase 3)
- Internal VAPT+SOC with code access (Phase 5)

**Competitive position:** Not another scanner. The gap between scanners and NodeZero/Pentigent is validated, chained, explainable attack paths. SentinelX closes that gap for the web + API + business logic surface that NodeZero explicitly defers — while adding an LLM security module that no competitor owns.

---

## 2. Product Modules (Phased)

| Module | Description | Phase |
|---|---|---|
| **Pentest** | External black-box: recon, active scan, attack chains, Find→Fix→Verify | 1–2 |
| **LLM Security** | OWASP LLM Top 10, prompt injection, RAG poisoning, MCP attack surface | 3 |
| **SIEM** | Real-time monitoring, log correlation, anomaly detection | 4 |
| **VAPT+SOC** | Code access, static analysis, dependency audit, patch+verify | 5 |

All modules share FastAPI/Celery/PostgreSQL/Redis/auth infrastructure. New ScanTypes added per module — no pipeline breakage.

---

## 3. Technology Stack

| Component | Technology |
|---|---|
| API framework | FastAPI (Python 3.11+), async |
| Database | PostgreSQL 16, SQLAlchemy asyncio + asyncpg |
| Queue / broker | Redis 7 + Celery |
| Auth | JWT (PyJWT >= 2.8) + bcrypt |
| AI interface | LiteLLM — switchable between Groq / OpenAI / Anthropic |
| RAG | FAISS + sentence-transformers (keyword/TF-IDF fallback) |
| Frontend | React + Vite + React Flow (execution graph) |
| Containerization | Docker Compose (dev) → Docker prod on Ubuntu 22.04 |
| Dev environment | Windows with MOCK_MODE for Linux-only tool binaries |

| External service | Purpose |
|---|---|
| Groq API (via LiteLLM) | Fast LLM inference |
| CISA KEV JSON feed | Actively exploited CVE catalog (auto-synced, 24h TTL) |
| Exploit-DB GitLab CSV | Full public exploit catalog (48,058 entries, one-shot refresh) |
| NVD API v2 | CVE summaries CVSS ≥ 7.0, last 3 years (one-shot refresh) |
| AlienVault OTX | Threat intelligence (passive recon) |
| Shodan | Passive host data |
| HaveIBeenPwned | Breach data (passive recon) |
| crt.sh | Subdomain enumeration |

---

## 4. Architecture Layers (Current — Phase 1)

### Layer 1 — Detection (Tools)
All vulnerability discovery is performed by deterministic tools. LLM never discovers vulnerabilities.

| Tool | Purpose | Notes |
|---|---|---|
| Nmap | Port/service/version enumeration | Async subprocess, MOCK_MODE |
| Nuclei | CVE + misconfiguration template scanning | Async subprocess, MOCK_MODE |
| ZAP | Web surface scanning | CLI-first (`zaproxy -cmd`), optional ZAP_DAEMON_MODE, MOCK_MODE |

Tool dispatch: all execution flows through `_execute_tool()` → `OPERATIONAL_REGISTRY` in `tool_registry.py`. No tool can be called outside this path.

### Layer 2 — Orchestrator (Agent 1)
**File:** `modules/pentest/active_scan.py` + `agents/orchestrator.py`

Two mutually exclusive modes:

**Deterministic mode:** Fixed sequence from `SCAN_PROFILES`. Zero LLM involvement. Research baseline (ADR-009).

**Adaptive mode:** `OrchestratorAgent` prompts LLM for next tool recommendation. LLM can only recommend from `ALLOWED_TOOLS` (derived from `TOOL_REGISTRY` catalogue). Every selection validated against `OPERATIONAL_REGISTRY` before dispatch. Invalid selection → rule-based fallback fires, execution never halts. LLM cannot: execute tools, skip steps, add tools outside registry, or request follow-up scans.

Research instrumentation per scan: `execution_mode`, `tool_timings`, `tools_selected_by` (llm | rule_fallback | fixed).

### Layer 3 — Execution Graph
**File:** `modules/pentest/execution_graph.py`

Pure Python causal DAG built additively during every active scan. No external graph library.

Node types:
- `tool_execution`: tool_name, target, status, duration_ms, finding_count, timestamp
- `finding`: severity, title, cve_ids, owasp_categories, tool_source
- `validation` *(Phase 2)*: validated, confidence, evidence, method

Edge type: `triggered_by` (finding → tool_execution that produced it)

Public API: `init_graph()`, `add_tool_execution()`, `add_finding()`, `link_nodes()`, `export_graph()`

Storage: `scan.results["execution_graph"]` JSONB, 500KB size guard, `None` for passive scans. LLM may read exported graph but cannot mutate it.

Future (Phase 2): graph drives PTT follow-up decisions and Find→Fix→Verify re-targeting.

### Layer 4 — AI Intelligence (Agents 2 + 3)

**RAG Engine (`modules/ai/rag_engine.py`)**

Knowledge base priority order at query time:
```
1. [KEV ALERT]        — CVEs matched in CISA KEV (regex extraction from findings)
2. [KEV CATALOG]      — Full KEV entry detail for matched CVEs
3. [OWASP]            — Category-matched OWASP Top 10 guidance
4. [Headers]          — Security header best practices
5. [Remediation]      — Vuln-type matched fix guides
6. [Exploit-DB]       — Public exploit evidence for matched CVEs
7. [CVE Summaries]    — NVD detail for matched CVEs
```

Retrieval: FAISS + sentence-transformers primary; TF-IDF keyword fallback on import failure. `retrieval_method: "faiss" | "keyword"` stored in every report (ADR-011, research data point).

`rag_engine.query()` return keys: `owasp`, `headers`, `exploits`, `cve_summaries`, `kev_matches`, `kev_alerts`, `kev_catalog`

**Analyst Agent (`modules/ai/analyst_agent.py`)**

Intelligence pipeline per scan:
1. Extract CVE IDs from findings (strict regex `CVE-\d{4}-\d+`, 2000-char cap)
2. Enrich findings with `known_exploited` flag from KEV matches (non-mutating)
3. Build ExploitDB lookup `{CVE_ID: entry}` from `codes` field only
4. Enrich findings with `exploit_available` flag
5. Apply 4-branch priority logic (escalates severity to CRITICAL when known_exploited=True)
6. Derive attack chains from execution graph DAG edges only (no text inference)
7. If kev_matches non-empty: append `_KEV_SYSTEM_PROMPT_BLOCK` to system prompt (never replaces base prompt)
8. Call LLM → parse → Pydantic validate → `AnalysisReport`
9. Annotate `analyst_notes` with KEV summary (additive)

`AnalysisReport` schema: `executive_summary`, `risk_score`, `attack_chains`, `owasp_coverage`, `critical_findings`, `remediation_priorities`, `analyst_notes`, `top_risks`, `key_priorities`, `rag_context_used`, `retrieval_method`, `model_used`, `known_exploited`, `exploit_available`, `priority_reason`

**Remediation Agent (`modules/ai/remediation_agent.py`)**

RAG-backed step-by-step fixes, priority-ordered by analyst output.

### Layer 5 — Validation (Phase 2)
**File:** `modules/pentest/validation/` *(to be created)*

Confirms findings before AI analysis. Only runs on findings flagged as exploitable by Nuclei/ZAP. Never performs destructive exploitation.

Validators: XSS (reflection/execution check), SQLi (boolean/time-based), IDOR (auth bypass check), CORS/header validation.

Output per validation: `{ validated: bool, confidence: float, evidence: str, method: str }`

Execution graph gains `validation` node type; edges: finding → validation.

---

## 5. Scan Pipeline (Complete Data Flow)

```
POST /api/v1/scans
  → [Auth + Tier check: require_paid_tier for active/full]
  → [Scan record: PostgreSQL, status=pending]
  → [Celery: scan_tasks.orchestrate_scan(scan_id, scan_type, scan_mode)]
      │
      ├─► scan_type="passive"
      │     → modules/recon/passive_recon.py (free tier)
      │       [DNS, SSL, Headers, TechFingerprint, BreachIntel]
      │
      └─► scan_type="active" | "full"  (paid tier)
            → modules/pentest/active_scan.py
                ├─ scan_mode="deterministic" → _deterministic_scan (SCAN_PROFILES)
                │     + execution_graph instrumentation (additive)
                └─ scan_mode="adaptive"     → _adaptive_scan (OrchestratorAgent)
                      [LLM → ALLOWED_TOOLS → OPERATIONAL_REGISTRY → dispatch]
  │
  ▼
  [Celery chain: analyst_tasks.run_analyst]
    → rag_engine.query()   [KEV match → FAISS/keyword → context priority block]
    → analyst_agent.analyze_findings(findings, kev_matches)
    → remediation_agent.run(findings, analysis)
  │
  ▼
  [PostgreSQL: status=complete]
  [scan.results JSONB: findings, ai_report, execution_graph, kev_matches, scan_metadata]

GET /api/v1/scans/{id}
  → Free tier: top 3 findings, remainder gated
  → Paid tier: full findings + AnalysisReport + execution_graph

GET /api/v1/scans/{id}/report  (Phase 1.5)
  → PDF: executive summary + risk score + critical findings + remediation
```

---

## 6. Directory Structure

```
sentinelX/
├── .env / .env.example
├── docker/
│   ├── docker-compose.dev.yml
│   └── docker-compose.prod.yml       ← Phase 1.5
├── ARCHITECTURE.md
├── CLAUDE.md
├── backend/
│   ├── main.py                        # FastAPI factory + lifespan (KEV pre-warm)
│   ├── config.py                      # Pydantic-settings (MOCK_MODE, SYNC_DATABASE_URL, etc.)
│   ├── requirements.txt
│   ├── api/
│   │   ├── deps.py                    # Auth, DB session, require_paid_tier DI
│   │   ├── router.py
│   │   └── v1/
│   │       ├── auth.py                # /register /login /refresh
│   │       ├── scans.py               # /scans CRUD + trigger + /report (Ph1.5)
│   │       └── health.py
│   ├── db/
│   │   └── session.py                 # Async SQLAlchemy engine
│   ├── models/
│   │   ├── user.py
│   │   └── scan.py
│   ├── schemas/
│   │   ├── user.py
│   │   └── scan.py                    # ScanResultResponse with execution_graph + kev_matches
│   ├── modules/
│   │   ├── recon/                     # ✅ COMPLETE
│   │   │   ├── passive_recon.py
│   │   │   ├── dns_intel.py
│   │   │   ├── ssl_analyzer.py
│   │   │   ├── header_checker.py
│   │   │   ├── tech_fingerprint.py
│   │   │   └── breach_check.py
│   │   ├── pentest/                   # ✅ COMPLETE (Ph1) / ⬜ validation (Ph2)
│   │   │   ├── active_scan.py
│   │   │   ├── tool_registry.py
│   │   │   ├── execution_graph.py
│   │   │   ├── nuclei_scanner.py
│   │   │   ├── nmap_scanner.py
│   │   │   ├── zap_scanner.py
│   │   │   └── validation/            # ⬜ Phase 2
│   │   ├── ai/                        # ✅ COMPLETE (Ph1) / ⬜ LLM security (Ph3)
│   │   │   ├── analyst_agent.py
│   │   │   ├── remediation_agent.py
│   │   │   ├── rag_engine.py
│   │   │   └── knowledge_base/
│   │   │       ├── kev_loader.py
│   │   │       ├── kev_catalog.json   # committed (1,579 entries)
│   │   │       ├── exploit_db.json    # gitignored, fetch_exploitdb.py
│   │   │       ├── cve_summaries.json # gitignored, fetch_cve.py
│   │   │       ├── owasp_top10.json
│   │   │       ├── security_headers.json
│   │   │       └── remediation_guides.json
│   │   ├── llm_security/              # ⬜ Phase 3
│   │   ├── detection/                 # ⬜ Phase 4 (SIEM)
│   │   └── report/                    # ⬜ Phase 1.5
│   │       └── report_generator.py
│   └── workers/
│       ├── scan_tasks.py
│       └── analyst_tasks.py
├── agents/
│   └── orchestrator.py                # OrchestratorAgent (adaptive mode)
└── frontend/                          # ⬜ Phase 1.5
    └── src/
        ├── components/
        │   ├── ScanForm.jsx
        │   ├── ScanStatus.jsx
        │   ├── FindingsTable.jsx
        │   ├── AIInsightsPanel.jsx
        │   ├── ExecutionGraph.jsx     # React Flow
        │   └── SeverityBadge.jsx
        └── App.jsx
```

---

## 7. Control Constraints (Never Violate)

| Rule | Status | Enforcement |
|---|---|---|
| LLM recommends tools only from code-enforced ALLOWED_TOOLS | ✅ | TOOL_REGISTRY + OPERATIONAL_REGISTRY validation |
| LLM cannot execute tools directly | ✅ | All dispatch via _execute_tool() → OPERATIONAL_REGISTRY |
| LLM cannot introduce tools outside registry | ✅ | Invalid selection → rule fallback, never halts |
| LLM cannot request follow-up scans | ✅ | follow_up_tools path removed (ADR-007); PTT in Phase 2 |
| AI only interprets structured tool output JSON | ✅ | Prompt boundaries in analyst_agent + remediation_agent |
| All LLM outputs validated before use | ✅ | Pydantic AnalysisReport in analyst_agent |
| KEV data is analysis-layer only | ✅ | KEV enrichment in rag_engine + analyst_agent only |
| Passive scans never touch active tooling | ✅ | Enforced in scan_tasks.py worker boundary |
| Tier-gating at API layer | ✅ | Depends(require_paid_tier) in route handlers |
| All LLM tool selections logged | ✅ | tools_selected_by field in scan_complete metadata |
| Attack chains from graph edges only, no inference | ✅ | _extract_attack_chains() in analyst_agent |
| Validation layer: confirm only, never destruct | ⬜ Phase 2 | Validator design constraint |

---

## 8. Research Instrumentation (ADR-009)

Every scan captures for the deterministic-vs-adaptive experiment:

| Field | Type | Source |
|---|---|---|
| `execution_mode` | `"deterministic"` \| `"adaptive"` | active_scan.py |
| `tool_timings` | `Dict[str, float]` | active_scan.py |
| `tools_selected_by` | `Dict[str, str]` | active_scan.py (adaptive only) |
| `execution_graph` | `Dict` (JSON DAG) | execution_graph.export_graph() |
| `rag_context_used` | `bool` | analyst_agent.py |
| `retrieval_method` | `"faiss"` \| `"keyword"` | rag_engine.py |
| `kev_matches` | `List[str]` | rag_engine.query() |
| `model_used` | `str` | analyst_agent.py |

Benchmark targets: HackTheBox, VulnHub, DVWA. Research question: does adaptive LLM-guided tool selection improve finding coverage vs deterministic sequential execution?

---

## 9. Phase 2 Additions (Queued)

### Validation Layer
XSS (reflection/execution), SQLi (boolean/time-based), IDOR (auth bypass), CORS/header. Output: `{validated, confidence, evidence, method}`. Execution graph gains validation nodes.

### Pentest Task Tree (PTT)
Replaces ADR-007's no-follow-up constraint with orchestrator-driven follow-ups (ADR-024). LLM Analyst updates PTT state (hypotheses + suggested next tools). Orchestrator reads PTT state → decides dispatch. LLM still cannot call tools directly. PTT stored in DB per scan.

### Chained Attack Paths
Execution graph drives: port open → service version → CVE → KEV confirm → LLM exploit narrative. Every hypothesis verified by deterministic execution before becoming a finding.

### Find → Fix → Verify
Re-run specific tool checks post-remediation to confirm patch. Closes the audit loop. Phase 2 flagship feature.

### Authenticated Scanning
Cookie/token injection into ZAP session → enables post-login business logic testing.

---

## 10. Phase 3 — LLM Security Module (Queued)

New ScanType: `llm_audit` — target is an LLM application endpoint.

OWASP LLM Top 10 coverage:

| ID | Category | SentinelX check |
|---|---|---|
| LLM01 | Prompt injection | Direct + indirect detection; HTML metadata embedding; multi-agent propagation |
| LLM02 | Insecure output handling | Downstream execution path analysis |
| LLM06 | Sensitive info disclosure | RAG poisoning detection; data leakage probes |
| LLM07 | Plugin/tool design flaws | MCP cross-tool contamination; tool shadowing |
| LLM08 | Excessive agency | Unsafe tool usage patterns; over-permissive API surface |
| LLM09 | Misinformation | Over-reliance detection patterns |

Research basis: 128-paper systematic review 2022–2025 (>90% attack success on unprotected systems). Market position: only platform that both attacks external systems AND defends internal LLM systems.
