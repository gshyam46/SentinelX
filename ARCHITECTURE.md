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

The platform follows a **two-layer controlled architecture**:

### Layer 1 — Tools Layer (Deterministic Execution)
Security tools perform all vulnerability detection. **No AI involvement in discovery.**
- All scanners execute as subprocesses (or async calls)
- Outputs are structured JSON findings fed into the pipeline
- Tools: `nuclei`, `nmap`, `gobuster`, passive HTTP/DNS modules

### Layer 2 — AI Layer (Controlled Intelligence)
The AI does **not** discover vulnerabilities. It strictly:
- Interprets structured findings
- Prioritizes risks with reasoning
- Generates remediation guidance
- Provides executive-level summaries

### Layer 3 — Execution Intelligence (Emerging)

SentinelX incrementally builds an internal execution graph during scans:

tool → finding → subsequent tool → verification

This transforms linear scan outputs into causal attack paths.

This layer enables:
- attack chain reconstruction
- audit-grade evidence trails
- future automated verification loops (Find → Fix → Verify)

(Currently additive — does not alter execution flow)

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

## 5. Agent Roles (Strictly Defined)

### 🔹 Agent 1 — Orchestrator (Deterministic + Constrained Adaptive Controller)

- Executes tools via fixed pipelines OR adaptive selection mode
- In adaptive mode:
  - LLM recommends next tool from TOOL_REGISTRY
  - Python validates against OPERATIONAL_REGISTRY
- Maintains execution state and (future) execution graph

### 🔹 Agent 2 — Analyst (LLM + RAG)
**Implementation:** LiteLLM + FAISS RAG
- **Input:** Structured findings JSON + RAG context
- **Output:** Vulnerability explanations, severity reasoning, attack context
- Queries RAG for relevant OWASP/CVE context before calling LLM
- Prompt is fully structured — LLM cannot modify flow
- Located: `modules/ai/analyst_agent.py`

### 🔹 Agent 3 — Remediation Advisor
**Implementation:** LiteLLM (structured output)
- **Input:** Processed findings from Agent 2
- **Output:** Step-by-step remediation, prioritized fix list
- Uses RAG to retrieve known remediation patterns
- Located: `modules/ai/remediation_agent.py`

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

## 9. In Progress (Week 2 — 🔧 Active Build)

### Active Scanning Engine
- [x] `nuclei_scanner.py` — Nuclei CVE/misconfiguration scanning
- [ ] `nmap_scanner.py` — Port/service enumeration
- [ ] `active_scan.py` — Full active pipeline orchestrator

### AI Agent Layer
- [ ] `rag_engine.py` — FAISS-based knowledge retrieval
- [ ] `analyst_agent.py` — Agent 2: LLM interpretation
- [ ] `remediation_agent.py` — Agent 3: Fix guidance
- [ ] Knowledge base JSON files

---

## 10. Data Flow: Complete Scan Pipeline

```
POST /api/v1/scans
        │
        ▼
  [Auth + Tier Check]
        │
        ▼
  [Scan Record: PostgreSQL status=pending]
        │
        ▼
  [BackgroundTask / Celery Worker]
        │
        ├──► [Agent 1: Orchestrator]
        │         │
        │         ├──► Passive Recon (always)
        │         │     ├── DNS Intel
        │         │     ├── SSL Analyzer
        │         │     ├── Header Checker
        │         │     ├── Tech Fingerprint
        │         │     └── Breach Check
        │         │
        │         └──► Active Scan (paid tier only)
        │               ├── Nuclei Scanner
        │               └── Nmap Scanner
        │
        ├──► [Agent 2: Analyst]
        │         └── RAG context + LLM analysis
        │
        ├──► [Agent 3: Remediation Advisor]
        │         └── Prioritized fix plan
        │
        └──► [PostgreSQL: status=complete, results=JSON]

GET /api/v1/scans/{id}
  └── Free: top 3 findings shown, rest blurred
  └── Paid: full findings + AI report
```

---

## 11. Control Constraints (Critical Safety Rules)

| Rule | Status |
|---|---|
| AI must NOT decide which tools to execute | ✅ Enforced — all flow in Python code |
| AI must NOT modify execution order | ✅ Fixed pipeline sequence |
| AI must NOT skip pipeline steps | ✅ Steps run unconditionally |
| AI ONLY analyzes tool outputs | ✅ Strict prompt boundaries |
| LLM outputs are structured JSON | ✅ Validated via Pydantic |

---

## 12. Next Steps & Roadmap

### Immediate (Week 2)
1. Build `nmap_scanner.py` — port/service enumeration wrapper
2. Build `active_scan.py` — full active scan orchestrator (Agent 1)
3. Build `rag_engine.py` — FAISS + knowledge base
4. Build `analyst_agent.py` — Agent 2 LLM interpretation
5. Build `remediation_agent.py` — Agent 3 fix advisor
6. Populate knowledge base JSON files
## 13. Execution Graph (Emerging Capability)

Each scan incrementally builds a directed graph:

- Nodes:
  - Tool executions
  - Findings

- Edges:
  - causal relationships (triggered_by)

This enables:
- attack path visualization
- reproducible verification
- structured research benchmarking

This graph is:
- written during execution
- immutable post-scan
- used by AI only for interpretation (not control)
### Week 3
7. Celery worker migration (Redis-backed, scalable)
8. Frontend dashboard (React/Vite) — findings table, AI panel
9. PDF report generation
10. Alembic database migrations

### Production (Linux Deploy)
11. Docker production image with pre-installed tools
12. Nginx reverse proxy + SSL termination
13. Environment variable management (secrets)
14. Monitoring + alerting
