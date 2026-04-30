# SentinelX — Advanced Architecture & Roadmap (NodeZero-Inspired, Research-Driven)

## 1. Vision

SentinelX aims to evolve into an **Explainable, AI-driven Security Decision Engine** combining:
- Deterministic + Adaptive scanning
- Validation (exploit confirmation)
- Execution graph (attack flow intelligence)
- LLM security analysis
- Research-backed prioritization (KEV, CVE, exploitability)

---

## 2. Core Architecture

### Layer 1 — Detection (Tools Layer)
- Nmap (network exposure)
- Nuclei (vulnerabilities)
- ZAP (web scanning)

Constraint:
- LLM cannot execute tools
- Python allowlist enforces execution

---

### Layer 2 — Orchestrator

#### Modes:
- Deterministic (fixed sequence)
- Adaptive (LLM-guided, validated)

Purpose:
- Tool sequencing
- Experimentation (research angle)

---

### Layer 3 — Validation Layer (NEW)

Purpose:
> Confirm vulnerabilities safely (no destructive exploitation)

#### Validators:
- XSS (reflection/execution)
- SQLi (boolean/time-based)
- IDOR (auth bypass check)
- CORS/Header validation

Output:
- validated: true/false
- confidence score

---

### Layer 4 — AI Intelligence

#### Analyst Agent:
- KEV prioritization
- CVE + ExploitDB correlation
- Risk scoring

#### Remediation Agent:
- Actionable fixes
- Priority-based recommendations

---

### Layer 5 — Execution Intelligence (Graph)

Structure:
- Nodes:
  - tool_execution
  - finding
  - validation (optional)
- Edges:
  - tool → finding

Purpose:
- Attack path modeling
- Auditability
- Explainability

---

### Parallel Module — LLM Security

Checks:
- Prompt injection
- RAG leakage
- Unsafe tool usage
- Over-permissive APIs

---

## 3. Operational Layer Model (Practical OSI Mapping)

### L4 — Network / Transport
- Ports, TLS, services

### L5 — Session / Auth
- Cookies, JWT, RBAC

### L6 — Input Surface
- Params, URLs, headers

### L7 — Application Logic
- IDOR, auth flaws, workflows

### Parallel:
- LLM / RAG Security

---

## 4. Execution Flow

1. User triggers scan
2. Celery orchestrates execution
3. Tools run → findings generated
4. Execution graph builds
5. Validation layer confirms findings
6. AI analyzes + prioritizes
7. Results stored
8. Frontend visualizes graph + insights

---

## 5. Frontend (Execution Graph UI)

### Features:
- React Flow graph
- Node types:
  - Tool
  - Finding
- Edge: Tool → Finding

### Enhancements:
- Severity color coding
- KEV highlighting
- Click → detail panel
- Live status (pending/running/completed)

---

## 6. Research Differentiation

### 1. Deterministic vs Adaptive Testing
- Compare:
  - coverage
  - time
  - accuracy

### 2. KEV-driven prioritization
- Focus on actively exploited vulnerabilities

### 3. Explainable Attack Chains
- Graph-based reasoning
- Human-readable attack paths

### 4. LLM Security Analysis
- Emerging domain
- High research + product value

---

## 7. Roadmap

### Phase 1 (MVP)
- Graph visualization
- Backend integration
- Linux deployment

### Phase 2
- Validation layer (4 validators)

### Phase 3
- LLM security module

### Phase 4
- Expand tools per layer

### Phase 5
- Attack chain intelligence

---

## 8. Strategic Positioning

Not:
- Another scanner

But:
> Explainable + Validated + Intelligence-driven security platform

---

## 9. Key Principles

- Controlled AI (no hallucinated execution)
- Explainability over complexity
- Validation over detection
- Research-backed development
