# SentinelX — Claude Code Workflow Guide
> Read this once, then it lives in your head.

---

## 1. Installation Check

```bash
# Verify Claude Code is installed
claude --version

# In your project root (sentinelX/)
cd sentinelX
claude  # opens interactive session
```

---

## 2. First-Time Setup (One-Time Steps)

### Drop the files into your project
```
sentinelX/
├── CLAUDE.md                    ← root memory file (copy from output)
└── .claude/
    ├── PROGRESS.md              ← session state tracker
    ├── DECISIONS.md             ← architecture log
    └── agents/
        ├── backend-engineer.md
        ├── pentest-engineer.md
        ├── ai-architect.md
        ├── recon-engineer.md
        └── reviewer.md
```

### Register agents (in Claude Code terminal)
```
/agents
```
This opens the agent manager. Your agents from `.claude/agents/` will appear automatically.

---

## 3. Every Session — The Ritual

**Start of session:**
```
Read .claude/PROGRESS.md and tell me where we are. 
Then confirm: today we're building [nmap_scanner.py / rag_engine.py / etc].
```

**End of session:**
```
Update .claude/PROGRESS.md with what we completed today and what the next 3 tasks are.
```

This is non-negotiable. Context amnesia kills productivity on complex projects.

---

## 4. How to Use Agents — Real Examples

### Building a new module (pentest)
```
@pentest-engineer Build nmap_scanner.py following the same patterns as nuclei_scanner.py.
Target schema: NmapResult with port, service, version data.
 Include pytest tests.
```

### Building AI layer
```
@ai-architect Build rag_engine.py using FAISS + sentence-transformers (all-MiniLM-L6-v2).
Load knowledge base from modules/ai/knowledge_base/*.json.
Embed at startup, save index to disk. Query method returns top-3 context chunks.
```

### Code review before shipping
```
@reviewer Review backend/modules/pentest/nmap_scanner.py
```

### Backend route work
```
@backend-engineer Add a GET /api/v1/scans/{scan_id}/report endpoint.
Free tier: return top 3 findings with rest blurred.
Paid tier: return full findings + AI report JSON.
Use existing auth deps and tier-gating patterns.
```

---

## 5. Context Management — The Rules

### Keep main context clean
- **Never** paste entire files into the chat — use `@file` references
- **Always** delegate file-heavy tasks to sub-agents
- When context gets long, start a new session and start with the ritual

### What goes where
| Information | Where |
|---|---|
| Permanent rules/architecture | `CLAUDE.md` |
| Current build state | `.claude/PROGRESS.md` |
| Architecture decisions | `.claude/DECISIONS.md` |
| Module-specific context | `modules/*/CONTEXT.md` (create as needed) |
| Agent specialization | `.claude/agents/*.md` |

### Module CONTEXT.md pattern
When starting a complex module, ask Claude to create a `CONTEXT.md` in that module:
```
Create a CONTEXT.md in modules/ai/ that documents:
- The module's purpose and boundaries
- Key design decisions
- Input/output contracts
- Dependencies
```
Then in future sessions: `Read modules/ai/CONTEXT.md before we continue.`

---

## 6. The Feature Build Loop

For every feature (e.g., nmap_scanner):

```
1. Start session → read PROGRESS.md
2. Delegate to specialist agent:
   @pentest-engineer Build nmap_scanner.py [spec]
3. Agent builds in its own context, returns summary
4. Review output:
   @reviewer Review modules/pentest/nmap_scanner.py
5. Run tests:
   Run: pytest backend/tests/test_nmap_scanner.py -v
6. If passes → update PROGRESS.md, mark complete
7. Integrate into orchestrator in next session
```

---

## 7. Useful Claude Code Commands

```bash
# In terminal (outside Claude Code)
claude                          # start interactive session
claude "do this specific task"  # one-shot task
claude --continue               # resume last session

# Inside Claude Code session
/agents                         # manage sub-agents
/clear                          # clear context (start fresh in same session)
/cost                           # see token usage
/compact                        # manually trigger context compaction
```

---

## 8. Week 2 Task Order

Execute in this order — each depends on the previous:

| # | Task | Agent | Est. Sessions |
|---|---|---|---|
| 1 | `nmap_scanner.py` | @pentest-engineer | 1 |
| 2 | `active_scan.py` (Agent 1) | @pentest-engineer | 1-2 |
| 3 | Knowledge base JSONs | @ai-architect | 1 |
| 4 | `rag_engine.py` | @ai-architect | 1-2 |
| 5 | `analyst_agent.py` (Agent 2) | @ai-architect | 1-2 |
| 6 | `remediation_agent.py` (Agent 3) | @ai-architect | 1 |
| 7 | Wire all agents in scan pipeline | @backend-engineer | 1 |
| 8 | Full integration test | Main + @reviewer | 1 |

---

## 9. When Things Go Wrong

**Claude drifting / losing context:**
→ `/compact` to compress, or start new session + read PROGRESS.md

**Agent not finding files:**
→ Make sure you're running `claude` from the `sentinelX/` root

**Tests failing:**
→ Never ask Claude to "fix tests by changing the test" — fix the implementation

**Architecture question:**
→ Check DECISIONS.md first. If not there, make the decision, document it in DECISIONS.md.
