# SentinelX — Bug Fix Audit Log

> Session: 2026-05-01 | All fixes applied to `main` branch (local)

---

## 1. Decommissioned LLM Model

**Files:** `backend/config.py`, `backend/.env.example`

**Problem:** `LITELLM_MODEL` was set to `groq/llama-3.1-70b-versatile` which Groq has decommissioned. Every LLM call failed silently, falling back to rule-based reports.

**Fix:** Changed default to `groq/llama3-70b-8192` (stable alias). Added `LITELLM_FALLBACK_MODEL=groq/llama-3.3-70b-versatile` as secondary.

---

## 2. `response_format` Breaking Groq Calls

**File:** `backend/modules/ai/analyst_agent.py`

**Problem:** `response_format={"type": "json_object"}` was passed to `litellm.acompletion()`. Groq llama3 models return a 400 error for this parameter.

**Fix:** Removed `response_format`. System prompt already instructs JSON-only output. Added primary→fallback model retry loop so a single bad model doesn't kill the pipeline.

---

## 3. No LLM Connectivity Visibility at Startup

**File:** `backend/main.py`

**Problem:** Server started with no indication of whether the LLM was reachable. LLM failures were only discoverable at scan time, buried in logs.

**Fix:** Added `_check_llm_connectivity()` to the lifespan startup event. Sends a 1-token probe to each configured model, logs `✅ connected` or `❌ failed` clearly. Auto-promotes working fallback to primary. Never blocks startup.

---

## 4. Celery Worker Event Loop Corruption (`Future attached to a different loop`)

**Files:** `backend/db/session.py`, `backend/workers/scan_tasks.py`, `backend/workers/analyst_tasks.py`

**Problem:** asyncpg connection pools are bound to the event loop they were created in. Celery prefork workers call `asyncio.run()` multiple times per process, each creating a new event loop. The pooled engine carried stale connections from previous loops, causing corrupted/partial DB reads — the root cause of "analyst sees only 1 finding".

**Fix:** Added `worker_async_session_factory()` to `session.py` using SQLAlchemy `NullPool`. NullPool creates a fresh TCP connection per session context with no shared pool state, making it safe across multiple `asyncio.run()` calls. Replaced all 13 lazy `async_session_factory` imports in both worker files with `worker_async_session_factory`.

---

## 5. Findings Overwrite in `_db_complete_scan`

**File:** `backend/workers/scan_tasks.py`

**Problem:** `_db_complete_scan` merged its data into `{**existing, ...}`. Due to the event loop bug (fix #4), `existing` could be a stale partial read with fewer findings than actually in the DB. The merge would then overwrite the DB with the stale finding count.

**Fix:** Added explicit `preserved_findings = existing.get("findings") or []` guard with a warning log if empty. Findings key is now explicitly re-asserted in the write to prevent silent loss.

---

## 6. Frontend Null Graph Crash (Blank Screen)

**File:** `frontend/src/components/ExecutionGraph.tsx`

**Problem:** Passive scans store `execution_graph: null` in the DB. The backend can also return `{"nodes": null, "edges": null}` when the graph object exists but has no data. `graphData.nodes.filter()` on a null value throws `TypeError` which crashed the entire scan detail page.

**Fix:** Replaced the ternary spread with `Array.isArray()` guards: `safeNodes = Array.isArray(graphData?.nodes) ? graphData.nodes : []`. All downstream operations use the safe arrays.

---

## 7. LLM Security — 3× Duplicate Execution Race Condition

**File:** `backend/api/v1/scans.py`

**Problem:** React StrictMode + 5-second polling fired 3 concurrent GETs to `/llm-security-report` before any one of them wrote the cache. All 3 passed the `if cached_report` check simultaneously and ran 3 full 20-second LLM analyses in parallel.

**Fix:** Added `_llm_sec_locks: dict[str, asyncio.Lock]` — a per-scan asyncio lock. Concurrent requests are serialised: first acquires lock and runs analysis, others wait then return the cached result. Cache is re-checked inside the lock after `db.refresh(scan)`.

---

## 8. LLM Security — Stale Write Overwrites Findings

**File:** `backend/api/v1/scans.py`

**Problem:** `scan_results` snapshot taken at request start. Analysis takes ~20 seconds. Write used `{**scan_results, "llm_security": report}` — overwriting whatever findings the scan worker had written during those 20 seconds with the 20-second-old snapshot.

**Fix:** Added `await db.refresh(scan)` immediately before the write to re-read current DB state. Write now merges into live data: `{**current_results, "llm_security": report_dict}`.

---

## 9. SQLAlchemy Model Registration in Celery Workers

**Files:** `backend/models/__init__.py`, `backend/workers/celery_app.py`

**Problem:** Celery workers started without importing all SQLAlchemy models. `Base.metadata` was incomplete, causing `ForeignKey("users.id")` resolution to fail with "table 'users' not found".

**Fix:** Added explicit model imports (`User`, `Scan`) to `models/__init__.py`. Added `import backend.models` to `celery_app.py` worker startup to force registration before any task runs.

---

## 10. `run_analyst` Celery Task Defined as `async def`

**File:** `backend/workers/analyst_tasks.py`

**Problem:** Celery's prefork executor cannot run `async def` tasks. Registering one causes Celery to return the coroutine object instead of executing it — the task appeared to succeed but did nothing.

**Fix:** Converted `run_analyst` to a synchronous `def` wrapper that calls `asyncio.run(_run_analyst_async(...))`, mirroring the pattern already used by `orchestrate_scan`.

---

## 11. FAISS Post-Fork OpenMP Deadlock (Scan Hangs Permanently)

**Files:** `backend/modules/ai/rag_engine.py`

**Problem:** Celery prefork workers `fork()` then call `asyncio.run()` multiple times. After fork, OpenMP threads initialised in the parent process are in inconsistent state. When `SentenceTransformer.encode()` runs in the child (to build the FAISS index over 1608 KB entries), OpenMP deadlocks. Symptom: worker logs show `Loading weights: 100%` then complete silence — scan never completes.

**Fix:** Added `DISABLE_FAISS=1` env var check in `rag_engine.py` `load()`. When set, FAISS and sentence-transformers are skipped entirely; keyword TF-IDF retrieval is used instead. Set `DISABLE_FAISS=1` in the Celery worker environment only. FastAPI process keeps FAISS enabled.

---

## 12. Orchestrator `response_format` Groq 400 Error

**File:** `backend/agents/orchestrator.py`

**Problem:** `_llm_decide()` passed `response_format={"type": "json_object"}` to Groq. Same bug as analyst agent (bug_fix.md #2) but missed in the orchestrator. Every adaptive scan LLM call failed with HTTP 400, fell back to rule-based, and logged an error. Wasted ~2-3s per tool decision.

**Fix:** Removed `response_format` parameter. Added primary→fallback model retry loop matching the analyst agent pattern.

---

## 13. SQLAlchemy JSONB `flag_modified` — Silent Write Skip

**Files:** `backend/workers/scan_tasks.py`, `backend/workers/analyst_tasks.py`

**Problem:** SQLAlchemy may not detect mutations on JSONB columns when reassigned via dict spread (`scan.results = {**existing, ...}`). If it treats the column as unchanged, the `UPDATE` is skipped silently. This can cause findings written during the scan to not be persisted in the final record.

**Fix:** Added `from sqlalchemy.orm.attributes import flag_modified` and `flag_modified(scan, "results")` before every `await db.commit()` that writes to `scan.results`, in: `_db_append_finding`, `_db_complete_scan`, `_db_save_ai_report`, `_db_save_remediation_plan`, `_db_fail_analyst`.

---

## 14. Analyst Overwrites Stale Findings on Save

**File:** `backend/workers/analyst_tasks.py`

**Problem:** `_db_save_ai_report` read `scan.results` at task-start time. LLM analysis + RAG takes ~20-60s. During that window `_db_complete_scan` may have committed (it runs before `run_analyst.delay()` is called, but task queuing can have latency). If the analyst's snapshot was taken before `_db_complete_scan` ran, the write would overwrite findings with an older state.

**Fix:** Added `await db.refresh(scan)` immediately before building `new_results` in `_db_save_ai_report`. This re-reads current DB state just before the write, matching the pattern already used in the LLM security endpoint (ADR-032 fix #8).

---

## 15. Frontend `/report` 404 Flood (WebSocket Reconnect Loop)

**File:** `frontend/src/pages/ScanDetail.tsx`

**Problem:** When a scan completes, the WS backend sends `stream_end` and closes the socket. The frontend auto-reconnected after 3s, the WS sent `stream_end` again, `handleScanComplete` was called again, `getScanReport` was called again (returning 404 since AI analysis may not be done). This repeated indefinitely.

**Fix:** Added `reportFetchedRef` ref. `getScanReport` is now called at most once per page load. Initial load only calls it when `status === 'complete'` AND `results.report_ready === true`. `handleScanComplete` also checks `report_ready` before calling and marks the ref after first successful fetch.
