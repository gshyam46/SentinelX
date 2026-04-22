# SentinelX Project Status & Documentation

## Overview
SentinelX is a full-stack cybersecurity assessment platform. The initial development phase is focused on building a robust backend to handle asynchronous passive reconnaissance scans, user management, and subscription tiering.

---

## 1. What Has Been Completed 

### Project Architecture & Scaffolding
- **Environment Setup:** Created `.env` and `.env.example` to manage external API keys (Shodan, HIBP, OTX, Groq).
- **Core Backend:** Initialized a FastAPI application layer (`backend/main.py`) with structured logging, CORS middleware, and application lifecycle events.
- **Database Subsystem:** Integrated `sqlalchemy[asyncio]` using asyncpg, configured connection pooling, and built dependency injection for db sessions (`backend/db/session.py`).
- **Configuration Parsing:** Used `pydantic-settings` to robustly load values like `SECRET_KEY`, `DATABASE_URL`, and various API tokens (`backend/config.py`).
- **Infrastructure:** Configured a `docker-compose.dev.yml` to effortlessly spin up local variants of `PostgreSQL 16` and `Redis 7`.

### Passive Reconnaissance Modules
All five key passive recon modules intended for the MVP free tier are completed and tested in isolation:
1. **DNS Intelligence (`dns_intel.py`):** Extracts A, AAAA, MX, NS records; checks DMARC/SPF configurations; queries crt.sh for subdomain enumeration.
2. **SSL/TLS Analyzer (`ssl_analyzer.py`):** Evaluates protocol and cipher suite strength, detects certificate expiration times, and maps them to severity risks.
3. **HTTP Header Checker (`header_checker.py`):** Checks OWASP-recommended headers (HSTS, CSP, X-Frame-Options) and handles misconfigurations and exposed paths.
4. **Technology Fingerprinting (`tech_fingerprint.py`):** Identifies CMS distributions, CDN usage, server banners, and matches against internal known-technology registries.
5. **Breach Intelligence (`breach_check.py`):** Integrates HaveIBeenPwned (HIBP) and AlienVault OTX APIs to detect historical domain breaches and credential leaks.
6. **Orchestrator (`passive_recon.py`):** Acts as the pipeline coordinator. Wraps modules in async gather with specific timeouts. Tallies up the severity points and assigns an aggregated Risk Score (0-100 scale).

### Identity & Authentication
- **User Models & Schemas:** Designed UUID-backed user layouts tracking `tier` limits and `scan_count` metrics.
- **JWT Flows:** Implemented standard Bearer token pipelines using bcrypt directly (dropping `passlib` due to dependencies bugs with bcrypt 5.x) and `python-jose`.

### API Exposure
- **Scans Router (`scans.py`):** Built endpoints to submit target domains, launch background scans via FastAPI `BackgroundTasks`, list historical scans, and retrieve specific scan results.
- **Free-Tier Limits:** Included logic to gate access limits. Free users only receive snippets of findings and are prompted with an upsell CTA when findings exceed limit caps, protecting core service value.

---

## 2. What Is Currently Working

- **Standalone Recon (`test_recon.py`):** The recon modules function perfectly when run directly. Scanning `example.com` synchronously generates deep SSL/Header JSON outputs without a hitch.
- **Docker Tooling:** The database starts properly and port 5433 mapping routes successfully to the `asyncpg` bindings.
- **SQLAlchemy Initialization:** The backend successfully constructs the `users` and `scans` tables automatically on boot without needing alembic migrations for this stage of dev.
- **Authentication E2E:** Healthcheck, User Registration, Web Token generation, and `/auth/me` profile routes natively resolve in the `test_api.py` endpoint checks. 

---

## 3. What I Am Doing Right Now

We are in the middle of standardizing the full **End-to-End API Integration** path. Specifically:

**Debugging the Background Scanner Exception:** 
During the execution of `test_api.py`, the registration and ping routines passed fine, but polling the newly created scan results triggered an error.
A review of the FastAPI server logs revealed this underlying issue:
```text
UnboundLocalError: cannot access local variable 'scan' where it is not associated with a value
```

**Why it happened:**
In `backend/api/v1/scans.py`, inside the `_run_scan_background` background task, if an exception happens immediately as the async block starts, the `Exception` catch block attempts to update `scan.status = "failed"`. However, if the failure occurred *before* the local variable `scan = result.scalar_one()` was instantiated, the exception block itself crashed trying to reference the nonexistent `scan`. 

**The Immediate Fix:**
I will rewrite `_run_scan_background` slightly to query and assign the `scan` variable safely so that the exception handler correctly triggers and the API polling gracefully returns `"failed"` instead of hanging internally. 

Once that is patched, the E2E api test should pass 100%. From there, we are formally done with "Week 1" targets and can shift gears into building Celery workers for queued scaling, active tools like baremetal `Nuclei` / `Nmap` integration, and dynamic PDF generation (Week 2 Objectives).
