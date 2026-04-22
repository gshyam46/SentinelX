
# SentinelX 🛡️

**AI-Powered Cybersecurity Assessment Platform**

SentinelX provides automated security reconnaissance and vulnerability assessment with AI-powered narrative reports. Built for security professionals, penetration testers, and organizations that need to understand their attack surface.

## Features

### Free Tier — Passive Recon (URL only)
- 🔍 **DNS Intelligence** — Record enumeration, SPF/DKIM/DMARC analysis, subdomain discovery
- 🔒 **SSL/TLS Analysis** — Certificate validation, protocol checks, cipher strength
- 🛡️ **HTTP Security Headers** — OWASP header audit, cookie flags, CORS config
- 🔧 **Technology Fingerprinting** — CMS, framework, server, CDN detection
- 📁 **Exposed Path Detection** — Git repos, env files, backups, admin panels
- 🚨 **Breach Intelligence** — HIBP, AlienVault OTX, Shodan passive lookup

### Paid Tier — Active Scanning (authorized targets)
- 🎯 **Nuclei CVE Scanning** — 7000+ vulnerability templates
- 🌐 **Nmap Port Scanning** — Full port + service detection
- 📂 **Directory Fuzzing** — Hidden paths and files
- 🤖 **AI Narrative Reports** — Attack chain analysis, MITRE ATT&CK mapping

## Quick Start

```bash
# 1. Clone and enter directory
cd sentinelX

# 2. Create Python virtual environment
cd backend
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy environment config
cd ..
copy .env.example .env  # Windows
# cp .env.example .env  # Linux/Mac

# 5. Run standalone test (no database needed)
python backend/test_recon.py example.com

# 6. Run the API server (requires PostgreSQL)
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

## Architecture

```
sentinelX/
├── backend/              # FastAPI + Python
│   ├── api/              # REST API routes
│   ├── models/           # SQLAlchemy models
│   ├── schemas/          # Pydantic validation
│   ├── modules/
│   │   ├── recon/        # Passive recon engine
│   │   ├── pentest/      # Active scanning (Nuclei, Nmap)
│   │   ├── ai/           # LiteLLM + FAISS RAG
│   │   └── report/       # PDF report generation
│   └── workers/          # Celery background tasks
├── frontend/             # React + Vite
├── docker/               # Docker Compose stack
└── data/                 # Knowledge base + reports
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Create account |
| POST | `/api/v1/auth/login` | Get JWT token |
| GET | `/api/v1/auth/me` | Current user profile |
| POST | `/api/v1/scans` | Start a scan |
| GET | `/api/v1/scans` | List scan history |
| GET | `/api/v1/scans/{id}` | Get scan results |
| GET | `/api/v1/health` | Health check |

## Tech Stack

- **Backend:** Python 3.11+, FastAPI, SQLAlchemy (async), PostgreSQL
- **Auth:** JWT (python-jose + bcrypt)
- **LLM:** LiteLLM (supports Groq, OpenAI, Anthropic, and more)
- **Scanning:** dnspython, httpx, python-nmap, Nuclei, Subfinder
- **AI/RAG:** FAISS, sentence-transformers
- **Frontend:** React 18, Vite, Recharts, Framer Motion
- **Infra:** Docker, Redis, Celery

## Legal

This tool is designed for **authorized security assessments only**. Active scanning features require explicit permission from the target owner. Unauthorized scanning of systems you don't own or have permission to test is illegal.

## License

MIT

