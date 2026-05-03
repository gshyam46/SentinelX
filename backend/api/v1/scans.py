"""
SentinelX — Scans Router (Celery-backed, with WebSocket live stream)
API endpoints for initiating, monitoring, and retrieving scan results.

Endpoints:
  POST   /scans                  → create scan & dispatch orchestrate_scan.delay()
  GET    /scans                  → list user scans (paginated)
  GET    /scans/{id}             → full scan record with progressive findings
  GET    /scans/{id}/progress    → lightweight progress poll
  WS     /scans/{id}/live        → subscribe to Redis scan:{id}:events, forward to client
  GET    /scans/{id}/report      → AnalysisReport JSON (tier-gated for enriched fields)
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

import jwt as _jwt
from jwt.exceptions import InvalidTokenError

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import get_db
from backend.models.user import User
from backend.models.scan import Scan
from backend.schemas.scan import (
    AuthConfig,  # noqa: F401 — re-exported so FastAPI can generate the request schema
    ScanRequest,
    ScanResultResponse,
    ScanStatusResponse,
    ScanListResponse,
)
from backend.api.deps import get_current_user, validate_scan_target
from backend.config import get_settings

settings = get_settings()
logger = logging.getLogger("sentinelx.api.scans")
router = APIRouter(prefix="/scans", tags=["Scans"])


# ---------------------------------------------------------------------------
# Additional response schemas (not in schemas/scan.py)
# ---------------------------------------------------------------------------

class ScanProgressResponse(BaseModel):
    scan_id: uuid.UUID
    status: str
    progress: int
    current_step: str | None
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    budget_remaining: int | None = None
    tools_run: list[str] = Field(default_factory=list)
    owasp_coverage: list[str] = Field(default_factory=list)


class AnalysisReportResponse(BaseModel):
    scan_id: uuid.UUID
    domain: str
    risk_score: float
    executive_summary: str
    attack_chains: list[dict] = Field(default_factory=list)
    owasp_coverage: dict[str, str] = Field(default_factory=dict)
    critical_findings: list[str] = Field(default_factory=list)
    remediation_priorities: list[dict] = Field(default_factory=list)
    analyst_notes: str = ""
    # Pro-only enriched fields (None for free tier)
    follow_up_tools: list[str] | None = None
    model_used: str | None = None
    generated_at: str | None = None


class VerifyRequest(BaseModel):
    """Request body for POST /scans/{id}/verify."""
    findings: list[dict] = Field(..., min_length=1, max_length=20,
                                 description="Finding dicts as returned by GET /scans/{id}")


class FindingVerifyResult(BaseModel):
    title: str
    original_severity: str
    fix_status: str           # fixed | still_present | unverifiable
    verified_at: str
    confidence: float
    note: str
    validation_method: str | None = None


class VerifyResponse(BaseModel):
    scan_id: uuid.UUID
    target: str
    verified_count: int
    results: list[FindingVerifyResult]


# ---------------------------------------------------------------------------
# Tier helper
# ---------------------------------------------------------------------------

def _user_tier(user: User) -> str:
    """Normalise User.tier to 'free' | 'pro'."""
    if user.tier in ("paid", "pro", "enterprise"):
        return "pro"
    return "free"


# ---------------------------------------------------------------------------
# POST /scans — create & dispatch
# ---------------------------------------------------------------------------

@router.post("", response_model=ScanStatusResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    data: ScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Initiate a new security scan.

    - Validates tier, authorisation, and daily rate limit.
    - Persists a Scan row (status="pending").
    - Dispatches orchestrate_scan Celery task.
    """
    # Block private IPs, metadata endpoints, and other dangerous targets
    validate_scan_target(data.domain)

    tier = _user_tier(current_user)

    # Tier check for active scans
    if data.scan_type in ("active", "full") and tier == "free":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Active scanning requires a paid subscription. "
                "Upgrade to access vulnerability scanning with Nuclei, Nmap, and more."
            ),
        )

    # Authenticated scans are pro-only — credentials enable probing auth-gated endpoints
    if data.auth_config is not None and tier == "free":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Authenticated scans require a paid subscription. "
                "Upgrade to SentinelX Pro to scan auth-gated endpoints."
            ),
        )

    # Active scans require explicit authorisation
    if data.scan_type in ("active", "full") and not data.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Active scanning requires written authorisation. "
                "Please confirm that you own or have permission to scan this domain."
            ),
        )

    # Rate limit free tier
    if tier == "free":
        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        count_result = await db.execute(
            select(func.count(Scan.id)).where(
                Scan.user_id == current_user.id,
                Scan.created_at >= today_start,
            )
        )
        today_count = count_result.scalar()
        if today_count >= settings.MAX_FREE_SCANS_PER_DAY:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Free tier is limited to {settings.MAX_FREE_SCANS_PER_DAY} scans/day. "
                    "Upgrade for unlimited scans."
                ),
            )

    # Build initial results blob — auth_config and llm_endpoint stored here so the
    # LLM security report endpoint can read them without passing through the task queue.
    # Credentials are NEVER logged, returned via API, or included in serialised responses.
    initial_results: dict | None = None
    if data.auth_config is not None or data.llm_endpoint is not None:
        initial_results = {}
        if data.auth_config is not None:
            initial_results["auth_config"] = data.auth_config.model_dump(exclude_none=True)
        if data.llm_endpoint is not None:
            initial_results["llm_endpoint"] = data.llm_endpoint

    # Persist the scan record
    scan = Scan(
        user_id=current_user.id,
        domain=data.domain,
        scan_type=data.scan_type,
        status="pending",
        authorization_confirmed=data.authorization_confirmed,
        results=initial_results,
    )
    db.add(scan)
    current_user.scan_count += 1
    await db.commit()
    await db.refresh(scan)

    # Dispatch Celery task (non-blocking)
    try:
        from backend.workers.scan_tasks import orchestrate_scan  # lazy — avoids circular at module load

        orchestrate_scan.delay(
            str(scan.id),
            data.domain,
            tier,
            data.scan_type,
            data.scan_mode,
        )
        logger.info(
            "[%s] Dispatched orchestrate_scan for domain=%s tier=%s scan_type=%s mode=%s",
            scan.id,
            data.domain,
            tier,
            data.scan_type,
            data.scan_mode,
        )
    except Exception as exc:
        # Celery unavailable — mark scan as failed immediately
        logger.error("Failed to dispatch Celery task: %s", exc)
        scan.status = "failed"
        scan.error_message = f"Task queue unavailable: {exc}"
        await db.commit()
        await db.refresh(scan)

    return ScanStatusResponse.model_validate(scan)


# ---------------------------------------------------------------------------
# GET /scans — list (paginated, newest first)
# ---------------------------------------------------------------------------

@router.get("", response_model=ScanListResponse)
async def list_scans(
    skip: int = 0,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all scans for the current user, newest first."""
    count_result = await db.execute(
        select(func.count(Scan.id)).where(Scan.user_id == current_user.id)
    )
    total = count_result.scalar()

    result = await db.execute(
        select(Scan)
        .where(Scan.user_id == current_user.id)
        .order_by(desc(Scan.created_at))
        .offset(skip)
        .limit(limit)
    )
    scans = result.scalars().all()

    return ScanListResponse(
        scans=[ScanStatusResponse.model_validate(s) for s in scans],
        total=total,
    )


# ---------------------------------------------------------------------------
# GET /scans/{scan_id} — full record with progressive findings
# ---------------------------------------------------------------------------

@router.get("/{scan_id}", response_model=ScanResultResponse)
async def get_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Return the full scan record including progressive findings.

    Progressive findings are stored incrementally in scan.results.findings
    so this endpoint returns real data at any point during the scan —
    not just when status='complete'.

    Free tier: first 3 findings shown in full; rest are redacted with upgrade CTA.
    """
    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    response = ScanResultResponse.model_validate(scan)

    # Strip credentials unconditionally — auth_config is write-only via the API
    if response.results:
        response.results = _strip_sensitive_results(response.results)

    tier = _user_tier(current_user)
    if tier == "free" and response.results:
        response.results = _gate_free_tier_results(response.results)

    return response


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/progress — lightweight progress poll
# ---------------------------------------------------------------------------

@router.get("/{scan_id}/progress", response_model=ScanProgressResponse)
async def get_scan_progress(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Lightweight progress endpoint for polling UIs.

    Returns: status, progress %, findings counts, budget_remaining, tools_run, owasp_coverage.
    Does NOT include full finding details — use GET /scans/{id} for that.
    """
    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    scan_results = scan.results or {}

    return ScanProgressResponse(
        scan_id=scan.id,
        status=scan.status,
        progress=scan.progress,
        current_step=scan.current_step,
        findings_count=scan.findings_count,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        info_count=scan.info_count,
        tools_run=scan_results.get("tools_run", []),
        owasp_coverage=scan_results.get("scan_metadata", {}).get("owasp_coverage", []),
    )


# ---------------------------------------------------------------------------
# WS /scans/{scan_id}/live — Redis pub/sub → WebSocket bridge
# ---------------------------------------------------------------------------

@router.websocket("/{scan_id}/live")
async def scan_live(
    scan_id: uuid.UUID,
    websocket: WebSocket,
    token: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    """
    WebSocket endpoint — subscribes to the Redis channel `scan:{scan_id}:events`
    and forwards every event message to the connected client in real-time.

    Authentication: JWT passed as `?token=<jwt>` query parameter.
    Browsers cannot set Authorization headers on WebSocket connections,
    so the standard Bearer header scheme does not work here.

    Client connection lifecycle:
      1. Connect → authenticate token → verify scan ownership.
      2. Subscribe to Redis channel.
      3. Relay messages until scan_complete / report_ready / disconnect.
      4. Send a synthetic `{"type": "stream_end"}` before closing.

    If the scan is already complete when the client connects, a summary
    snapshot is sent immediately before closing.
    """
    # ── Authenticate via query-param token ──────────────────────────────
    try:
        payload = _jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        user_id_str: str | None = payload.get("sub")
        if not user_id_str:
            await websocket.close(code=4001)
            return
    except (InvalidTokenError, Exception):
        await websocket.close(code=4001)
        return

    user_result = await db.execute(
        select(User).where(User.id == uuid.UUID(user_id_str))
    )
    current_user = user_result.scalar_one_or_none()
    if not current_user or not current_user.is_active:
        await websocket.close(code=4001)
        return

    # Verify scan ownership before accepting WebSocket
    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        await websocket.close(code=4004)
        return

    await websocket.accept()
    channel = f"scan:{scan_id}:events"

    # If scan already complete, send snapshot and close
    if scan.status in ("complete", "failed"):
        _r = scan.results or {}
        _analysis = _r.get("analysis") or {}
        snapshot = {
            "type": "scan_snapshot",
            "status": scan.status,
            "findings_count": scan.findings_count,
            "risk_score": scan.risk_score,
            "ai_report": _analysis.get("ai_report") or _r.get("ai_report"),
        }
        await websocket.send_text(json.dumps(snapshot))
        await websocket.send_text(json.dumps({"type": "stream_end"}))
        await websocket.close()
        return

    # Live subscription via Redis pub/sub
    import redis.asyncio as aioredis

    redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(channel)

    TERMINAL_TYPES = {"report_ready", "scan_failed", "stream_end"}

    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue

            data = message["data"]
            await websocket.send_text(data)

            # Check if this is a terminal event
            try:
                parsed = json.loads(data)
                if parsed.get("type") in TERMINAL_TYPES:
                    await websocket.send_text(json.dumps({"type": "stream_end"}))
                    break
            except json.JSONDecodeError:
                pass

    except WebSocketDisconnect:
        logger.info("[%s] WebSocket client disconnected", scan_id)
    except Exception as exc:
        logger.error("[%s] WebSocket relay error: %s", scan_id, exc)
        try:
            await websocket.send_text(
                json.dumps({"type": "error", "message": str(exc)})
            )
        except Exception:
            pass
    finally:
        await pubsub.unsubscribe(channel)
        await redis_client.aclose()
        try:
            await websocket.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/report — AnalysisReport (tier-gated)
# ---------------------------------------------------------------------------

@router.get("/{scan_id}/report", response_model=AnalysisReportResponse)
async def get_scan_report(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Full AnalysisReport generated by the analyst LLM.

    Tier gating:
      - Free tier: executive_summary, risk_score, critical_findings, owasp_coverage.
        Enriched fields (attack_chains, remediation_priorities, follow_up_tools,
        model_used) are stripped or returned as None.
      - Pro tier: all fields.

    Returns 404 if the scan is not yet complete or the report hasn't been generated.
    """
    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    scan_results = scan.results or {}
    # analysis key (new schema); fallback to top-level for old records
    _analysis = scan_results.get("analysis") or {}
    ai_report: dict = _analysis.get("ai_report") or scan_results.get("ai_report") or {}

    if not ai_report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis report not yet available. Check back after the scan completes.",
        )

    tier = _user_tier(current_user)
    is_pro = tier == "pro"

    return AnalysisReportResponse(
        scan_id=scan.id,
        domain=scan.domain,
        risk_score=float(ai_report.get("risk_score", scan.risk_score)),
        executive_summary=ai_report.get("executive_summary", ""),
        owasp_coverage=ai_report.get("owasp_coverage", {}),
        critical_findings=ai_report.get("critical_findings", []),
        analyst_notes=ai_report.get("analyst_notes", "") if is_pro else "",
        # Pro-only enriched fields
        attack_chains=ai_report.get("attack_chains", []) if is_pro else [],
        remediation_priorities=ai_report.get("remediation_priorities", []) if is_pro else [],
        follow_up_tools=ai_report.get("follow_up_tools") if is_pro else None,
        model_used=ai_report.get("model_used") if is_pro else None,
        generated_at=ai_report.get("generated_at"),
    )


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/pdf-report — PDF binary download (paid tier only)
# ---------------------------------------------------------------------------

@router.get("/{scan_id}/pdf-report")
async def download_scan_pdf(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Generate and stream a PDF report for the scan.

    - Requires paid tier (pro/enterprise).
    - Returns 404 if scan not found or analysis not yet complete.
    - Returns 403 if scan belongs to a different user.
    """
    tier = _user_tier(current_user)
    if tier == "free":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="PDF reports require a paid subscription.",
        )

    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    if scan.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    if scan.status != "complete":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not available — scan has not completed yet.",
        )

    _pdf_r = scan.results or {}
    _pdf_analysis = _pdf_r.get("analysis") or {}
    scan_result = {
        "target": scan.domain,
        "domain": scan.domain,
        "created_at": scan.created_at.isoformat() if scan.created_at else "",
        "risk_score": scan.risk_score,
        "findings": _pdf_r.get("scan_findings") or _pdf_r.get("findings", []),
        "ai_report": _pdf_analysis.get("ai_report") or _pdf_r.get("ai_report") or {},
    }

    try:
        from backend.modules.report.report_generator import generate_report
        pdf_bytes = generate_report(str(scan_id), scan_result)
    except Exception as exc:
        logger.error("[%s] PDF generation failed: %s", scan_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate PDF report.",
        )

    filename = f"sentinelx-report-{scan.domain}-{scan_id}.pdf"
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# POST /scans/{scan_id}/verify — Find→Fix→Verify (Phase 2 P2-03)
# ---------------------------------------------------------------------------

@router.post("/{scan_id}/verify", response_model=VerifyResponse)
async def verify_scan_findings(
    scan_id: uuid.UUID,
    data: VerifyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Re-validate specified findings to check whether developer fixes were effective.

    - Pro tier only — verification requires active re-probing.
    - Scan must be in `complete` status.
    - Sends each finding back through the P2-01 validator pipeline.
    - Interprets the result as fix status: if the probe can no longer confirm
      the vulnerability, the finding is marked "fixed"; if it re-confirms it,
      the status is "still_present".
    - Patches fix_status / verified_at / verification_note back into
      scan.results["findings"] (matched by title).
    - Returns per-finding VerifyResult objects.
    """
    tier = _user_tier(current_user)
    if tier == "free":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Find→Fix→Verify requires a paid subscription.",
        )

    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    if scan.status != "complete":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Scan must be complete before running verification.",
        )

    from backend.modules.pentest.ffv.engine import verify_findings as _verify_findings

    vresults = await _verify_findings(data.findings, scan.domain)

    # Patch fix_status + metadata back into the scan_findings array (matched by title).
    # Reads scan_findings key (new schema) with fallback to findings (legacy records).
    _r = scan.results or {}
    existing = _r.get("scan_findings") or _r.get("findings", [])
    if existing:
        result_by_title = {vr.title: vr for vr in vresults}
        patched = False
        for f in existing:
            vr = result_by_title.get(f.get("title", ""))
            if vr:
                f["fix_status"] = vr.fix_status
                f["verified_at"] = vr.verified_at
                f["verification_note"] = vr.note
                patched = True
        if patched:
            # Atomic SQL — write only scan_findings; never clobber other keys
            _findings_key = "scan_findings" if "scan_findings" in _r else "findings"
            await db.execute(
                text(
                    "UPDATE scans SET results = COALESCE(results, '{}') || :patch::jsonb"
                    " WHERE id = :scan_id"
                ),
                {"patch": json.dumps({_findings_key: existing}, default=str), "scan_id": scan_id},
            )
            await db.commit()

    logger.info(
        "[%s] verify_scan_findings: %d findings checked — fixed=%d still_present=%d unverifiable=%d",
        scan_id,
        len(vresults),
        sum(1 for r in vresults if r.fix_status == "fixed"),
        sum(1 for r in vresults if r.fix_status == "still_present"),
        sum(1 for r in vresults if r.fix_status == "unverifiable"),
    )

    return VerifyResponse(
        scan_id=scan_id,
        target=scan.domain,
        verified_count=len(vresults),
        results=[FindingVerifyResult(**vr.model_dump()) for vr in vresults],
    )


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/llm-security-report — Phase 3 LLM security assessment
# ---------------------------------------------------------------------------

class LLMSecurityReportResponse(BaseModel):
    scan_id: uuid.UUID
    target: str
    llm_risk_score: float
    checks_run: int
    issues_found: int
    risks: list[dict]
    attack_chains: list[dict] = Field(default_factory=list)
    ai_endpoints_discovered: list[str] = Field(default_factory=list)
    executive_summary: str
    scan_duration: float
    cached: bool = False
    # Surface detection metadata
    llm_surface_detected: bool = False
    llm_surface_confidence: float = 0.0
    surface_warning: str | None = None


# Per-scan asyncio lock — prevents concurrent requests triggering duplicate
# 20-second LLM analyses for the same scan_id (React StrictMode + polling).
_llm_sec_locks: dict[str, asyncio.Lock] = {}


@router.get("/{scan_id}/llm-security-report", response_model=LLMSecurityReportResponse)
async def get_llm_security_report(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    force_refresh: bool = False,
):
    """
    Run the OWASP LLM Top 10 security assessment against the scan's target domain.

    - Pro tier only — active probing requires authorization.
    - Results are cached in scan.results["llm_security"] after first run.
    - Pass ?force_refresh=true to bypass cache and re-run all 10 checks.
    - The scan must exist and belong to the current user; it does NOT need to
      be complete (LLM checks run independently against the live target).
    - Concurrent requests for the same scan_id are serialised via a per-scan
      asyncio.Lock to prevent duplicate 20-second analyses.
    """
    tier = _user_tier(current_user)
    if tier == "free":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="LLM security assessment requires a paid subscription.",
        )

    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    # ── Serialise concurrent requests with a per-scan lock ────────────────
    # React StrictMode + polling can fire 3 concurrent GETs before any one
    # caches.  Without the lock all 3 bypass the cache check and run 3 full
    # LLM analyses in parallel.  With the lock the first wins, the rest wait
    # and then return the cached result on their second cache check.
    lock = _llm_sec_locks.setdefault(str(scan_id), asyncio.Lock())

    async with lock:
        # Re-read fresh state inside the lock — a racing request may have
        # just written the cache while we were waiting.
        await db.refresh(scan)
        scan_results = scan.results or {}

        # Return cached report unless force_refresh requested
        cached_report: dict | None = scan_results.get("llm_security")
        if cached_report and not force_refresh:
            logger.info("[%s] Returning cached LLM security report", scan_id)
            return LLMSecurityReportResponse(
                scan_id=scan_id,
                target=scan.domain,
                cached=True,
                **{k: cached_report[k] for k in LLMSecurityReportResponse.model_fields
                   if k not in ("scan_id", "target", "cached") and k in cached_report},
            )

        # Build recon context from existing scan results
        recon_result: dict = {}
        findings: list[dict] = scan_results.get("scan_findings") or scan_results.get("findings", [])
        if "recon" in scan_results:
            recon_result = scan_results["recon"]
        elif "scan_metadata" in scan_results:
            recon_result = {"headers": scan_results["scan_metadata"].get("headers", {})}

        # Read explicit LLM endpoint stored at scan creation time
        llm_endpoint: str | None = scan_results.get("llm_endpoint")

        # Run the LLM security assessment
        from backend.modules.ai.llm_security.analyzer import get_llm_security_analyzer

        analyzer = get_llm_security_analyzer()
        try:
            report = await analyzer.analyze(
                target=scan.domain,
                recon_result=recon_result,
                findings=findings,
                llm_endpoint=llm_endpoint,
            )
        except Exception as exc:
            logger.error("[%s] LLM security analysis failed: %s", scan_id, exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"LLM security analysis failed: {exc}",
            )

        # Atomic SQL write — only touches 'llm_security' key.
        # No ORM read-modify-write needed; || preserves all other keys including
        # scan_findings regardless of what was written during the ~20s analysis.
        report_dict = report.model_dump()
        await db.execute(
            text(
                "UPDATE scans SET results = COALESCE(results, '{}') || :patch::jsonb"
                " WHERE id = :scan_id"
            ),
            {"patch": json.dumps({"llm_security": report_dict}, default=str), "scan_id": scan_id},
        )
        await db.commit()

        logger.info(
            "[%s] LLM security report stored — score=%.1f issues=%d surface_detected=%s",
            scan_id, report.llm_risk_score, report.issues_found, report.llm_surface_detected,
        )

        return LLMSecurityReportResponse(
            scan_id=scan_id,
            target=report.target,
            llm_risk_score=report.llm_risk_score,
            checks_run=report.checks_run,
            issues_found=report.issues_found,
            risks=[r.model_dump() for r in report.risks],
            attack_chains=report.attack_chains,
            ai_endpoints_discovered=report.ai_endpoints_discovered,
            executive_summary=report.executive_summary,
            scan_duration=report.scan_duration,
            llm_surface_detected=report.llm_surface_detected,
            llm_surface_confidence=report.llm_surface_confidence,
            surface_warning=report.surface_warning,
            cached=False,
        )


# ---------------------------------------------------------------------------
# Sensitive field scrubbing — applied to ALL tiers before any response
# ---------------------------------------------------------------------------

def _strip_sensitive_results(results: dict) -> dict:
    """
    Remove credential fields and normalise internal schema keys for API responses.

    Applied unconditionally before any response — tier does not affect this.
    auth_config is write-only: stored at scan creation, never returned via API.

    Schema normalisation (backward compat):
      scan_findings  → findings       (worker-internal key → frontend-expected key)
      analysis.*     → top-level keys (ai_report, kev_matches, attack_chains)
      report.*       → top-level keys (remediation_plan)
    Old records that already use top-level keys pass through unchanged.
    """
    stripped = dict(results)
    stripped.pop("auth_config", None)

    # scan_findings → findings
    if "scan_findings" in stripped:
        if "findings" not in stripped:
            stripped["findings"] = stripped.pop("scan_findings")
        else:
            stripped.pop("scan_findings")

    # analysis.{ai_report,kev_matches,attack_chains} → top-level
    if "analysis" in stripped:
        analysis = stripped.pop("analysis")
        if "ai_report" not in stripped:
            stripped["ai_report"] = analysis.get("ai_report")
        if "kev_matches" not in stripped and "kev_matches" in analysis:
            stripped["kev_matches"] = analysis["kev_matches"]
        if "attack_chains" not in stripped and "attack_chains" in analysis:
            stripped["attack_chains"] = analysis["attack_chains"]

    # report.remediation_plan → top-level
    if "report" in stripped:
        report_obj = stripped.pop("report")
        if "remediation_plan" not in stripped and "remediation_plan" in report_obj:
            stripped["remediation_plan"] = report_obj["remediation_plan"]

    return stripped


# ---------------------------------------------------------------------------
# Free tier result gating (progressive findings)
# ---------------------------------------------------------------------------

def _gate_free_tier_results(results: dict) -> dict:
    """
    Gate scan results for free tier users.
    Show 3 full findings, redact the rest with upgrade CTA.
    Preserves all non-findings keys (tools_run, scan_metadata, etc.).
    Called AFTER _strip_sensitive_results, so findings key is already normalised.
    """
    gated = dict(results)
    all_findings: list[dict] = gated.get("findings", [])

    if len(all_findings) > 3:
        visible = all_findings[:3]
        hidden_count = len(all_findings) - 3

        gated_findings = []
        for f in all_findings[3:]:
            gated_findings.append(
                {
                    "severity": f.get("severity"),
                    "title": "🔒 " + f.get("title", "Finding Hidden")[:30] + "...",
                    "description": (
                        "Upgrade to SentinelX Pro to see full details, "
                        "remediation steps, and AI-powered analysis."
                    ),
                    "gated": True,
                }
            )

        gated["findings"] = visible + gated_findings
        gated["gated"] = True
        gated["hidden_findings_count"] = hidden_count
        gated["upgrade_message"] = (
            f"{hidden_count} additional findings found. "
            "Upgrade to SentinelX Pro to unlock all findings, "
            "detailed remediation, attack chain analysis, and PDF reports."
        )

    # Strip pro-only and sensitive fields
    # analysis/report are normalised to top-level keys by _strip_sensitive_results
    # before this function runs, so we only need to strip the normalised names.
    gated.pop("ai_report", None)
    gated.pop("remediation_plan", None)
    gated.pop("auth_config", None)  # defence-in-depth

    return gated
