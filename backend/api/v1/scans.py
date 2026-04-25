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

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
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
    ScanRequest,
    ScanResultResponse,
    ScanStatusResponse,
    ScanListResponse,
)
from backend.api.deps import get_current_user
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

    # Persist the scan record
    scan = Scan(
        user_id=current_user.id,
        domain=data.domain,
        scan_type=data.scan_type,
        status="pending",
        authorization_confirmed=data.authorization_confirmed,
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

    tier = _user_tier(current_user)
    if tier == "free" and scan.results:
        response.results = _gate_free_tier_results(scan.results)

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
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    WebSocket endpoint — subscribes to the Redis channel `scan:{scan_id}:events`
    and forwards every event message to the connected client in real-time.

    Authentication: expects a JWT in the `Authorization: Bearer <token>` header
    (handled via get_current_user dependency).

    Client connection lifecycle:
      1. Connect → verify scan ownership.
      2. Subscribe to Redis channel.
      3. Relay messages until scan_complete / report_ready / disconnect.
      4. Send a synthetic `{"type": "stream_end"}` before closing.

    If the scan is already complete when the client connects, a summary
    snapshot is sent immediately before closing.
    """
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
        snapshot = {
            "type": "scan_snapshot",
            "status": scan.status,
            "findings_count": scan.findings_count,
            "risk_score": scan.risk_score,
            "ai_report": (scan.results or {}).get("ai_report"),
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
    ai_report: dict = scan_results.get("ai_report") or {}

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

    scan_result = {
        "target": scan.domain,
        "domain": scan.domain,
        "created_at": scan.created_at.isoformat() if scan.created_at else "",
        "risk_score": scan.risk_score,
        "findings": (scan.results or {}).get("findings", []),
        "ai_report": (scan.results or {}).get("ai_report", {}),
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
# Free tier result gating (progressive findings)
# ---------------------------------------------------------------------------

def _gate_free_tier_results(results: dict) -> dict:
    """
    Gate scan results for free tier users.
    Show 3 full findings, redact the rest with upgrade CTA.
    Preserves all non-findings keys (tools_run, scan_metadata, etc.).
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

    # Strip AI report details from free tier (available via /report endpoint with gating)
    gated.pop("ai_report", None)

    return gated
