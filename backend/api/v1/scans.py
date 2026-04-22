"""
SentinelX — Scans Router
API endpoints for initiating, monitoring, and retrieving scan results.
"""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
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
from backend.modules.recon.passive_recon import run_passive_recon
from backend.modules.pentest.active_scan import run_active_scan
from backend.modules.ai import run_ai_pipeline

settings = get_settings()
router = APIRouter(prefix="/scans", tags=["Scans"])


async def _run_scan_background(scan_id: uuid.UUID, domain: str, scan_type: str):
    """
    Background task that runs the scan and updates the database.
    This runs outside the request lifecycle.
    """
    import asyncio
    from backend.db.session import async_session_factory

    await asyncio.sleep(0.5)  # Let the invoking request finish committing

    async with async_session_factory() as db:
        scan = None
        try:
            # Mark as running
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one()
            scan.status = "running"
            scan.current_step = "Starting scan..."
            await db.commit()

            # Progress callback to update scan status in DB
            async def update_progress(step: str, pct: int):
                scan.current_step = step
                scan.progress = pct
                await db.commit()

            # Run the appropriate scan pipeline (Agent 1 — pure Python control flow)
            if scan_type == "passive":
                results = await run_passive_recon(domain, progress_callback=update_progress)
            else:
                # Active scan: Passive Recon → Nuclei → Nmap → Aggregation
                results = await run_active_scan(
                    domain,
                    scan.id,
                    include_passive=True,
                    progress_callback=update_progress,
                )

            # AI Layer (Agents 2 + 3) — interpretation and remediation
            # Runs AFTER all tools complete. AI has no control over tool execution.
            await update_progress("AI Analysis", 92)
            try:
                ai_output = await run_ai_pipeline(results)
                results["ai"] = ai_output
            except Exception as ai_err:
                import logging
                logging.getLogger(__name__).warning(f"AI pipeline failed (non-fatal): {ai_err}")
                results["ai"] = {"error": str(ai_err), "pipeline_complete": False}

            # Update scan with results
            summary = results.get("summary", {})
            severity_counts = summary.get("severity_counts", {})

            scan.status = "complete"
            scan.progress = 100
            scan.current_step = "Complete"
            scan.results = results
            scan.findings_count = summary.get("total_findings", 0)
            scan.critical_count = severity_counts.get("critical", 0)
            scan.high_count = severity_counts.get("high", 0)
            scan.medium_count = severity_counts.get("medium", 0)
            scan.low_count = severity_counts.get("low", 0)
            scan.info_count = severity_counts.get("info", 0)
            scan.risk_score = summary.get("risk_score", 0)
            scan.completed_at = datetime.now(timezone.utc)

            await db.commit()

        except Exception as e:
            if scan:
                scan.status = "failed"
                scan.error_message = str(e)
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()
            else:
                import logging
                logging.getLogger(__name__).error(f"Failed to load scan {scan_id} in background task: {e}")


@router.post("", response_model=ScanStatusResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    data: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Initiate a new security scan.
    - Free tier: passive scans only (max 3/day)
    - Paid tier: passive + active scans
    """
    # Tier check for active scans
    if data.scan_type in ("active", "full") and current_user.tier == "free":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Active scanning requires a paid subscription. Upgrade to access vulnerability scanning with Nuclei, Nmap, and more.",
        )

    # Active scan requires authorization confirmation
    if data.scan_type in ("active", "full") and not data.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Active scanning requires written authorization. Please confirm that you own or have permission to scan this domain.",
        )

    # Rate limit free tier
    if current_user.tier == "free":
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
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
                detail=f"Free tier is limited to {settings.MAX_FREE_SCANS_PER_DAY} scans per day. Upgrade for unlimited scans.",
            )

    # Create scan record
    scan = Scan(
        user_id=current_user.id,
        domain=data.domain,
        scan_type=data.scan_type,
        status="pending",
        authorization_confirmed=data.authorization_confirmed,
    )
    db.add(scan)
    
    # Update user scan count
    current_user.scan_count += 1
    
    # Commit transaction explicitly so background task can see the DB writes immediately
    await db.commit()
    await db.refresh(scan)

    # Launch scan in background
    background_tasks.add_task(
        _run_scan_background, scan.id, data.domain, data.scan_type
    )

    return ScanStatusResponse.model_validate(scan)


@router.get("", response_model=ScanListResponse)
async def list_scans(
    skip: int = 0,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all scans for the current user, newest first."""
    # Get total count
    count_result = await db.execute(
        select(func.count(Scan.id)).where(Scan.user_id == current_user.id)
    )
    total = count_result.scalar()

    # Get paginated scans
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


@router.get("/{scan_id}", response_model=ScanResultResponse)
async def get_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get scan details and results. Used for polling scan progress."""
    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        )

    response = ScanResultResponse.model_validate(scan)

    # Gate results for free tier users
    if current_user.tier == "free" and scan.results:
        response.results = _gate_free_tier_results(scan.results)

    return response


def _gate_free_tier_results(results: dict) -> dict:
    """
    Gate scan results for free tier users.
    Show 3 full findings, blur/hide the rest with upgrade CTA.
    """
    gated = dict(results)
    all_findings = gated.get("all_findings", [])

    if len(all_findings) > 3:
        # Show first 3 findings in full
        visible_findings = all_findings[:3]
        hidden_count = len(all_findings) - 3

        # Replace detailed findings with gated version
        gated_findings = []
        for finding in all_findings[3:]:
            gated_findings.append({
                "severity": finding.get("severity"),
                "title": "🔒 " + finding.get("title", "Finding Hidden")[:30] + "...",
                "description": "Upgrade to SentinelX Pro to see full details, remediation steps, and AI-powered analysis.",
                "gated": True,
            })

        gated["all_findings"] = visible_findings + gated_findings
        gated["gated"] = True
        gated["hidden_findings_count"] = hidden_count
        gated["upgrade_message"] = (
            f"{hidden_count} additional findings found. "
            "Upgrade to SentinelX Pro to unlock all findings, "
            "detailed remediation, attack chain analysis, and PDF reports."
        )

    return gated
