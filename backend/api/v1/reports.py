"""
SentinelX - Reports Router
API endpoints for fetching scan reports in JSON or PDF format.
"""

import uuid
import os
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import get_db
from backend.models.user import User
from backend.models.scan import Scan
from backend.api.deps import get_current_user
from backend.modules.report.generator import generate_json_report
from backend.modules.report.pdf_builder import build_pdf_report

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.get("/{scan_id}")
async def get_scan_report(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get a fully structured JSON report for a specific scan.
    Enforces Free Tier blurring via the report generator.
    """
    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.user_id == current_user.id
        )
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
        
    if scan.status != "complete":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=f"Cannot generate report. Scan is currently '{scan.status}'."
        )

    # Convert results via report logic
    report = generate_json_report(scan.results, current_user.tier)
    
    return report

@router.get("/{scan_id}/pdf")
async def get_scan_report_pdf(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Download a PDF version of the scan report.
    Free users will see PDF sections blurred out per the generator logic.
    """
    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.user_id == current_user.id
        )
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    if scan.status != "complete":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Cannot generate PDF. Scan incomplete."
        )

    # 1. Structure the data using the generator
    report_data = generate_json_report(scan.results, current_user.tier)
    
    # 2. Build the PDF
    pdf_path = build_pdf_report(report_data)
    
    if not pdf_path or not os.path.exists(pdf_path):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="PDF generation engine encountered a critical rendering fault."
        )
        
    return FileResponse(
        path=pdf_path, 
        filename=f"SentinelX-Report-{scan.domain}.pdf", 
        media_type="application/pdf",
        background=None  # Can be expanded to delete file via BackgroundTask
    )

