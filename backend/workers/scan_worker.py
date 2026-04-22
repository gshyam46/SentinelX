"""
SentinelX - Celery Scan Workers
Background execution of intensive passive and active scans.
"""

from celery import Celery
import asyncio
import logging
from typing import Dict, Any
import json
import uuid

# To avoid circular imports, we initialize the app simply
from backend.config import get_settings

settings = get_settings()
logger = logging.getLogger("sentinelx.workers")

celery_app = Celery(
    "sentinelx_worker",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL
)

# Standard configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True
)

@celery_app.task(bind=True, name="run_passive_scan_task")
def run_passive_scan_task(self, scan_id: str, domain: str) -> Dict[str, Any]:
    """
    Synchronous wrapper for running the async passive recon orchestrator.
    """
    from backend.modules.recon.passive_recon import run_passive_recon
    
    logger.info(f"Worker received PASSIVE scan task for {domain}")
    
    # We must run the async code inside a synchronous celery task wrapper
    loop = asyncio.get_event_loop()
    if loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    try:
        # Define a progress callback for Celery state updates
        async def celery_progress(step: str, pct: int):
            self.update_state(state="PROGRESS", meta={"step": step, "progress": pct})
            
        results = loop.run_until_complete(
            run_passive_recon(domain, progress_callback=celery_progress)
        )
        return results
    except Exception as e:
        logger.error(f"Error in passive scan worker: {e}")
        return {"error": str(e), "status": "failed"}


@celery_app.task(bind=True, name="run_active_scan_task")
def run_active_scan_task(self, scan_id: str, domain: str) -> Dict[str, Any]:
    """
    Synchronous wrapper for running the full active pentest suite.
    """
    from backend.modules.pentest.nuclei_scanner import run_nuclei
    from backend.modules.pentest.nmap_scanner import run_nmap
    from backend.modules.pentest.dir_fuzzer import run_dir_fuzz
    
    logger.info(f"Worker received ACTIVE scan task for {domain}")
    
    loop = asyncio.get_event_loop()
    if loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    async def execute_active():
        self.update_state(state="PROGRESS", meta={"step": "Running Nmap port scans", "progress": 10})
        nmap_res = await run_nmap(domain, scan_id)
        
        self.update_state(state="PROGRESS", meta={"step": "Discovering hidden directories", "progress": 40})
        dir_res = await run_dir_fuzz(domain, scan_id)
        
        self.update_state(state="PROGRESS", meta={"step": "Scanning vulnerabilities with Nuclei", "progress": 60})
        nuclei_res = await run_nuclei(domain, scan_id)
        
        self.update_state(state="PROGRESS", meta={"step": "Aggregating findings", "progress": 95})
        
        # Combine all findings
        all_findings = []
        if nmap_res.get("findings"):
            all_findings.extend(nmap_res["findings"])
        if dir_res.get("findings"):
            all_findings.extend(dir_res["findings"])
        if nuclei_res.get("findings"):
            all_findings.extend(nuclei_res["findings"])
            
        # Tally severities
        critical = sum(1 for f in all_findings if f.get("severity") == "critical")
        high = sum(1 for f in all_findings if f.get("severity") == "high")
        medium = sum(1 for f in all_findings if f.get("severity") == "medium")
        low = sum(1 for f in all_findings if f.get("severity") == "low")
        info = sum(1 for f in all_findings if f.get("severity") == "info")
        
        score_calc = min((critical * 20) + (high * 10) + (medium * 5) + (low * 2), 100)
        
        # Active scans don't recreate the passive recon data unless strictly specified,
        # but normally a "full" scan implies running passive + active.
        return {
            "summary": {
                "total_findings": len(all_findings),
                "severity_counts": {
                    "critical": critical, "high": high, "medium": medium, "low": low, "info": info
                },
                "risk_score": score_calc,
                "scan_type": "active"
            },
            "all_findings": all_findings,
            "components": {
                "nmap": nmap_res,
                "dir_fuzzer": dir_res,
                "nuclei": nuclei_res
            }
        }

    try:
        results = loop.run_until_complete(execute_active())
        return results
    except Exception as e:
        logger.error(f"Error in active scan worker: {e}")
        return {"error": str(e), "status": "failed"}

