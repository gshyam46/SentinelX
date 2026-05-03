"""
SentinelX — Health Check Router

Reports real runtime readiness: binary resolution for Nmap/Nuclei,
live HTTP probe for ZAP daemon.
Always returns 200 OK — null values indicate unavailability.
"""

import logging

import aiohttp
from fastapi import APIRouter

from backend.modules.pentest.nmap_scanner import _resolve_binary as _resolve_nmap
from backend.modules.pentest.nuclei_scanner import _resolve_binary as _resolve_nuclei

logger = logging.getLogger("sentinelx.health")

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    from backend.config import get_settings
    settings = get_settings()

    nmap_path = _check_binary("nmap", settings.NMAP_PATH)
    nuclei_path = _check_binary("nuclei", settings.NUCLEI_PATH)
    zap_status = await _check_zap(settings.ZAP_BASE_URL)

    all_ok = nmap_path is not None and nuclei_path is not None and zap_status is not None

    return {
        "status": "ok" if all_ok else "degraded",
        "tools": {
            "nmap": nmap_path,
            "nuclei": nuclei_path,
            "zap": zap_status,
        },
    }


def _check_binary(name: str, config_path: str) -> str | None:
    try:
        return _resolve_nmap(name, config_path) if name == "nmap" else _resolve_nuclei(name, config_path)
    except RuntimeError:
        logger.warning("%s not found", name)
        return None


async def _check_zap(zap_base_url: str) -> str | None:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{zap_base_url}/JSON/core/view/version/",
                timeout=aiohttp.ClientTimeout(total=2),
            ) as resp:
                if resp.status == 200:
                    return "reachable"
    except Exception:
        logger.warning("zap unreachable at %s", zap_base_url)
    return None
