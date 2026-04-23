"""
SentinelX — Scan Schemas
Pydantic models for scan request/response validation.
"""

import uuid
from datetime import datetime
from pydantic import BaseModel, Field, field_validator
import re


class ScanRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255)
    scan_type: str = Field(default="passive", pattern="^(passive|active|full)$")
    scan_mode: str = Field(default="adaptive", pattern="^(deterministic|adaptive)$")
    authorization_confirmed: bool = False

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Strip protocol and trailing slashes, validate domain format."""
        # Remove protocol
        v = re.sub(r"^https?://", "", v)
        # Remove trailing slash
        v = v.rstrip("/")
        # Remove www prefix for consistency
        v = re.sub(r"^www\.", "", v)
        # Basic domain validation
        domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"
        if not re.match(domain_pattern, v):
            raise ValueError(f"Invalid domain format: {v}")
        return v


class FindingSchema(BaseModel):
    severity: str  # critical | high | medium | low | info
    title: str
    description: str
    remediation: str | None = None
    path: str | None = None
    status_code: int | None = None
    category: str | None = None
    cvss_score: float | None = None
    cve_id: str | None = None
    mitre_id: str | None = None


class ScanStatusResponse(BaseModel):
    id: uuid.UUID
    domain: str
    scan_type: str
    status: str
    progress: int
    current_step: str | None
    created_at: datetime
    completed_at: datetime | None

    model_config = {"from_attributes": True}


class ScanResultResponse(BaseModel):
    id: uuid.UUID
    domain: str
    scan_type: str
    status: str
    progress: int
    current_step: str | None
    results: dict | None
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    risk_score: float
    error_message: str | None
    created_at: datetime
    completed_at: datetime | None

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    scans: list[ScanStatusResponse]
    total: int
