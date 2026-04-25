"""
SentinelX — Scan Schemas
Pydantic models for scan request/response validation.
"""

import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator, model_validator
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
    # Additive metadata fields — default to safe values so old DB records
    # that pre-date these fields still deserialize without error.
    execution_graph_present: bool = False
    kev_matches: list[str] = Field(default_factory=list)
    execution_graph: Optional[dict] = None

    model_config = {"from_attributes": True}

    @model_validator(mode="after")
    def _extract_from_results(self) -> "ScanResultResponse":
        """
        Populate derived fields from scan.results (a JSONB dict stored on the ORM
        object).  These fields are NOT ORM columns — they live inside the JSON blob
        and must be pulled out manually after Pydantic has hydrated the flat ORM
        attributes.

        Runs only when the fields still carry their defaults, so an explicit caller
        that already provides values (e.g. tests) is never overwritten.
        """
        results_dict: dict | None = self.results  # hydrated from ORM .results column
        if not results_dict:
            return self

        scan_metadata = results_dict.get("scan_metadata") or {}

        if not self.execution_graph_present:
            # Prefer the flag stored in scan_metadata; fall back to inferring from
            # the full graph payload stored at the top-level results key.
            stored_flag = scan_metadata.get("execution_graph_present")
            if stored_flag is not None:
                self.execution_graph_present = bool(stored_flag)
            elif results_dict.get("execution_graph") is not None:
                self.execution_graph_present = True

        if not self.kev_matches:
            stored_kev = scan_metadata.get("kev_matches")
            if stored_kev:
                self.kev_matches = list(stored_kev)

        if self.execution_graph is None:
            self.execution_graph = results_dict.get("execution_graph")

        return self


class ScanListResponse(BaseModel):
    scans: list[ScanStatusResponse]
    total: int
