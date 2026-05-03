"""
SentinelX — Scan Schemas
Pydantic models for scan request/response validation.
"""

import uuid
from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator, model_validator
import re


class AuthConfig(BaseModel):
    """Scan-level authentication credentials. Stored encrypted in scan.results — never returned via API."""

    type: Literal["cookie", "bearer", "basic"]
    cookie: Optional[str] = None    # raw Cookie header string (cookie auth)
    token: Optional[str] = None     # bearer token value (bearer auth)
    username: Optional[str] = None  # HTTP Basic username
    password: Optional[str] = None  # HTTP Basic password
    login_url: Optional[str] = None # optional login endpoint for session-based auth

    # Phase 3 hardening note: cookie / token / password require field-level encryption
    # (Fernet or AES-256-GCM) before the JSONB column is written to disk.


class ScanRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255)
    scan_type: str = Field(default="passive", pattern="^(passive|active|full)$")
    scan_mode: str = Field(default="adaptive", pattern="^(deterministic|adaptive)$")
    authorization_confirmed: bool = False
    auth_config: Optional[AuthConfig] = None
    llm_endpoint: Optional[str] = Field(
        default=None,
        description=(
            "Explicit LLM API endpoint (e.g. https://api.example.com/v1/chat/completions). "
            "When provided, pre-flight detection is skipped and the endpoint is tested directly."
        ),
    )

    @field_validator("llm_endpoint")
    @classmethod
    def validate_llm_endpoint(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip().rstrip("/")
        if not re.match(r"^https?://[^\s/$.?#].[^\s]*$", v):
            raise ValueError("llm_endpoint must be a full HTTP or HTTPS URL")
        return v

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
    # Phase 2 P2-01: validation layer — None means not yet validated (old findings safe to deserialize)
    validated: Optional[bool] = None
    confidence: Optional[float] = None
    validation_method: Optional[str] = None
    # Phase 2 P2-03: Find→Fix→Verify — None until verification is explicitly triggered
    fix_status: Optional[str] = None          # fixed | still_present | unverifiable
    verified_at: Optional[str] = None         # ISO timestamp of last verification run
    verification_note: Optional[str] = None   # human-readable outcome summary


class ScanStatusResponse(BaseModel):
    id: uuid.UUID
    domain: str
    scan_type: str
    status: str
    progress: int
    current_step: str | None
    created_at: datetime
    completed_at: datetime | None
    # Denormalized counters — available without reading the full results JSONB blob
    risk_score: float = 0.0
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

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
    # Phase 2: PTT state — None means scan predates PTT or ran in deterministic mode
    ptt_state: Optional[dict] = None
    # Phase 2 P2-05: structured attack chains derived from DAG edges; None on old records
    attack_chains: Optional[list[dict]] = None
    # Phase 3: LLM security report — None until GET /scans/{id}/llm-security-report is called
    llm_security: Optional[dict] = None

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

        # analysis key (new schema) contains ai_report, kev_matches, attack_chains.
        # Fall back to top-level keys for records written before the schema migration.
        analysis_data: dict = results_dict.get("analysis") or {}

        if not self.kev_matches:
            stored_kev = (
                analysis_data.get("kev_matches")
                or scan_metadata.get("kev_matches")
                or results_dict.get("kev_matches")
            )
            if stored_kev:
                self.kev_matches = list(stored_kev)

        if self.execution_graph is None:
            self.execution_graph = results_dict.get("execution_graph")

        if self.ptt_state is None:
            self.ptt_state = scan_metadata.get("ptt_state")

        if self.attack_chains is None:
            self.attack_chains = (
                analysis_data.get("attack_chains")
                or results_dict.get("attack_chains")
            )

        if self.llm_security is None:
            self.llm_security = results_dict.get("llm_security")

        return self


class ScanListResponse(BaseModel):
    scans: list[ScanStatusResponse]
    total: int
