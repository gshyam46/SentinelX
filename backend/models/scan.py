"""
SentinelX — Scan Model
Tracks scan jobs, their status, and results (stored as JSONB).
"""

import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, ForeignKey, Text, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.db.session import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    scan_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default="passive"
    )  # "passive" | "active" | "full"
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending"
    )  # "pending" | "running" | "complete" | "failed"
    progress: Mapped[int] = mapped_column(default=0)  # 0-100
    current_step: Mapped[str] = mapped_column(String(100), nullable=True)
    results: Mapped[dict] = mapped_column(JSONB, nullable=True)
    findings_count: Mapped[int] = mapped_column(default=0)
    critical_count: Mapped[int] = mapped_column(default=0)
    high_count: Mapped[int] = mapped_column(default=0)
    medium_count: Mapped[int] = mapped_column(default=0)
    low_count: Mapped[int] = mapped_column(default=0)
    info_count: Mapped[int] = mapped_column(default=0)
    risk_score: Mapped[float] = mapped_column(default=0.0)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    authorization_confirmed: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return f"<Scan {self.domain} type={self.scan_type} status={self.status}>"
