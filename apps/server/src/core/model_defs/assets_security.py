from datetime import datetime
from typing import List

from sqlalchemy import Column, DateTime, Enum, Float, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, relationship

from src.core.database import Base
from src.core.model_defs.common import (
    FindingStatus,
    JiraTicketStatus,
    SEVERITY_ENUM,
    ScanStatus,
    SeverityLevel,
    utcnow,
)


class CloudAsset(Base):
    """Cloud resources discovered across providers."""

    __tablename__ = "cloud_assets"

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    asset_id: Mapped[str] = Column(String(500), unique=True, nullable=False, index=True)
    asset_type: Mapped[str] = Column(String(100), nullable=False, index=True)
    cloud_provider: Mapped[str] = Column(String(50), nullable=False, index=True)
    region: Mapped[str | None] = Column(String(100), index=True)
    name: Mapped[str] = Column(String(500), nullable=False)
    asset_metadata: Mapped[dict | None] = Column(JSON)
    discovered_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    last_scanned: Mapped[datetime | None] = Column(DateTime)

    organization: Mapped["Organization"] = relationship("Organization")
    findings: Mapped[List["Finding"]] = relationship(
        "Finding", back_populates="asset", cascade="all, delete-orphan"
    )


class ScanRun(Base):
    """Individual scan execution records."""

    __tablename__ = "scan_runs"

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    scan_type: Mapped[str] = Column(String(50), nullable=False, index=True)
    status: Mapped[ScanStatus] = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    cloud_provider: Mapped[str | None] = Column(String(50), index=True)
    scope: Mapped[dict | None] = Column(JSON)
    started_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False, index=True)
    completed_at: Mapped[datetime | None] = Column(DateTime)
    duration_seconds: Mapped[int | None] = Column(Integer)
    total_assets: Mapped[int] = Column(Integer, default=0)
    total_findings: Mapped[int] = Column(Integer, default=0)
    error_message: Mapped[str | None] = Column(Text)

    organization: Mapped["Organization"] = relationship("Organization")
    findings: Mapped[List["Finding"]] = relationship(
        "Finding", back_populates="scan_run", cascade="all, delete-orphan"
    )


class Finding(Base):
    """Security and compliance findings from scans."""

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_finding_scan_status", "scan_run_id", "status"),
        Index("ix_finding_asset_severity", "asset_id", "severity"),
        Index("ix_finding_org", "organization_id"),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    scan_run_id: Mapped[int] = Column(Integer, ForeignKey("scan_runs.id"), nullable=False, index=True)
    asset_id: Mapped[int] = Column(Integer, ForeignKey("cloud_assets.id"), nullable=False, index=True)
    rule_id: Mapped[int | None] = Column(Integer, ForeignKey("policy_rules.id"), index=True)
    severity: Mapped[SeverityLevel] = Column(SEVERITY_ENUM, nullable=False, index=True)
    title: Mapped[str] = Column(String(500), nullable=False)
    description: Mapped[str | None] = Column(Text)
    evidence: Mapped[dict | None] = Column(JSON)
    risk_score: Mapped[float | None] = Column(Float)
    business_impact_score: Mapped[float | None] = Column(Float)
    status: Mapped[FindingStatus] = Column(
        Enum(FindingStatus), default=FindingStatus.OPEN, nullable=False, index=True
    )
    detected_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False, index=True)
    resolved_at: Mapped[datetime | None] = Column(DateTime)
    resolved_by: Mapped[str | None] = Column(String(100))
    resolution_notes: Mapped[str | None] = Column(Text)

    organization: Mapped["Organization"] = relationship("Organization")
    scan_run: Mapped["ScanRun"] = relationship("ScanRun", back_populates="findings")
    asset: Mapped["CloudAsset"] = relationship("CloudAsset", back_populates="findings")
    rule: Mapped["PolicyRule | None"] = relationship("PolicyRule", back_populates="findings")
    jira_ticket: Mapped["JiraTicket | None"] = relationship(
        "JiraTicket", back_populates="finding", uselist=False, cascade="all, delete-orphan"
    )


class JiraTicket(Base):
    """Jira tickets created for findings."""

    __tablename__ = "jira_tickets"

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    finding_id: Mapped[int] = Column(Integer, ForeignKey("findings.id"), unique=True, nullable=False, index=True)
    ticket_key: Mapped[str] = Column(String(50), unique=True, nullable=False, index=True)
    ticket_url: Mapped[str] = Column(String(500), nullable=False)
    status: Mapped[JiraTicketStatus] = Column(
        Enum(JiraTicketStatus), default=JiraTicketStatus.CREATED, nullable=False
    )
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")
    finding: Mapped["Finding"] = relationship("Finding", back_populates="jira_ticket")


class RiskAppetite(Base):
    """Organization risk appetite thresholds."""

    __tablename__ = "risk_appetite"
    __table_args__ = (
        Index("ix_risk_appetite_org_domain", "organization_id", "domain", unique=True),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    domain: Mapped[str] = Column(String(100), nullable=False, index=True)
    max_acceptable_score: Mapped[float] = Column(Float, nullable=False)
    threshold_critical: Mapped[int] = Column(Integer, default=0)
    threshold_high: Mapped[int] = Column(Integer, default=5)
    threshold_medium: Mapped[int] = Column(Integer, default=20)
    threshold_low: Mapped[int] = Column(Integer, default=100)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    updated_by: Mapped[str | None] = Column(String(100))

    organization: Mapped["Organization"] = relationship("Organization")


class KeyRiskIndicator(Base):
    """Key Risk Indicators (KRIs) for monitoring."""

    __tablename__ = "key_risk_indicators"

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name: Mapped[str] = Column(String(200), nullable=False, index=True)
    description: Mapped[str | None] = Column(Text)
    calculation_method: Mapped[dict | None] = Column(JSON)
    threshold_value: Mapped[float] = Column(Float, nullable=False)
    current_value: Mapped[float | None] = Column(Float)
    status: Mapped[str] = Column(String(50), default="normal", nullable=False, index=True)
    measured_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False, index=True)

    organization: Mapped["Organization"] = relationship("Organization")


__all__ = [
    "CloudAsset",
    "Finding",
    "JiraTicket",
    "KeyRiskIndicator",
    "RiskAppetite",
    "ScanRun",
]
