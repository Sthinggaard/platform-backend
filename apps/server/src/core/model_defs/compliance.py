from datetime import datetime
from typing import List

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, relationship

from src.core.database import Base
from src.core.model_defs.common import SEVERITY_ENUM, SeverityLevel, utcnow


class ComplianceFramework(Base):
    """Compliance frameworks (CIS, NIST, ISO 27001, etc.).

    Multi-tenant: organization_id is nullable.
    - NULL = global/system framework (CIS, NIST, SOC2, etc.)
    - Non-NULL = custom framework for specific organization
    """

    __tablename__ = "compliance_frameworks"

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int | None] = Column(
        Integer, ForeignKey("organizations.id"), nullable=True, index=True
    )
    name: Mapped[str] = Column(String(100), unique=True, nullable=False, index=True)
    version: Mapped[str] = Column(String(20), nullable=False)
    description: Mapped[str | None] = Column(Text)

    # Customization metadata
    is_template: Mapped[bool] = Column(Boolean, default=False, nullable=False)
    source_framework_id: Mapped[int | None] = Column(
        Integer, ForeignKey("compliance_frameworks.id"), nullable=True
    )
    customization_level: Mapped[str] = Column(String(50), default="none", nullable=False)

    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )

    # Relationships
    organization: Mapped["Organization | None"] = relationship("Organization")
    controls: Mapped[List["ComplianceControl"]] = relationship(
        "ComplianceControl", back_populates="framework", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<ComplianceFramework(name='{self.name}', version='{self.version}')>"


class ComplianceControl(Base):
    """Individual compliance controls within a framework.

    Multi-tenant: organization_id is nullable (inherits from framework).
    """

    __tablename__ = "compliance_controls"

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int | None] = Column(
        Integer, ForeignKey("organizations.id"), nullable=True, index=True
    )
    framework_id: Mapped[int] = Column(
        Integer, ForeignKey("compliance_frameworks.id"), nullable=False, index=True
    )
    control_id: Mapped[str] = Column(String(50), nullable=False, index=True)
    title: Mapped[str] = Column(String(500), nullable=False)
    description: Mapped[str | None] = Column(Text)
    severity: Mapped[SeverityLevel] = Column(SEVERITY_ENUM, nullable=False, index=True)
    remediation: Mapped[str | None] = Column(Text)
    references: Mapped[dict | None] = Column(JSON)

    # Relationships
    organization: Mapped["Organization | None"] = relationship("Organization")
    framework: Mapped["ComplianceFramework"] = relationship(
        "ComplianceFramework", back_populates="controls"
    )
    rules: Mapped[List["PolicyRule"]] = relationship(
        "PolicyRule", back_populates="control", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<ComplianceControl(control_id='{self.control_id}', title='{self.title}')>"


class PolicyRule(Base):
    """Specific rules that evaluate compliance controls.

    Multi-tenant: organization_id is nullable (inherits from control).
    """

    __tablename__ = "policy_rules"

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int | None] = Column(
        Integer, ForeignKey("organizations.id"), nullable=True, index=True
    )
    control_id: Mapped[int] = Column(
        Integer, ForeignKey("compliance_controls.id"), nullable=False, index=True
    )
    name: Mapped[str] = Column(String(200), nullable=False)
    description: Mapped[str | None] = Column(Text)
    rule_definition: Mapped[dict] = Column(JSON, nullable=False)
    cloud_provider: Mapped[str] = Column(String(50), nullable=False, index=True)
    resource_type: Mapped[str] = Column(String(100), nullable=False, index=True)
    enabled: Mapped[bool] = Column(Boolean, default=True, nullable=False)

    # Relationships
    organization: Mapped["Organization | None"] = relationship("Organization")
    control: Mapped["ComplianceControl"] = relationship(
        "ComplianceControl", back_populates="rules"
    )
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="rule")

    def __repr__(self) -> str:
        return f"<PolicyRule(name='{self.name}', provider='{self.cloud_provider}')>"


__all__ = [
    "ComplianceControl",
    "ComplianceFramework",
    "PolicyRule",
]
