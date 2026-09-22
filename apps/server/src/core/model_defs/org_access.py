"""Tenant-scoped organisation mandate mappings and visibility policies."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from src.core.constants.org_access_enums import (
    MandateAssignmentSubjectType,
    MandateScopeType,
)
from src.core.database import Base
from src.core.model_defs.common import utcnow


class OrgMandateRoleAssignment(Base):
    """Maps a user or verified identity group to a canonical mandate role.

    This is role eligibility at organisation scope. Process and service mandate
    bindings are intentionally added in the later ownership slice.
    """

    __tablename__ = "org_mandate_role_assignments"
    __table_args__ = (
        CheckConstraint(
            "(subject_type = 'user' AND user_id IS NOT NULL AND identity_group_id IS NULL AND identity_provider IS NULL) "
            "OR (subject_type = 'identity_group' AND user_id IS NULL AND identity_group_id IS NOT NULL AND identity_provider IS NOT NULL)",
            name="ck_org_mandate_role_assignment_subject",
        ),
        Index("ix_org_mandate_role_assignments_org_role", "organization_id", "canonical_role"),
        Index("ix_org_mandate_role_assignments_org_user", "organization_id", "user_id"),
        Index("ix_org_mandate_role_assignments_org_group", "organization_id", "identity_group_id"),
        Index(
            "uq_org_mandate_role_assignments_user",
            "organization_id",
            "canonical_role",
            "user_id",
            unique=True,
            # False positive (A1 security remediation review): the
            # interpolated value is a Python Enum .value — a fixed,
            # developer-controlled constant evaluated once at table-
            # definition time, never runtime/user input.
            postgresql_where=text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                f"subject_type = '{MandateAssignmentSubjectType.USER.value}'"
            ),
        ),
        Index(
            "uq_org_mandate_role_assignments_group",
            "organization_id",
            "canonical_role",
            "identity_provider",
            "identity_group_id",
            unique=True,
            # False positive — see the USER index above; same reasoning.
            postgresql_where=text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                f"subject_type = '{MandateAssignmentSubjectType.IDENTITY_GROUP.value}'"
            ),
        ),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    canonical_role: Mapped[str] = Column(String(80), nullable=False)
    subject_type: Mapped[str] = Column(String(40), nullable=False)
    user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )
    identity_group_id: Mapped[str | None] = Column(String(255), nullable=True)
    identity_provider: Mapped[str | None] = Column(String(50), nullable=True)
    created_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class OrgMandateScopeBinding(Base):
    """Applies an eligible canonical role to one process or service scope.

    The role assignment owns subject eligibility. This binding owns the
    accountable scope, so a user never receives decision mandate merely from
    their title or a broad organisation-level assignment.
    """

    __tablename__ = "org_mandate_scope_bindings"
    __table_args__ = (
        CheckConstraint(
            "(scope_type = 'business_process' AND value_stream_id IS NOT NULL AND business_service_id IS NULL) "
            "OR (scope_type = 'business_service' AND value_stream_id IS NULL AND business_service_id IS NOT NULL)",
            name="ck_org_mandate_scope_binding_scope",
        ),
        Index(
            "ix_org_mandate_scope_bindings_org_role",
            "organization_id",
            "canonical_role",
        ),
        Index(
            "ix_org_mandate_scope_bindings_role_assignment",
            "role_assignment_id",
        ),
        Index(
            "uq_org_mandate_scope_bindings_process_role",
            "organization_id",
            "value_stream_id",
            "canonical_role",
            unique=True,
            # False positive (A1 security remediation review): the
            # interpolated value is a Python Enum .value, a fixed
            # developer-controlled constant, never runtime/user input.
            postgresql_where=text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                f"scope_type = '{MandateScopeType.BUSINESS_PROCESS.value}'"
            ),
        ),
        Index(
            "uq_org_mandate_scope_bindings_service_role",
            "organization_id",
            "business_service_id",
            "canonical_role",
            unique=True,
            # False positive — see the BUSINESS_PROCESS index above; same reasoning.
            postgresql_where=text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                f"scope_type = '{MandateScopeType.BUSINESS_SERVICE.value}'"
            ),
        ),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    scope_type: Mapped[str] = Column(String(40), nullable=False)
    value_stream_id: Mapped[str | None] = Column(
        String(36), ForeignKey("value_streams.id", ondelete="CASCADE"), nullable=True
    )
    business_service_id: Mapped[str | None] = Column(
        String(36), ForeignKey("business_services.id", ondelete="CASCADE"), nullable=True
    )
    canonical_role: Mapped[str] = Column(String(80), nullable=False)
    role_assignment_id: Mapped[str] = Column(
        String(36),
        ForeignKey("org_mandate_role_assignments.id"),
        nullable=False,
    )
    created_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class OrgVisibilityPolicy(Base):
    """Independent organisation-wide overview and full-detail visibility policy."""

    __tablename__ = "org_visibility_policies"
    __table_args__ = (
        UniqueConstraint("organization_id", name="uq_org_visibility_policies_organization"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    overview_role_keys: Mapped[list] = Column(JSONB, nullable=False, default=list)
    full_detail_role_keys: Mapped[list] = Column(JSONB, nullable=False, default=list)
    created_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class OrgReportingLineException(Base):
    """Explicit fallback when runtime identity data cannot resolve a manager.

    This records an exception, not an authoritative organisation chart. Future
    identity-provider/JIT resolution takes precedence over this fallback.
    """

    __tablename__ = "org_reporting_line_exceptions"
    __table_args__ = (
        CheckConstraint(
            "employee_user_id <> manager_user_id",
            name="ck_org_reporting_line_exception_distinct_users",
        ),
        UniqueConstraint(
            "organization_id",
            "employee_user_id",
            name="uq_org_reporting_line_exceptions_employee",
        ),
        Index(
            "ix_org_reporting_line_exceptions_org_manager",
            "organization_id",
            "manager_user_id",
        ),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    employee_user_id: Mapped[int] = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    manager_user_id: Mapped[int] = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    exception_reason: Mapped[str] = Column(String(500), nullable=False)
    created_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
