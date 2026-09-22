from datetime import datetime
from typing import List

from sqlalchemy import ARRAY, JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, relationship

from src.core.database import Base
from src.core.model_defs.common import utcnow


class Organization(Base):
    """Tenant root entity for multi-tenancy."""

    __tablename__ = "organizations"

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    name: Mapped[str] = Column(String(200), nullable=False)
    slug: Mapped[str] = Column(String(100), unique=True, nullable=False, index=True)
    industry: Mapped[str | None] = Column(String(100))
    company_size: Mapped[str | None] = Column(String(50))
    country: Mapped[str | None] = Column(String(2))
    required_frameworks: Mapped[list[str] | None] = Column(ARRAY(String))
    compliance_level: Mapped[str | None] = Column(String(50))
    regulatory_requirements: Mapped[dict | None] = Column(JSON)
    plan_tier: Mapped[str] = Column(String(50), default="free", nullable=False)
    trial_ends_at: Mapped[datetime | None] = Column(DateTime)
    subscription_status: Mapped[str] = Column(String(50), default="trial", nullable=False)
    cvr_number: Mapped[str | None] = Column(String(20), nullable=True)
    nace_code: Mapped[str | None] = Column(String(10), nullable=True)
    org_value_stream_profile: Mapped[dict | None] = Column(JSONB, nullable=True)
    # Organisation Identity Setup (post-signup confirmation stage) — optional
    # enrichment only, never required for identity readiness. Confirmed
    # legal-entity structure and identity provenance live in
    # organization_identity.py, not here.
    organization_type: Mapped[str | None] = Column(String(30), nullable=True)
    headquarters_country: Mapped[str | None] = Column(String(2), nullable=True)
    operating_countries: Mapped[list[str] | None] = Column(ARRAY(String), nullable=True)
    employee_range: Mapped[str | None] = Column(String(30), nullable=True)
    website_domain: Mapped[str | None] = Column(String(255), nullable=True)
    # Organisation Structure (post-ORG-ID stage) — a real User, like every
    # other accountable-actor field in this codebase. Required for
    # structure readiness (confirmed with Søren: this is just picking a
    # person, not the bigger unbuilt collector/connector install journey
    # ONB-GOV-06 parked Technical Setup Owner against).
    # use_alter=True: organizations.technical_setup_owner_user_id -> users.id
    # would otherwise form a table-creation cycle with users.organization_id
    # -> organizations.id, breaking metadata create_all/drop_all ordering
    # (used throughout the test suite) — deferring this FK via ALTER breaks
    # the cycle without changing runtime behaviour.
    technical_setup_owner_user_id: Mapped[int | None] = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL", use_alter=True, name="fk_organizations_technical_setup_owner"),
        nullable=True,
    )
    settings: Mapped[dict | None] = Column(JSON)
    onboarding_completed: Mapped[bool] = Column(Boolean, default=False, nullable=False)
    onboarding_data: Mapped[dict | None] = Column(JSON)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    auth_settings: Mapped["AuthTenantSettings | None"] = relationship(
        "AuthTenantSettings", back_populates="organization", uselist=False, cascade="all, delete-orphan"
    )
    users: Mapped[List["User"]] = relationship(
        "User",
        back_populates="organization",
        cascade="all, delete-orphan",
        foreign_keys="User.organization_id",
    )
    cloud_credentials: Mapped[List["CloudCredentials"]] = relationship(
        "CloudCredentials", back_populates="organization", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Organization(name='{self.name}', slug='{self.slug}')>"


class AuthTenantSettings(Base):
    """Auth settings for a tenant (separate from core org details)."""

    __tablename__ = "auth_tenant_settings"

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id"), nullable=False, unique=True, index=True
    )
    domain_allowlist: Mapped[List[str]] = Column(ARRAY(String), default=list, nullable=False)
    local_login_enabled: Mapped[bool] = Column(Boolean, default=True, nullable=False)
    sso_google_enabled: Mapped[bool] = Column(Boolean, default=False, nullable=False)
    sso_ms_enabled: Mapped[bool] = Column(Boolean, default=False, nullable=False)
    sso_required: Mapped[bool] = Column(Boolean, default=False, nullable=False)
    mfa_sms_enabled: Mapped[bool] = Column(Boolean, default=True, nullable=False)
    mfa_required_for_all: Mapped[bool] = Column(Boolean, default=False, nullable=False)
    mfa_required_for_admins: Mapped[bool] = Column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="auth_settings")
    ms_tenant_allowlist: Mapped[List["AuthMsTenantAllowlist"]] = relationship(
        "AuthMsTenantAllowlist", back_populates="auth_settings", cascade="all, delete-orphan"
    )
    ms_group_roles: Mapped[List["AuthMsGroupRole"]] = relationship(
        "AuthMsGroupRole", back_populates="auth_settings", cascade="all, delete-orphan"
    )


class AuthMsTenantAllowlist(Base):
    """Allowed Entra tenant IDs for an organization."""

    __tablename__ = "auth_ms_tenant_allowlist"
    __table_args__ = (
        Index(
            "ix_auth_ms_tenant_allowlist_settings_tenant",
            "auth_settings_id",
            "tenant_id",
            unique=True,
        ),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    auth_settings_id: Mapped[int] = Column(
        Integer, ForeignKey("auth_tenant_settings.id"), nullable=False, index=True
    )
    tenant_id: Mapped[str] = Column(String(255), nullable=False)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)

    auth_settings: Mapped["AuthTenantSettings"] = relationship(
        "AuthTenantSettings", back_populates="ms_tenant_allowlist"
    )


class AuthMsGroupRole(Base):
    """Role mapping for Entra group IDs."""

    __tablename__ = "auth_ms_group_roles"
    __table_args__ = (
        Index(
            "ix_auth_ms_group_roles_settings_group",
            "auth_settings_id",
            "group_id",
            unique=True,
        ),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    auth_settings_id: Mapped[int] = Column(
        Integer, ForeignKey("auth_tenant_settings.id"), nullable=False, index=True
    )
    group_id: Mapped[str] = Column(String(255), nullable=False)
    role: Mapped[str] = Column(String(50), nullable=False)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)

    auth_settings: Mapped["AuthTenantSettings"] = relationship(
        "AuthTenantSettings", back_populates="ms_group_roles"
    )


class CloudCredentials(Base):
    """Encrypted cloud credentials storage per organization."""

    __tablename__ = "cloud_credentials"

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id"), nullable=False, index=True
    )
    cloud_provider: Mapped[str] = Column(String(50), nullable=False)
    credential_name: Mapped[str] = Column(String(200), nullable=False)
    description: Mapped[str | None] = Column(Text)
    encrypted_credentials: Mapped[bytes] = Column(Text, nullable=False)
    encryption_key_id: Mapped[str] = Column(String(100), nullable=False)
    scope: Mapped[dict | None] = Column(JSON)
    is_active: Mapped[bool] = Column(Boolean, default=True, nullable=False)
    last_validated_at: Mapped[datetime | None] = Column(DateTime)
    validation_status: Mapped[str | None] = Column(String(50))
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="cloud_credentials"
    )

    def __repr__(self) -> str:
        return f"<CloudCredentials(provider='{self.cloud_provider}', name='{self.credential_name}')>"


__all__ = [
    "AuthMsGroupRole",
    "AuthMsTenantAllowlist",
    "AuthTenantSettings",
    "CloudCredentials",
    "Organization",
]
