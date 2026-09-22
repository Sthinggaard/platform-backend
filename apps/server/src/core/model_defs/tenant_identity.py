from datetime import datetime
from typing import List

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, relationship

from src.core.database import Base
from src.core.constants.user_locale import (
    CITY_MAX_LENGTH,
    COUNTRY_CODE_LENGTH,
    TIMEZONE_MAX_LENGTH,
)
from src.core.model_defs.common import USER_STATUS_ENUM, UserStatus, utcnow


class User(Base):
    """Multi-tenant user linked to Auth0."""

    __tablename__ = "users"

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id"), nullable=False, index=True
    )
    auth0_user_id: Mapped[str | None] = Column(String(255), unique=True, nullable=True, index=True)
    email: Mapped[str] = Column(String(255), nullable=False)
    email_verified: Mapped[bool] = Column(Boolean, default=False, nullable=False)
    password_hash: Mapped[str | None] = Column(Text)
    first_name: Mapped[str | None] = Column(String(100))
    last_name: Mapped[str | None] = Column(String(100))
    title: Mapped[str | None] = Column(String(200))
    avatar_url: Mapped[str | None] = Column(Text)
    role: Mapped[str] = Column(String(50), default="member", nullable=False)
    permissions: Mapped[list | None] = Column(JSON)
    is_active: Mapped[bool] = Column(Boolean, default=True, nullable=False)
    status: Mapped[UserStatus] = Column(USER_STATUS_ENUM, default=UserStatus.ACTIVE, nullable=False)
    last_login_at: Mapped[datetime | None] = Column(DateTime)
    mfa_enabled: Mapped[bool] = Column(Boolean, default=False, nullable=False)
    mfa_phone_e164: Mapped[str | None] = Column(String(20))
    mfa_phone_verified_at: Mapped[datetime | None] = Column(DateTime)
    mfa_method: Mapped[str | None] = Column(String(20), default="sms")
    mfa_enforced_by_policy: Mapped[bool] = Column(Boolean, default=False, nullable=False)
    # DISC-44 — required for role=consultant (enforced at invite time, not a
    # DB constraint — matches this codebase's existing application-level-only
    # enforcement convention, e.g. SlotInstance.mapping_status); null means
    # "never expires," which the invite route must never allow for a
    # consultant. Checked at login/refresh (auth_service.is_access_expired)
    # and in discovery_execution_permissions.py so a consultant's actual
    # capability is re-derived fresh on every request, not just gated once
    # at token issuance.
    access_expires_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    # #279 (TZ-1) — where this person is, and what clock they read. Two fields,
    # not one: location answers *where are they based* and timezone answers
    # *what clock do they read*, they change at different times, and a country
    # cannot produce a zone. Greenland alone spans four; the Danish realm is
    # three separate country codes. Location may propose a zone
    # (`propose_timezone_for_country`); it never determines one.
    #
    # An IANA identifier, never an offset — `Europe/Copenhagen`, not `CET`,
    # which names a winter offset Denmark leaves in March. Validated through
    # `user_locale_service.validate_timezone`, and read through
    # `resolve_reader_timezone` rather than off this column, so "what does unset
    # mean?" has one answer instead of one per caller.
    timezone: Mapped[str | None] = Column(String(TIMEZONE_MAX_LENGTH), nullable=True)
    location_country: Mapped[str | None] = Column(String(COUNTRY_CODE_LENGTH), nullable=True)
    location_city: Mapped[str | None] = Column(String(CITY_MAX_LENGTH), nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="users", foreign_keys="User.organization_id"
    )
    identities: Mapped[List["UserIdentity"]] = relationship(
        "UserIdentity", back_populates="user", cascade="all, delete-orphan"
    )
    sessions: Mapped[List["UserSession"]] = relationship(
        "UserSession", back_populates="user", cascade="all, delete-orphan"
    )
    password_reset_tokens: Mapped[List["PasswordResetToken"]] = relationship(
        "PasswordResetToken", back_populates="user", cascade="all, delete-orphan"
    )
    mfa_challenges: Mapped[List["MfaChallenge"]] = relationship(
        "MfaChallenge", back_populates="user", cascade="all, delete-orphan"
    )
    invite_tokens: Mapped[List["InviteToken"]] = relationship(
        "InviteToken",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="InviteToken.user_id",
    )
    invites_sent: Mapped[List["InviteToken"]] = relationship(
        "InviteToken",
        back_populates="invited_by",
        foreign_keys="InviteToken.invited_by_user_id",
    )

    def __repr__(self) -> str:
        return f"<User(email='{self.email}', role='{self.role}')>"


class UserIdentity(Base):
    """SSO identity bindings for users."""

    __tablename__ = "user_identities"
    __table_args__ = (
        Index(
            "ix_user_identities_provider_subject",
            "provider",
            "provider_subject",
            unique=True,
        ),
        Index(
            "ix_user_identities_org_provider_email",
            "organization_id",
            "provider",
            "email",
            unique=True,
        ),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id"), nullable=False, index=True
    )
    user_id: Mapped[int] = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    provider: Mapped[str] = Column(String(50), nullable=False)
    provider_subject: Mapped[str] = Column(String(255), nullable=False)
    provider_tenant: Mapped[str | None] = Column(String(255))
    email: Mapped[str] = Column(String(255), nullable=False)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="identities")


class UserSession(Base):
    """Refresh token sessions for rotating tokens."""

    __tablename__ = "user_sessions"

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id"), nullable=False, index=True
    )
    user_id: Mapped[int] = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    refresh_token_hash: Mapped[str] = Column(String(255), nullable=False, unique=True)
    rotated_from_session_id: Mapped[int | None] = Column(Integer, ForeignKey("user_sessions.id"))
    expires_at: Mapped[datetime] = Column(DateTime, nullable=False, index=True)
    revoked_at: Mapped[datetime | None] = Column(DateTime, index=True)
    ip: Mapped[str | None] = Column(String(64))
    user_agent: Mapped[str | None] = Column(Text)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="sessions")


class PasswordResetToken(Base):
    """Password reset token storage."""

    __tablename__ = "password_reset_tokens"

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id"), nullable=False, index=True
    )
    user_id: Mapped[int] = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token_hash: Mapped[str] = Column(String(255), nullable=False, unique=True, index=True)
    expires_at: Mapped[datetime] = Column(DateTime, nullable=False, index=True)
    used_at: Mapped[datetime | None] = Column(DateTime)
    requested_ip: Mapped[str | None] = Column(String(64))
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="password_reset_tokens")


class InviteToken(Base):
    """Invite-only signup tokens."""

    __tablename__ = "invite_tokens"
    __table_args__ = (
        Index("ix_invite_tokens_user_expires", "user_id", "expires_at"),
        Index("ix_invite_tokens_user_used", "user_id", "used_at"),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id"), nullable=False, index=True
    )
    user_id: Mapped[int] = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    invited_by_user_id: Mapped[int | None] = Column(Integer, ForeignKey("users.id"))
    token_hash: Mapped[str] = Column(String(255), nullable=False, unique=True, index=True)
    expires_at: Mapped[datetime] = Column(DateTime, nullable=False, index=True)
    used_at: Mapped[datetime | None] = Column(DateTime, index=True)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    user: Mapped["User"] = relationship(
        "User", back_populates="invite_tokens", foreign_keys=[user_id]
    )
    invited_by: Mapped["User | None"] = relationship(
        "User", back_populates="invites_sent", foreign_keys=[invited_by_user_id]
    )


class MfaChallenge(Base):
    """One-time MFA challenges for SMS verification."""

    __tablename__ = "mfa_challenges"
    __table_args__ = (
        Index("ix_mfa_challenges_user_expires", "user_id", "expires_at"),
        Index("ix_mfa_challenges_user_used", "user_id", "used_at"),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id"), nullable=False, index=True
    )
    user_id: Mapped[int] = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    purpose: Mapped[str] = Column(String(20), nullable=False)
    channel: Mapped[str] = Column(String(20), nullable=False, default="sms")
    destination_hash: Mapped[str] = Column(String(64), nullable=False)
    code_hash: Mapped[str] = Column(String(255), nullable=False)
    salt: Mapped[str] = Column(String(64), nullable=False)
    expires_at: Mapped[datetime] = Column(DateTime, nullable=False, index=True)
    used_at: Mapped[datetime | None] = Column(DateTime, index=True)
    attempt_count: Mapped[int] = Column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = Column(Integer, default=5, nullable=False)
    resend_count: Mapped[int] = Column(Integer, default=0, nullable=False)
    last_sent_at: Mapped[datetime | None] = Column(DateTime)
    created_ip: Mapped[str | None] = Column(String(64))
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="mfa_challenges")


class AuditEvent(Base):
    """Security and audit event log."""

    __tablename__ = "audit_events"
    __table_args__ = (
        Index(
            "ix_audit_events_org_type_created",
            "organization_id",
            "event_type",
            "created_at",
        ),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id"), nullable=False, index=True
    )
    actor_user_id: Mapped[int | None] = Column(Integer, ForeignKey("users.id"), index=True)
    event_type: Mapped[str] = Column(String(100), nullable=False, index=True)
    metadata_json: Mapped[dict | None] = Column("metadata", JSON)
    # #284 (TZ-6) — where the actor was and what clock they were on **at the
    # time of the event**, copied rather than joined.
    #
    # Copied on purpose: `actor_user_id` points at a row that changes. Somebody
    # who relocates to Singapore next year would otherwise retroactively change
    # where last year's decision was made, and an audit trail that rewrites
    # itself when a profile is edited is not evidence.
    #
    # Null for a system event, and for every row written before this existed.
    # A null reads as "not recorded", never as "UTC" — inventing a value for a
    # past event is the same failure in the other direction.
    actor_timezone: Mapped[str | None] = Column(String(TIMEZONE_MAX_LENGTH), nullable=True)
    actor_location_country: Mapped[str | None] = Column(String(COUNTRY_CODE_LENGTH), nullable=True)
    actor_location_city: Mapped[str | None] = Column(String(CITY_MAX_LENGTH), nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)


class ActivationAuditOutbox(Base):
    """Transactional outbox for activation audit events."""

    __tablename__ = "activation_audit_outbox"
    __table_args__ = (
        Index(
            "ix_activation_audit_outbox_status_created",
            "status",
            "created_at",
        ),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int | None] = Column(
        Integer, ForeignKey("organizations.id"), nullable=True, index=True
    )
    actor_user_id: Mapped[int | None] = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    event_type: Mapped[str] = Column(String(100), nullable=False, index=True)
    metadata_json: Mapped[dict | None] = Column("metadata", JSON)
    status: Mapped[str] = Column(String(32), nullable=False, default="pending", index=True)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    processed_at: Mapped[datetime | None] = Column(DateTime)
    last_error: Mapped[str | None] = Column(Text)


__all__ = [
    "ActivationAuditOutbox",
    "AuditEvent",
    "InviteToken",
    "MfaChallenge",
    "PasswordResetToken",
    "User",
    "UserIdentity",
    "UserSession",
]
