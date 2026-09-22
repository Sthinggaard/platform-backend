"""CA-07.2 — restricted access that the platform can describe but never perform.

A Connector says *how* deeper access to one target would be made, and *by which
Collector*. It holds addressing and identity metadata — host, port, the account
name — and a **fingerprint** of the credential. It holds no credential.

The columns that are absent are as much the design as the ones present: there is
no ``encrypted_credentials``, no ``encryption_key_id``, no ``token_hash``, and
nothing else that could carry secret material even reversibly. Compare
``CloudCredentials`` (``tenant_org.py``), which stores exactly that and which
this story names as an explicit non-goal — reusing it would satisfy "don't
duplicate" while breaking the contract.

``credential_fingerprint`` deserves its own note. It is not a hash of a secret
kept for later comparison; it is the kind of identifier SSH already publishes for
a key pair — derived from **public** material, meaningful to whoever holds the
private half, useless to anyone else. Nullable, because an operator-supplied
credential (Mode B) leaves nothing durable behind at all, not even an identifier.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped

from src.core.constants.access_connector_enums import (
    ACCESS_CONNECTOR_INOPERABLE_STATUSES,
    CONNECTOR_ERROR_INOPERABLE,
    AccessConnectorStatus,
)
from src.core.database import Base
from src.core.model_defs.common import utcnow


class AccessConnector(Base):
    __tablename__ = "access_connectors"
    __table_args__ = (
        Index("ix_access_connectors_org_status", "organization_id", "status"),
        Index("ix_access_connectors_instance", "scanner_instance_id", "status"),
        Index("ix_access_connectors_asset", "organization_id", "asset_id"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # NOT NULL and the point of the story: a credential stays local to the
    # Collector that uses it, so a Connector with no Collector would be a
    # credential with nowhere local to be.
    scanner_instance_id: Mapped[str] = Column(
        String(36), ForeignKey("scanner_instances.id", ondelete="CASCADE"), nullable=False
    )
    # What deeper access would reach. Nullable because a Connector can be
    # configured for a host that is not yet an inventory artefact.
    asset_id: Mapped[int | None] = Column(
        Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )

    # This Connector's row in the permission supertable. UNIQUE + NOT NULL, so a
    # Connector always has exactly one permissionable identity and a profile can
    # reach it through a real foreign key rather than a type/id pair the database
    # cannot check. See permission_subject.py for why that trade matters.
    permission_subject_id: Mapped[str] = Column(
        String(36),
        ForeignKey("permission_subjects.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    connector_type: Mapped[str] = Column(String(30), nullable=False)
    # Follows CA-07.0's approved operating mode; never chosen freely per
    # Connector, because where a credential may live is the organisation's
    # governed decision rather than an implementation detail.
    credential_model: Mapped[str] = Column(String(30), nullable=False)

    # Addressing and identity metadata — deliberately the only things stored.
    target_host: Mapped[str] = Column(String(255), nullable=False)
    target_port: Mapped[int | None] = Column(Integer, nullable=True)
    # The account name access would use. A username is not a secret; it is how
    # a reviewer answers "what would this reach, and as whom?" — the question
    # that makes restricted access reviewable at all.
    target_username: Mapped[str | None] = Column(String(255), nullable=True)

    # Identifies which credential is in use, derived from public material.
    # NULL for operator-supplied: nothing durable exists to identify.
    credential_fingerprint: Mapped[str | None] = Column(String(128), nullable=True)
    credential_registered_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    credential_rotated_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    # Docker socket access is called out by the contract as needing explicit
    # approval. Recorded here as a *declared requirement*; the approval itself
    # is CA-07.3's permission profile, and this flag grants nothing on its own.
    requires_docker_socket: Mapped[bool] = Column(Boolean, nullable=False, default=False)

    status: Mapped[str] = Column(
        String(20), nullable=False, default=AccessConnectorStatus.CONFIGURED.value
    )

    # CA-07.4 — the three withdrawal verbs, recorded as three independent facts.
    #
    # ``status`` alone cannot hold them, because revocation and disconnection are
    # genuinely independent: a Connector can be revoked while its credential is
    # still sitting on the Collector awaiting cleanup, and a Collector can be
    # rebuilt (disconnected) while the authorisation still stands. One column
    # would force the second act to erase the first.
    #
    # So the rule is: **``status`` shows the strongest standing withdrawal, and
    # the timestamps below record each act in its own right.** Disconnecting a
    # revoked Connector stamps ``disconnected_at`` and leaves the status
    # ``revoked``, because revocation is the permanent governance statement and
    # must stay visible.
    paused_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    revoked_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # Required when revoking. Revocation outlives everyone who remembers it, and
    # "who withdrew this, and why?" is the question an auditor actually asks.
    revocation_reason: Mapped[str | None] = Column(Text, nullable=True)
    disconnected_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    note: Mapped[str | None] = Column(Text, nullable=True)
    created_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(
        DateTime, nullable=False, default=utcnow, onupdate=utcnow
    )

    @property
    def permission_subject_inactive_reason(self) -> str | None:
        """Why this Connector may not be used right now, or ``None`` when it may.

        This is what makes ``PermissionSubjectBearer`` enough for enforcement to
        refuse a withdrawn subject. Without it, a *revoked* Connector holding an
        approved profile would still pass ``assert_capability_permitted`` —
        and a revocation that does not stop access is not a revocation.

        The wording lives here rather than in the enforcement path because the
        verbs are this model's vocabulary; enforcement stays polymorphic and
        every future subject kind supplies its own answer.
        """
        if self.status in ACCESS_CONNECTOR_INOPERABLE_STATUSES:
            return CONNECTOR_ERROR_INOPERABLE.format(status=self.status)
        return None


__all__ = ["AccessConnector"]
