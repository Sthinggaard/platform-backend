from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    ARRAY,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, relationship

from src.core.constants import (
    DEFAULT_SERVICE_TIER,
    SERVICE_TIER_SQL_CHECK,
    SERVICE_TIER_SQL_CHECK_CONSTRAINT,
)
from src.core.database import Base
from src.core.model_defs.common import utcnow

if TYPE_CHECKING:
    # Named only in the `Mapped["..."]` annotations of the relationships below. Imported for
    # type checkers, never at runtime: the relationships resolve by name through SQLAlchemy's
    # registry, and a runtime import would tie this module's load order to theirs.
    from src.core.model_defs.assets_runtime import Asset
    from src.core.model_defs.tenant_org import Organization


class Threat(Base):
    """A risk threat surfaced by the intelligence engine for an organisation.

    Threats are created by the signal processing pipeline (GLIC, Splunk, CMDB,
    cross-org pattern matching). A Decision record is embedded as JSONB so that
    the full decision audit trail is stored alongside the threat without an extra
    join.

    Every row is scoped to a single organisation — the ``organization_id``
    column is **mandatory** and must be present on every query.
    """

    __tablename__ = "threats"
    __table_args__ = (
        Index("ix_threats_org_status", "organization_id", "status"),
        Index("ix_threats_org_severity", "organization_id", "severity"),
    )

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )

    status: Mapped[str] = Column(String(20), nullable=False, default="detected")
    severity: Mapped[str] = Column(String(20), nullable=False)
    source: Mapped[str] = Column(String(20), nullable=False)
    asset: Mapped[str] = Column(String(200), nullable=False)
    tier: Mapped[str] = Column(String(50), nullable=False)
    signal: Mapped[str] = Column(Text, nullable=False)
    what_it_means: Mapped[str] = Column(Text, nullable=False)
    recommendation: Mapped[str] = Column(Text, nullable=False)

    intelligence: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    daily_cost: Mapped[int] = Column(Integer, nullable=False, default=0)
    frameworks: Mapped[list] = Column(ARRAY(String), nullable=False, default=list)
    requires_escalation: Mapped[bool] = Column(Boolean, nullable=False, default=False)

    decision: Mapped[dict | None] = Column(JSONB, nullable=True)
    saved_per_hour: Mapped[int | None] = Column(Integer, nullable=True)
    resolved_on: Mapped[str | None] = Column(String(30), nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")

    def __repr__(self) -> str:
        return f"<Threat(id='{self.id}', org={self.organization_id}, severity='{self.severity}', status='{self.status}')>"


class Recommendation(Base):
    """A recommendation snapshot generated for a tenant runtime context."""

    __tablename__ = "recommendations"
    __table_args__ = (
        Index("ix_recommendations_org", "organization_id"),
        Index("ix_recommendations_threat", "threat_id"),
        Index("ix_recommendations_org_status", "organization_id", "status"),
    )

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    threat_id: Mapped[str | None] = Column(
        String(36), ForeignKey("threats.id", ondelete="SET NULL"), nullable=True
    )

    status: Mapped[str] = Column(String(20), nullable=False, default="open")
    linked_context_type: Mapped[str] = Column(String(20), nullable=False, default="asset")
    linked_context_id: Mapped[str] = Column(String(200), nullable=False)
    linked_context_label: Mapped[str | None] = Column(String(255), nullable=True)

    problem: Mapped[str] = Column(Text, nullable=False)
    why_it_matters: Mapped[str] = Column(Text, nullable=False)
    suggested_action: Mapped[str] = Column(String(20), nullable=False)
    confidence_score: Mapped[int] = Column(Integer, nullable=False, default=0)
    is_stale: Mapped[bool] = Column(Boolean, nullable=False, default=False)
    intelligence_snapshot: Mapped[dict] = Column(JSONB, nullable=False, default=dict)

    generated_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")

    def __repr__(self) -> str:
        return (
            f"<Recommendation(id='{self.id}', org={self.organization_id}, "
            f"threat_id='{self.threat_id}', status='{self.status}')>"
        )


class DecisionRecord(Base):
    """Append-only audit record of a human decision against a recommendation."""

    __tablename__ = "decision_records"
    __table_args__ = (
        Index("ix_decision_records_org", "organization_id"),
        Index("ix_decision_records_recommendation", "recommendation_id"),
        Index("ix_decision_records_threat", "threat_id"),
        Index("ix_decision_records_org_created", "organization_id", "created_at"),
    )

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    recommendation_id: Mapped[str] = Column(
        String(36), ForeignKey("recommendations.id", ondelete="CASCADE"), nullable=False
    )
    threat_id: Mapped[str | None] = Column(
        String(36), ForeignKey("threats.id", ondelete="SET NULL"), nullable=True
    )

    selected_action: Mapped[str] = Column(String(20), nullable=False)
    decision_type: Mapped[str] = Column(String(20), nullable=False)
    rationale: Mapped[str] = Column(Text, nullable=False, default="")
    decided_by: Mapped[str] = Column(String(255), nullable=False)
    decided_role: Mapped[str] = Column(String(100), nullable=False)
    review_date: Mapped[str | None] = Column(String(30), nullable=True)
    stale: Mapped[bool] = Column(Boolean, nullable=False, default=False)

    recommendation_snapshot: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    reasoning_snapshot: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    forecast_snapshot: Mapped[dict | None] = Column(JSONB, nullable=True, default=None)

    integration_ref: Mapped[str | None] = Column(String(200), nullable=True)
    integration_provider: Mapped[str | None] = Column(String(50), nullable=True)
    external_url: Mapped[str | None] = Column(String(500), nullable=True)
    recovery_action_id: Mapped[int | None] = Column(
        Integer, ForeignKey("recovery_actions.id", ondelete="SET NULL"), nullable=True
    )

    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")

    def __repr__(self) -> str:
        return (
            f"<DecisionRecord(id='{self.id}', recommendation_id='{self.recommendation_id}', "
            f"action='{self.selected_action}')>"
        )


class ResolutionRecord(Base):
    """Append-only resolution record captured after decision and recovery work."""

    __tablename__ = "resolution_records"
    __table_args__ = (
        Index("ix_resolution_records_org", "organization_id"),
        Index("ix_resolution_records_recommendation", "recommendation_id"),
        Index("ix_resolution_records_decision", "decision_record_id"),
        Index("ix_resolution_records_recovery_action", "recovery_action_id"),
        Index("ix_resolution_records_org_created", "organization_id", "created_at"),
    )

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    recommendation_id: Mapped[str] = Column(
        String(36), ForeignKey("recommendations.id", ondelete="CASCADE"), nullable=False
    )
    decision_record_id: Mapped[str | None] = Column(
        String(36), ForeignKey("decision_records.id", ondelete="SET NULL"), nullable=True
    )
    threat_id: Mapped[str | None] = Column(
        String(36), ForeignKey("threats.id", ondelete="SET NULL"), nullable=True
    )
    recovery_action_id: Mapped[int | None] = Column(
        Integer, ForeignKey("recovery_actions.id", ondelete="SET NULL"), nullable=True
    )

    resolution_type: Mapped[str] = Column(String(40), nullable=False)
    selected_action_option: Mapped[str] = Column(String(20), nullable=False)
    alternative_category: Mapped[str | None] = Column(String(40), nullable=True)
    resolution_summary: Mapped[str | None] = Column(Text, nullable=True)
    resolved_by: Mapped[str] = Column(String(255), nullable=False)
    resolved_role: Mapped[str] = Column(String(100), nullable=False)
    status: Mapped[str] = Column(String(20), nullable=False)
    verification_status: Mapped[str] = Column(String(30), nullable=False)

    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")

    def __repr__(self) -> str:
        return (
            f"<ResolutionRecord(id='{self.id}', recommendation_id='{self.recommendation_id}', "
            f"type='{self.resolution_type}')>"
        )


class VerificationRecord(Base):
    """Append-only scanner-backed verification outcomes for a captured resolution."""

    __tablename__ = "verification_records"
    __table_args__ = (
        Index("ix_verification_records_org", "organization_id"),
        Index("ix_verification_records_resolution", "resolution_record_id"),
        Index("ix_verification_records_recommendation", "recommendation_id"),
        Index("ix_verification_records_org_created", "organization_id", "created_at"),
    )

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    resolution_record_id: Mapped[str] = Column(
        String(36), ForeignKey("resolution_records.id", ondelete="CASCADE"), nullable=False
    )
    recommendation_id: Mapped[str] = Column(
        String(36), ForeignKey("recommendations.id", ondelete="CASCADE"), nullable=False
    )
    threat_id: Mapped[str | None] = Column(
        String(36), ForeignKey("threats.id", ondelete="SET NULL"), nullable=True
    )

    verification_status: Mapped[str] = Column(String(30), nullable=False)
    confidence_score: Mapped[int] = Column(Integer, nullable=False, default=0)
    observed_changes: Mapped[list] = Column(JSONB, nullable=False, default=list)
    notes: Mapped[str | None] = Column(Text, nullable=True)
    linked_context_type: Mapped[str | None] = Column(String(20), nullable=True)
    linked_context_id: Mapped[str | None] = Column(String(200), nullable=True)
    compared_observed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")

    def __repr__(self) -> str:
        return (
            f"<VerificationRecord(id='{self.id}', resolution_record_id='{self.resolution_record_id}', "
            f"status='{self.verification_status}')>"
        )


class BusinessService(Base):
    """A business service grouping that maps L1/L2/L3 asset dependencies."""

    __tablename__ = "business_services"
    __table_args__ = (
        Index("ix_business_services_org", "organization_id"),
        CheckConstraint(SERVICE_TIER_SQL_CHECK, name=SERVICE_TIER_SQL_CHECK_CONSTRAINT),
    )

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )

    name: Mapped[str] = Column(String(200), nullable=False)
    tier: Mapped[str] = Column(String(50), nullable=False, default=DEFAULT_SERVICE_TIER)
    tolerance_window: Mapped[str | None] = Column(String(20), nullable=True)
    trading_impact: Mapped[str] = Column(Text, nullable=False, default="")
    bia_answers: Mapped[dict | None] = Column(JSONB, nullable=True)
    archetype: Mapped[str | None] = Column(String(50), nullable=True)
    library_item_id: Mapped[str | None] = Column(String(100), nullable=True)
    template_key: Mapped[str | None] = Column(String(100), nullable=True)
    # Accountable business owner (skill: ownership is the load-bearing link —
    # the owner owns every asset the service depends on).
    owner_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    owner_source: Mapped[str | None] = Column(String(20), nullable=True)
    template_version: Mapped[int | None] = Column(Integer, nullable=True)
    value_stream_ids: Mapped[list] = Column(ARRAY(String), nullable=False, default=list)

    l1: Mapped[list] = Column(ARRAY(String), nullable=False, default=list)
    l2: Mapped[list] = Column(ARRAY(String), nullable=False, default=list)
    l3: Mapped[list] = Column(ARRAY(String), nullable=False, default=list)

    archived_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")

    def __repr__(self) -> str:
        return f"<BusinessService(id='{self.id}', org={self.organization_id}, name='{self.name}')>"


class ValueStream(Base):
    """An org-level business process instance (Value Stream)."""

    __tablename__ = "value_streams"
    __table_args__ = (Index("ix_value_streams_org", "organization_id"),)

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )

    library_item_id: Mapped[str | None] = Column(String(100), nullable=True)
    name: Mapped[str] = Column(String(200), nullable=False)
    description: Mapped[str | None] = Column(Text, nullable=True)
    priority: Mapped[str] = Column(String(20), nullable=False, default="standard")
    source: Mapped[str] = Column(String(30), nullable=False, default="inferred")
    # Process-level Business Impact Assessment — asked once here; member
    # BusinessService rows inherit it and only record exceptions (BSP-04,
    # risklence-business-service-profiles skill: BIA scaling rule).
    bia_answers: Mapped[dict | None] = Column(JSONB, nullable=True)
    # Tenant-owned BPMN topology. Canonical template topology is never mutated
    # here; this graph records the organisation's reviewed operating process.
    bpmn_definition: Mapped[dict | None] = Column(JSONB, nullable=True)

    # The Risk Appetite this process runs under, once its owner has decided.
    #
    # ⚠️ **It is the decision, not the policy's scope.** It points at the
    # organisation's policy when the owner accepted the inherited baseline, and
    # at the process's own once leadership approves a deviation — both are a
    # decision this process has made, and the reader is asked for one only while
    # this is null.
    #
    # Søren, 2026-09-11: *"the inherent process should be registered on the
    # business process linking to the saved risk appetite. If the user chooses
    # to create their own risk appetite for the process that is then registered
    # on the business process and linked to the newly created risk appetite."*
    #
    # Until this existed, accepting the inherited appetite wrote no process
    # record at all — only an audit line that did not carry the process id — so
    # nothing could tell an answered process from an unasked one, and the map
    # asked again on every load.
    # ⚠️ `use_alter` because the two tables point at each other:
    # `risk_appetite_policies.process_id` already references this one, so
    # without it SQLAlchemy cannot order the CREATE TABLEs and raises
    # CircularDependencyError on any metadata create_all. Named, because an
    # ALTER-added constraint needs one to be droppable.
    #
    # ⚠️ SET NULL, never CASCADE: a deleted policy must not take the process
    # with it. The process survives and is asked again, which is the honest
    # state — it no longer has an appetite it can name.
    risk_appetite_policy_id: Mapped[str | None] = Column(
        String(36),
        ForeignKey(
            "risk_appetite_policies.id",
            ondelete="SET NULL",
            use_alter=True,
            name="fk_value_streams_risk_appetite_policy",
        ),
        nullable=True,
    )

    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")

    def __repr__(self) -> str:
        return f"<ValueStream(id='{self.id}', org={self.organization_id}, name='{self.name}', priority='{self.priority}')>"


class ValueStreamSignal(Base):
    """Append-only value stream signal log for learning."""

    __tablename__ = "value_stream_signals"
    __table_args__ = (
        Index("ix_value_stream_signals_org_event", "organization_id", "event"),
        Index("ix_value_stream_signals_stream", "stream_id"),
        Index("ix_value_stream_signals_library_item", "library_item_id"),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # Nullable: engine-initiated signals (e.g. ingestion evidence refresh)
    # have no acting user — a system event must not fabricate attribution.
    user_id: Mapped[int | None] = Column(Integer, nullable=True)
    event: Mapped[str] = Column(String(50), nullable=False)

    stream_id: Mapped[str | None] = Column(String(36), nullable=True)
    library_item_id: Mapped[str | None] = Column(String(100), nullable=True)
    stream_key: Mapped[str | None] = Column(String(100), nullable=True)
    name: Mapped[str | None] = Column(String(200), nullable=True)
    priority: Mapped[str | None] = Column(String(20), nullable=True)
    source: Mapped[str | None] = Column(String(30), nullable=True)

    payload: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")

    def __repr__(self) -> str:
        return (
            f"<ValueStreamSignal(id='{self.id}', event='{self.event}', "
            f"stream_id='{self.stream_id}')>"
        )


class DependencyBundle(Base):
    """A structured dependency map for a single BusinessService."""

    __tablename__ = "dependency_bundles"
    __table_args__ = (
        Index("ix_dependency_bundles_service", "service_id"),
        Index("ix_dependency_bundles_org", "organization_id"),
    )

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    service_id: Mapped[str] = Column(
        String(36), ForeignKey("business_services.id", ondelete="CASCADE"), nullable=False
    )

    status: Mapped[str] = Column(String(20), nullable=False, default="draft")
    mode: Mapped[str] = Column(String(30), nullable=False, default="manual_training")
    lifecycle_state: Mapped[str] = Column(String(40), nullable=False, default="template_loaded")

    groups: Mapped[list] = Column(JSONB, nullable=False, default=list)
    validation_snapshot: Mapped[dict | None] = Column(JSONB, nullable=True)
    acknowledged_warning_ids: Mapped[list] = Column(JSONB, nullable=False, default=list)

    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")
    service: Mapped["BusinessService"] = relationship("BusinessService")

    def __repr__(self) -> str:
        return f"<DependencyBundle(id='{self.id}', service='{self.service_id}', status='{self.status}')>"


class DependencyBundleVersion(Base):
    """Immutable published snapshot of a DependencyBundle."""

    __tablename__ = "dependency_bundle_versions"
    __table_args__ = (
        Index("ix_dependency_bundle_versions_bundle", "bundle_id"),
        Index("ix_dependency_bundle_versions_service", "service_id"),
        Index("ix_dependency_bundle_versions_org", "organization_id"),
        Index(
            "ix_dependency_bundle_versions_bundle_version",
            "bundle_id",
            "version_number",
            unique=True,
        ),
    )

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    bundle_id: Mapped[str] = Column(
        String(36), ForeignKey("dependency_bundles.id", ondelete="CASCADE"), nullable=False
    )
    service_id: Mapped[str] = Column(
        String(36), ForeignKey("business_services.id", ondelete="CASCADE"), nullable=False
    )
    version_number: Mapped[int] = Column(Integer, nullable=False)
    status: Mapped[str] = Column(String(20), nullable=False, default="published")
    lifecycle_state: Mapped[str] = Column(String(40), nullable=False, default="bundle_published")
    groups_snapshot: Mapped[list] = Column(JSONB, nullable=False, default=list)
    validation_snapshot: Mapped[dict | None] = Column(JSONB, nullable=True)
    acknowledged_warning_ids: Mapped[list] = Column(JSONB, nullable=False, default=list)
    published_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")
    service: Mapped["BusinessService"] = relationship("BusinessService")
    bundle: Mapped["DependencyBundle"] = relationship("DependencyBundle")

    def __repr__(self) -> str:
        return (
            f"<DependencyBundleVersion(bundle='{self.bundle_id}', "
            f"version={self.version_number}, service='{self.service_id}')>"
        )


class MappingDecision(Base):
    """Append-only audit log of every user action on a DependencyBundle."""

    __tablename__ = "mapping_decisions"
    __table_args__ = (
        Index("ix_mapping_decisions_bundle", "bundle_id"),
        Index("ix_mapping_decisions_service", "service_id"),
        Index("ix_mapping_decisions_org", "organization_id"),
    )

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    service_id: Mapped[str] = Column(String(36), nullable=False)
    bundle_id: Mapped[str] = Column(String(36), nullable=False)
    node_id: Mapped[str | None] = Column(String(36), nullable=True)
    action: Mapped[str] = Column(String(50), nullable=False)
    group_key: Mapped[str | None] = Column(String(50), nullable=True)
    before_state: Mapped[dict | None] = Column(JSONB, nullable=True)
    after_state: Mapped[dict | None] = Column(JSONB, nullable=True)
    reason: Mapped[str | None] = Column(Text, nullable=True)
    actor_type: Mapped[str] = Column(String(20), nullable=False, default="human")
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)

    def __repr__(self) -> str:
        return (
            f"<MappingDecision(id='{self.id}', action='{self.action}', bundle='{self.bundle_id}')>"
        )


class ServiceJourneySignal(Base):
    """Append-only service-journey signal log for recommendation learning."""

    __tablename__ = "service_journey_signals"
    __table_args__ = (
        Index("ix_service_journey_signals_org_event", "organization_id", "event"),
        Index("ix_service_journey_signals_service_key", "service_key"),
        Index(
            "ix_service_journey_signals_segment",
            "organization_type",
            "industry",
            "company_size",
            "country",
        ),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[int] = Column(Integer, nullable=False)
    event: Mapped[str] = Column(String(50), nullable=False)

    service_id: Mapped[str | None] = Column(String(36), nullable=True)
    library_item_id: Mapped[str | None] = Column(String(100), nullable=True)
    service_key: Mapped[str | None] = Column(String(100), nullable=True)
    service_name: Mapped[str | None] = Column(String(200), nullable=True)
    search_query: Mapped[str | None] = Column(String(200), nullable=True)

    recommended_service_keys: Mapped[list] = Column(JSONB, nullable=False, default=list)
    matched_service_keys: Mapped[list] = Column(JSONB, nullable=False, default=list)
    warning_ids: Mapped[list] = Column(JSONB, nullable=False, default=list)

    organization_type: Mapped[str | None] = Column(String(100), nullable=True)
    industry: Mapped[str | None] = Column(String(100), nullable=True)
    company_size: Mapped[str | None] = Column(String(50), nullable=True)
    country: Mapped[str | None] = Column(String(10), nullable=True)

    payload: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")

    def __repr__(self) -> str:
        return (
            f"<ServiceJourneySignal(id='{self.id}', event='{self.event}', "
            f"service_key='{self.service_key}')>"
        )


class AssetAppetiteConfig(Base):
    """Per-asset risk appetite configuration."""

    __tablename__ = "asset_appetite_configs"
    __table_args__ = (
        UniqueConstraint("organization_id", "asset_id", name="uq_asset_appetite_org_asset"),
        Index("ix_asset_appetite_configs_org", "organization_id"),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[int] = Column(
        Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    answers: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    approved_by: Mapped[str] = Column(String(255), nullable=False)
    approved_at: Mapped[datetime] = Column(DateTime, nullable=False)
    version: Mapped[int] = Column(Integer, nullable=False, default=1)
    note: Mapped[str | None] = Column(Text, nullable=True)
    history: Mapped[list] = Column(JSONB, nullable=False, default=list)

    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")
    asset: Mapped["Asset"] = relationship("Asset")

    def __repr__(self) -> str:
        return f"<AssetAppetiteConfig(org={self.organization_id}, asset={self.asset_id}, v{self.version})>"


class BusinessServiceAppetiteConfig(Base):
    """Per-business-service risk appetite configuration.

    Legacy (BPS-38): no route serves this model any longer — a service's
    appetite is now the RiskAppetitePolicy cascade overlaid with
    ServiceAppetiteReassessment, resolved via
    ``service_appetite_reassessment_service.resolve_effective_service_appetite``.
    Table kept, not dropped: it holds real historical rows and this
    codebase's convention is to preserve history rather than hard-delete it.
    """

    __tablename__ = "business_service_appetite_configs"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "business_service_id",
            name="uq_business_service_appetite_org_service",
        ),
        Index("ix_business_service_appetite_configs_org", "organization_id"),
        Index("ix_business_service_appetite_configs_service", "business_service_id"),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    business_service_id: Mapped[str] = Column(
        String(36), ForeignKey("business_services.id", ondelete="CASCADE"), nullable=False
    )
    answers: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    approved_by: Mapped[str] = Column(String(255), nullable=False)
    approved_at: Mapped[datetime] = Column(DateTime, nullable=False)
    version: Mapped[int] = Column(Integer, nullable=False, default=1)
    note: Mapped[str | None] = Column(Text, nullable=True)
    history: Mapped[list] = Column(JSONB, nullable=False, default=list)

    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")
    business_service: Mapped["BusinessService"] = relationship("BusinessService")

    def __repr__(self) -> str:
        return (
            f"<BusinessServiceAppetiteConfig(org={self.organization_id}, "
            f"service={self.business_service_id}, v{self.version})>"
        )


class RecoveryAction(Base):
    """Per-threat recovery action tracking remediation work after a decision is made."""

    __tablename__ = "recovery_actions"
    __table_args__ = (
        Index("ix_recovery_actions_org", "organization_id"),
        Index("ix_recovery_actions_threat", "threat_id"),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    threat_id: Mapped[str | None] = Column(
        String(100), ForeignKey("threats.id", ondelete="SET NULL"), nullable=True
    )

    title: Mapped[str] = Column(String(500), nullable=False)
    issue: Mapped[str] = Column(Text, nullable=False)
    action: Mapped[str] = Column(Text, nullable=False)
    affected_services: Mapped[list] = Column(JSONB, nullable=False, default=list)
    exposure_reduction: Mapped[str | None] = Column(String(100), nullable=True)
    priority: Mapped[str] = Column(String(20), nullable=False, default="high")
    status: Mapped[str] = Column(String(20), nullable=False, default="open")
    assigned_to: Mapped[str | None] = Column(String(255), nullable=True)
    due_date: Mapped[datetime | None] = Column(DateTime, nullable=True)
    ref: Mapped[str | None] = Column(String(200), nullable=True)
    progress: Mapped[int] = Column(Integer, nullable=False, default=0)
    steps: Mapped[list] = Column(JSONB, nullable=False, default=list)

    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")

    def __repr__(self) -> str:
        return f"<RecoveryAction(id={self.id}, org={self.organization_id}, status={self.status})>"


class OrgProcessConfig(Base):
    """Org-level overrides for a canonical process template."""

    __tablename__ = "org_process_configs"
    __table_args__ = (
        UniqueConstraint("organization_id", "template_key", name="uq_org_process_configs_org_key"),
        Index("ix_org_process_configs_org", "organization_id"),
    )

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    template_key: Mapped[str] = Column(String(100), nullable=False)
    excluded_service_keys: Mapped[list] = Column(ARRAY(String), nullable=False, default=list)
    custom_service_slots: Mapped[list] = Column(JSONB, nullable=False, default=list)
    note: Mapped[str | None] = Column(Text, nullable=True)
    created_by: Mapped[str | None] = Column(String(255), nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")

    def __repr__(self) -> str:
        return f"<OrgProcessConfig(org={self.organization_id}, key='{self.template_key}')>"


class ProcessTailoringSignal(Base):
    """Append-only, tenant-owned record of one approved process-tailoring decision.

    Every column a future learning pipeline (ONB-08C) may read is a controlled key or
    code — never a tenant, asset, or service *name*, and never free text. `note` is the
    one free-text escape hatch and must be excluded from any learning export. Never
    mutated after insert.
    """

    __tablename__ = "process_tailoring_signals"
    __table_args__ = (
        Index("ix_process_tailoring_signals_org", "organization_id"),
        Index("ix_process_tailoring_signals_process", "process_id"),
        Index("ix_process_tailoring_signals_template", "template_key"),
        Index("ix_process_tailoring_signals_created", "created_at"),
    )

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    process_id: Mapped[str | None] = Column(
        String(36), ForeignKey("value_streams.id", ondelete="SET NULL"), nullable=True
    )

    # Base template identity/version, if this process is template-backed.
    template_key: Mapped[str | None] = Column(String(100), nullable=True)
    template_version: Mapped[int | None] = Column(Integer, nullable=True)

    # Structured change + affected keys — controlled vocabulary only, never a service name.
    change_type: Mapped[str] = Column(String(40), nullable=False)
    affected_service_keys: Mapped[list] = Column(ARRAY(String), nullable=False, default=list)
    detail: Mapped[dict] = Column(JSONB, nullable=False, default=dict)

    # Rationale + evidence state — both controlled vocabularies.
    rationale_code: Mapped[str] = Column(String(60), nullable=False)
    evidence_state: Mapped[str] = Column(String(30), nullable=False)

    actor_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Materiality + invalidation outcome.
    is_process_boundary_change: Mapped[bool] = Column(Boolean, nullable=False, default=True)
    is_critical_service_change: Mapped[bool] = Column(Boolean, nullable=False, default=False)
    invalidated_activation: Mapped[bool] = Column(Boolean, nullable=False, default=False)

    audit_event_id: Mapped[int | None] = Column(
        Integer, ForeignKey("audit_events.id", ondelete="SET NULL"), nullable=True
    )

    # Free-text escape hatch — EXCLUDE from any learning export (ONB-08C).
    note: Mapped[str | None] = Column(Text, nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")

    def __repr__(self) -> str:
        return (
            f"<ProcessTailoringSignal(id='{self.id}', change_type='{self.change_type}', "
            f"process_id='{self.process_id}')>"
        )


class OrgServiceConfig(Base):
    """Org-level overrides for a canonical service template / archetype."""

    __tablename__ = "org_service_configs"
    __table_args__ = (
        UniqueConstraint("organization_id", "service_key", name="uq_org_service_configs_org_key"),
        Index("ix_org_service_configs_org", "organization_id"),
    )

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    service_key: Mapped[str] = Column(String(100), nullable=False)
    excluded_group_keys: Mapped[list] = Column(ARRAY(String), nullable=False, default=list)
    custom_groups: Mapped[list] = Column(JSONB, nullable=False, default=list)
    note: Mapped[str | None] = Column(Text, nullable=True)
    created_by: Mapped[str | None] = Column(String(255), nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")

    def __repr__(self) -> str:
        return f"<OrgServiceConfig(org={self.organization_id}, key='{self.service_key}')>"


class SlotInstance(Base):
    """Per-org, per-service slot mapping decision."""

    __tablename__ = "slot_instances"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "service_id", "slot_id", name="uq_slot_instances_org_service_slot"
        ),
        Index("ix_slot_instances_org", "organization_id"),
        Index("ix_slot_instances_service", "service_id"),
        Index("ix_slot_instances_slot", "slot_id"),
    )

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    service_id: Mapped[str] = Column(
        String(36), ForeignKey("business_services.id", ondelete="CASCADE"), nullable=False
    )
    slot_id: Mapped[str] = Column(String(100), nullable=False)
    template_version: Mapped[int | None] = Column(Integer, nullable=True)
    status: Mapped[str] = Column(String(20), nullable=False)
    asset_id: Mapped[str | None] = Column(String(36), nullable=True)
    asset_label: Mapped[str | None] = Column(String(255), nullable=True)
    group_key: Mapped[str | None] = Column(String(100), nullable=True)
    # #464 — stored on the logical dependency decision, never inferred from
    # the physical Artefact mapped to it.
    dependency_category: Mapped[str | None] = Column(String(30), nullable=True)
    # Mapping lifecycle (skill: DependencySlotMapping) — how trustworthy is
    # this artefact→slot link and who decided it.
    mapping_status: Mapped[str] = Column(String(20), nullable=False, default="approved")
    mapping_confidence: Mapped[float | None] = Column(Float, nullable=True)
    evidence_source: Mapped[str | None] = Column(String(30), nullable=True)
    mapping_reason: Mapped[str | None] = Column(Text, nullable=True)
    # Step 4.1C — controlled companion to the free-text mapping_reason
    # above, validated at the service layer against SlotMappingReasonCode
    # (dependency_mapping_enums.py), not a DB-level enum, matching this
    # table's own String-not-Enum precedent for mapping_status/provenance.
    mapping_reason_code: Mapped[str | None] = Column(String(60), nullable=True)
    provenance: Mapped[str | None] = Column(String(30), nullable=True)
    decided_by: Mapped[str | None] = Column(String(120), nullable=True)
    decided_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    # #460 (Søren, 2026-09-15) — the owner's resilience answers about this
    # dependency. They lived only on bundle nodes; the slot record is now the
    # one live record of a dependency decision, and nodes are the published
    # snapshot. Null means "not answered", never "no" (#362). Allowed values:
    # `core/constants/dependency_assessment_enums.py`, validated in the service
    # layer. Business impact becomes per process later (#463, #108).
    spof: Mapped[bool | None] = Column(Boolean, nullable=True)
    fallback_status: Mapped[str | None] = Column(String(10), nullable=True)
    recovery_dependent: Mapped[bool | None] = Column(Boolean, nullable=True)
    impact_type: Mapped[str | None] = Column(String(20), nullable=True)
    business_impact_level: Mapped[str | None] = Column(String(10), nullable=True)
    business_consequence: Mapped[str | None] = Column(Text, nullable=True)
    critical_for_business: Mapped[bool | None] = Column(Boolean, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")

    def __repr__(self) -> str:
        return f"<SlotInstance(org={self.organization_id}, service='{self.service_id}', slot='{self.slot_id}', status='{self.status}')>"


class TemplateLearningRun(Base):
    """Audit record for each template learning analysis run.

    One row per run invocation. Tracks which service keys were analysed,
    how many candidates were generated, and whether any were auto-staged
    (class A governance). Completed runs are immutable.
    """

    __tablename__ = "template_learning_runs"
    __table_args__ = (
        Index("ix_template_learning_runs_status", "status"),
        Index("ix_template_learning_runs_started_at", "started_at"),
    )

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    status: Mapped[str] = Column(
        String(20), nullable=False, default="running"
    )  # running | completed | failed
    triggered_by: Mapped[str] = Column(
        String(30), nullable=False, default="manual"
    )  # scheduled | manual
    service_keys_analysed: Mapped[list] = Column(ARRAY(String), nullable=False, default=list)
    candidates_generated: Mapped[int] = Column(Integer, nullable=False, default=0)
    candidates_auto_staged: Mapped[int] = Column(Integer, nullable=False, default=0)
    summary: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    error: Mapped[str | None] = Column(Text, nullable=True)
    started_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    def __repr__(self) -> str:
        return f"<TemplateLearningRun(id='{self.id}', status='{self.status}', candidates={self.candidates_generated})>"


class TemplateCandidate(Base):
    """A proposed evolution of a ServiceTemplate produced by the learning engine.

    The engine analyses SlotInstance decisions across all orgs and emits a
    TemplateCandidate when the data supports a meaningful change to slot
    configuration (required→optional, expected_asset_types update, etc.).

    Governance classes:
        A — high confidence, auto-staged to published without human review.
        B — medium confidence, surfaced for internal review before publish.
        C — low confidence or structural change, explicit approval required.

    Status lifecycle:
        pending       → awaiting review (class B / C only)
        auto_staged   → class A, waiting for next publish window
        approved      → reviewer approved, publish will proceed
        published     → new ServiceTemplate version created and set active
        rejected      → dismissed, no version change
    """

    __tablename__ = "template_candidates"
    __table_args__ = (
        Index("ix_template_candidates_service_key", "service_key"),
        Index("ix_template_candidates_status", "status"),
        Index("ix_template_candidates_run", "run_id"),
        Index("ix_template_candidates_governance_class", "governance_class"),
    )

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    run_id: Mapped[str] = Column(
        String(36), ForeignKey("template_learning_runs.id", ondelete="CASCADE"), nullable=False
    )
    service_key: Mapped[str] = Column(String(100), nullable=False)
    current_version: Mapped[int] = Column(Integer, nullable=False)
    candidate_version: Mapped[int] = Column(Integer, nullable=False)
    governance_class: Mapped[str] = Column(String(1), nullable=False)  # A | B | C
    status: Mapped[str] = Column(String(20), nullable=False, default="pending")
    # analysis holds slot-level statistics from the learning run
    analysis: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    # proposed_changes describes what would be updated in the new template version
    proposed_changes: Mapped[list] = Column(JSONB, nullable=False, default=list)
    reviewed_by: Mapped[str | None] = Column(String(255), nullable=True)
    review_note: Mapped[str | None] = Column(Text, nullable=True)
    published_template_id: Mapped[str | None] = Column(String(36), nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    run: Mapped["TemplateLearningRun"] = relationship("TemplateLearningRun")

    def __repr__(self) -> str:
        return (
            f"<TemplateCandidate(id='{self.id}', service_key='{self.service_key}', "
            f"class={self.governance_class}, status='{self.status}')>"
        )


class LearningLoopRun(Base):
    """Audit record for each governed learning-loop run."""

    __tablename__ = "learning_loop_runs"
    __table_args__ = (
        Index("ix_learning_loop_runs_status", "status"),
        Index("ix_learning_loop_runs_started_at", "started_at"),
    )

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    status: Mapped[str] = Column(String(20), nullable=False, default="running")
    triggered_by: Mapped[str] = Column(String(30), nullable=False, default="manual")
    since: Mapped[datetime | None] = Column(DateTime, nullable=True)
    signals_ingested: Mapped[int] = Column(Integer, nullable=False, default=0)
    candidates_generated: Mapped[int] = Column(Integer, nullable=False, default=0)
    candidates_auto_staged: Mapped[int] = Column(Integer, nullable=False, default=0)
    summary: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    error: Mapped[str | None] = Column(Text, nullable=True)
    started_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<LearningLoopRun(id='{self.id}', status='{self.status}', "
            f"signals={self.signals_ingested}, candidates={self.candidates_generated})>"
        )


class TrainingSignal(Base):
    """Append-only normalized training signal derived from runtime evidence."""

    __tablename__ = "training_signals"
    __table_args__ = (
        UniqueConstraint("source_type", "source_id", name="uq_training_signals_source"),
        Index("ix_training_signals_signal_type", "signal_type"),
        Index("ix_training_signals_target", "target_type", "target_key"),
        Index("ix_training_signals_source_created", "source_created_at"),
        Index("ix_training_signals_run", "run_id"),
        Index("ix_training_signals_org", "organization_id"),
    )

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    run_id: Mapped[str] = Column(
        String(36), ForeignKey("learning_loop_runs.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    source_type: Mapped[str] = Column(String(40), nullable=False)
    source_id: Mapped[str] = Column(String(64), nullable=False)
    signal_type: Mapped[str] = Column(String(50), nullable=False)
    target_type: Mapped[str] = Column(String(40), nullable=False)
    target_key: Mapped[str] = Column(String(200), nullable=False)
    outcome: Mapped[str] = Column(String(50), nullable=False)
    payload: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    source_created_at: Mapped[datetime] = Column(DateTime, nullable=False)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)

    run: Mapped["LearningLoopRun"] = relationship("LearningLoopRun")
    organization: Mapped["Organization"] = relationship("Organization")

    def __repr__(self) -> str:
        return (
            f"<TrainingSignal(id='{self.id}', signal_type='{self.signal_type}', "
            f"target='{self.target_key}', outcome='{self.outcome}')>"
        )


class LearningImprovementCandidate(Base):
    """Governed candidate improvement derived from training-signal aggregation."""

    __tablename__ = "learning_improvement_candidates"
    __table_args__ = (
        Index("ix_learning_improvement_candidates_status", "status"),
        Index("ix_learning_improvement_candidates_type", "candidate_type"),
        Index("ix_learning_improvement_candidates_target", "target_type", "target_key"),
        Index("ix_learning_improvement_candidates_run", "run_id"),
        Index("ix_learning_improvement_candidates_governance", "governance_class"),
    )

    id: Mapped[str] = Column(
        String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
    )
    run_id: Mapped[str] = Column(
        String(36), ForeignKey("learning_loop_runs.id", ondelete="CASCADE"), nullable=False
    )
    candidate_type: Mapped[str] = Column(String(50), nullable=False)
    target_type: Mapped[str] = Column(String(40), nullable=False)
    target_key: Mapped[str] = Column(String(200), nullable=False)
    governance_class: Mapped[str] = Column(String(1), nullable=False)
    status: Mapped[str] = Column(String(20), nullable=False, default="pending")
    sample_size: Mapped[int] = Column(Integer, nullable=False, default=0)
    confidence_score: Mapped[int] = Column(Integer, nullable=False, default=0)
    summary: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    proposed_changes: Mapped[list] = Column(JSONB, nullable=False, default=list)
    reviewed_by: Mapped[str | None] = Column(String(255), nullable=True)
    review_note: Mapped[str | None] = Column(Text, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    run: Mapped["LearningLoopRun"] = relationship("LearningLoopRun")

    def __repr__(self) -> str:
        return (
            f"<LearningImprovementCandidate(id='{self.id}', type='{self.candidate_type}', "
            f"target='{self.target_key}', class='{self.governance_class}', status='{self.status}')>"
        )


__all__ = [
    "AssetAppetiteConfig",
    "BusinessServiceAppetiteConfig",
    "BusinessService",
    "DependencyBundle",
    "DependencyBundleVersion",
    "LearningImprovementCandidate",
    "LearningLoopRun",
    "MappingDecision",
    "OrgProcessConfig",
    "OrgServiceConfig",
    "ProcessTailoringSignal",
    "RecoveryAction",
    "ServiceJourneySignal",
    "SlotInstance",
    "TemplateCandidate",
    "TemplateLearningRun",
    "Threat",
    "TrainingSignal",
    "ValueStream",
    "ValueStreamSignal",
]
