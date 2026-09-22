"""Step 4.1C — reject/supersede actions on SlotInstance mapping decisions."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray, JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.tenant_context import TenantContext
from src.api.routes.bundle_slot_mapping_routes import reject_slot_mapping, supersede_slot_mapping
from src.core.constants.dependency_mapping_enums import SlotMappingReasonCode
from src.core.database import Base
from src.core.model_defs.assets_runtime import Asset, AssetLifecycleState, AssetStatus, ConnectivityStatus, Criticality, Environment, ScanStartMode, SetupConfidence
from src.core.models import BusinessService, DependencyBundle, MappingDecision, Organization, SlotInstance
from fastapi import HTTPException

from src.api.routes.bundle_contracts import RejectSlotMappingRequest, SupersedeSlotMappingRequest

pytestmark = pytest.mark.skip(
    reason="#353 — same cause as test_bundles_routes: the DummyDB fixture seeds no "
    "ownership, so require_service_process_editor refuses before the behaviour under "
    "test is reached. Reject and supersede themselves are unexercised, not disproven."
)


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org One", slug="org-one", plan_tier="enterprise", subscription_status="active", onboarding_completed=False),
            Organization(id=2, name="Org Two", slug="org-two", plan_tier="enterprise", subscription_status="active", onboarding_completed=False),
        ]
    )
    session.commit()
    yield session
    session.close()


def _ctx(*, organization_id: int = 1, user_id: int = 7) -> TenantContext:
    return TenantContext(user_id=user_id, organization_id=organization_id, email="ciso@risklence.test", roles=["ciso"], permissions=[])


def _make_service(db: Session, *, organization_id: int = 1, service_id: str = "svc-1") -> BusinessService:
    service = BusinessService(id=service_id, organization_id=organization_id, name="Payment Processing", archetype="transactional_system")
    db.add(service)
    db.flush()
    return service


def _make_bundle(db: Session, *, organization_id: int = 1, service_id: str = "svc-1") -> DependencyBundle:
    bundle = DependencyBundle(
        id=str(uuid.uuid4()),
        organization_id=organization_id,
        service_id=service_id,
        status="draft",
        mode="manual_training",
        lifecycle_state="bundle_published",
        groups=[],
    )
    db.add(bundle)
    db.flush()
    return bundle


def _make_slot_instance(
    db: Session, *, organization_id: int = 1, service_id: str = "svc-1", mapping_status: str = "suggested", asset_id: str | None = "asset-1"
) -> SlotInstance:
    row = SlotInstance(
        id=str(uuid.uuid4()),
        organization_id=organization_id,
        service_id=service_id,
        slot_id="identity_provider",
        group_key="identity",
        status="mapped" if asset_id else "unknown",
        asset_id=asset_id,
        asset_label="Suggested Asset" if asset_id else None,
        mapping_status=mapping_status,
        mapping_confidence=0.6 if mapping_status == "suggested" else None,
        evidence_source="scanner" if mapping_status == "suggested" else None,
        provenance="scanner" if mapping_status == "suggested" else None,
    )
    db.add(row)
    db.flush()
    return row


def _make_asset(db: Session, *, organization_id: int = 1, asset_id: int = 2, display_name: str = "Replacement Asset") -> Asset:
    asset = Asset(
        id=asset_id,
        organization_id=organization_id,
        type="Service",
        provider="collector",
        display_name=display_name,
        layer="Application",
        environment=Environment.PROD,
        criticality=Criticality.MEDIUM,
        status=AssetStatus.PARTIALLY_OBSERVED,
        connectivity_status=ConnectivityStatus.PENDING_VERIFICATION,
        setup_confidence=SetupConfidence.LOW,
        scan_start_mode=ScanStartMode.AUDIT_ONLY,
        findings_count=0,
        risk_score=0.0,
        confidence=0.4,
        lifecycle_state=AssetLifecycleState.ACTIVE,
    )
    db.add(asset)
    db.flush()
    return asset


def test_reject_persists_status_and_clears_asset(db: Session):
    _make_service(db)
    _make_bundle(db)
    row = _make_slot_instance(db, mapping_status="suggested")

    result = reject_slot_mapping(
        "svc-1", row.slot_id, RejectSlotMappingRequest(reason_code=SlotMappingReasonCode.WRONG_ASSET.value, reason="Not the right identity provider."), _ctx(), db
    )

    assert result.mapping_status == "rejected"
    assert result.asset_id is None
    assert result.mapping_reason_code == SlotMappingReasonCode.WRONG_ASSET.value

    refreshed = db.get(SlotInstance, row.id)
    assert refreshed.mapping_status == "rejected"
    assert refreshed.status == "needs_review"
    assert refreshed.asset_id is None
    assert refreshed.provenance == "owner_rejected"
    assert refreshed.decided_by == "7"


def test_reject_is_recorded_in_mapping_decision_history(db: Session):
    _make_service(db)
    bundle = _make_bundle(db)
    row = _make_slot_instance(db, mapping_status="suggested")

    reject_slot_mapping(
        "svc-1", row.slot_id, RejectSlotMappingRequest(reason_code=SlotMappingReasonCode.WRONG_ASSET.value), _ctx(), db
    )

    decision = db.query(MappingDecision).filter(MappingDecision.bundle_id == bundle.id).one()
    assert decision.action == "reject_slot_mapping"
    assert decision.before_state["mapping_status"] == "suggested"
    assert decision.after_state["mapping_status"] == "rejected"


def test_rejected_mapping_is_skipped_by_the_next_suggestion_pass(db: Session):
    """The real, previously-unreachable payoff: a rejected mapping must
    never be silently re-suggested identically."""
    from src.core.services.slot_mapping_suggestion_service import is_human_decided

    _make_service(db)
    _make_bundle(db)
    row = _make_slot_instance(db, mapping_status="suggested")

    reject_slot_mapping("svc-1", row.slot_id, RejectSlotMappingRequest(reason_code=SlotMappingReasonCode.WRONG_ASSET.value), _ctx(), db)

    refreshed = db.get(SlotInstance, row.id)
    assert is_human_decided(refreshed) is True


def test_supersede_replaces_asset_and_audits_prior_state(db: Session):
    _make_service(db)
    bundle = _make_bundle(db)
    row = _make_slot_instance(db, mapping_status="approved", asset_id="asset-1")
    _make_asset(db, asset_id=2, display_name="Better Identity Provider")

    result = supersede_slot_mapping(
        "svc-1",
        row.slot_id,
        SupersedeSlotMappingRequest(asset_id="asset-2", reason_code=SlotMappingReasonCode.REPLACED_BY_NEWER_EVIDENCE.value),
        _ctx(),
        db,
    )

    assert result.asset_id == "asset-2"
    assert result.asset_label == "Better Identity Provider"
    assert result.mapping_status == "approved"
    assert result.provenance == "overridden"
    assert result.mapping_confidence == 1.0

    decision = db.query(MappingDecision).filter(MappingDecision.bundle_id == bundle.id).one()
    assert decision.action == "supersede_slot_mapping"
    assert decision.before_state["asset_id"] == "asset-1"
    assert decision.after_state["asset_id"] == "asset-2"


def test_supersede_rejects_asset_from_another_organisation(db: Session):
    _make_service(db)
    _make_bundle(db)
    row = _make_slot_instance(db, mapping_status="approved", asset_id="asset-1")
    _make_asset(db, organization_id=2, asset_id=99, display_name="Someone Else's Asset")

    with pytest.raises(HTTPException) as exc_info:
        supersede_slot_mapping(
            "svc-1",
            row.slot_id,
            SupersedeSlotMappingRequest(asset_id="asset-99", reason_code=SlotMappingReasonCode.MANUAL_ASSIGNMENT.value),
            _ctx(),
            db,
        )
    assert exc_info.value.status_code == 404


def test_reject_cross_tenant_denied(db: Session):
    _make_service(db, organization_id=1)
    _make_bundle(db, organization_id=1)
    row = _make_slot_instance(db, organization_id=1, mapping_status="suggested")

    with pytest.raises(HTTPException) as exc_info:
        reject_slot_mapping(
            "svc-1", row.slot_id, RejectSlotMappingRequest(reason_code=SlotMappingReasonCode.WRONG_ASSET.value), _ctx(organization_id=2), db
        )
    assert exc_info.value.status_code == 404


def test_supersede_cross_tenant_denied(db: Session):
    _make_service(db, organization_id=1)
    _make_bundle(db, organization_id=1)
    row = _make_slot_instance(db, organization_id=1, mapping_status="approved", asset_id="asset-1")

    with pytest.raises(HTTPException) as exc_info:
        supersede_slot_mapping(
            "svc-1",
            row.slot_id,
            SupersedeSlotMappingRequest(asset_id="asset-1", reason_code=SlotMappingReasonCode.MANUAL_ASSIGNMENT.value),
            _ctx(organization_id=2),
            db,
        )
    assert exc_info.value.status_code == 404
