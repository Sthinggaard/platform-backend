"""#493 — reusable, human-confirmed Artefact links remain service-scoped."""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.tenant_context import TenantContext
from src.api.routes.service_artefact_dependencies import list_service_artefacts
from src.core.database import Base
from src.core.model_defs.assets_runtime import (
    Asset,
    AssetLifecycleState,
    AssetStatus,
    ConnectivityStatus,
    Criticality,
    Environment,
    ScanStartMode,
    SetupConfidence,
)
from src.core.model_defs.service_artefact_dependency import ServiceArtefactDependencyLink
from src.core.model_defs.tenant_org import Organization
from src.core.model_defs.value_streams import BusinessService, SlotInstance


def _asset(db: Session) -> Asset:
    asset = Asset(
        organization_id=1,
        type="Hosting",
        provider="cmdb",
        display_name="Verified web host",
        layer="Infrastructure",
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
        dependency_category="infrastructure",
    )
    db.add(asset)
    db.flush()
    return asset


def test_one_library_artefact_can_be_linked_to_multiple_business_services():
    engine = create_engine("sqlite:///:memory:")
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(bind=engine)
    db = Session(bind=engine)
    try:
        db.add(Organization(id=1, name="Org One", slug="org-one"))
        service_ids = [str(uuid4()), str(uuid4())]
        db.add_all([BusinessService(id=service_id, organization_id=1, name=f"Service {index}") for index, service_id in enumerate(service_ids)])
        asset = _asset(db)
        db.add_all([
            ServiceArtefactDependencyLink(
                id=str(uuid4()),
                organization_id=1,
                service_id=service_id,
                asset_id=asset.id,
                dependency_category="infrastructure",
            )
            for service_id in service_ids
        ])
        db.commit()

        links = db.query(ServiceArtefactDependencyLink).filter_by(asset_id=asset.id).all()
        assert {link.service_id for link in links} == set(service_ids)
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


def test_existing_slot_mapping_is_returned_during_the_library_transition():
    engine = create_engine("sqlite:///:memory:")
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(bind=engine)
    db = Session(bind=engine)
    try:
        service_id = str(uuid4())
        db.add(Organization(id=1, name="Org One", slug="org-one"))
        db.add(BusinessService(id=service_id, organization_id=1, name="Service One"))
        asset = _asset(db)
        db.add(
            SlotInstance(
                id=str(uuid4()),
                organization_id=1,
                service_id=service_id,
                slot_id="hosting",
                group_key="hosting",
                status="mapped",
                mapping_status="confirmed",
                asset_id=f"asset-{asset.id}",
                asset_label=asset.display_name,
                dependency_category="infrastructure",
            )
        )
        db.commit()

        links = list_service_artefacts(
            service_id,
            TenantContext(
                user_id=1,
                organization_id=1,
                email="owner@example.com",
                roles=["org_admin"],
                permissions=[],
            ),
            db,
        )

        assert [(link.asset_id, link.dependency_category, link.origin) for link in links] == [
            (asset.id, "infrastructure", "legacy_slot")
        ]
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
