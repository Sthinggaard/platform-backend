"""CA-05.C — discovery results summary: run lineage via audit provenance,
new-vs-matched counting, exclusion surfacing, and tenant isolation (an asset id
read out of audit metadata must never surface another tenant's asset)."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.discovery_execution_enums import EVIDENCE_PACKAGE_AUDIT_NORMALIZED
from src.core.constants.evidence_scanner_enums import ScannerTargetStatus
from src.core.database import Base
from src.core.model_defs.common import utcnow
from src.core.model_defs.assets_runtime import (
    Asset,
    AssetFinding,
    AssetFindingStatus,
    SeverityLevel,
)
from src.core.model_defs.discovery_execution import EvidencePackage
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.model_defs.evidence_scanner import ScannerDomainTarget, ScannerNetworkTarget
from src.core.model_defs.organization_identity import OrganizationScope
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.model_defs.tenant_org import Organization
from src.core.services.artefact_classification_service import ObservedService
from src.core.services.discovery_results_service import get_discovery_results

RUN_ID = "run-1"
SOURCE_ID = "src-1"
PACKAGE_ID = "pkg-1"

_TABLES = (
    Organization.__table__,
    Asset.__table__,
    # The results page now reports what a scan found on each artefact, so the
    # table that holds those findings has to exist for the page to build.
    AssetFinding.__table__,
    AuditEvent.__table__,
    DiscoveryRun.__table__,
    EvidencePackage.__table__,
    ScannerDomainTarget.__table__,
    ScannerNetworkTarget.__table__,
    OrganizationScope.__table__,
)


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in _TABLES:
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine, tables=list(_TABLES))
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org", country="DK"),
            Organization(id=2, name="Other", slug="other", country="DK"),
        ]
    )
    session.add(
        DiscoveryRun(
            id=RUN_ID,
            organization_id=1,
            evidence_source_id=SOURCE_ID,
            scanner_instance_id="inst",
            requested_by_user_id=1,
            request_source="tenant",
            discovery_purpose="first_organisation_discovery",
            profile_snapshot={},
            target_ids=[],
            target_snapshot=[],
            status="completed",
            current_stage="completed",
            approval_status="approved",
        )
    )
    session.commit()
    yield session
    session.close()


def _package(db: Session, package_id: str = PACKAGE_ID, *, org: int = 1, run: str = RUN_ID) -> None:
    db.add(
        EvidencePackage(
            id=package_id,
            discovery_run_id=run,
            execution_plan_id="plan",
            execution_stage_id="stage",
            provider_execution_id=f"exec-{package_id}",
            organization_id=org,
            provider_id="nmap",
            schema_version="1",
            raw_evidence_reference="ref",
            evidence_format="xml",
            execution_metadata={},
            provenance_metadata={},
            processing_status="processed",
            normalization_status="normalized",
        )
    )
    db.commit()


def _asset(db: Session, asset_id: int, name: str, *, org: int = 1) -> None:
    db.add(
        Asset(
            id=asset_id,
            organization_id=org,
            type="server",
            display_name=name,
            layer="infrastructure",
        )
    )
    db.commit()


def _normalized_event(
    db: Session,
    *,
    org: int = 1,
    package_id: str = PACKAGE_ID,
    matched: list | None = None,
    created: list | None = None,
) -> None:
    db.add(
        AuditEvent(
            organization_id=org,
            event_type=EVIDENCE_PACKAGE_AUDIT_NORMALIZED,
            metadata_json={
                "evidencePackageId": package_id,
                "matchedAssetIds": matched or [],
                "createdAssetIds": created or [],
            },
        )
    )
    db.commit()


def _results(db: Session, *, org: int = 1, run: str = RUN_ID):
    return get_discovery_results(db, organization_id=org, discovery_run_id=run)


def test_unknown_run_raises(db: Session) -> None:
    with pytest.raises(ValueError):
        _results(db, run="missing")


def test_run_from_another_tenant_is_not_readable(db: Session) -> None:
    with pytest.raises(ValueError):
        _results(db, org=2)


def test_run_with_no_evidence_is_empty_not_an_error(db: Session) -> None:
    summary = _results(db)

    assert summary.evidence_package_count == 0
    assert summary.discovered == ()
    assert summary.new_count == 0


def test_created_and_matched_assets_are_reported_and_counted(db: Session) -> None:
    _package(db)
    _asset(db, 10, "new-host")
    _asset(db, 11, "known-host")
    _normalized_event(db, created=[10], matched=[11])

    summary = _results(db)

    assert summary.evidence_package_count == 1
    assert {a.asset_id for a in summary.discovered} == {10, 11}
    assert summary.new_count == 1
    assert summary.matched_count == 1
    assert next(a for a in summary.discovered if a.asset_id == 10).is_new is True


def test_asset_both_created_and_matched_counts_as_new_once(db: Session) -> None:
    _package(db)
    _asset(db, 10, "host")
    _normalized_event(db, created=[10], matched=[10])

    summary = _results(db)

    assert len(summary.discovered) == 1
    assert summary.new_count == 1
    assert summary.matched_count == 0


def test_audit_from_another_run_is_ignored(db: Session) -> None:
    _package(db)
    _asset(db, 10, "ours")
    _asset(db, 99, "other-run")
    _normalized_event(db, created=[10])
    _normalized_event(db, package_id="pkg-other", created=[99])

    assert {a.asset_id for a in _results(db).discovered} == {10}


def test_asset_id_from_audit_never_crosses_tenant(db: Session) -> None:
    """Audit metadata is free-form JSON; a stale or tampered id must not be
    trusted to fetch another organisation's asset."""
    _package(db)
    _asset(db, 50, "tenant2-host", org=2)
    _normalized_event(db, created=[50])

    assert _results(db).discovered == ()


def test_malformed_audit_ids_are_skipped(db: Session) -> None:
    _package(db)
    _asset(db, 10, "host")
    _normalized_event(db, created=[10, "not-an-id", None])

    assert {a.asset_id for a in _results(db).discovered} == {10}


def test_exclusions_are_surfaced_alongside_results(db: Session) -> None:
    _package(db)
    db.add(
        ScannerDomainTarget(
            organization_id=1,
            evidence_source_id=SOURCE_ID,
            domain="secret.example.com",
            source="manual",
            ownership_status="owned",
            status=ScannerTargetStatus.EXCLUDED.value,
        )
    )
    db.commit()

    assert "secret.example.com" in _results(db).excluded_values


def test_new_assets_sort_before_matched(db: Session) -> None:
    _package(db)
    _asset(db, 10, "zzz-new")
    _asset(db, 11, "aaa-matched")
    _normalized_event(db, created=[10], matched=[11])

    assert [a.asset_id for a in _results(db).discovered] == [10, 11]


# --- #249: the review list answers the same questions the inventory does --------------


def _intent(db: Session, asset_id: int, intent: dict) -> None:
    asset = db.query(Asset).filter(Asset.id == asset_id).one()
    asset.intent = intent
    db.add(asset)
    db.commit()


def test_the_review_list_says_what_the_scan_concluded_the_artefact_is(db: Session) -> None:
    """The defect (Søren, 2026-08-25): a reviewer deciding "is this ours?" was
    handed `192.168.1.20` and a row of chips, while the standing inventory held
    a determined identity for the same record. One record, two answers."""
    _package(db)
    _asset(db, 10, "192.168.1.20")
    _intent(
        db,
        10,
        {
            "networkAddress": "192.168.1.20",
            "identity": {
                "name": "Uvicorn",
                "basis": "service_product",
                "undeterminedReason": None,
                "explanation": None,
            },
        },
    )
    _normalized_event(db, created=[10])

    found = _results(db).discovered[0]
    assert found.identity_name == "Uvicorn"
    assert found.identity_basis == "service_product"
    assert found.network_address == "192.168.1.20"


def test_an_artefact_ingested_before_identity_was_recorded_says_so(db: Session) -> None:
    """`intent` predates the identity block, so a row from that era must render
    as "we have not established this" rather than raise."""
    _package(db)
    _asset(db, 10, "192.168.1.20")
    _normalized_event(db, created=[10])

    found = _results(db).discovered[0]
    assert found.identity_name is None
    assert found.network_address is None


def test_a_looked_up_port_reaches_the_reviewer_marked_as_a_lookup(db: Session) -> None:
    _package(db)
    _asset(db, 10, "192.168.1.20")
    _intent(
        db,
        10,
        {
            "observedServices": ["http-proxy", "https"],
            "observedServiceEvidence": [
                {"name": "http-proxy", "port": 8080, "probed": False},
                {"name": "https", "port": 443, "probed": True},
            ],
        },
    )
    _normalized_event(db, created=[10])

    found = _results(db).discovered[0]
    assert found.observed_service_evidence == (
        ObservedService(name="http-proxy", port=8080, probed=False),
        ObservedService(name="https", port=443, probed=True),
    )
    # The de-duplicated names are untouched — older rows have only those, and
    # the reading side falls back to them.
    assert found.observed_services == ("http-proxy", "https")


def test_evidence_is_never_invented_for_an_artefact_that_predates_it(db: Session) -> None:
    """Reconstructing `probed: False` entries from the bare names would look
    like a positive statement that nothing was probed. Having none says the
    honest thing: nobody recorded it."""
    _package(db)
    _asset(db, 10, "192.168.1.20")
    _intent(db, 10, {"observedServices": ["http-proxy", "https"]})
    _normalized_event(db, created=[10])

    found = _results(db).discovered[0]
    assert found.observed_service_evidence == ()
    assert found.observed_services == ("http-proxy", "https")


def test_malformed_evidence_cannot_break_a_results_page(db: Session) -> None:
    _package(db)
    _asset(db, 10, "192.168.1.20")
    _intent(
        db,
        10,
        {
            "observedServiceEvidence": [
                "not-a-dict",
                {"port": 80},
                {"name": "  ", "port": 81},
                {"name": "https", "port": "443", "probed": "yes"},
            ]
        },
    )
    _normalized_event(db, created=[10])

    # A non-integer port is dropped rather than coerced, and only the literal
    # `True` counts as probed — a truthy string is not a recorded probe.
    assert _results(db).discovered[0].observed_service_evidence == (
        ObservedService(name="https", port=None, probed=False),
    )


# --- What a scan found, on the results page the reviewer is already reading ---


def _scan_finding(
    db: Session,
    asset_id: int,
    *,
    org: int = 1,
    domain: str = "risk_intelligence_ingestion",
    status: AssetFindingStatus = AssetFindingStatus.OPEN,
    title: str = "mDNS Enumeration",
) -> None:
    db.add(
        AssetFinding(
            organization_id=org,
            asset_id=asset_id,
            domain=domain,
            severity=SeverityLevel.LOW,
            title=title,
            description=None,
            evidence_refs=[],
            risk_score=25.0,
            first_seen_at=utcnow(),
            last_seen_at=utcnow(),
            status=status,
        )
    )
    db.commit()


def test_the_results_page_reports_what_the_scan_found(db: Session) -> None:
    """The reviewer is deciding whether to keep this artefact, and what a scan
    already found on it bears on that."""
    _package(db)
    _asset(db, 10, "192.168.50.152")
    _normalized_event(db, created=[10], matched=[])
    _scan_finding(db, 10, title="mDNS Enumeration")
    _scan_finding(db, 10, title="Zeroconf - Detect")

    asset = next(a for a in _results(db).discovered if a.asset_id == 10)

    assert asset.scan_finding_count == 2


def test_an_artefact_no_scan_has_reached_reports_zero(db: Session) -> None:
    _package(db)
    _asset(db, 10, "192.168.50.8")
    _normalized_event(db, created=[10], matched=[])

    asset = next(a for a in _results(db).discovered if a.asset_id == 10)

    assert asset.scan_finding_count == 0


def test_a_monitoring_row_is_not_a_scan_result_here_either(db: Session) -> None:
    """The same trap as on the inventory: `asset_findings` is shared, and the
    asset-monitoring engine writes into it under the `network` domain."""
    _package(db)
    _asset(db, 10, "192.168.50.8")
    _normalized_event(db, created=[10], matched=[])
    _scan_finding(db, 10, domain="network", title="Port 22 open")

    asset = next(a for a in _results(db).discovered if a.asset_id == 10)

    assert asset.scan_finding_count == 0


def test_the_two_pages_cannot_report_different_numbers(db: Session) -> None:
    """The reason the query lives in `asset_scan_findings_service` rather than
    being written once per surface: one artefact reporting three findings on the
    results page and two on the inventory would make both untrustworthy, and
    nothing would say which was right."""
    from src.core.services.asset_scan_findings_service import scan_findings_by_asset

    _package(db)
    _asset(db, 10, "192.168.50.152")
    _normalized_event(db, created=[10], matched=[])
    _scan_finding(db, 10, title="one")
    _scan_finding(db, 10, title="two")
    _scan_finding(db, 10, domain="network", title="not a scan result")
    _scan_finding(db, 10, status=AssetFindingStatus.RESOLVED, title="already dealt with")

    page = next(a for a in _results(db).discovered if a.asset_id == 10)
    shared = scan_findings_by_asset(db, organization_id=1, asset_ids=[10])

    assert page.scan_finding_count == shared[10][0] == 2
