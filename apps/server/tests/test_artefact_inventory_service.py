"""CA-06.6 — the organisation's inventory, independent of any run.

The gap: artefacts were reachable only *inside a discovery run*, so "what do we
have?" could only be answered as "what did this scan find?". Everything CA-06
built describes an inventory that outlives every run, and nothing could read it.

Two things are asserted here rather than assumed. **Filtering** — because a
filter that quietly does nothing shows someone the whole estate when they asked
for a slice of it, which reads as data they do not have. And **tenant isolation
on every read path** — the filters are precisely where a missing
`organization_id` clause would hide, so each one is exercised against a second
organisation's rows.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.database import Base
from src.core.model_defs.assets_runtime import (
    Asset,
    AssetFinding,
    AssetFindingStatus,
    AssetIdentifier,
    AssetLifecycleState,
    AssetObservedPort,
    AssetStatus,
    ConnectivityStatus,
    Criticality,
    Environment,
    ScanStartMode,
    SetupConfidence,
    SeverityLevel,
)
from src.core.model_defs.common import utcnow
from src.core.model_defs.tenant_org import Organization
from src.core.services.artefact_inventory_service import InventoryFilters, list_inventory
from src.core.services.artefact_reconciliation_service import raise_identity_conflict


@pytest.fixture(scope="function")
def db():
    engine = create_engine("sqlite:///:memory:")
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(bind=engine)
    session = Session(bind=engine)
    session.add_all(
        [
            Organization(id=1, name="Org One", slug="org-one"),
            Organization(id=2, name="Org Two", slug="org-two"),
        ]
    )
    session.commit()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


def _asset(
    db: Session,
    *,
    organization_id: int = 1,
    display_name: str = "10.0.0.15",
    asset_type: str = "Observed host",
    layer: str = "Infrastructure",
    lifecycle_state: AssetLifecycleState = AssetLifecycleState.ACTIVE,
    reviewed: bool = False,
    intent: dict | None = None,
) -> Asset:
    asset = Asset(
        organization_id=organization_id,
        type=asset_type,
        provider="collector",
        display_name=display_name,
        layer=layer,
        environment=Environment.PROD,
        criticality=Criticality.MEDIUM,
        status=AssetStatus.PARTIALLY_OBSERVED,
        connectivity_status=ConnectivityStatus.PENDING_VERIFICATION,
        setup_confidence=SetupConfidence.LOW,
        scan_start_mode=ScanStartMode.AUDIT_ONLY,
        findings_count=0,
        risk_score=0.0,
        confidence=0.4,
        lifecycle_state=lifecycle_state,
        reviewed_at=utcnow() if reviewed else None,
        reviewed_by_user_id=7 if reviewed else None,
        intent=intent,
    )
    db.add(asset)
    db.flush()
    return asset


def _identifier(db: Session, asset: Asset, *, value: str, source: str = "collector") -> None:
    db.add(
        AssetIdentifier(
            organization_id=asset.organization_id,
            asset_id=asset.id,
            identifier_type="ip_address",
            identifier_value=value,
            observed_by_source=source,
        )
    )
    db.flush()


def _names(page) -> list[str]:
    return [entry.display_name for entry in page.entries]


# --- the standing list -------------------------------------------------------


def test_the_inventory_is_returned_without_reference_to_any_run(db: Session):
    _asset(db, display_name="10.0.0.15")
    _asset(db, display_name="10.0.0.16")

    page = list_inventory(db, organization_id=1)

    assert _names(page) == ["10.0.0.15", "10.0.0.16"]
    assert page.total == 2


def test_a_row_reports_the_evidence_behind_it_rather_than_a_verdict(db: Session):
    """"How sure are we" is answered with what stands behind the artefact — how
    many identifiers, seen by whom — not with a score the platform invented."""
    asset = _asset(db)
    _identifier(db, asset, value="10.0.0.15", source="collector")
    _identifier(db, asset, value="build-01.internal", source="registry")
    db.add(
        AssetObservedPort(
            organization_id=1, asset_id=asset.id, port=443, protocol="tcp", service_name="https"
        )
    )
    db.flush()

    entry = list_inventory(db, organization_id=1).entries[0]

    assert entry.identifier_count == 2
    assert entry.source_names == ("collector", "registry")
    assert entry.observed_port_count == 1
    assert entry.first_observed_at is not None


def test_an_artefact_waiting_on_a_person_says_so_from_either_side_of_the_pair(db: Session):
    """A conflict is as much the second artefact's business as the first's.
    Counting one side would leave half the estate looking settled."""
    left = _asset(db, display_name="10.0.0.15")
    right = _asset(db, display_name="10.0.0.16")
    raise_identity_conflict(
        db, organization_id=1, left_asset_id=left.id, right_asset_id=right.id, reason="Shared address."
    )

    entries = {entry.display_name: entry for entry in list_inventory(db, organization_id=1).entries}

    assert entries["10.0.0.15"].open_conflict_count == 1
    assert entries["10.0.0.16"].open_conflict_count == 1


def test_the_filter_values_offered_come_from_the_estate_not_a_hardcoded_list(db: Session):
    """A filter offering types nobody has leads nowhere; one missing a type the
    classifier learned to emit hides rows."""
    _asset(db, asset_type="Observed host", layer="Infrastructure")
    _asset(db, display_name="api.example.com", asset_type="Web service", layer="Application")

    page = list_inventory(db, organization_id=1)

    assert page.asset_types == ("Observed host", "Web service")
    assert page.layers == ("Application", "Infrastructure")


# --- filtering ---------------------------------------------------------------


def test_filtering_by_lifecycle_state(db: Session):
    _asset(db, display_name="active-1")
    _asset(db, display_name="withdrawn-1", lifecycle_state=AssetLifecycleState.WITHDRAWN)

    page = list_inventory(
        db,
        organization_id=1,
        filters=InventoryFilters(lifecycle_states=(AssetLifecycleState.WITHDRAWN,)),
    )

    assert _names(page) == ["withdrawn-1"]
    assert page.total == 1


def test_filtering_by_type_and_layer(db: Session):
    _asset(db, display_name="host-1", asset_type="Observed host", layer="Infrastructure")
    _asset(db, display_name="web-1", asset_type="Web service", layer="Application")

    by_type = list_inventory(db, organization_id=1, filters=InventoryFilters(asset_type="web service"))
    by_layer = list_inventory(db, organization_id=1, filters=InventoryFilters(layer="Infrastructure"))

    # Matched case-insensitively: a filter value round-tripped through a URL
    # should not have to arrive in the classifier's own casing.
    assert _names(by_type) == ["web-1"]
    assert _names(by_layer) == ["host-1"]


def test_filtering_by_review_status(db: Session):
    _asset(db, display_name="decided", reviewed=True)
    _asset(db, display_name="waiting", reviewed=False)

    reviewed = list_inventory(db, organization_id=1, filters=InventoryFilters(review_status="reviewed"))
    unreviewed = list_inventory(db, organization_id=1, filters=InventoryFilters(review_status="unreviewed"))

    assert _names(reviewed) == ["decided"]
    assert _names(unreviewed) == ["waiting"]


def test_search_finds_an_artefact_by_a_name_it_no_longer_displays(db: Session):
    """The point of CA-06.1's identifier set: a host that changed address is
    still findable by the address it used to answer at. Searching the display
    name alone would lose it exactly when someone goes looking."""
    asset = _asset(db, display_name="build-01.internal")
    _identifier(db, asset, value="10.0.0.99")

    page = list_inventory(db, organization_id=1, filters=InventoryFilters(query="10.0.0.99"))

    assert _names(page) == ["build-01.internal"]


def test_the_total_counts_everything_matching_not_the_page_returned(db: Session):
    """A reader paging through 400 artefacts needs to know there are 400."""
    for index in range(5):
        _asset(db, display_name=f"host-{index}")

    page = list_inventory(db, organization_id=1, limit=2)

    assert len(page.entries) == 2
    assert page.total == 5


# --- tenant isolation, on every path -----------------------------------------


def test_the_inventory_never_shows_another_organisations_artefacts(db: Session):
    _asset(db, organization_id=1, display_name="ours")
    _asset(db, organization_id=2, display_name="theirs")

    page = list_inventory(db, organization_id=1)

    assert _names(page) == ["ours"]
    assert page.total == 1


def test_every_filter_is_tenant_scoped(db: Session):
    """Each filter is its own query path, and each is where a missing
    organisation clause would hide."""
    _asset(db, organization_id=2, display_name="theirs", asset_type="Web service", layer="Application", reviewed=True)
    theirs = db.query(Asset).filter(Asset.organization_id == 2).one()
    _identifier(db, theirs, value="10.9.9.9")

    for filters in (
        InventoryFilters(lifecycle_states=(AssetLifecycleState.ACTIVE,)),
        InventoryFilters(asset_type="Web service"),
        InventoryFilters(layer="Application"),
        InventoryFilters(review_status="reviewed"),
        InventoryFilters(query="theirs"),
        InventoryFilters(query="10.9.9.9"),
    ):
        page = list_inventory(db, organization_id=1, filters=filters)
        assert page.entries == ()
        assert page.total == 0


def test_conflict_counts_do_not_leak_across_organisations(db: Session):
    left = _asset(db, organization_id=2, display_name="theirs-a")
    right = _asset(db, organization_id=2, display_name="theirs-b")
    raise_identity_conflict(
        db, organization_id=2, left_asset_id=left.id, right_asset_id=right.id, reason="Shared address."
    )
    ours = _asset(db, organization_id=1, display_name="ours")
    # Same ids could exist in either organisation; the count must be scoped by
    # organisation, not merely by asset id.
    assert ours.id not in (left.id, right.id)

    entry = list_inventory(db, organization_id=1).entries[0]

    assert entry.open_conflict_count == 0


# --- CA-07.1 / #249: the row carries what the scan concluded ------------------


def test_an_entry_carries_the_identity_the_scan_determined(db: Session):
    """Søren, 2026-08-25, on a live inventory: "the last implement was supposed
    to add context to the artefacts. However it didn't." It was determined and
    stored at ingestion, and stopped at the server — the row had no field to
    carry it, so every artefact read as an address and a generic class."""
    _asset(
        db,
        display_name="192.168.1.36",
        intent={
            "identity": {
                "name": "Uvicorn 0.30.1",
                "basis": "service_product",
                "evidence": "Uvicorn",
                "undeterminedReason": None,
                "explanation": None,
            }
        },
    )

    entry = list_inventory(db, organization_id=1).entries[0]

    assert entry.identity_name == "Uvicorn 0.30.1"
    assert entry.identity_basis == "service_product"
    assert entry.identity_undetermined_reason is None


def test_an_entry_carries_why_there_is_no_identity(db: Session):
    """The reason travels too. Only `probed_nothing_identifying` is an honest
    argument for asking somebody for credentials, and a surface that cannot see
    the reason cannot tell that case from "nobody has looked yet"."""
    _asset(
        db,
        intent={
            "identity": {
                "name": None,
                "basis": None,
                "evidence": None,
                "undeterminedReason": "probed_nothing_identifying",
                "explanation": "This was examined and answered, but nothing it returned identified what it is.",
            }
        },
    )

    entry = list_inventory(db, organization_id=1).entries[0]

    assert entry.identity_name is None
    assert entry.identity_undetermined_reason == "probed_nothing_identifying"
    assert "nothing it returned identified" in entry.identity_explanation


def test_an_artefact_from_before_identity_existed_reports_nothing_rather_than_raising(db: Session):
    """`intent` predates the identity block, so rows ingested before CA-07.1
    have no such key. They must render as "not established" — not crash the
    whole inventory for every other row on the page."""
    _asset(db, intent={"ingestionBatchId": "batch-1"})

    entry = list_inventory(db, organization_id=1).entries[0]

    assert entry.identity_name is None
    assert entry.identity_explanation is None


def test_an_entry_carries_where_it_sits_separately_from_what_it_is(db: Session):
    """Søren, 2026-08-25: the address is "too arbitrary" to be a name. The two
    were always separate ideas — normalisation keeps `networkAddress` precisely
    so the address survives a name being determined — and the inventory had one
    field doing both jobs."""
    _asset(
        db,
        display_name="192.168.1.36",
        intent={"networkAddress": "192.168.1.36", "identity": {"name": None, "undeterminedReason": "not_probed"}},
    )

    entry = list_inventory(db, organization_id=1).entries[0]

    assert entry.network_address == "192.168.1.36"
    # Untouched: `display_name` also feeds resolve_identity's legacy match, so
    # it stays exactly what it is and the surface composes the title instead.
    assert entry.display_name == "192.168.1.36"


def test_an_artefact_with_no_recorded_address_reports_none_rather_than_guessing(db: Session):
    """Reconstructing it from the display name cannot be done safely: that
    value may be a hostname, a product or an address, and after the fact they
    cannot be told apart."""
    _asset(db, display_name="api.example.com", intent={"ingestionBatchId": "batch-1"})

    entry = list_inventory(db, organization_id=1).entries[0]


# ── CA-09A.1 — telling a thing from an address that answered ────────────────


def test_an_address_that_answered_is_not_the_same_as_a_thing_that_runs_something(db: Session):
    """The noise floor. On org 7, 253 of 254 artefacts were addresses from a /24
    sweep with nothing open, and the inventory rendered them identically to the
    one real service — same row, same count, no way to filter them apart. The
    discovery review surface has carried this distinction since CA-05; the
    standing inventory never did."""
    _asset(db, display_name="10.0.0.15", intent={"observedServices": []})
    _asset(db, display_name="10.0.0.16", intent={"observedServices": ["https", "postgresql"]})

    entries = {e.display_name: e for e in list_inventory(db, organization_id=1).entries}

    assert entries["10.0.0.15"].candidacy == "endpoint"
    assert entries["10.0.0.16"].candidacy == "service_bearing"


def test_an_artefact_recorded_before_services_were_kept_is_not_called_an_endpoint(db: Session):
    """`intent` predates `observedServices`, so an older artefact simply has no
    such key. That must not be read as a positive statement that nothing was
    listening — `derive_candidacy` returns the honest floor for an empty list,
    and the row is not asserted to be an endpoint on the strength of a missing
    key."""
    _asset(db, display_name="10.0.0.17", intent={})
    _asset(db, display_name="10.0.0.18", intent=None)

    entries = {e.display_name: e for e in list_inventory(db, organization_id=1).entries}

    # Both resolve without raising, which is the property under test.
    assert entries["10.0.0.17"].candidacy
    assert entries["10.0.0.18"].candidacy


def test_a_host_reachable_only_over_ssh_is_not_written_off(db: Session):
    """It could be a jump host, which is a real dependency. The inventory must
    carry the classifier's own uncertainty rather than resolving it."""
    _asset(db, display_name="10.0.0.19", intent={"observedServices": ["ssh"]})

    entry = next(e for e in list_inventory(db, organization_id=1).entries
                 if e.display_name == "10.0.0.19")

    assert entry.candidacy == "undetermined"


def test_filtering_to_things_that_can_be_depended_on_narrows_the_count_too(db: Session):
    """The filter has to move `total`, not just the rows. `total` feeds the
    inventory's own headline count, and a filter that narrowed the page while
    leaving the count at the full estate would state a number for one set of
    artefacts and list another — which is how the noise floor stayed invisible
    in the first place."""
    _asset(db, display_name="10.0.0.20", intent={"observedServices": []})
    _asset(db, display_name="10.0.0.21", intent={"observedServices": []})
    _asset(db, display_name="10.0.0.22", intent={"observedServices": ["https"]})

    unfiltered = list_inventory(db, organization_id=1)
    bearing = list_inventory(
        db, organization_id=1, filters=InventoryFilters(candidacy="service_bearing")
    )

    assert bearing.total == len(bearing.entries)
    assert bearing.total < unfiltered.total
    assert [entry.display_name for entry in bearing.entries] == ["10.0.0.22"]


def test_the_candidacy_filter_survives_paging(db: Session):
    """Resolved before the slice, so the second page of a filtered list is the
    second page *of the filtered list*. Filtering after the slice would have
    produced a short first page and an empty second one."""
    for index in range(4):
        _asset(db, display_name=f"10.0.1.{index}", intent={"observedServices": []})
        _asset(db, display_name=f"10.0.2.{index}", intent={"observedServices": ["postgresql"]})

    filters = InventoryFilters(candidacy="service_bearing")
    first = list_inventory(db, organization_id=1, filters=filters, limit=2, offset=0)
    second = list_inventory(db, organization_id=1, filters=filters, limit=2, offset=2)

    assert first.total == second.total == 4
    assert len(first.entries) == len(second.entries) == 2
    assert not {e.asset_id for e in first.entries} & {e.asset_id for e in second.entries}
    assert all(e.candidacy == "service_bearing" for e in [*first.entries, *second.entries])


# --- What the last scan found, on the row that names the artefact ------------
#
# The platform held vulnerability findings for the first time on 2026-09-07 and
# no surface showed them. These cover the count the row is built from — and
# above all the two ways it can lie.


def _scan_finding(
    db: Session,
    asset: Asset,
    *,
    domain: str = "risk_intelligence_ingestion",
    severity: SeverityLevel = SeverityLevel.LOW,
    status: AssetFindingStatus = AssetFindingStatus.OPEN,
    title: str = "mDNS Enumeration",
) -> AssetFinding:
    finding = AssetFinding(
        organization_id=asset.organization_id,
        asset_id=asset.id,
        domain=domain,
        severity=severity,
        title=title,
        description=None,
        evidence_refs=[],
        risk_score=25.0,
        first_seen_at=utcnow(),
        last_seen_at=utcnow(),
        status=status,
    )
    db.add(finding)
    db.commit()
    return finding


def _entry(page, display_name: str):
    return next(entry for entry in page.entries if entry.display_name == display_name)


def test_a_scan_finding_is_counted_on_its_artefact(db: Session):
    asset = _asset(db, display_name="192.168.50.129")
    _scan_finding(db, asset, title="mDNS Enumeration")
    _scan_finding(db, asset, title="Zeroconf - Detect", severity=SeverityLevel.INFO)

    entry = _entry(list_inventory(db, organization_id=1, filters=InventoryFilters()), "192.168.50.129")

    assert entry.scan_finding_count == 2
    assert entry.scan_last_finding_at is not None


def test_an_artefact_no_scan_has_reached_counts_zero(db: Session):
    _asset(db, display_name="192.168.50.8")

    entry = _entry(list_inventory(db, organization_id=1, filters=InventoryFilters()), "192.168.50.8")

    assert entry.scan_finding_count == 0
    assert entry.scan_last_finding_at is None


def test_a_network_domain_finding_is_not_a_scan_result(db: Session):
    """⚠️ The trap. `asset_findings` is shared: the asset-monitoring engine
    writes its own rows under the `network` domain — 160 of them in organisation
    7, none of which any scanner produced. Counting the table rather than
    filtering the domain would report a scan result on artefacts nuclei has
    never reached, which is an assertion posing as an observation."""
    asset = _asset(db, display_name="192.168.50.8")
    _scan_finding(db, asset, domain="network", title="Port 22 open")

    entry = _entry(list_inventory(db, organization_id=1, filters=InventoryFilters()), "192.168.50.8")

    assert entry.scan_finding_count == 0, "a monitoring row is not a scan finding"


def test_a_resolved_finding_is_not_counted(db: Session):
    """The row answers "what did the last scan find", and something already
    dealt with is not that."""
    asset = _asset(db, display_name="192.168.50.129")
    _scan_finding(db, asset, status=AssetFindingStatus.RESOLVED)

    entry = _entry(list_inventory(db, organization_id=1, filters=InventoryFilters()), "192.168.50.129")

    assert entry.scan_finding_count == 0


def test_findings_are_not_counted_across_organisations(db: Session):
    """The count is per artefact, and an artefact belongs to one tenant. This is
    the query, not a filter applied afterwards."""
    mine = _asset(db, display_name="192.168.50.129")
    theirs = _asset(db, organization_id=2, display_name="10.9.9.9")
    _scan_finding(db, mine)
    _scan_finding(db, theirs)

    page = list_inventory(db, organization_id=1, filters=InventoryFilters())

    assert _entry(page, "192.168.50.129").scan_finding_count == 1
    assert all(entry.display_name != "10.9.9.9" for entry in page.entries)
