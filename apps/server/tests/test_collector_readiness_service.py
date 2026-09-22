"""CA-02.3 — readiness comes from the Collector, never from a user.

The rules worth pinning here are the ones that decide what counts as *verified*:
absence of evidence must not read as health, a stored answer nobody can attribute
must not read as a measurement, and "has this been checked?" must not quietly
become "is this reachable right now?".
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.evidence_scanner_enums import (
    CollectorCapability,
    CollectorComponentStatus,
    CollectorReadinessStatus,
    ScannerInstanceStatus,
    ScannerToolName,
    ScannerToolStatus,
)
from src.core.database import Base
from src.core.model_defs.common import utcnow
from src.core.model_defs.evidence_scanner import CollectorReadinessReport, ScannerInstance
from src.core.model_defs.tenant_org import Organization
from src.core.services.collector_readiness_service import (
    READINESS_SCHEMA_VERSION,
    collector_can_see_hardware_addresses,
    component_is_ready,
    readiness_from_tool_statuses,
    record_readiness_report,
    resolve_collector_readiness,
)

ALL_READY = {tool.value: ScannerToolStatus.AVAILABLE.value for tool in ScannerToolName}


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            ScannerInstance.__table__,
            CollectorReadinessReport.__table__,
        ],
    )
    session = Session(bind=engine)
    session.add(Organization(id=1, name="Org", slug="org"))
    session.commit()
    yield session
    session.close()


def _instance(db: Session, *, heartbeat_age_seconds: int | None = 10, status: str | None = None) -> ScannerInstance:
    instance = ScannerInstance(
        id="inst-1",
        organization_id=1,
        evidence_source_id="src-1",
        name="Primary",
        installation_method="docker",
        activation_token_hash="x" * 64,
        status=status or ScannerInstanceStatus.ONLINE.value,
        last_heartbeat_at=(
            None if heartbeat_age_seconds is None else utcnow() - timedelta(seconds=heartbeat_age_seconds)
        ),
    )
    db.add(instance)
    db.flush()
    return instance


class TestAbsenceOfEvidence:
    def test_a_collector_that_has_never_reported_is_unknown_not_ready(self, db: Session):
        # Every instance predating readiness reporting lands here. Its stored
        # tool_status may have been typed by a person, so it cannot be read as a
        # measurement — and "we cannot tell" must never render as health.
        instance = _instance(db)

        readiness = resolve_collector_readiness(db, instance)

        assert readiness.status == CollectorReadinessStatus.UNKNOWN.value
        assert readiness.has_report is False
        assert "no_readiness_report" in readiness.failure_reason_codes

    def test_legacy_tool_status_alone_never_makes_a_component_ready(self, db: Session):
        # The whole point of the story: a value in the old column, with no
        # report behind it, buys nothing.
        instance = _instance(db)
        instance.tool_status = ALL_READY
        db.flush()

        readiness = resolve_collector_readiness(db, instance)

        assert component_is_ready(readiness, ScannerToolName.NMAP.value) is False


class TestReportedReadiness:
    def test_a_real_self_check_makes_its_components_ready(self, db: Session):
        instance = _instance(db)
        record_readiness_report(db, instance, report=readiness_from_tool_statuses(ALL_READY))

        readiness = resolve_collector_readiness(db, instance)

        assert component_is_ready(readiness, ScannerToolName.NMAP.value) is True
        assert readiness.has_report is True

    def test_a_failed_component_is_not_ready_and_does_not_block_the_others(self, db: Session):
        # Per-component on purpose: a missing subfinder blocks domain
        # enumeration and nothing else.
        partial = {**ALL_READY, ScannerToolName.SUBFINDER.value: ScannerToolStatus.NOT_AVAILABLE.value}
        instance = _instance(db)
        record_readiness_report(db, instance, report=readiness_from_tool_statuses(partial))

        readiness = resolve_collector_readiness(db, instance)

        assert component_is_ready(readiness, ScannerToolName.SUBFINDER.value) is False
        assert component_is_ready(readiness, ScannerToolName.NMAP.value) is True
        assert readiness.status == CollectorReadinessStatus.DEGRADED.value

    def test_the_newest_report_wins(self, db: Session):
        instance = _instance(db)
        record_readiness_report(db, instance, report=readiness_from_tool_statuses(ALL_READY))
        broken = {tool.value: ScannerToolStatus.NOT_AVAILABLE.value for tool in ScannerToolName}
        record_readiness_report(db, instance, report=readiness_from_tool_statuses(broken))

        readiness = resolve_collector_readiness(db, instance)

        assert component_is_ready(readiness, ScannerToolName.NMAP.value) is False

    def test_reports_are_kept_as_history_not_overwritten(self, db: Session):
        # "When did this stop working, and what did it say at the time?" is
        # unanswerable if each report replaces the last.
        instance = _instance(db)
        record_readiness_report(db, instance, report=readiness_from_tool_statuses(ALL_READY))
        record_readiness_report(db, instance, report=readiness_from_tool_statuses(ALL_READY))

        assert db.query(CollectorReadinessReport).count() == 2

    def test_receipt_time_is_the_platforms_not_the_collectors(self, db: Session):
        # A Collector with a wrong clock must not be able to date its report
        # into the future and win "latest" permanently.
        instance = _instance(db)
        payload = readiness_from_tool_statuses(ALL_READY)
        payload["reportedAt"] = "2099-01-01T00:00:00"

        row = record_readiness_report(db, instance, report=payload)

        assert row.reported_at.year != 2099

    def test_every_report_carries_a_schema_version(self, db: Session):
        instance = _instance(db)

        row = record_readiness_report(db, instance, report=readiness_from_tool_statuses(ALL_READY))

        assert row.schema_version == READINESS_SCHEMA_VERSION


class TestUnclaimedFactsStayUnclaimed:
    def test_the_legacy_payload_does_not_invent_storage_or_connectivity_health(self):
        # It genuinely does not carry them. Assuming "fine" would be the same
        # failure this story exists to remove, one level down.
        report = readiness_from_tool_statuses(ALL_READY)

        assert report["evidenceStorageStatus"] == CollectorComponentStatus.UNKNOWN.value
        assert report["platformConnectivityStatus"] == CollectorComponentStatus.UNKNOWN.value

    def test_lost_platform_connectivity_blocks_regardless_of_local_tools(self, db: Session):
        instance = _instance(db)
        payload = readiness_from_tool_statuses(ALL_READY)
        payload["platformConnectivityStatus"] = CollectorComponentStatus.UNAVAILABLE.value

        record_readiness_report(db, instance, report=payload)

        assert resolve_collector_readiness(db, instance).status == (
            CollectorReadinessStatus.BLOCKED.value
        )


class TestLivenessIsADifferentQuestion:
    def test_a_collector_that_stopped_reporting_reads_as_offline(self, db: Session):
        # A month-old "everything works" describes a machine, not a capability
        # available now.
        instance = _instance(db, heartbeat_age_seconds=60 * 60)
        record_readiness_report(db, instance, report=readiness_from_tool_statuses(ALL_READY))

        readiness = resolve_collector_readiness(db, instance)

        assert readiness.status == CollectorReadinessStatus.OFFLINE.value
        assert "collector_not_reporting" in readiness.failure_reason_codes

    def test_going_offline_does_not_un_verify_a_component(self, db: Session):
        # Otherwise the setup gate flaps: complete the wizard, walk away for
        # twenty minutes, and it quietly un-completes itself. "Has this been
        # checked?" and "is it reachable now?" are different questions with
        # different remedies.
        instance = _instance(db, heartbeat_age_seconds=60 * 60)
        record_readiness_report(db, instance, report=readiness_from_tool_statuses(ALL_READY))

        readiness = resolve_collector_readiness(db, instance)

        assert component_is_ready(readiness, ScannerToolName.NMAP.value) is True

    def test_a_deliberately_paused_collector_is_not_reported_as_offline(self, db: Session):
        # Paused/revoked/retired are decisions a person made, not failures.
        instance = _instance(
            db, heartbeat_age_seconds=60 * 60, status=ScannerInstanceStatus.PAUSED.value
        )
        record_readiness_report(db, instance, report=readiness_from_tool_statuses(ALL_READY))

        readiness = resolve_collector_readiness(db, instance)

        assert readiness.status != CollectorReadinessStatus.OFFLINE.value


class TestTheScreenAndTheGateAgree:
    """Søren caught the screen saying "your Collector has checked its own
    components and reported them working" directly above a step the gate was
    blocking. The message read the legacy `tool_status` column while the gate
    read the readiness report — two sources, one question, which is the failure
    this whole story exists to remove, reintroduced by me one layer up."""

    def test_readiness_shown_to_the_user_comes_from_the_same_place_as_the_gate(self, db: Session):
        from src.core.model_defs.evidence_source import EvidenceSource
        from src.core.services.evidence_scanner_readiness_service import required_tools_available

        instance = _instance(db)
        # Exactly Søren's scanner: legacy answers stored, no report.
        instance.tool_status = ALL_READY
        instance.scan_profile = "safe_discovery"
        db.flush()

        readiness = resolve_collector_readiness(db, instance)

        # The gate refuses...
        assert required_tools_available(db, instance) is False
        # ...and what the user is shown must say the same thing, not the opposite.
        assert readiness.status == CollectorReadinessStatus.UNKNOWN.value
        assert readiness.components == ()


class TestOnlyWhatTheProfileNeeds:
    """Søren, on `standard_discovery` with no template pack: the block is
    correct, but a Collector missing the vulnerability pack is not a problem at
    all on a profile that does no vulnerability checks. The view explains a
    block from the same set the gate decided on, so it cannot report a fault
    that is not one."""

    def test_a_profile_without_vulnerability_checks_does_not_require_the_pack(self, db: Session):
        from src.core.services.evidence_scanner_readiness_service import required_tools_for

        instance = _instance(db)
        instance.scan_profile = "safe_discovery"
        db.flush()

        required = required_tools_for(instance)

        assert ScannerToolName.NUCLEI_TEMPLATES.value not in required
        assert ScannerToolName.NMAP.value in required

    def test_a_profile_with_vulnerability_checks_does_require_it(self, db: Session):
        from src.core.services.evidence_scanner_readiness_service import required_tools_for

        instance = _instance(db)
        instance.scan_profile = "standard_discovery"
        db.flush()

        assert ScannerToolName.NUCLEI_TEMPLATES.value in required_tools_for(instance)

    def test_a_missing_pack_blocks_the_profile_that_needs_it_and_not_the_one_that_does_not(
        self, db: Session
    ):
        from src.core.services.evidence_scanner_readiness_service import required_tools_available

        instance = _instance(db)
        no_pack = {**ALL_READY, ScannerToolName.NUCLEI_TEMPLATES.value: ScannerToolStatus.NOT_AVAILABLE.value}
        record_readiness_report(db, instance, report=readiness_from_tool_statuses(no_pack))

        instance.scan_profile = "standard_discovery"
        db.flush()
        assert required_tools_available(db, instance) is False

        instance.scan_profile = "safe_discovery"
        db.flush()
        assert required_tools_available(db, instance) is True


class TestStorageAndConnectivityAffectTheRollup:
    """CA-02.3 slice 3 — these are not components, so they are absent from the
    component list the rollup reads. Without explicit handling a Collector
    running out of disk, or on a link that keeps dropping, rolled up as fully
    ready."""

    def test_degraded_storage_degrades_the_collector(self, db: Session):
        instance = _instance(db)
        payload = readiness_from_tool_statuses(ALL_READY)
        payload["evidenceStorageStatus"] = CollectorComponentStatus.DEGRADED.value

        record_readiness_report(db, instance, report=payload)

        assert resolve_collector_readiness(db, instance).status == (
            CollectorReadinessStatus.DEGRADED.value
        )

    def test_a_flapping_link_degrades_the_collector(self, db: Session):
        instance = _instance(db)
        payload = readiness_from_tool_statuses(ALL_READY)
        payload["platformConnectivityStatus"] = CollectorComponentStatus.DEGRADED.value

        record_readiness_report(db, instance, report=payload)

        assert resolve_collector_readiness(db, instance).status == (
            CollectorReadinessStatus.DEGRADED.value
        )

    def test_unknown_does_not_degrade_anything(self, db: Session):
        # Søren's decision for this slice: unknown means unverified, not
        # unhealthy. Treating "we did not look" as "it is failing" would mark
        # every not-yet-upgraded Collector degraded on the day this ships —
        # the same dead end as blocking on it.
        instance = _instance(db)
        payload = readiness_from_tool_statuses(ALL_READY)
        assert payload["evidenceStorageStatus"] == CollectorComponentStatus.UNKNOWN.value
        assert payload["platformConnectivityStatus"] == CollectorComponentStatus.UNKNOWN.value

        record_readiness_report(db, instance, report=payload)

        assert resolve_collector_readiness(db, instance).status == (
            CollectorReadinessStatus.READY.value
        )

    def test_unknown_still_never_blocks_a_component(self, db: Session):
        instance = _instance(db)
        record_readiness_report(db, instance, report=readiness_from_tool_statuses(ALL_READY))

        readiness = resolve_collector_readiness(db, instance)

        assert component_is_ready(readiness, ScannerToolName.NMAP.value) is True

    def test_unavailable_storage_still_blocks(self, db: Session):
        # The distinction that makes "unknown never blocks" safe: a Collector
        # that measured its storage and found it broken is a different fact
        # from one that never looked.
        instance = _instance(db)
        payload = readiness_from_tool_statuses(ALL_READY)
        payload["evidenceStorageStatus"] = CollectorComponentStatus.UNAVAILABLE.value

        record_readiness_report(db, instance, report=payload)

        assert resolve_collector_readiness(db, instance).status == (
            CollectorReadinessStatus.BLOCKED.value
        )


class TestHardwareAddressCapability:
    """Whether a Collector could see MAC addresses at all — the fact that makes
    an *absence* of them readable. Without it, "no device at this address" and
    "we were never permitted to look" arrive as the same observation, which is
    how 242 echoes became artefacts (#175)."""

    def test_a_collector_granted_the_capability_can_see_hardware_addresses(self, db: Session):
        instance = _instance(db)
        record_readiness_report(
            db,
            instance,
            report={
                "schemaVersion": READINESS_SCHEMA_VERSION,
                "components": [
                    {"componentKey": ScannerToolName.NMAP.value, "status": CollectorComponentStatus.READY.value},
                    {
                        "componentKey": CollectorCapability.RAW_PACKET_ACCESS.value,
                        "status": CollectorComponentStatus.READY.value,
                    },
                ],
            },
        )

        assert collector_can_see_hardware_addresses(resolve_collector_readiness(db, instance)) is True

    def test_a_collector_without_the_capability_says_so_and_is_still_ready(self, db: Session):
        """The capability widens what can be learned; it is not a prerequisite.
        A Collector without it scans exactly as before and simply learns less,
        so it must not be reported as broken."""
        instance = _instance(db)
        record_readiness_report(
            db,
            instance,
            report={
                "schemaVersion": READINESS_SCHEMA_VERSION,
                "components": [
                    {"componentKey": ScannerToolName.NMAP.value, "status": CollectorComponentStatus.READY.value},
                    {
                        "componentKey": CollectorCapability.RAW_PACKET_ACCESS.value,
                        "status": CollectorComponentStatus.UNAVAILABLE.value,
                    },
                ],
            },
        )
        readiness = resolve_collector_readiness(db, instance)

        assert collector_can_see_hardware_addresses(readiness) is False
        assert component_is_ready(readiness, ScannerToolName.NMAP.value) is True

    def test_a_collector_that_never_reported_is_not_assumed_to_have_it(self, db: Session):
        """An unknown capability is not a granted one. Treating silence as
        permission puts the platform back to reading a missing MAC as a missing
        device, which is the whole failure being removed."""
        instance = _instance(db)

        assert collector_can_see_hardware_addresses(resolve_collector_readiness(db, instance)) is False
