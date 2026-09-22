"""Step 4.2 Part 2 — DISC-32: DiscoveryExecutionEvidenceAdapter + the
normalization handoff sweep. Uses the full real EvidencePackage-creation
path (dispatch -> acknowledge -> result-report, exactly like
test_discovery_execution_agent.py) rather than hand-constructing a package
row, so the adapter is exercised against a genuinely real row."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.routes import discovery_command_agent as command_agent_routes
from src.api.routes import discovery_execution_agent as execution_agent_routes
from src.core.constants.discovery_execution_enums import (
    EVIDENCE_PACKAGE_AUDIT_NORMALIZATION_FAILED,
    EVIDENCE_PACKAGE_AUDIT_NORMALIZED,
    EvidenceNormalizationStatus,
    ProviderExecutionStatus,
)
from src.core.constants.discovery_run_enums import DiscoveryRunStatus
from src.core.constants.evidence_scanner_enums import ScannerInstallationMethod, ScannerProfile
from src.core.constants.evidence_source_enums import EvidenceSourceType
from src.core.database import Base
from src.core.model_defs.discovery_execution import EvidencePackage, ProviderExecution
from src.core.model_defs.discovery_run import DiscoveryRun, ScannerCommand
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.models import (
    Asset,
    AssetEvidenceSignal,
    AssetObservedPort,
    Organization,
    RiskIngestionBatch,
    User,
)
from src.core.services import evidence_storage_backend
from src.core.services.discovery_execution_evidence_adapter import (
    DiscoveryEvidenceNormalizationError,
    DiscoveryExecutionEvidenceAdapter,
    _parse_nmap_xml,
    _parse_subfinder_text,
)
from src.core.services.discovery_execution_plan_service import generate_execution_plan
from src.core.services.discovery_execution_scheduler_service import dispatch_ready_jobs
from src.core.services.discovery_normalization_handoff_service import process_pending_evidence_packages
from src.core.services.discovery_normalization_service import normalize_execution
from src.core.services.discovery_run_service import approve_discovery_run, create_discovery_run
from src.core.services.evidence_scanner_service import (
    add_domain_target,
    approve_domain_target,
    confirm_scanner_scope,
    install_scanner,
    record_heartbeat,
    record_tool_validation,
    select_scan_profile,
)
from src.core.services.evidence_source_service import create_evidence_source
from discovery_boundary_fixture import approve_test_boundary

_REAL_NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames>
      <hostname name="app.example.com" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
  </host>
</nmaprun>"""


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
            Organization(id=1, name="Org", slug="org", country="DK", technical_setup_owner_user_id=1),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
        ]
    )
    session.commit()
    yield session
    session.close()


@pytest.fixture()
def local_evidence_dir(monkeypatch, tmp_path):
    backend = evidence_storage_backend.LocalFilesystemBackend(base_dir=str(tmp_path))
    monkeypatch.setitem(evidence_storage_backend._BACKENDS_BY_ID, backend.backend_id, backend)
    return tmp_path


def _evidence_package_from_real_flow(
    db: Session, *, raw_payload: str, evidence_format: str = "nmap_xml", provider_id: str = "nmap"
) -> EvidencePackage:
    """Drives the real dispatch -> acknowledge -> result-report path (same
    as test_discovery_execution_agent.py) to produce a genuinely real
    EvidencePackage row, rather than hand-constructing one with fabricated
    FKs."""
    source = create_evidence_source(db, organization_id=1, name="Scanner", source_type=EvidenceSourceType.SCANNER)
    db.commit()
    result = install_scanner(db, source, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    instance = result.instance
    record_heartbeat(db, instance)
    select_scan_profile(db, instance, profile=ScannerProfile.SAFE_DISCOVERY.value)
    record_tool_validation(
        db,
        instance,
        tool_status={"nmap": "available", "subfinder": "available", "nuclei": "available", "nuclei_templates": "available"},
    )
    db.commit()
    target = add_domain_target(db, source, domain="example.com")
    approve_domain_target(db, target, approved_by_user_id=1)
    # Real setup confirms the source scope (POST .../scanner/scope/confirm)
    # before discovery can be considered set up — evidence_source_readiness
    # gates on a CONFIRMED scope, so skipping it made the fixture unrealistic.
    confirm_scanner_scope(db, source, instance, confirmed_by_user_id=1)
    db.commit()

    approve_test_boundary(db, organization_id=1, evidence_source_id=source.id)
    organization = db.query(Organization).filter(Organization.id == 1).first()
    run = create_discovery_run(db, organization=organization, instance=instance, requested_by_user_id=1)
    if run.status == DiscoveryRunStatus.AWAITING_APPROVAL.value:
        approve_discovery_run(db, run, approved_by_user_id=1)
    db.commit()
    db.refresh(run)

    generate_execution_plan(db, run)
    db.commit()

    dispatch_ready_jobs(db)
    db.commit()

    # SAFE_DISCOVERY enables 3 stages (external/internal/service_fingerprinting);
    # only external/internal are READY and dispatched immediately — pick a
    # dispatched (LEASED) job, not fingerprinting's still-PENDING one.
    provider_execution = (
        db.query(ProviderExecution)
        .filter(
            ProviderExecution.provider_id == provider_id, ProviderExecution.status == ProviderExecutionStatus.LEASED.value
        )
        .order_by(ProviderExecution.created_at.desc())
        .first()
    )
    command = db.query(ScannerCommand).filter(ScannerCommand.provider_execution_id == provider_execution.id).first()

    command_agent_routes.acknowledge_command_route(
        command.id,
        command_agent_routes.AcknowledgeCommandRequest(accepted=True),
        _fake_request(result.activation_token),
        db,
    )
    db.commit()

    execution_agent_routes.provider_execution_result_route(
        command.id,
        execution_agent_routes.ProviderExecutionResultRequest(
            status=ProviderExecutionStatus.COMPLETED.value,
            evidence_format=evidence_format,
            raw_evidence_payload=raw_payload,
        ),
        _fake_request(result.activation_token),
        db,
    )
    db.commit()

    package = db.query(EvidencePackage).filter(EvidencePackage.provider_execution_id == provider_execution.id).first()
    assert package is not None
    return package


def _fake_request(token: str | None):
    from fastapi import Request

    headers = [(b"authorization", f"Bearer {token}".encode())] if token else []
    return Request({"type": "http", "headers": headers})


# --- _parse_nmap_xml -----------------------------------------------------------------------


def test_parse_nmap_xml_extracts_open_ports_and_skips_down_hosts_without_address():
    host_records = _parse_nmap_xml(_REAL_NMAP_XML.encode())
    assert len(host_records) == 1  # the second <host> (down, no address/hostname) is skipped
    host = host_records[0]
    assert host["hostname"] == "app.example.com"
    assert host["ip"] == "10.0.0.5"
    assert host["findings"] == []
    assert host["services"] == [
        {
            "port": 443,
            "protocol": "tcp",
            "service": "https",
            "product": "nginx",
            "version": "1.24.0",
            # CA-07.1 — kept from the same <service> element. Without them the
            # `service` name above is nmap's port-number table and nothing more.
            "extra_info": None,
            # #249 slice 2 — absent here because this fixture's <service>
            # carries no `method`, which is itself the honest answer.
            "method": None,
            "scripts": {},
        }
    ]  # the closed 8080 port is excluded
    # No `args` on <nmaprun> and no probed service, so the scan's depth is
    # genuinely unknown and is reported as such rather than assumed.
    assert host["fingerprinting_ran"] is None


# --- #249 slice 2: scan depth is read, not inferred --------------------------------------


def _nmap_xml(*, args: str | None = None, method: str | None = None, product: str | None = None) -> bytes:
    """One host, one open port, with only the attributes under test varying."""
    run_attrs = f' args="{args}"' if args is not None else ""
    service_attrs = "".join(
        [
            ' name="http-proxy"',
            f' product="{product}"' if product else "",
            f' method="{method}"' if method else "",
        ]
    )
    return f"""<?xml version="1.0"?>
<nmaprun scanner="nmap"{run_attrs}>
  <host>
    <status state="up"/>
    <address addr="192.168.1.33" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service{service_attrs}/>
      </port>
    </ports>
  </host>
</nmaprun>""".encode()


def test_a_scan_that_ran_version_detection_says_so_even_when_it_learned_nothing():
    """The defect this closes: a probed host that yields no product was
    indistinguishable from a host nobody ever probed, so the platform reported
    the weaker of the two and asked for credentials it had not earned."""
    host = _parse_nmap_xml(_nmap_xml(args="nmap -sT -sV -T4 --top-ports 50 -oX - 192.168.1.33"))[0]
    assert host["fingerprinting_ran"] is True


def test_a_connect_sweep_is_recorded_as_not_probed():
    host = _parse_nmap_xml(_nmap_xml(args="nmap -sT -T4 --top-ports 50 -oX - 192.168.1.33"))[0]
    assert host["fingerprinting_ran"] is False


def test_aggregate_scan_flag_counts_as_version_detection():
    """`-A` includes -sV. Reading only for the literal flag would report a
    deeper scan as a shallower one."""
    host = _parse_nmap_xml(_nmap_xml(args="nmap -A 192.168.1.33"))[0]
    assert host["fingerprinting_ran"] is True


def test_a_probed_service_settles_the_question_without_any_arguments():
    """Evidence outranks the command line: nmap marking a service `probed` is
    what actually happened, and a document may reach us with no args at all."""
    host = _parse_nmap_xml(_nmap_xml(method="probed"))[0]
    assert host["fingerprinting_ran"] is True
    assert host["services"][0]["method"] == "probed"


def test_a_table_lookup_is_kept_so_a_guess_is_never_read_as_an_observation():
    """`http-proxy` from nmap's port-number table is not an observation of
    anything. Recording how the name was reached is what lets a reader be told
    the difference — the original complaint that opened #249."""
    host = _parse_nmap_xml(_nmap_xml(args="nmap -sT 192.168.1.33", method="table"))[0]
    assert host["services"][0]["method"] == "table"
    assert host["fingerprinting_ran"] is False


def test_parse_nmap_xml_raises_on_malformed_document():
    import xml.etree.ElementTree as ET

    with pytest.raises(ET.ParseError):
        _parse_nmap_xml(b"<not-valid-xml")


# --- hostile XML (Plane #137 — Semgrep use-defused-xml) ------------------------------------
# Evidence arrives over a channel-authenticated but content-untrusted path, and
# its content originates on the scanned network, not in the Collector.

_XXE_EVIDENCE = b"""<?xml version="1.0"?>
<!DOCTYPE nmaprun [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="&xxe;"/></hostnames>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml_refuses_external_entities():
    """defusedxml blocks the read outright — the raised type is a ValueError
    subclass, deliberately *not* ET.ParseError, which is why every caller has to
    name it explicitly."""
    import xml.etree.ElementTree as ET
    from defusedxml.common import DefusedXmlException

    with pytest.raises(DefusedXmlException):
        _parse_nmap_xml(_XXE_EVIDENCE)

    assert not issubclass(DefusedXmlException, ET.ParseError)


def test_normalize_marks_failed_on_hostile_xml_rather_than_crashing(db: Session, local_evidence_dir):
    """The gap this closes: before naming DefusedXmlException in the caller's
    except clause, a hostile package was blocked by defusedxml but escaped the
    handler — normalisation crashed and the package was left in a non-terminal
    state, never marked failed and never audited."""
    package = _evidence_package_from_real_flow(db, raw_payload=_XXE_EVIDENCE.decode())

    with pytest.raises(DiscoveryEvidenceNormalizationError):
        normalize_execution(
            db,
            organization_id=1,
            actor_user_id=1,
            source_type=DiscoveryExecutionEvidenceAdapter.source_type,
            execution_id=package.id,
        )
    db.commit()

    db.refresh(package)
    assert package.normalization_status == EvidenceNormalizationStatus.NORMALIZATION_FAILED.value
    audit = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.organization_id == 1,
            AuditEvent.event_type == EVIDENCE_PACKAGE_AUDIT_NORMALIZATION_FAILED,
        )
        .first()
    )
    assert audit is not None


# --- _parse_subfinder_text (CA-04.3) --------------------------------------------------------


def test_parse_subfinder_text_extracts_one_host_record_per_subdomain():
    raw = b"app.example.com\nmail.example.com\n\n  \napi.example.com\n"
    host_records = _parse_subfinder_text(raw)
    assert [h["hostname"] for h in host_records] == ["app.example.com", "mail.example.com", "api.example.com"]
    for host in host_records:
        # A real, disclosed narrower shape than Nmap's — no ip/services.
        assert host["ip"] is None
        assert host["services"] == []
        assert host["findings"] == []


def test_parse_subfinder_text_deduplicates_repeated_subdomains():
    raw = b"app.example.com\napp.example.com\nmail.example.com\n"
    host_records = _parse_subfinder_text(raw)
    assert [h["hostname"] for h in host_records] == ["app.example.com", "mail.example.com"]


def test_parse_subfinder_text_handles_empty_output():
    assert _parse_subfinder_text(b"") == []


# --- DiscoveryExecutionEvidenceAdapter.normalize -------------------------------------------


def test_normalize_creates_asset_and_signal_and_marks_package_normalized(db: Session, local_evidence_dir):
    package = _evidence_package_from_real_flow(db, raw_payload=_REAL_NMAP_XML)

    result = normalize_execution(
        db,
        organization_id=1,
        actor_user_id=1,
        source_type=DiscoveryExecutionEvidenceAdapter.source_type,
        execution_id=package.id,
    )
    db.commit()

    assert len(result.created_asset_ids) == 1
    asset = db.query(Asset).filter(Asset.id == result.created_asset_ids[0]).first()
    assert asset is not None
    assert asset.display_name == "app.example.com"

    db.refresh(package)
    assert package.normalization_status == EvidenceNormalizationStatus.NORMALIZED.value

    batch = db.query(RiskIngestionBatch).filter(RiskIngestionBatch.source_name == "discovery_execution:nmap").first()
    assert batch is not None
    assert batch.raw_payload["hosts"][0]["hostname"] == "app.example.com"

    audit = (
        db.query(AuditEvent)
        .filter(AuditEvent.organization_id == 1, AuditEvent.event_type == EVIDENCE_PACKAGE_AUDIT_NORMALIZED)
        .first()
    )
    assert audit is not None
    assert audit.metadata_json["evidencePackageId"] == package.id
    assert audit.metadata_json["lifecycle"]["family"] == "evidence"
    assert audit.metadata_json["lifecycle"]["currentState"] == EvidenceNormalizationStatus.NORMALIZED.value


def test_normalize_creates_assets_from_real_subfinder_flow(db: Session, local_evidence_dir):
    """CA-04.3 — Subfinder evidence reconciles through the exact same
    normalization path Nmap's does (same adapter, same engine), not a
    silent gap or a second mechanism."""
    package = _evidence_package_from_real_flow(
        db, raw_payload="app.example.com\napi.example.com\n", evidence_format="text", provider_id="subfinder"
    )

    result = normalize_execution(
        db,
        organization_id=1,
        actor_user_id=1,
        source_type=DiscoveryExecutionEvidenceAdapter.source_type,
        execution_id=package.id,
    )
    db.commit()

    assert len(result.created_asset_ids) == 2
    hostnames = {
        db.query(Asset).filter(Asset.id == asset_id).first().display_name for asset_id in result.created_asset_ids
    }
    assert hostnames == {"app.example.com", "api.example.com"}

    db.refresh(package)
    assert package.normalization_status == EvidenceNormalizationStatus.NORMALIZED.value

    batch = (
        db.query(RiskIngestionBatch).filter(RiskIngestionBatch.source_name == "discovery_execution:subfinder").first()
    )
    assert batch is not None
    assert {h["hostname"] for h in batch.raw_payload["hosts"]} == {"app.example.com", "api.example.com"}
    assert all(h["ip"] is None and h["services"] == [] for h in batch.raw_payload["hosts"])


def test_normalize_rejects_unsupported_evidence_format(db: Session, local_evidence_dir):
    package = _evidence_package_from_real_flow(db, raw_payload="{}", evidence_format="json")

    with pytest.raises(ValueError):
        normalize_execution(
            db,
            organization_id=1,
            actor_user_id=1,
            source_type=DiscoveryExecutionEvidenceAdapter.source_type,
            execution_id=package.id,
        )


def test_normalize_marks_failed_and_audits_on_malformed_xml(db: Session, local_evidence_dir):
    package = _evidence_package_from_real_flow(db, raw_payload="<not-valid-xml")

    with pytest.raises(DiscoveryEvidenceNormalizationError):
        normalize_execution(
            db,
            organization_id=1,
            actor_user_id=1,
            source_type=DiscoveryExecutionEvidenceAdapter.source_type,
            execution_id=package.id,
        )
    db.commit()

    db.refresh(package)
    assert package.normalization_status == EvidenceNormalizationStatus.NORMALIZATION_FAILED.value
    audit = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.organization_id == 1, AuditEvent.event_type == EVIDENCE_PACKAGE_AUDIT_NORMALIZATION_FAILED
        )
        .first()
    )
    assert audit is not None
    assert audit.metadata_json["lifecycle"]["family"] == "evidence"
    assert audit.metadata_json["lifecycle"]["currentState"] == EvidenceNormalizationStatus.NORMALIZATION_FAILED.value


# --- process_pending_evidence_packages (the durability sweep) ------------------------------


def test_sweep_normalizes_pending_nmap_packages_and_isolates_one_failure(db: Session, local_evidence_dir):
    good_package = _evidence_package_from_real_flow(db, raw_payload=_REAL_NMAP_XML)
    bad_package = _evidence_package_from_real_flow(db, raw_payload="<not-valid-xml")

    processed = process_pending_evidence_packages(db)
    db.commit()

    processed_ids = {p.id for p in processed}
    assert good_package.id in processed_ids
    assert bad_package.id not in processed_ids  # failed package isn't counted as processed...

    db.refresh(good_package)
    db.refresh(bad_package)
    assert good_package.normalization_status == EvidenceNormalizationStatus.NORMALIZED.value
    assert bad_package.normalization_status == EvidenceNormalizationStatus.NORMALIZATION_FAILED.value  # ...but it was still attempted, not skipped


# --- Evidence source lifecycle (BUG-DISC-13) -----------------------------------------------
# Before this, first_evidence_received_at and a non-draft status were set only by
# the CSV import and manual-entry paths, and no discovery service referenced
# EvidenceSource at all — so a Collector source could never leave `draft`
# however much evidence it delivered, and onboarding readiness never completed.


def test_normalising_collector_evidence_takes_its_source_out_of_draft(db: Session, local_evidence_dir):
    from src.core.constants.evidence_source_enums import EvidenceReceiptStatus, EvidenceSourceStatus
    from src.core.model_defs.evidence_source import EvidenceReceipt, EvidenceSource
    from src.core.model_defs.discovery_run import DiscoveryRun

    package = _evidence_package_from_real_flow(db, raw_payload=_REAL_NMAP_XML)
    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == package.discovery_run_id).one()
    source = db.query(EvidenceSource).filter(EvidenceSource.id == run.evidence_source_id).one()

    # The state this bug left every Collector source in, permanently.
    assert source.status == EvidenceSourceStatus.DRAFT.value
    assert source.first_evidence_received_at is None

    normalize_execution(
        db,
        organization_id=1,
        actor_user_id=1,
        source_type=DiscoveryExecutionEvidenceAdapter.source_type,
        execution_id=package.id,
    )
    db.commit()
    db.refresh(source)

    assert source.status == EvidenceSourceStatus.HEALTHY.value
    assert source.first_evidence_received_at is not None
    assert source.last_successful_sync_at is not None

    # Recorded as a receipt with no import batch — a discovery run is not a CSV
    # upload, and EvidenceReceipt.evidence_import_batch_id is nullable for
    # exactly this reason.
    receipt = db.query(EvidenceReceipt).filter(EvidenceReceipt.evidence_source_id == source.id).one()
    assert receipt.evidence_import_batch_id is None
    assert receipt.status == EvidenceReceiptStatus.PROCESSED.value


def test_a_source_that_delivers_unusable_evidence_is_degraded_not_healthy(db: Session, local_evidence_dir):
    """The channel works, the content did not — degraded, never left in draft
    (which would read as "no Collector") and never healthy (which would hide a
    Collector delivering junk)."""
    from src.core.constants.evidence_source_enums import EvidenceSourceStatus
    from src.core.model_defs.evidence_source import EvidenceSource
    from src.core.model_defs.discovery_run import DiscoveryRun

    package = _evidence_package_from_real_flow(db, raw_payload="<not-valid-xml")
    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == package.discovery_run_id).one()
    source = db.query(EvidenceSource).filter(EvidenceSource.id == run.evidence_source_id).one()

    with pytest.raises(DiscoveryEvidenceNormalizationError):
        normalize_execution(
            db,
            organization_id=1,
            actor_user_id=1,
            source_type=DiscoveryExecutionEvidenceAdapter.source_type,
            execution_id=package.id,
        )
    db.commit()
    db.refresh(source)

    assert source.status == EvidenceSourceStatus.DEGRADED.value
    assert source.first_evidence_received_at is not None


def test_collector_source_becomes_functioning_for_onboarding_readiness(db: Session, local_evidence_dir):
    """The end of the causal chain: a scanner source produces no
    EvidenceImportBatch, so evidence_source_readiness_service could never report
    it as functioning — which is what sent a user back through setup on refresh
    (UX-ONB-01)."""
    from src.core.model_defs.discovery_run import DiscoveryRun
    from src.core.services.evidence_source_readiness_service import (
        evaluate_evidence_source_readiness,
    )

    package = _evidence_package_from_real_flow(db, raw_payload=_REAL_NMAP_XML)
    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == package.discovery_run_id).one()

    assert evaluate_evidence_source_readiness(db, organization_id=1).ready is False

    normalize_execution(
        db,
        organization_id=1,
        actor_user_id=1,
        source_type=DiscoveryExecutionEvidenceAdapter.source_type,
        execution_id=package.id,
    )
    db.commit()

    result = evaluate_evidence_source_readiness(db, organization_id=1)
    assert result.ready is True
    assert run.evidence_source_id in result.functioning_source_ids


def test_a_connected_collector_completes_setup_before_it_has_delivered(db: Session, local_evidence_dir):
    """UX-ONB-01. Installing, activating and scoping a Collector finishes the
    evidence-source *setup step*; whether it has scanned yet is the next step's
    question. Collapsing the two is what sent a user with a Collector showing
    "Connected" back to "let's connect a source of evidence" on refresh."""
    from src.core.services.evidence_source_readiness_service import (
        evaluate_evidence_source_readiness,
    )

    # Drives the real setup path and stops before any evidence is reported.
    _evidence_package_from_real_flow(db, raw_payload=_REAL_NMAP_XML)
    db.commit()

    # Undo the delivery so only the setup steps remain done.
    from src.core.model_defs.evidence_source import EvidenceReceipt

    db.query(EvidenceReceipt).delete()
    db.commit()

    result = evaluate_evidence_source_readiness(db, organization_id=1)

    # Set up: yes. Delivering: not yet. Both true at once, and both visible.
    assert result.setup_complete is True
    assert result.ready is False
    assert result.configured_source_ids != []
    assert result.functioning_source_ids == []


# --- Empty scan results (BUG-DISC-14) ------------------------------------------------------
# A provider that observed nothing used to have a host record synthesised for it
# — named after an internal evidence-package id — which became a real Asset row
# on the screen where an executive approves what their organisation owns.

_EMPTY_SUBFINDER_OUTPUT = "\n"


def test_a_provider_that_finds_nothing_creates_no_asset(db: Session, local_evidence_dir):
    from src.core.models import Asset

    package = _evidence_package_from_real_flow(
        db,
        raw_payload=_EMPTY_SUBFINDER_OUTPUT,
        evidence_format="text",
        provider_id="subfinder",
    )

    normalize_execution(
        db,
        organization_id=1,
        actor_user_id=1,
        source_type=DiscoveryExecutionEvidenceAdapter.source_type,
        execution_id=package.id,
    )
    db.commit()

    assets = db.query(Asset).filter(Asset.organization_id == 1).all()
    # Neither fabrication point fires: not the adapter's "<provider>-scan-<id>",
    # nor the normalisation service's "discovery_execution:<provider>".
    assert [a.display_name for a in assets] == []


def test_an_empty_result_is_still_reported_to_the_reviewer(db: Session, local_evidence_dir):
    """"We scanned and found nothing" must stay visible — it is just not an
    asset. Removing the placeholder without this would have made a real outcome
    silently invisible."""
    from src.core.model_defs.discovery_run import DiscoveryRun
    from src.core.services.discovery_results_service import get_discovery_results

    package = _evidence_package_from_real_flow(
        db,
        raw_payload=_EMPTY_SUBFINDER_OUTPUT,
        evidence_format="text",
        provider_id="subfinder",
    )
    normalize_execution(
        db,
        organization_id=1,
        actor_user_id=1,
        source_type=DiscoveryExecutionEvidenceAdapter.source_type,
        execution_id=package.id,
    )
    db.commit()

    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == package.discovery_run_id).one()
    summary = get_discovery_results(db, organization_id=1, discovery_run_id=run.id)

    assert summary.discovered == ()
    assert "subfinder" in summary.empty_result_providers


def test_a_provider_that_finds_something_is_not_reported_as_empty(db: Session, local_evidence_dir):
    from src.core.model_defs.discovery_run import DiscoveryRun
    from src.core.services.discovery_results_service import get_discovery_results

    package = _evidence_package_from_real_flow(db, raw_payload=_REAL_NMAP_XML)
    normalize_execution(
        db,
        organization_id=1,
        actor_user_id=1,
        source_type=DiscoveryExecutionEvidenceAdapter.source_type,
        execution_id=package.id,
    )
    db.commit()

    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == package.discovery_run_id).one()
    summary = get_discovery_results(db, organization_id=1, discovery_run_id=run.id)

    assert summary.discovered != ()
    assert "nmap" not in summary.empty_result_providers


# --- CA-06.2: an observation records where it came from ----------------------


def test_a_signal_points_back_at_the_evidence_the_job_and_the_collector(db: Session, local_evidence_dir):
    """The whole chain artefact → signal → evidence package → discovery run →
    Collector must be answerable by following references, not by re-parsing a
    raw scanner payload or reading an id out of a JSON blob."""
    package = _evidence_package_from_real_flow(db, raw_payload=_REAL_NMAP_XML)

    result = normalize_execution(
        db,
        organization_id=1,
        actor_user_id=1,
        source_type=DiscoveryExecutionEvidenceAdapter.source_type,
        execution_id=package.id,
    )
    db.commit()

    signal = (
        db.query(AssetEvidenceSignal)
        .filter(AssetEvidenceSignal.asset_id == result.created_asset_ids[0])
        .one()
    )
    assert signal.evidence_package_id == package.id
    assert signal.provider_execution_id == package.provider_execution_id

    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == package.discovery_run_id).one()
    assert signal.scanner_instance_id == run.scanner_instance_id
    assert signal.scanner_instance_id is not None

    # And the batch carries the package, which is what got it there.
    batch = db.query(RiskIngestionBatch).filter(RiskIngestionBatch.id == signal.payload_json["ingestionBatchId"]).one()
    assert batch.evidence_package_id == package.id


def test_the_ports_nmap_reported_are_recorded_structurally(db: Session, local_evidence_dir):
    """Previously these survived only inside payload_json and as service-name
    strings in Asset.intent, so "what is this exposing, since when" could not be
    asked of the database."""
    package = _evidence_package_from_real_flow(db, raw_payload=_REAL_NMAP_XML)

    result = normalize_execution(
        db,
        organization_id=1,
        actor_user_id=1,
        source_type=DiscoveryExecutionEvidenceAdapter.source_type,
        execution_id=package.id,
    )
    db.commit()

    ports = (
        db.query(AssetObservedPort)
        .filter(AssetObservedPort.asset_id == result.created_asset_ids[0])
        .all()
    )
    assert len(ports) == 1  # the closed 8080 port is not an observation
    assert ports[0].port == 443
    assert ports[0].protocol == "tcp"
    assert ports[0].service_name == "https"
    assert ports[0].product == "nginx"
    assert ports[0].product_version == "1.24.0"
    assert ports[0].first_seen_at is not None
    assert ports[0].last_seen_at is not None


# --- CA-07.1 slice 1: identity evidence survives the parse ---------------------------------

_FINGERPRINTED_NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="AA:BB:CC:11:22:33" addrtype="mac" vendor="Hewlett Packard"/>
    <address addr="192.168.1.33" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack"/>
        <service name="http-proxy" product="nginx" version="1.25.3" extrainfo="Ubuntu"/>
        <script id="http-title" output="Plane"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def test_parse_nmap_xml_selects_the_ip_by_addrtype_not_by_order():
    """nmap emits one <address> per type and the MAC can come first. Reading
    whichever came first would have recorded a MAC address as the host's IP."""
    host = _parse_nmap_xml(_FINGERPRINTED_NMAP_XML.encode())[0]
    assert host["ip"] == "192.168.1.33"


def test_parse_nmap_xml_keeps_the_hardware_vendor():
    """The only evidence that can name a host with nothing listening."""
    host = _parse_nmap_xml(_FINGERPRINTED_NMAP_XML.encode())[0]
    assert host["vendor"] == "Hewlett Packard"
    assert host["mac"] == "AA:BB:CC:11:22:33"


def test_parse_nmap_xml_keeps_script_output():
    """`http-title` is what tells a Plane instance from a monitoring dashboard;
    both are 'http-proxy on 8080' without it."""
    host = _parse_nmap_xml(_FINGERPRINTED_NMAP_XML.encode())[0]
    assert host["services"][0]["scripts"] == {"http-title": "Plane"}
    assert host["services"][0]["extra_info"] == "Ubuntu"


def test_parse_nmap_xml_has_no_vendor_when_the_scan_could_not_see_one():
    """An unprivileged connect scan emits no MAC element at all — the field is
    absent, not wrong."""
    host = _parse_nmap_xml(_REAL_NMAP_XML.encode())[0]
    assert host["vendor"] is None
    assert host["mac"] is None
