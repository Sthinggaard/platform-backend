"""CA-09V — which targets a command actually carries, against a real database.

``test_discovery_target_narrowing.py`` proves the containment rule in isolation.
This proves the wiring: that a **nuclei** command receives the discovered hosts
and an **nmap** command still receives the approved scope, resolved through the
provider registry rather than a name check, with real rows in real tables.

Persistence is not mocked here on purpose — the defect being fixed survived a
green suite for ten days precisely because every nuclei fixture used a target
shape and a scope the production path never produces.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from src.core.constants.artefact_identity_enums import ArtefactIdentifierType
from src.core.constants.discovery_run_enums import (
    CheckKey,
    DiscoveryRunStatus,
    DiscoveryStage,
    DiscoveryTargetType,
    ScannerCommandStatus,
    ScannerCommandType,
)
from src.core.constants.evidence_scanner_enums import ScannerTargetStatus
from src.core.model_defs.assets_runtime import Asset, AssetIdentifier, AssetStatus
from src.core.model_defs.discovery_run import DiscoveryRun, ScannerCommand
from src.core.model_defs.evidence_scanner import ScannerInstance, ScannerNetworkTarget
from src.core.model_defs.evidence_source import EvidenceSource
from src.core.models import Organization, User
from src.core.services.discovery_command_service import get_command_target_snapshot
from src.core.services.discovery_run_service import utcnow

APPROVED_RANGE = "192.168.50.0/24"

# The addresses org 7's nmap runs actually observed inside that range, plus one
# that is not in it — a laptop, a cloud host, anything the inventory holds that
# the customer never approved for scanning.
DISCOVERED_IN_RANGE = ["192.168.50.152", "192.168.50.176", "192.168.50.1"]
DISCOVERED_OUT_OF_RANGE = "10.20.0.5"


@pytest.fixture()
def scanner_scope(db_session: Session, sample_organization):
    """One approved /24 on a real scanner, and the artefacts discovery found."""
    source = EvidenceSource(
        id=str(uuid4()),
        organization_id=sample_organization.id,
        name="Scanner",
        type="scanner",
        mode="agent",
    )
    db_session.add(source)
    db_session.flush()

    requester = User(
        organization_id=sample_organization.id,
        email=f"tech-owner-{uuid4().hex[:8]}@example.com",
        role="org_admin",
    )
    db_session.add(requester)
    db_session.flush()

    instance = ScannerInstance(
        id=str(uuid4()),
        organization_id=sample_organization.id,
        evidence_source_id=source.id,
        name="Primary",
        public_instance_id=uuid4().hex[:12],
        installation_method="docker",
        activation_token_hash="x" * 64,
    )
    network_target = ScannerNetworkTarget(
        id=str(uuid4()),
        organization_id=sample_organization.id,
        evidence_source_id=source.id,
        cidr=APPROVED_RANGE,
        name="Network IP",
        network_type="corporate",
        status=ScannerTargetStatus.APPROVED.value,
        approved_by_user_id=None,
        approved_at=utcnow(),
    )
    db_session.add_all([instance, network_target])
    db_session.flush()

    for address in [*DISCOVERED_IN_RANGE, DISCOVERED_OUT_OF_RANGE]:
        asset = Asset(
            organization_id=sample_organization.id,
            type="host",
            display_name=address,
            layer="infrastructure",
            status=AssetStatus.PARTIALLY_OBSERVED,
            risk_score=0.0,
            findings_count=0,
            confidence=1.0,
        )
        db_session.add(asset)
        db_session.flush()
        db_session.add(
            AssetIdentifier(
                organization_id=sample_organization.id,
                asset_id=asset.id,
                identifier_type=ArtefactIdentifierType.IP_ADDRESS.value,
                identifier_value=address,
                observed_by_source="nmap",
                first_seen_at=utcnow(),
                last_seen_at=utcnow(),
            )
        )
    db_session.flush()
    return source, instance, network_target, requester


def _command(
    db_session: Session, scanner_scope, organization_id: int, *, check_key: str
) -> ScannerCommand:
    _source, instance, network_target, requester = scanner_scope
    run = DiscoveryRun(
        id=str(uuid4()),
        organization_id=organization_id,
        evidence_source_id=instance.evidence_source_id,
        scanner_instance_id=instance.id,
        requested_by_user_id=requester.id,
        request_source="user",
        discovery_purpose="asset_discovery",
        profile_snapshot={"profileType": "standard_discovery"},
        target_ids=[network_target.id],
        target_snapshot=[
            {
                "targetId": network_target.id,
                "targetType": DiscoveryTargetType.NETWORK_RANGE.value,
                "displayName": network_target.name,
                "approvedValue": network_target.cidr,
                "networkType": network_target.network_type,
                "approvedAt": network_target.approved_at.isoformat(),
                "approvedByUserId": None,
            }
        ],
        status=DiscoveryRunStatus.RUNNING.value,
        current_stage=DiscoveryStage.VULNERABILITY_DISCOVERY.value,
        approval_status="not_required",
    )
    db_session.add(run)
    db_session.flush()

    command = ScannerCommand(
        id=str(uuid4()),
        organization_id=organization_id,
        scanner_instance_id=instance.id,
        discovery_run_id=run.id,
        check_key=check_key,
        command_type=ScannerCommandType.RUN_DISCOVERY.value,
        status=ScannerCommandStatus.PENDING.value,
        issued_at=utcnow(),
        expires_at=utcnow(),
        execution_policy={"maximumDurationSeconds": 900},
        signature_version="v1",
        signature="unused-here",
    )
    db_session.add(command)
    db_session.flush()
    return command, run


def test_a_nuclei_command_carries_the_hosts_discovery_found(
    db_session, sample_organization, scanner_scope
):
    """The fix. Nuclei was handed the /24 itself, expanded it to 256 addresses
    and was killed at its time budget on every run since 2026-08-27."""
    command, run = _command(
        db_session, scanner_scope, sample_organization.id, check_key=CheckKey.NUCLEI.value
    )

    targets = get_command_target_snapshot(db_session, command, run)

    assert sorted(target["approvedValue"] for target in targets) == sorted(DISCOVERED_IN_RANGE)
    assert APPROVED_RANGE not in {target["approvedValue"] for target in targets}


def test_a_nuclei_command_never_carries_a_host_outside_the_approved_scope(
    db_session, sample_organization, scanner_scope
):
    """The safety property, end to end: the artefact inventory holds an address
    on another network, and narrowing must not smuggle it into a scan."""
    command, run = _command(
        db_session, scanner_scope, sample_organization.id, check_key=CheckKey.NUCLEI.value
    )

    targets = get_command_target_snapshot(db_session, command, run)
    values = {target["approvedValue"] for target in targets}

    # Narrowing really happened — without this the assertion below passes
    # trivially, because the unnarrowed scope is the range itself.
    assert values == set(DISCOVERED_IN_RANGE)
    assert DISCOVERED_OUT_OF_RANGE not in values


def test_an_nmap_command_still_carries_the_approved_scope(
    db_session, sample_organization, scanner_scope
):
    """A discovery provider's whole job is to find what is not yet known.
    Narrowing it to what is known would make it incapable of discovering
    anything — which is why this is a declared provider capability and not a
    change to how targets are resolved for everyone."""
    command, run = _command(
        db_session, scanner_scope, sample_organization.id, check_key=CheckKey.NMAP.value
    )

    targets = get_command_target_snapshot(db_session, command, run)

    assert [target["approvedValue"] for target in targets] == [APPROVED_RANGE]


def test_a_whole_run_command_with_no_check_key_carries_the_approved_scope(
    db_session, sample_organization, scanner_scope
):
    """A Step 4.1 whole-run command names no single check, so there is no
    provider to ask and nothing to narrow against."""
    command, run = _command(
        db_session, scanner_scope, sample_organization.id, check_key=CheckKey.NMAP.value
    )
    command.check_key = None
    db_session.flush()

    assert [t["approvedValue"] for t in get_command_target_snapshot(db_session, command, run)] == [
        APPROVED_RANGE
    ]


def test_narrowing_reads_only_this_organizations_artefacts(
    db_session, sample_organization, scanner_scope
):
    """Tenant isolation on the query that feeds targeting: another
    organisation's artefact inside the same private range must never become
    something this organisation's scanner is told to scan."""
    other_org = Organization(name="Other Org", slug=f"other-org-{uuid4().hex[:8]}")
    db_session.add(other_org)
    db_session.flush()
    other_org_asset = Asset(
        organization_id=other_org.id,
        type="host",
        display_name="192.168.50.99",
        layer="infrastructure",
        status=AssetStatus.PARTIALLY_OBSERVED,
        risk_score=0.0,
        findings_count=0,
        confidence=1.0,
    )
    db_session.add(other_org_asset)
    db_session.flush()
    db_session.add(
        AssetIdentifier(
            organization_id=other_org.id,
            asset_id=other_org_asset.id,
            identifier_type=ArtefactIdentifierType.IP_ADDRESS.value,
            identifier_value="192.168.50.99",
            observed_by_source="nmap",
            first_seen_at=utcnow(),
            last_seen_at=utcnow(),
        )
    )
    db_session.flush()

    command, run = _command(
        db_session, scanner_scope, sample_organization.id, check_key=CheckKey.NUCLEI.value
    )

    values = {t["approvedValue"] for t in get_command_target_snapshot(db_session, command, run)}

    # The other organisation's address sits *inside* this approved range, so it
    # would be scanned if the query that feeds targeting were not tenant-scoped.
    # Asserting the narrowed set exactly also proves narrowing ran at all.
    assert values == set(DISCOVERED_IN_RANGE)
    assert "192.168.50.99" not in values


def test_a_target_revoked_since_run_creation_narrows_to_nothing(
    db_session, sample_organization, scanner_scope
):
    """Narrowing runs on the *live* approved scope, so revoking approval still
    removes everything inside it — CA-04.2's guarantee is not weakened by
    resolving hosts underneath it."""
    _source, _instance, network_target, _requester = scanner_scope
    command, run = _command(
        db_session, scanner_scope, sample_organization.id, check_key=CheckKey.NUCLEI.value
    )
    network_target.status = ScannerTargetStatus.EXCLUDED.value
    db_session.flush()

    assert get_command_target_snapshot(db_session, command, run) == []


# --- The scope the command carries, not just the hosts ----------------------
#
# Narrowing to discovered hosts was correct and was not enough. The run on
# 2026-09-07 07:12:52 still took 606 seconds and returned 0 bytes, because this
# organisation holds an artefact per address across a whole /24 — 258 of its 269
# "discovered" hosts have no open port at all. So the command now carries which
# template trees each host is worth scanning, and drops the ones worth none.


def _fingerprint(db_session, organization_id: int, address: str, services: list[dict]) -> None:
    """Record what service fingerprinting saw on a host, the way nmap
    normalisation stores it."""
    from src.core.model_defs.assets_runtime import AssetEvidenceSignal

    asset = (
        db_session.query(Asset)
        .join(AssetIdentifier, AssetIdentifier.asset_id == Asset.id)
        .filter(
            Asset.organization_id == organization_id,
            AssetIdentifier.identifier_value == address,
        )
        .first()
    )
    assert asset is not None, f"no artefact for {address}"
    db_session.add(
        AssetEvidenceSignal(
            organization_id=organization_id,
            asset_id=asset.id,
            kind="risk_intelligence_ingestion",
            payload_json={"host": {"ip": address, "services": services}},
            observed_at=utcnow(),
        )
    )
    db_session.flush()


def test_a_host_with_no_open_port_is_dropped_from_the_command(
    db_session, sample_organization, scanner_scope
):
    """The 606 seconds, and where they went.

    A host fingerprinting found nothing open on cannot match any template —
    nuclei has nothing to connect to. Scanning it buys a guaranteed-empty result
    at full price, so it does not go in the command at all.
    """
    _fingerprint(db_session, sample_organization.id, "192.168.50.152", [{"port": 80, "service": "http"}])
    _fingerprint(db_session, sample_organization.id, "192.168.50.176", [])
    _fingerprint(db_session, sample_organization.id, "192.168.50.1", [])

    command, run = _command(
        db_session, scanner_scope, sample_organization.id, check_key=CheckKey.NUCLEI.value
    )
    targets = get_command_target_snapshot(db_session, command, run)

    assert [target["approvedValue"] for target in targets] == ["192.168.50.152"]


def test_a_host_serving_http_carries_the_http_tree(
    db_session, sample_organization, scanner_scope
):
    _fingerprint(db_session, sample_organization.id, "192.168.50.152", [{"port": 80, "service": "http"}])
    _fingerprint(db_session, sample_organization.id, "192.168.50.176", [])
    _fingerprint(db_session, sample_organization.id, "192.168.50.1", [])

    command, run = _command(
        db_session, scanner_scope, sample_organization.id, check_key=CheckKey.NUCLEI.value
    )
    target = get_command_target_snapshot(db_session, command, run)[0]

    assert "http" in target["templateTrees"]
    assert target["templateScopeReason"]


def test_a_host_with_no_web_server_carries_no_http_tree(
    db_session, sample_organization, scanner_scope
):
    """Where 82% of the pack is saved on a host that is genuinely up."""
    _fingerprint(db_session, sample_organization.id, "192.168.50.152", [{"port": 22, "service": "ssh"}])
    _fingerprint(db_session, sample_organization.id, "192.168.50.176", [])
    _fingerprint(db_session, sample_organization.id, "192.168.50.1", [])

    command, run = _command(
        db_session, scanner_scope, sample_organization.id, check_key=CheckKey.NUCLEI.value
    )
    target = get_command_target_snapshot(db_session, command, run)[0]

    assert "http" not in target["templateTrees"]
    assert "network" in target["templateTrees"]
    assert "ssh" in target["templateScopeReason"]


def test_a_host_never_fingerprinted_keeps_the_full_pack(
    db_session, sample_organization, scanner_scope
):
    """No fingerprint at all is not the same as nothing open, and must never be
    scoped down — that would be a guess, and the whole rule is evidence-based."""
    command, run = _command(
        db_session, scanner_scope, sample_organization.id, check_key=CheckKey.NUCLEI.value
    )
    targets = get_command_target_snapshot(db_session, command, run)

    assert len(targets) == len(DISCOVERED_IN_RANGE), "nothing is dropped on no evidence"
    for target in targets:
        assert "http" in target["templateTrees"]


def test_the_most_recent_fingerprint_wins(db_session, sample_organization, scanner_scope):
    """A host that was closed and has since opened a web server must get the
    http tree back — stale evidence silently suppressing it is the failure."""
    _fingerprint(db_session, sample_organization.id, "192.168.50.152", [])
    _fingerprint(db_session, sample_organization.id, "192.168.50.152", [{"port": 443, "service": "https"}])
    _fingerprint(db_session, sample_organization.id, "192.168.50.176", [])
    _fingerprint(db_session, sample_organization.id, "192.168.50.1", [])

    command, run = _command(
        db_session, scanner_scope, sample_organization.id, check_key=CheckKey.NUCLEI.value
    )
    targets = get_command_target_snapshot(db_session, command, run)

    assert [target["approvedValue"] for target in targets] == ["192.168.50.152"]
    assert "http" in targets[0]["templateTrees"]


def test_an_nmap_command_is_not_scoped_or_dropped(
    db_session, sample_organization, scanner_scope
):
    """Scoping belongs to the vulnerability stage alone. Dropping a host with no
    open port from a *discovery* command would stop discovery ever noticing that
    the host had opened one."""
    _fingerprint(db_session, sample_organization.id, "192.168.50.152", [])
    _fingerprint(db_session, sample_organization.id, "192.168.50.176", [])
    _fingerprint(db_session, sample_organization.id, "192.168.50.1", [])

    command, run = _command(
        db_session, scanner_scope, sample_organization.id, check_key=CheckKey.NMAP.value
    )
    targets = get_command_target_snapshot(db_session, command, run)

    assert [target["approvedValue"] for target in targets] == [APPROVED_RANGE]
    assert "templateTrees" not in targets[0]
