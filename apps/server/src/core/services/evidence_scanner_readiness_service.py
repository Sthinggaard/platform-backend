"""Risklence Scanner setup — readiness evaluation + prepared read model
(spec §16/§17/§19).

Mirrors ``evidence_source_readiness_service``'s pattern: readiness is
always derived from underlying records, never a status a caller can set
directly. The returned ``state`` names the single next blocking step so a
future tenant UI can drive the setup wizard the same way
``processActivationViewModel`` already drives the process-activation
ladder — the wizard-step sub-states of spec §16 that this slice cannot
observe (``INSTALLATION_METHOD_SELECTED``/``SCANNER_INSTALLING``) collapse
into ``ACTIVATION_REQUIRED`` because installation is one atomic call here,
not a polled remote process.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from src.core.constants.evidence_scanner_enums import (
    SCANNER_PROFILE_CAPABILITIES,
    ScannerInstanceStatus,
    ScannerOperationStatus,
    ScannerReadiness,
    ScannerSetupState,
    ScannerTargetStatus,
    ScannerToolName,
    ScannerToolStatus,
)
from src.core.model_defs.evidence_scanner import ScannerDomainTarget, ScannerInstance, ScannerNetworkTarget
from src.core.model_defs.evidence_source import EvidenceSource
from src.core.models import User
from src.core.constants.evidence_scanner_enums import (
    CollectorComponentStatus,
    CollectorReadinessStatus,
)
from src.core.services.collector_readiness_service import (
    latest_readiness_report,
    component_is_ready,
    resolve_collector_readiness,
)

# Which tool must be available for which profile capability (spec §17: each
# tool "validates where [its capability] is enabled" — a profile that never
# turns vulnerability scanning on must never block readiness on Nuclei).
_CAPABILITY_REQUIRED_TOOLS: dict[str, tuple[str, ...]] = {
    "internalDiscoveryEnabled": (ScannerToolName.NMAP.value,),
    "externalDiscoveryEnabled": (ScannerToolName.SUBFINDER.value,),
    "vulnerabilityScanningEnabled": (ScannerToolName.NUCLEI.value, ScannerToolName.NUCLEI_TEMPLATES.value),
}


def required_tools_for(instance: ScannerInstance) -> set[str]:
    """The components this instance's *currently selected profile* actually
    needs. Public so the view can explain a block in terms of the same set the
    gate decides on — a message naming a component the profile does not require
    would be reporting a problem that is not one."""
    if instance.scan_profile is None:
        return set()
    capabilities = SCANNER_PROFILE_CAPABILITIES.get(instance.scan_profile, {})
    required: set[str] = set()
    for capability, tools in _CAPABILITY_REQUIRED_TOOLS.items():
        if capabilities.get(capability):
            required.update(tools)
    return required


def required_tools_available(db: Session, instance: ScannerInstance) -> bool:
    """True once every tool the instance's *currently selected profile*
    actually enables has validated as available — public so Step 4.1's
    discovery-run preconditions can reuse this exact per-profile mapping
    instead of re-deriving it (single source of truth for "does this
    scanner have what this profile needs")."""
    if instance.scan_profile is None:
        return False
    capabilities = SCANNER_PROFILE_CAPABILITIES.get(instance.scan_profile, {})
    required_tools: set[str] = set()
    for capability, tools in _CAPABILITY_REQUIRED_TOOLS.items():
        if capabilities.get(capability):
            required_tools.update(tools)
    if not required_tools:
        return True
    # CA-02.3 — read from the Collector's own reported readiness, never from
    # `instance.tool_status`. That column was written by both a real agent
    # self-check and a user clicking "Available", with nothing to tell them
    # apart, so it cannot answer "has this been verified?". It is kept for audit
    # continuity and is deliberately not consulted here.
    readiness = resolve_collector_readiness(db, instance)
    return all(component_is_ready(readiness, tool) for tool in required_tools)


@dataclass(frozen=True)
class ScannerSetupReadinessResult:
    ready: bool
    readiness: ScannerReadiness
    state: ScannerSetupState
    instance_id: str | None
    approved_domain_count: int = 0
    approved_network_count: int = 0
    blocking_reasons: list[str] = field(default_factory=list)
    # CA-02.3 — the Collector's own reported readiness, carried on the same
    # result the tool gate is computed from. Deliberately here rather than left
    # for a view to assemble from `instance.tool_status`: the screen said "your
    # Collector reported its components working" while this gate said they were
    # not validated, because the two were reading different sources. One object,
    # one answer.
    collector_readiness: str = CollectorReadinessStatus.UNKNOWN.value
    collector_components: list[dict] = field(default_factory=list)
    collector_reported_at: str | None = None
    collector_required_components: list[str] = field(default_factory=list)
    # CA-02.3 slice 3 — what the readiness view renders. Assembled here, on the
    # same object the gate is computed from, for the same reason as the fields
    # above: two sources for one question is how a screen ends up contradicting
    # the thing it is describing.
    collector_machine: dict = field(default_factory=dict)
    collector_version: str | None = None
    collector_template_pack_version: str | None = None
    collector_evidence_storage: str = CollectorComponentStatus.UNKNOWN.value
    collector_platform_link: str = CollectorComponentStatus.UNKNOWN.value
    collector_trigger: str | None = None
    #: The person who asked for the last check, resolved to a display name.
    #: None for a periodic check — most reports have no person behind them.
    collector_requested_by: str | None = None



def _requested_by_name(db: Session, report) -> str | None:
    """The person who asked for this check, as a name a user would recognise.

    Only ever set for a requested check — most reports have no person behind
    them, and inventing one would be exactly the kind of false attribution this
    story removes. A deleted user resolves to None rather than a dangling id.
    """
    if report is None or report.requested_by_user_id is None:
        return None
    user = db.query(User).filter(User.id == report.requested_by_user_id).first()
    if user is None:
        return None
    name = " ".join(part for part in (user.first_name, user.last_name) if part).strip()
    return name or user.email


def evaluate_scanner_readiness(db: Session, source: EvidenceSource) -> ScannerSetupReadinessResult:
    instance = db.query(ScannerInstance).filter(ScannerInstance.evidence_source_id == source.id).first()

    if instance is None:
        return ScannerSetupReadinessResult(
            ready=False,
            readiness=ScannerReadiness.MISSING,
            state=ScannerSetupState.ACTIVATION_REQUIRED,
            instance_id=None,
            blocking_reasons=["scanner_not_installed"],
        )

    if instance.status in (ScannerInstanceStatus.REVOKED.value, ScannerInstanceStatus.RETIRED.value):
        return ScannerSetupReadinessResult(
            ready=False,
            readiness=ScannerReadiness.BLOCKED,
            state=ScannerSetupState.ACTIVATION_REQUIRED,
            instance_id=instance.id,
            blocking_reasons=["scanner_access_revoked"],
        )

    approved_domain_count = (
        db.query(ScannerDomainTarget)
        .filter(
            ScannerDomainTarget.evidence_source_id == source.id,
            ScannerDomainTarget.status == ScannerTargetStatus.APPROVED.value,
        )
        .count()
    )
    approved_network_count = (
        db.query(ScannerNetworkTarget)
        .filter(
            ScannerNetworkTarget.evidence_source_id == source.id,
            ScannerNetworkTarget.status == ScannerTargetStatus.APPROVED.value,
        )
        .count()
    )

    collector = resolve_collector_readiness(db, instance)
    report = latest_readiness_report(db, instance)
    collector_fields = {
        "collector_readiness": collector.status,
        "collector_components": [
            {"componentKey": c.component_key, "status": c.status, "version": c.version}
            for c in collector.components
        ],
        "collector_reported_at": collector.reported_at.isoformat() if collector.reported_at else None,
        # What this profile actually needs, so the view explains a block using
        # the same set the gate decided on.
        "collector_required_components": sorted(required_tools_for(instance)),
        "collector_machine": {
            # Only what the Collector can actually vouch for. `operatingSystem`
            # is null inside a container by design, and the view renders the
            # kernel as the machine rather than showing an empty OS row.
            "kernel": instance.kernel_release,
            "architecture": instance.architecture,
            "operatingSystem": instance.os_name,
            "runtime": instance.container_runtime,
        },
        "collector_version": instance.scanner_version,
        "collector_template_pack_version": report.template_pack_version if report else None,
        "collector_evidence_storage": collector.evidence_storage_status,
        "collector_platform_link": collector.platform_connectivity_status,
        "collector_trigger": report.trigger if report else None,
        "collector_requested_by": _requested_by_name(db, report),
    }

    def _blocked(state: ScannerSetupState, reason: str) -> ScannerSetupReadinessResult:
        return ScannerSetupReadinessResult(
            ready=False,
            readiness=ScannerReadiness.IN_PROGRESS,
            state=state,
            instance_id=instance.id,
            approved_domain_count=approved_domain_count,
            approved_network_count=approved_network_count,
            blocking_reasons=[reason],
            **collector_fields,
        )

    if approved_domain_count + approved_network_count == 0:
        return _blocked(ScannerSetupState.DOMAIN_OR_NETWORK_SCOPE_REQUIRED, "no_approved_target")
    if instance.scan_profile is None:
        return _blocked(ScannerSetupState.SCAN_PROFILE_REQUIRED, "scan_profile_not_selected")
    if instance.scope_confirmed_at is None:
        return _blocked(ScannerSetupState.SCOPE_CONFIRMATION_REQUIRED, "scope_not_confirmed")
    if not required_tools_available(db, instance):
        return _blocked(ScannerSetupState.TOOL_VALIDATION_REQUIRED, "required_tools_not_validated")
    if instance.test_scan_status != ScannerOperationStatus.COMPLETED.value or instance.connection_verified_at is None:
        return _blocked(ScannerSetupState.TARGET_TEST_REQUIRED, "controlled_test_scan_not_passed")
    # UX-SETUP-03 (#129) — the last hidden precondition. discovery_run_service
    # refuses any run without an approved boundary; until this check existed,
    # setup did not know that and reported ready anyway. Imported inside the
    # function for the same reason discovery_run_service imports it that way:
    # the proposal service reaches back into environment detection, and a
    # module-level import closes a cycle.
    from src.core.services.discovery_scope_proposal_service import get_approved_scope

    if get_approved_scope(
        db, organization_id=instance.organization_id, evidence_source_id=instance.evidence_source_id
    ) is None:
        return _blocked(
            ScannerSetupState.DISCOVERY_BOUNDARY_APPROVAL_REQUIRED, "discovery_boundary_not_approved"
        )

    return ScannerSetupReadinessResult(
        **collector_fields,
        ready=True,
        readiness=ScannerReadiness.READY,
        state=ScannerSetupState.SCANNER_READY,
        instance_id=instance.id,
        approved_domain_count=approved_domain_count,
        approved_network_count=approved_network_count,
        blocking_reasons=[],
    )


@dataclass(frozen=True)
class PreparedScannerConfiguration:
    """Read-model handoff to Step 4 (spec §19) — Step 4 executes the first
    controlled discovery from this configuration. Never includes anything
    about actual scan results; those belong to Step 4/5."""

    organization_id: int
    evidence_source_id: str
    scanner_instance_id: str | None
    capabilities: dict[str, bool]
    approved_domains: list[dict]
    approved_networks: list[dict]
    scan_profile: str | None
    tool_status: dict[str, str]
    connection_verified: bool
    test_scan_passed: bool
    readiness: ScannerReadiness
    ready: bool


def build_prepared_scanner_configuration(db: Session, source: EvidenceSource) -> PreparedScannerConfiguration:
    instance = db.query(ScannerInstance).filter(ScannerInstance.evidence_source_id == source.id).first()
    readiness_result = evaluate_scanner_readiness(db, source)

    approved_domains = (
        db.query(ScannerDomainTarget)
        .filter(
            ScannerDomainTarget.evidence_source_id == source.id,
            ScannerDomainTarget.status == ScannerTargetStatus.APPROVED.value,
        )
        .all()
    )
    approved_networks = (
        db.query(ScannerNetworkTarget)
        .filter(
            ScannerNetworkTarget.evidence_source_id == source.id,
            ScannerNetworkTarget.status == ScannerTargetStatus.APPROVED.value,
        )
        .all()
    )

    capabilities = SCANNER_PROFILE_CAPABILITIES.get(instance.scan_profile, {}) if instance and instance.scan_profile else {}

    return PreparedScannerConfiguration(
        organization_id=source.organization_id,
        evidence_source_id=source.id,
        scanner_instance_id=instance.id if instance else None,
        capabilities=capabilities,
        approved_domains=[
            {"id": d.id, "domain": d.domain, "include_subdomains": d.include_subdomains} for d in approved_domains
        ],
        approved_networks=[
            {"id": n.id, "name": n.name, "cidr": n.cidr, "organisation_unit_id": n.organisation_unit_id}
            for n in approved_networks
        ],
        scan_profile=instance.scan_profile if instance else None,
        tool_status=(instance.tool_status or {}) if instance else {},
        connection_verified=bool(instance and instance.connection_verified_at is not None),
        test_scan_passed=bool(
            instance and instance.test_scan_status == ScannerOperationStatus.COMPLETED.value
        ),
        readiness=readiness_result.readiness,
        ready=readiness_result.ready,
    )
