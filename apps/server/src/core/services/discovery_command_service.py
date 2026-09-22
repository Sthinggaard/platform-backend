"""Step 4.1 — the signed command envelope: creation, delivery, and
acknowledgement (spec §14/§15/§16).

The platform never sends free-form commands — a ``ScannerCommand`` row is
the only thing ever delivered, always ``RUN_DISCOVERY`` today, always
scoped to one organisation/scanner instance/discovery run, always signed.

**Signing note (CA-04.1 — supersedes this module's earlier docstring,
which disclosed that client-side verification was impossible as designed):**
commands are signed with a per-scanner-instance key —
``crypto.derive_command_signing_key`` (real HKDF-SHA256) over the raw
activation token, salted by the scanner_instance_id — not the platform's
shared JWT secret. Both sides can reach this key: the server derives and
Fernet-encrypts it once, at the moment the raw token exists
(``evidence_scanner_service.install_scanner``/``regenerate_activation_token``,
before it is discarded), and the Collector re-derives the identical key
locally from the same raw token it already keeps in ``credentials.json``
(see ``apps/scanner/scanner_agent/command_signing.py``). This is real
defense-in-depth (a compromised relay holding only the Bearer credential
cannot forge a valid signature without also holding this derived key) *and*
supports non-repudiation (the platform can prove, and the Collector can
independently confirm, that a specific signed command was genuinely
issued) — resolved deliberately as both, not one or the other, with
invalid-signature and expired-command kept as distinct
``CommandRejectionCode`` values precisely so either failure mode can be
reasoned about independently in the audit trail.

Fallback: an instance activated before this shipped has no stored signing
key yet (``ScannerInstance.command_signing_key_encrypted is None``) — for
that instance only, signing/verification fall back to the previous
shared-secret scheme so existing installs are not broken until their next
activation/rotation naturally provisions a real per-instance key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import timedelta

from sqlalchemy.orm import Session

from src.core.constants.discovery_run_enums import (
    MAX_COMMAND_REVIVAL_DOWNTIME_SECONDS,
    DISCOVERY_COMMAND_EXPIRY_SECONDS,
    DISCOVERY_COMMAND_SIGNATURE_VERSION,
    STAGE_REQUIRES_CAPABILITY,
    STAGES_ALWAYS_ALLOWED,
    CommandRejectionCode,
    DiscoveryRunStatus,
    DiscoveryTargetType,
    ScannerCommandStatus,
    ScannerCommandType,
)
from src.core.constants.artefact_identity_enums import ArtefactIdentifierType
from src.core.constants.evidence_scanner_enums import ScannerTargetStatus
from src.core.crypto import decrypt_command_signing_key
from src.core.model_defs.common import to_utc_iso
from src.core.model_defs.discovery_run import DiscoveryRun, ScannerCommand
from src.core.model_defs.assets_runtime import AssetEvidenceSignal, AssetIdentifier
from src.core.model_defs.evidence_scanner import ScannerDomainTarget, ScannerInstance, ScannerNetworkTarget
from src.core.services.discovery_providers import ProviderNotRegisteredError, get_provider
from src.core.services.discovery_target_narrowing import narrow_targets_to_discovered_hosts
from src.core.services.discovery_template_scoping import scope_templates_for_host
from src.core.services.discovery_run_service import (
    DiscoveryRunValidationError,
    can_transition_discovery_run,
    transition_discovery_run,
    utcnow,
)
from src.core.utils.jwt_secrets import get_jwt_secret_bytes


class DiscoveryCommandError(ValueError):
    """Raised for a command-delivery/acknowledgement/status-update failure —
    kept distinct from DiscoveryRunValidationError since routes need to
    surface a rejection_code, not just a message."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


def _signable_payload(command: ScannerCommand) -> str:
    payload = {
        "commandId": command.id,
        "commandType": command.command_type,
        "organisationId": command.organization_id,
        "scannerInstanceId": command.scanner_instance_id,
        "discoveryRunId": command.discovery_run_id,
        # Step 4.2 — None for every Step 4.1 whole-run command (unchanged
        # signable shape for those); set for a per-job delegated command.
        # Safe to add: verify_command_signature is a standalone utility
        # (only ever called in tests today, never a production gate), and
        # commands expire in 15 minutes anyway, so there is no live command
        # whose already-stored signature this could invalidate in practice.
        "providerExecutionId": command.provider_execution_id,
        # CA-04.7 — snapshotted from the run at command-creation time (see
        # create_command_for_run/create_command_for_provider_execution),
        # both None for a command issued before this column existed or for
        # an org-wide, not-process-scoped run. Safe to add here for the
        # same reason providerExecutionId was: no live command's
        # already-stored signature could be invalidated by this addition.
        "businessProcessId": command.business_process_id,
        "businessServiceId": command.business_service_id,
        # 🐞 These signed the *naive* value while the API serialises the same
        # fields through ``UtcTimestamp``, which appends ``+00:00`` (#281). The
        # Collector signs what it received, so every signature mismatched and
        # **no discovery command could ever execute** — every provider failed
        # with ``command_signature_invalid``.
        #
        # ``to_utc_iso`` is the one definition of how a UTC instant leaves this
        # system, so signing through it is what keeps the two sides identical
        # by construction rather than by two places agreeing to format a
        # datetime the same way. The agent's ``_isoformat`` already passes
        # ``+00:00`` through untouched, so nothing changes on that side.
        "issuedAt": to_utc_iso(command.issued_at),
        "expiresAt": to_utc_iso(command.expires_at),
    }
    return json.dumps(payload, sort_keys=True)


def _signing_secret(db: Session, scanner_instance_id: str) -> bytes:
    """Per-instance HKDF-derived key when one has been provisioned
    (install_scanner/regenerate_activation_token); the legacy shared JWT
    secret otherwise, for an instance that has not (re)activated since
    CA-04.1 shipped — see this module's docstring."""
    instance = db.query(ScannerInstance).filter(ScannerInstance.id == scanner_instance_id).first()
    if instance is not None and instance.command_signing_key_encrypted is not None:
        return decrypt_command_signing_key(instance.id, instance.command_signing_key_encrypted)
    return get_jwt_secret_bytes()


def sign_command(db: Session, command: ScannerCommand) -> str:
    secret = _signing_secret(db, command.scanner_instance_id)
    return hmac.new(secret, _signable_payload(command).encode("utf-8"), hashlib.sha256).hexdigest()


def verify_command_signature(db: Session, command: ScannerCommand) -> bool:
    expected = sign_command(db, command)
    return hmac.compare_digest(expected, command.signature)


def command_type_for_run(run: DiscoveryRun) -> str:
    """CA-04.8 — a real, not cosmetic, command_type distinction: a
    process/service-scoped run (CA-04.7's business_process_id) gets its
    own command_type rather than being identifiable only by inspecting
    business_process_id separately. Shared by both command-creation paths
    (whole-run and per-job) so the two never drift apart."""
    if run.business_process_id is not None:
        return ScannerCommandType.RUN_PROCESS_SCOPED_DISCOVERY.value
    return ScannerCommandType.RUN_DISCOVERY.value


def create_command_for_run(db: Session, run: DiscoveryRun) -> ScannerCommand:
    """Approved run -> QUEUED -> COMMAND_AVAILABLE, with a signed,
    short-lived PENDING command created in the same step."""
    transition_discovery_run(run, DiscoveryRunStatus.QUEUED.value)
    run.queued_at = utcnow()

    now = utcnow()
    command = ScannerCommand(
        organization_id=run.organization_id,
        scanner_instance_id=run.scanner_instance_id,
        discovery_run_id=run.id,
        business_process_id=run.business_process_id,
        business_service_id=run.business_service_id,
        command_type=command_type_for_run(run),
        status=ScannerCommandStatus.PENDING.value,
        issued_at=now,
        expires_at=now + timedelta(seconds=DISCOVERY_COMMAND_EXPIRY_SECONDS),
        execution_policy={
            "maximumDurationSeconds": DISCOVERY_COMMAND_EXPIRY_SECONDS,
            "stopAtWindowEnd": True,
            "allowPartialUpload": True,
        },
        signature_version=DISCOVERY_COMMAND_SIGNATURE_VERSION,
        signature="",
    )
    db.add(command)
    db.flush()  # populate command.id (client-side UUID default) before it's signed
    command.signature = sign_command(db, command)

    transition_discovery_run(run, DiscoveryRunStatus.COMMAND_AVAILABLE.value)
    run.command_available_at = utcnow()
    db.add(run)
    return command


def _live_approved_target_ids(db: Session, run: DiscoveryRun) -> set[str]:
    """CA-04.2 — re-checks *current* approval state for every target
    frozen into run.target_snapshot at creation. A target approved then
    but excluded/disabled since must not still count as approved now —
    the frozen snapshot only ever proves what was true at creation time."""
    snapshot_ids_by_type: dict[str, list[str]] = {
        DiscoveryTargetType.DOMAIN.value: [],
        DiscoveryTargetType.NETWORK_RANGE.value: [],
    }
    for target in run.target_snapshot:
        target_type = target.get("targetType")
        if target_type in snapshot_ids_by_type:
            snapshot_ids_by_type[target_type].append(target["targetId"])

    live_ids: set[str] = set()
    if snapshot_ids_by_type[DiscoveryTargetType.DOMAIN.value]:
        live_ids.update(
            row.id
            for row in db.query(ScannerDomainTarget.id)
            .filter(
                ScannerDomainTarget.id.in_(snapshot_ids_by_type[DiscoveryTargetType.DOMAIN.value]),
                ScannerDomainTarget.status == ScannerTargetStatus.APPROVED.value,
            )
            .all()
        )
    if snapshot_ids_by_type[DiscoveryTargetType.NETWORK_RANGE.value]:
        live_ids.update(
            row.id
            for row in db.query(ScannerNetworkTarget.id)
            .filter(
                ScannerNetworkTarget.id.in_(snapshot_ids_by_type[DiscoveryTargetType.NETWORK_RANGE.value]),
                ScannerNetworkTarget.status == ScannerTargetStatus.APPROVED.value,
            )
            .all()
        )
    return live_ids


def get_live_target_snapshot(db: Session, run: DiscoveryRun) -> list[dict]:
    """CA-04.2 — target scope re-validated against live approval state,
    not the frozen run.target_snapshot alone. A target removed from
    approval after run creation is provably excluded from what this
    returns, even though it is still present in the stored snapshot."""
    live_ids = _live_approved_target_ids(db, run)
    return [target for target in run.target_snapshot if target["targetId"] in live_ids]


def _discovered_host_addresses(db: Session, organization_id: int) -> list[str]:
    """Every IP this organisation's artefacts have been observed under.

    Tenant-scoped in the query itself, never filtered afterwards — the same
    structural rule the rest of this module follows. Reads the identifier set
    rather than a scan result because that set is what survives a host being
    re-observed under a second address (CA-06.1), so a DHCP move does not make
    a known host invisible to the next vulnerability run.
    """
    return [
        row.identifier_value
        for row in db.query(AssetIdentifier.identifier_value)
        .filter(
            AssetIdentifier.organization_id == organization_id,
            AssetIdentifier.identifier_type == ArtefactIdentifierType.IP_ADDRESS.value,
        )
        .all()
    ]


def _fingerprinted_services_by_address(db: Session, organization_id: int) -> dict[str, list[dict]]:
    """The most recent service fingerprint held for each address.

    ``SERVICE_FINGERPRINTING`` already ran — ``VULNERABILITY_DISCOVERY`` depends
    on it in the stage DAG — and its result is stored on the evidence signal as
    ``host.services``. This reads that back so the vulnerability command can be
    scoped to what the host actually exposes.

    An address absent from this map has **never been fingerprinted**, which is
    not the same as one mapping to ``[]`` — that one was looked at and found to
    expose nothing. ``discovery_template_scoping`` treats the two oppositely, so
    the distinction must survive this query: a missing key and an empty list
    mean different things and neither may be normalised into the other.

    Tenant-scoped in the query itself, never filtered afterwards.
    """
    services_by_address: dict[str, list[dict]] = {}
    rows = (
        db.query(AssetEvidenceSignal.payload_json, AssetEvidenceSignal.observed_at)
        .filter(AssetEvidenceSignal.organization_id == organization_id)
        .order_by(AssetEvidenceSignal.observed_at.asc())
        .all()
    )
    for payload, _observed_at in rows:
        host = (payload or {}).get("host") if isinstance(payload, dict) else None
        if not isinstance(host, dict):
            continue
        address = host.get("ip")
        services = host.get("services")
        if not isinstance(address, str) or not isinstance(services, list):
            continue
        # Ascending order, so a later observation overwrites an earlier one and
        # the map ends up holding the most recent fingerprint per address.
        services_by_address[address.strip()] = services
    return services_by_address


def _scoped_target(target: dict, services_by_address: dict[str, list[dict]]) -> dict | None:
    """One narrowed host target, carrying the templates it is worth running.

    Returns ``None`` for a host scoped to no templates at all — fingerprinting
    found no open port, so there is nothing for a vulnerability template to
    connect to and the target is dropped rather than scanned. Measured on
    organisation 7 on 2026-09-07, that is 258 of 269 addresses: the whole of
    ``192.168.1.0/24`` carries an artefact per address, network and broadcast
    included, so narrowing to "discovered hosts" alone still handed nuclei 269
    targets. That is why the 2026-09-07 07:12 run still took 606 seconds.
    """
    address = str(target.get("approvedValue") or "").strip()
    scope = scope_templates_for_host(services_by_address.get(address))
    if not scope.trees:
        return None
    scoped = dict(target)
    scoped["templateTrees"] = list(scope.trees)
    scoped["templateScopeReason"] = scope.reason
    return scoped


def get_command_target_snapshot(db: Session, command: ScannerCommand, run: DiscoveryRun) -> list[dict]:
    """CA-09V — the targets *this* command carries.

    For every provider but one this is the live approved scope unchanged. A
    provider that declares ``targets_discovered_hosts`` (Nuclei) receives the
    hosts discovery has already found inside that scope instead of the scope
    itself: a vulnerability check answers what is wrong with what we found, and
    re-sweeping the range to find it again is what exhausted the timeout on
    every nuclei run since 2026-08-27.

    Asks the provider registry rather than testing ``check_key`` against a name
    — the registry's own rule is that callers never branch on provider identity,
    so a second provider needing this behaviour declares it and changes nothing
    here. An unregistered or absent check key falls back to the unnarrowed
    scope: narrowing is an optimisation of an already-approved scope, and
    failing to apply it must never fail a command.
    """
    live_targets = get_live_target_snapshot(db, run)
    if not command.check_key:
        return live_targets
    try:
        provider = get_provider(command.check_key)
    except ProviderNotRegisteredError:
        return live_targets
    if not provider.capabilities().targets_discovered_hosts:
        return live_targets
    narrowed = narrow_targets_to_discovered_hosts(
        live_targets, _discovered_host_addresses(db, command.organization_id)
    )
    # Narrowing answers *which hosts*; scoping answers *which templates*, and
    # without the second the first was not enough — see `_scoped_target`.
    services_by_address = _fingerprinted_services_by_address(db, command.organization_id)
    scoped = (_scoped_target(target, services_by_address) for target in narrowed)
    return [target for target in scoped if target is not None]


def _expire_command(db: Session, command: ScannerCommand, run: DiscoveryRun | None) -> None:
    """Expire a stale whole-run command, and expire the run only if the run was
    actually waiting on it.

    BUG-DISC-04. The old code pushed the run to EXPIRED whenever the command
    expired, guarded only by "is the run already cancelled/expired". That is
    illegal from RUNNING — the Step 4.2 pipeline's own state — so
    ``transition_discovery_run`` raised, out of an agent-facing route with no
    handler, and ``commands/next`` returned 500 on *every* poll cycle from then
    on. The Collector could not drain past the poisoned command, so one stale
    command disabled discovery for that scanner permanently.

    The semantics, chosen rather than compiled: expiring a command does not mean
    the run expired. It means nobody claimed this command in time.

    * A run **waiting on the command** (QUEUED / COMMAND_AVAILABLE /
      AWAITING_APPROVAL — exactly the states from which EXPIRED is legal) has
      genuinely expired, because the command was the work it was waiting for.
    * A **RUNNING** run is driven by its DiscoveryExecutionPlan, not by this
      envelope. A leftover whole-run command going stale says nothing about it,
      and marking it EXPIRED would kill a healthy run.
    * A terminal run has nothing left to say.

    Reading that off the transition table rather than re-encoding a state list
    here keeps one authority for what is legal, so this cannot drift when the
    table changes.
    """
    command.status = ScannerCommandStatus.EXPIRED.value
    db.add(command)
    if run is not None and can_transition_discovery_run(run, DiscoveryRunStatus.EXPIRED.value):
        transition_discovery_run(run, DiscoveryRunStatus.EXPIRED.value)
        db.add(run)


def _reject_command_for_run(db: Session, command: ScannerCommand, run: DiscoveryRun | None, *, code: str) -> None:
    """Shared rejection path for a command failing an integrity check
    (signature, target re-validation) before ever reaching the Collector —
    same shape as the pre-existing expiry-rejection branch, generalised so
    CA-04.2 doesn't duplicate it a third time.

    🐞 BUG-DISC-04's twin, and exactly the drift ``_expire_command``'s docstring
    warned about. This guarded a hardcoded list — CANCELLED and EXPIRED — which
    omitted FAILED. A command rejected against an already-failed run therefore
    attempted ``failed -> failed``, ``transition_discovery_run`` raised out of
    an agent-facing route, and ``commands/next`` returned 422 on *every*
    subsequent poll. The Collector could not drain past it, so one stale
    delivered command disabled discovery for that scanner permanently — the
    same permanent-stall shape, reached through the sibling function.

    Now asks the transition table instead of restating it, so there is one
    authority for what is legal and this cannot drift again. Rejecting a command
    against a run that is already finished is a no-op on the run: the run has
    nothing left to say.
    """
    command.status = ScannerCommandStatus.REJECTED.value
    command.rejection_code = code
    db.add(command)
    if run is not None and can_transition_discovery_run(run, DiscoveryRunStatus.FAILED.value):
        transition_discovery_run(run, DiscoveryRunStatus.FAILED.value)
        run.failed_at = utcnow()
        run.failure_code = code
        db.add(run)


def get_next_command_for_scanner(db: Session, instance: ScannerInstance) -> ScannerCommand | None:
    """Scanner-facing poll (spec §15). Resolves the scanner's organisation
    and instance from its own authenticated credential — the caller never
    supplies an organisation id that gets trusted independently."""
    now = utcnow()
    pending = (
        db.query(ScannerCommand)
        .filter(
            ScannerCommand.scanner_instance_id == instance.id,
            ScannerCommand.status == ScannerCommandStatus.PENDING.value,
        )
        .order_by(ScannerCommand.issued_at.asc())
        .all()
    )
    for command in pending:
        run = db.query(DiscoveryRun).filter(DiscoveryRun.id == command.discovery_run_id).first()

        if command.expires_at <= now:
            _expire_command(db, command, run)
            # Move on to the next pending command rather than failing the poll:
            # a stale command must never stop a Collector from receiving live
            # work behind it.
            continue
        # CA-04.1 — real production use of verify_command_signature (until
        # now called only in tests): a defense-in-depth integrity check that
        # the stored envelope hasn't been altered between creation and
        # delivery, independent of whatever the Collector checks on its own
        # side. A command that fails this check is not corrected or
        # re-signed — it is rejected outright, exactly as if a tampered
        # command had come back from the Collector itself.
        if not verify_command_signature(db, command):
            _reject_command_for_run(db, command, run, code=CommandRejectionCode.COMMAND_SIGNATURE_INVALID.value)
            continue
        # CA-04.2 — target scope re-validated against live approval state
        # at the moment of delivery, not trusted from run creation alone.
        # If every target frozen into the run has since been excluded,
        # there is nothing left this command could legitimately discover —
        # reject it outright rather than deliver an effectively-empty scope.
        if run is not None and not get_live_target_snapshot(db, run):
            _reject_command_for_run(db, command, run, code=CommandRejectionCode.TARGET_NOT_LOCALLY_APPROVED.value)
            continue
        command.status = ScannerCommandStatus.DELIVERED.value
        command.delivered_at = now
        db.add(command)
        return command
    return None


def acknowledge_command(
    db: Session,
    instance: ScannerInstance,
    command_id: str,
    *,
    accepted: bool,
    rejection_code: str | None = None,
    rejection_message: str | None = None,
    scanner_runtime_version: str | None = None,
) -> ScannerCommand:
    command = (
        db.query(ScannerCommand)
        .filter(ScannerCommand.id == command_id, ScannerCommand.scanner_instance_id == instance.id)
        .first()
    )
    if command is None:
        raise DiscoveryCommandError("Command not found for this scanner instance.", code="scanner_instance_mismatch")

    # Idempotent: a duplicate acknowledgement of an already-settled command
    # returns the existing result instead of erroring (spec's own
    # "duplicate command acknowledgement" test scenario).
    if command.status in (ScannerCommandStatus.ACKNOWLEDGED.value, ScannerCommandStatus.REJECTED.value):
        return command

    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == command.discovery_run_id).first()

    if command.expires_at <= utcnow():
        _expire_command(db, command, run)
        # Still an error for *this* acknowledgement — the Collector is telling us
        # about a command that is no longer valid — but a 4xx the route already
        # handles, not the unhandled transition error that used to escape first.
        raise DiscoveryCommandError("This command has expired.", code="command_expired")

    if run is not None and accepted and not get_live_target_snapshot(db, run):
        # CA-04.2 — re-checked again here, not only at delivery: closes the
        # narrow window between delivery and acknowledgement in which a
        # target's approval could be revoked. The Collector's own
        # accepted=True is not the last word if nothing it was approved to
        # touch is still approved.
        accepted = False
        rejection_code = CommandRejectionCode.TARGET_NOT_LOCALLY_APPROVED.value
        rejection_message = "Target scope is no longer approved."

    command.acknowledged_at = utcnow()
    command.accepted = accepted
    command.rejection_code = rejection_code
    command.rejection_message = rejection_message
    command.scanner_runtime_version = scanner_runtime_version

    # Step 4.2 — a command created for one delegated ProviderExecution job
    # never drives the whole DiscoveryRun's status (a run's execution plan
    # may have several concurrent jobs); only the job itself changes.
    # Local import to avoid a circular top-level import between these two
    # sibling command-lifecycle modules — both are fully loaded by the time
    # this call happens.
    if command.provider_execution_id is not None:
        from src.core.services.discovery_execution_command_service import (
            handle_provider_execution_acknowledgement,
        )

        command.status = ScannerCommandStatus.ACKNOWLEDGED.value if accepted else ScannerCommandStatus.REJECTED.value
        handle_provider_execution_acknowledgement(db, command, accepted=accepted, rejection_code=rejection_code)
        db.add(command)
        return command

    if run is not None:
        # A run that is cancelling, or already finished, cannot be dragged back
        # into ACKNOWLEDGED by a command the Collector happens to still be
        # holding. Before this check that transition simply raised — out of an
        # agent-facing route whose only handler is for DiscoveryCommandError —
        # so acknowledging any command against a cancelling run returned 500 and
        # the agent's loop died on it. Observed live: "Error: …/acknowledge
        # failed (500)" with the run in CANCELLATION_REQUESTED.
        if accepted and not can_transition_discovery_run(
            run, DiscoveryRunStatus.ACKNOWLEDGED.value
        ):
            command.status = ScannerCommandStatus.REJECTED.value
            command.accepted = False
            command.rejection_code = CommandRejectionCode.RUN_NOT_ACCEPTING_WORK.value
            command.rejection_message = "This discovery is no longer accepting work."
            db.add(command)
            raise DiscoveryCommandError(
                "This discovery is no longer accepting work.",
                code=CommandRejectionCode.RUN_NOT_ACCEPTING_WORK.value,
            )

        if accepted:
            command.status = ScannerCommandStatus.ACKNOWLEDGED.value
            transition_discovery_run(run, DiscoveryRunStatus.ACKNOWLEDGED.value)
            run.acknowledged_at = utcnow()
        elif can_transition_discovery_run(run, DiscoveryRunStatus.FAILED.value):
            command.status = ScannerCommandStatus.REJECTED.value
            transition_discovery_run(run, DiscoveryRunStatus.FAILED.value)
            run.failed_at = utcnow()
            run.failure_code = rejection_code or "command_rejected"
            run.failure_message = rejection_message
        else:
            # Rejected against a run that can no longer fail (cancelling or
            # already terminal): record it on the command and leave the run's
            # real outcome alone.
            command.status = ScannerCommandStatus.REJECTED.value
        db.add(run)

    db.add(command)
    return command


def _validate_stage(run: DiscoveryRun, stage: str) -> None:
    if stage in STAGES_ALWAYS_ALLOWED:
        return
    required_capability = STAGE_REQUIRES_CAPABILITY.get(stage)
    if required_capability is None or not run.profile_snapshot.get(required_capability):
        raise DiscoveryCommandError(
            f"Stage '{stage}' is not enabled by this run's scan profile.", code="capability_unavailable"
        )


def record_status_update(
    db: Session, instance: ScannerInstance, discovery_run_id: str, *, status: str | None, stage: str | None
) -> DiscoveryRun:
    """Lifecycle/stage updates only (spec §21) — no technical observation
    payload is accepted or parsed here; that's Step 4.3+."""
    run = (
        db.query(DiscoveryRun)
        .filter(DiscoveryRun.id == discovery_run_id, DiscoveryRun.scanner_instance_id == instance.id)
        .first()
    )
    if run is None:
        raise DiscoveryCommandError("Discovery run not found for this scanner instance.", code="organisation_mismatch")

    if stage is not None:
        _validate_stage(run, stage)
        run.current_stage = stage

    if status is not None:
        try:
            transition_discovery_run(run, status)
        except DiscoveryRunValidationError as exc:
            raise DiscoveryCommandError(str(exc), code="invalid_status_transition") from exc
        if status == DiscoveryRunStatus.RUNNING.value and run.started_at is None:
            run.started_at = utcnow()
        elif status in (DiscoveryRunStatus.COMPLETED.value, DiscoveryRunStatus.PARTIALLY_COMPLETED.value):
            run.completed_at = utcnow()
        elif status == DiscoveryRunStatus.FAILED.value:
            run.failed_at = utcnow()
        elif status == DiscoveryRunStatus.CANCELLED.value:
            run.cancelled_at = utcnow()

    db.add(run)
    return run


#: As a timedelta, resolved once rather than reconstructed per call.
MAX_COMMAND_REVIVAL_DOWNTIME = timedelta(seconds=MAX_COMMAND_REVIVAL_DOWNTIME_SECONDS)


def revive_commands_after_downtime(
    db: Session, instance: ScannerInstance, *, offline_for: timedelta
) -> list[ScannerCommand]:
    """Give pending commands their window back after the Collector was down.

    UX-DISC-06. Command expiry is a safety property: it stops a scan running
    against someone's network long after they asked for it. But it was measured
    in wall-clock time from issue, while the only thing that ever evaluates it
    is the Collector's own poll — so it punished exactly the case the platform
    had just told the user to fix.

    The numbers made that concrete. A command expires after 15 minutes; a
    heartbeat goes stale after 10. The panel tells the user their Collector is
    stopped at t+10, and at t+15 the work is forfeit — so someone who read the
    message, found the machine and started the agent at t+20 lost their run
    *because* they did what was asked, and the loss landed on the very poll that
    proved they had fixed it.

    So expiry now measures **opportunity, not elapsed time**: time the Collector
    spent offline is time it could not have taken the command, and does not
    count. The property is kept where it actually protects — a Collector that is
    online and ignoring its queue still lets commands expire.

    Bounded by ``MAX_COMMAND_REVIVAL_DOWNTIME``. Reviving a week-old discovery
    because a Collector came back would be its own surprise: the person who
    asked for it has long since moved on, and a scan starting unannounced is
    the outcome expiry exists to prevent.
    """
    if offline_for > MAX_COMMAND_REVIVAL_DOWNTIME:
        return []

    now = utcnow()
    pending = (
        db.query(ScannerCommand)
        .filter(
            ScannerCommand.scanner_instance_id == instance.id,
            ScannerCommand.status == ScannerCommandStatus.PENDING.value,
        )
        .all()
    )

    revived: list[ScannerCommand] = []
    for command in pending:
        # Only ones the downtime actually cost. A command still inside its
        # window needs nothing, and moving its deadline would quietly extend
        # every command on every reconnect.
        if command.expires_at > now:
            continue
        command.expires_at = now + timedelta(seconds=DISCOVERY_COMMAND_EXPIRY_SECONDS)
        # `expiresAt` is inside the signed payload, so moving the deadline
        # without re-signing makes the command fail its own integrity check at
        # the next poll — and `get_next_command_for_scanner` does not treat that
        # as a stale command, it rejects it as *tampered*. Reviving the work
        # would have turned "your run quietly expired" into "your run was
        # refused as altered", which is both worse and alarming. The platform is
        # the signer, so re-signing its own deliberate change is correct.
        command.signature = sign_command(db, command)
        db.add(command)
        revived.append(command)

    return revived
