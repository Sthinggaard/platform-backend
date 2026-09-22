"""CA-08.3 (#291) — an inspection cannot exceed the approved permission profile.

The contract's words: *technical evidence cannot exceed the approved access
boundary.* That is a claim about what the code is **capable** of, so it holds
structurally or not at all.

**This module decides nothing about what is permitted.** It asks
``permission_enforcement_service.assert_capability_permitted`` — the one decision
point, kept the only one by #248's structural tests — and then does the separate
job of turning a permitted capability into the exact command that answers it,
under Søren's option C (2026-08-24).

The order matters and is deliberate: *permission first, template second.* A
capability outside the profile is refused before this module looks at what it
would have run, so a denial is never contaminated by a template problem and the
audit trail names the real reason. The reverse order would let "we have no
command for that" mask "you were never allowed to ask".

**Nothing here executes anything.** It issues a signed instruction; #290 owns the
Collector that verifies the signature and runs it. That split is the whole point
of option C — the boundary is enforced by the signature, so the thing that runs
commands cannot widen its own boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import NoReturn

from sqlalchemy.orm import Session

from src.core.constants.verification_command_templates import (
    COMMAND_TEMPLATES,
    NOT_A_HOST_READ,
    SERVICE_CONFIG_TARGETS,
    parameter_names,
    parameter_pattern,
)
from src.core.constants.verification_inspection_enums import (
    PLATFORM_ANY,
    VERIFICATION_COMMAND_EXPIRY_SECONDS,
    VERIFICATION_COMMAND_SIGNATURE_VERSION,
    VERIFICATION_INSPECTION_AUDIT_AUTHORISED,
    VERIFICATION_INSPECTION_AUDIT_REFUSED,
    VERIFICATION_INSPECTION_ERROR_BAD_PARAMETER,
    VERIFICATION_INSPECTION_ERROR_MISSING_PARAMETER,
    VERIFICATION_INSPECTION_ERROR_NOT_A_HOST_READ,
    VERIFICATION_INSPECTION_ERROR_NO_SIGNING_KEY,
    VERIFICATION_INSPECTION_ERROR_NO_TEMPLATE,
    VERIFICATION_INSPECTION_ERROR_RUN_NOT_OPEN,
    VERIFICATION_INSPECTION_ERROR_UNKNOWN_CONFIG_TARGET,
    VERIFICATION_INSPECTION_ERROR_UNKNOWN_PARAMETER,
    VERIFICATION_INSPECTION_ERROR_UNKNOWN_PLATFORM,
    VerificationPlatform,
)
from src.core.constants.permission_profile_enums import ConnectorCapability
from src.core.constants.verification_run_enums import VERIFICATION_RUN_TERMINAL
from src.core.crypto import decrypt_command_signing_key
from src.core.model_defs.access_connector import AccessConnector
from src.core.model_defs.evidence_scanner import ScannerInstance
from src.core.model_defs.verification_run import VerificationRun
from src.core.services.audit_service import append_audit_event
from src.core.services.permission_enforcement_service import assert_capability_permitted


class InspectionRefusedError(ValueError):
    """The capability was permitted, and the inspection still cannot proceed.

    Its own type, distinct from ``CapabilityNotPermittedError``: "policy says
    no" and "we have no approved way to do that here" are different facts about
    the organisation, and collapsing them would tell an operator to go and change
    a permission profile that was never the problem.
    """


@dataclass(frozen=True)
class AuthorisedInspection:
    """A signed instruction to read one thing, on one host, once."""

    run_id: str
    organization_id: int
    asset_id: int
    connector_id: str
    capability: str
    platform: str
    argv: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    signature: str
    signature_version: str
    #: Which profile version authorised it — recorded so "what was this allowed
    #: to do?" survives that profile being superseded.
    permission_profile_id: str


def inspection_envelope(inspection: AuthorisedInspection, *, scanner_instance_id: str) -> dict:
    """The wire shape the Collector receives — and nothing more.

    Deliberately built by hand rather than by dumping the dataclass. The one
    property this function exists to hold is **negative**: there is no field for
    a credential, a key, a username or a password, because CA-07.2 settled that
    the platform cannot receive secret material rather than merely not sending
    it. The Collector already holds what it needs to log in; an envelope with a
    place to put a credential is an invitation to start putting one there.

    ``scannerInstanceId`` rides outside the signature for the same reason
    discovery's does: the Collector checks the command was issued for *it*
    before it spends a key derivation on verifying the signature.
    """
    return {
        "signature_version": inspection.signature_version,
        "signature": inspection.signature,
        "scanner_instance_id": scanner_instance_id,
        "run_id": inspection.run_id,
        "organization_id": inspection.organization_id,
        "asset_id": inspection.asset_id,
        "connector_id": inspection.connector_id,
        "capability": inspection.capability,
        "argv": list(inspection.argv),
        "issued_at": inspection.issued_at.isoformat(),
        "expires_at": inspection.expires_at.isoformat(),
    }


def authorise_inspection(
    db: Session,
    *,
    run: VerificationRun,
    connector: AccessConnector,
    capability: str,
    platform: str | None,
    parameters: dict[str, str] | None = None,
    config_target: str | None = None,
) -> AuthorisedInspection:
    """Permit one inspection, or refuse it — and record either way."""
    if run.status in VERIFICATION_RUN_TERMINAL:
        _refuse(db, run, capability, VERIFICATION_INSPECTION_ERROR_RUN_NOT_OPEN)

    # The one decision point. Raises CapabilityNotPermittedError, already
    # audited by the enforcement service, before anything below runs.
    profile = assert_capability_permitted(db, connector, capability)

    argv_template, resolved_platform = _resolve_template(db, run, capability, platform)
    supplied = _resolve_parameters(db, run, capability, parameters, config_target)
    argv = _substitute(db, run, capability, argv_template, supplied)

    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(seconds=VERIFICATION_COMMAND_EXPIRY_SECONDS)
    signature = _sign(
        db,
        run=run,
        connector=connector,
        capability=capability,
        argv=argv,
        issued_at=issued_at,
        expires_at=expires_at,
    )

    append_audit_event(
        db,
        run.organization_id,
        VERIFICATION_INSPECTION_AUDIT_AUTHORISED,
        metadata={
            "run_id": run.id,
            "asset_id": run.asset_id,
            "connector_id": connector.id,
            "capability": capability,
            "platform": resolved_platform,
            # The command itself, because "these exact commands ran on your
            # host" is the sentence option C was chosen to be able to say.
            "argv": list(argv),
            "profile_id": profile.id,
        },
    )

    return AuthorisedInspection(
        run_id=run.id,
        organization_id=run.organization_id,
        asset_id=run.asset_id,
        connector_id=connector.id,
        capability=capability,
        platform=resolved_platform,
        argv=argv,
        issued_at=issued_at,
        expires_at=expires_at,
        signature=signature,
        signature_version=VERIFICATION_COMMAND_SIGNATURE_VERSION,
        permission_profile_id=profile.id,
    )


def _resolve_template(
    db: Session, run: VerificationRun, capability: str, platform: str | None
) -> tuple[tuple[str, ...], str]:
    if capability in NOT_A_HOST_READ:
        _refuse(
            db,
            run,
            capability,
            VERIFICATION_INSPECTION_ERROR_NOT_A_HOST_READ.format(capability=capability),
        )

    by_platform = COMMAND_TEMPLATES.get(capability)
    if by_platform is None:
        _refuse(
            db,
            run,
            capability,
            VERIFICATION_INSPECTION_ERROR_NO_TEMPLATE.format(
                capability=capability, platform=platform or "unrecognised"
            ),
        )

    if PLATFORM_ANY in by_platform:
        return by_platform[PLATFORM_ANY], PLATFORM_ANY

    # Only now does the platform matter, and only now is it required to be one
    # we actually know. Checked here rather than at the top so a capability that
    # does not vary by platform is not blocked by a host we could not name.
    if platform not in {member.value for member in VerificationPlatform}:
        _refuse(db, run, capability, VERIFICATION_INSPECTION_ERROR_UNKNOWN_PLATFORM)

    template = by_platform.get(platform)
    if template is None:
        _refuse(
            db,
            run,
            capability,
            VERIFICATION_INSPECTION_ERROR_NO_TEMPLATE.format(
                capability=capability, platform=platform
            ),
        )
    return template, platform


def _resolve_parameters(
    db: Session,
    run: VerificationRun,
    capability: str,
    parameters: dict[str, str] | None,
    config_target: str | None,
) -> dict[str, str]:
    supplied = dict(parameters or {})

    # The caller never supplies a path. It names a target, and the path comes
    # from the approved set — Søren's condition on keeping read_service_config
    # in scope at all (2026-08-24).
    if capability == ConnectorCapability.READ_SERVICE_CONFIG.value:
        supplied.pop("config_path", None)
        path = SERVICE_CONFIG_TARGETS.get(config_target or "")
        if path is None:
            _refuse(
                db,
                run,
                capability,
                VERIFICATION_INSPECTION_ERROR_UNKNOWN_CONFIG_TARGET.format(
                    target=config_target or ""
                ),
            )
        supplied["config_path"] = path

    return supplied


def _substitute(
    db: Session,
    run: VerificationRun,
    capability: str,
    argv_template: tuple[str, ...],
    supplied: dict[str, str],
) -> tuple[str, ...]:
    required = parameter_names(argv_template)

    for name in supplied:
        if name not in required:
            _refuse(
                db,
                run,
                capability,
                VERIFICATION_INSPECTION_ERROR_UNKNOWN_PARAMETER.format(
                    parameter=name, capability=capability
                ),
            )

    resolved: dict[str, str] = {}
    for name in required:
        value = supplied.get(name)
        if value is None:
            _refuse(
                db,
                run,
                capability,
                VERIFICATION_INSPECTION_ERROR_MISSING_PARAMETER.format(
                    capability=capability, parameter=name
                ),
            )
        pattern = parameter_pattern(name)
        # A parameter with no declared pattern is refused rather than trusted.
        # The default has to be refusal, or adding a placeholder to a template
        # silently opens a hole nobody reviewed.
        if pattern is None or not pattern.fullmatch(value):
            _refuse(
                db,
                run,
                capability,
                VERIFICATION_INSPECTION_ERROR_BAD_PARAMETER.format(parameter=name),
            )
        resolved[name] = value

    return tuple(
        resolved[element[1:-1]] if element[1:-1] in resolved else element
        for element in argv_template
    )


def _sign(
    db: Session,
    *,
    run: VerificationRun,
    connector: AccessConnector,
    capability: str,
    argv: tuple[str, ...],
    issued_at: datetime,
    expires_at: datetime,
) -> str:
    # Filtered by organisation as well as id. The id already comes from a
    # connector that was scoped, so this is defence in depth rather than a
    # discovered hole — but "every query filters by organization_id" stops being
    # a rule the moment it has convenient exceptions.
    instance = (
        db.query(ScannerInstance)
        .filter(
            ScannerInstance.id == connector.scanner_instance_id,
            ScannerInstance.organization_id == run.organization_id,
        )
        .first()
    )
    # Discovery keeps a shared-secret fallback for instances activated before
    # per-instance keys existed. This does not inherit it: a new capability
    # starting life with a legacy weakness is how a compatibility shim becomes
    # permanent. No key means no inspection.
    if instance is None or instance.command_signing_key_encrypted is None:
        _refuse(db, run, capability, VERIFICATION_INSPECTION_ERROR_NO_SIGNING_KEY)

    secret = decrypt_command_signing_key(instance.id, instance.command_signing_key_encrypted)
    return hmac.new(secret, _signable_payload(
        run=run,
        connector=connector,
        capability=capability,
        argv=argv,
        issued_at=issued_at,
        expires_at=expires_at,
    ).encode("utf-8"), hashlib.sha256).hexdigest()


def _signable_payload(
    *,
    run: VerificationRun,
    connector: AccessConnector,
    capability: str,
    argv: tuple[str, ...],
    issued_at: datetime,
    expires_at: datetime,
) -> str:
    """Every field that must not change between signing and running.

    ``signatureVersion`` is first among them. The signing key is shared with
    discovery on purpose, so without a distinct domain string a discovery
    command's signature could be presented as an inspection's — see
    ``VERIFICATION_COMMAND_SIGNATURE_VERSION``.
    """
    return json.dumps(
        {
            "signatureVersion": VERIFICATION_COMMAND_SIGNATURE_VERSION,
            "runId": run.id,
            "organizationId": run.organization_id,
            "assetId": run.asset_id,
            "connectorId": connector.id,
            "capability": capability,
            "argv": list(argv),
            "issuedAt": issued_at.isoformat(),
            "expiresAt": expires_at.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _refuse(db: Session, run: VerificationRun, capability: str, reason: str) -> NoReturn:
    """Refuse, and leave the attempt behind.

    CA-08.3's criterion is explicit that the attempt is the interesting record —
    a refusal nobody can see afterwards is indistinguishable from a call that was
    never made.
    """
    append_audit_event(
        db,
        run.organization_id,
        VERIFICATION_INSPECTION_AUDIT_REFUSED,
        metadata={
            "run_id": run.id,
            "asset_id": run.asset_id,
            "capability": capability,
            "reason": reason,
        },
    )
    raise InspectionRefusedError(reason)
