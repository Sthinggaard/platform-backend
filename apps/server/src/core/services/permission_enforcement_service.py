"""CA-07.3 — the server-side check that makes a permission profile real.

A profile nothing checks is documentation. The acceptance criterion says the
check is server-side, and this is it — written to **fail closed in every
direction**:

- **the subject itself withdrawn** → denied before the profile is even read
- no active profile at all → denied, not "allow, none configured yet"
- capability absent from the profile → denied
- Docker socket needed but not separately approved → denied, even when the
  profile is approved and the capability is present

The first of those was missing until CA-07.4 and is the reason this file
changed: a *revoked* Connector holding an approved profile passed every check,
because the profile and the Connector are separate records and only the profile
was consulted. A revocation that does not stop access is not a revocation. The
subject is asked first, and answers for itself — see
``PermissionSubjectBearer.permission_subject_inactive_reason``.

Every denial is audited. A refusal nobody can see afterwards is
indistinguishable from a call that was never made, and *"why did this return
nothing?"* is exactly the question a denial must be able to answer.

Separate from ``permission_profile_service`` (which owns the approval lifecycle)
because this is what CA-08 will call on every action, while that is what a person
calls a handful of times.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.constants.permission_profile_enums import (
    PROFILE_AUDIT_CAPABILITY_DENIED,
    PROFILE_ERROR_CAPABILITY_NOT_PERMITTED,
    PROFILE_ERROR_DOCKER_SOCKET_NOT_APPROVED,
    PROFILE_ERROR_NO_ACTIVE_PROFILE,
    PROFILE_ERROR_SERVICE_CONFIG_NOT_APPROVED,
    ConnectorCapability,
)
from src.core.constants.discovery_scope_proposal_enums import DiscoveryCapability
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.services.audit_service import append_audit_event
from src.core.services.permission_subject_service import PermissionSubjectBearer
from src.core.services.permission_profile_service import (
    PermissionProfileValidationError,
    get_active_profile,
)

# Capabilities that cannot be exercised without touching the Docker socket.
# Named by what the capability *does*, not by what kind of Connector asked for
# it — the rule is about the action, not the label on the caller.
DOCKER_SOCKET_CAPABILITIES = frozenset(
    {
        ConnectorCapability.LIST_CONTAINERS.value,
        ConnectorCapability.INSPECT_CONTAINER.value,
        ConnectorCapability.READ_IMAGE_METADATA.value,
    }
)

# The same shape, for the capability Søren ruled needs its own approval
# (2026-08-24). A frozenset of one rather than an ``==`` so the next capability
# that reads a file joins it here instead of adding a third branch below.
SERVICE_CONFIG_CAPABILITIES = frozenset({ConnectorCapability.READ_SERVICE_CONFIG.value})


class CapabilityNotPermittedError(PermissionProfileValidationError):
    """Raised when a Connector attempts something outside its approved profile.

    Its own type so a caller can tell "refused by policy" apart from "malformed
    request" — they need different handling and mean very different things to
    whoever reads the result.
    """


def assert_capability_permitted(
    db: Session,
    subject: PermissionSubjectBearer,
    capability: str,
    *,
    audit: bool = True,
) -> PermissionProfile:
    """Fail unless this Connector may do this, right now, under an approved profile.

    Returns the profile that authorised it, so a caller can record *which
    version* permitted the action rather than merely that something did.
    """
    # First, and before the profile is read: an approved grant on a withdrawn
    # subject authorises nothing. Checked here rather than at each call site
    # because a check callers must remember is a check that will be forgotten.
    inactive_reason = subject.permission_subject_inactive_reason
    if inactive_reason is not None:
        _deny(db, subject, capability, inactive_reason, audit=audit)

    profile = get_active_profile(
        db, organization_id=subject.organization_id, subject_id=subject.permission_subject_id
    )
    if profile is None:
        _deny(db, subject, capability, PROFILE_ERROR_NO_ACTIVE_PROFILE, audit=audit)

    granted = (
        profile.discovery_capabilities
        if capability in {item.value for item in DiscoveryCapability}
        else profile.capabilities
    )
    if capability not in (granted or []):
        _deny(
            db,
            subject,
            capability,
            PROFILE_ERROR_CAPABILITY_NOT_PERMITTED.format(capability=capability),
            audit=audit,
            profile=profile,
        )

    # The contract's own rule. Checked after the capability check so the denial
    # names the real reason: the capability *is* granted, and still may not run.
    if capability in DOCKER_SOCKET_CAPABILITIES and profile.docker_socket_approved_at is None:
        _deny(
            db,
            subject,
            capability,
            PROFILE_ERROR_DOCKER_SOCKET_NOT_APPROVED,
            audit=audit,
            profile=profile,
        )

    # Added here, at the one decision point, rather than in CA-08's inspection
    # code — a second place that decides what is permitted is exactly what
    # #248's structural test exists to prevent, and CA-08.3's criterion repeats.
    if capability in SERVICE_CONFIG_CAPABILITIES and profile.service_config_approved_at is None:
        _deny(
            db,
            subject,
            capability,
            PROFILE_ERROR_SERVICE_CONFIG_NOT_APPROVED,
            audit=audit,
            profile=profile,
        )

    return profile


def _deny(
    db: Session,
    subject: PermissionSubjectBearer,
    capability: str,
    reason: str,
    *,
    audit: bool,
    profile: PermissionProfile | None = None,
) -> None:
    if audit:
        append_audit_event(
            db,
            subject.organization_id,
            PROFILE_AUDIT_CAPABILITY_DENIED,
            metadata={
                "subject_id": subject.permission_subject_id,
                "capability": capability,
                "reason": reason,
                "profile_id": profile.id if profile else None,
            },
        )
    raise CapabilityNotPermittedError(reason)
