"""CA-07.3 — defining and approving a permission profile.

The approval lifecycle: draft → awaiting approval → active, superseded rather
than edited. A profile that could be widened in place would make *"what was
permitted when this ran?"* unanswerable after the fact, which is the whole
reason it is an object rather than a setting.

The server-side check that enforces an approved profile lives in
``permission_enforcement_service`` — it is called on every action, while this is
called a handful of times by a person.

The caller owns the transaction (commit).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.constants.permission_profile_enums import (
    PROFILE_AUDIT_APPROVED,
    PROFILE_AUDIT_DOCKER_SOCKET_APPROVED,
    PROFILE_AUDIT_SERVICE_CONFIG_APPROVED,
    PROFILE_AUDIT_DRAFTED,
    PROFILE_AUDIT_REJECTED,
    PROFILE_AUDIT_SUBMITTED,
    PROFILE_ERROR_DOCKER_SOCKET_NOT_REQUIRED,
    PROFILE_ERROR_NO_CAPABILITIES,
    PROFILE_ERROR_NOT_AWAITING_APPROVAL,
    PROFILE_ERROR_NOT_DRAFT,
    PROFILE_ERROR_UNKNOWN_CAPABILITY,
    ConnectorCapability,
    PermissionProfileStatus,
)
from src.core.constants.discovery_scope_proposal_enums import DiscoveryCapability
from src.core.model_defs.access_connector import AccessConnector
from src.core.services.permission_subject_service import PermissionSubjectBearer
from src.core.model_defs.common import utcnow
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.services.audit_service import append_audit_event

class PermissionProfileValidationError(ValueError):
    """Raised when a profile transition is invalid."""


def _validate_capabilities(capabilities: list[str]) -> list[str]:
    if not capabilities:
        raise PermissionProfileValidationError(PROFILE_ERROR_NO_CAPABILITIES)
    known = {c.value for c in ConnectorCapability}
    cleaned = []
    for capability in capabilities:
        if capability not in known:
            raise PermissionProfileValidationError(
                PROFILE_ERROR_UNKNOWN_CAPABILITY.format(capability=capability)
            )
        if capability not in cleaned:
            cleaned.append(capability)
    return cleaned


def _validate_discovery_capabilities(capabilities: list[str]) -> list[str]:
    known = {c.value for c in DiscoveryCapability}
    cleaned: list[str] = []
    for capability in capabilities:
        if capability not in known:
            raise PermissionProfileValidationError(
                PROFILE_ERROR_UNKNOWN_CAPABILITY.format(capability=capability)
            )
        if capability not in cleaned:
            cleaned.append(capability)
    return cleaned


def create_discovery_profile(
    db: Session,
    *,
    subject_id: str,
    organization_id: int,
    name: str,
    discovery_capabilities: list[str],
    prepared_by_user_id: int | None = None,
    note: str | None = None,
) -> PermissionProfile:
    cleaned = _validate_discovery_capabilities(discovery_capabilities)
    profile = PermissionProfile(
        organization_id=organization_id,
        subject_id=subject_id,
        name=name.strip(),
        capabilities=[],
        discovery_capabilities=cleaned,
        status=PermissionProfileStatus.DRAFT.value,
        prepared_by_user_id=prepared_by_user_id,
        note=note,
    )
    db.add(profile)
    db.flush()
    append_audit_event(
        db,
        organization_id,
        PROFILE_AUDIT_DRAFTED,
        actor_user_id=prepared_by_user_id,
        metadata=_metadata(profile),
    )
    return profile


def get_active_profile(
    db: Session, *, organization_id: int, subject_id: str
) -> PermissionProfile | None:
    """The Connector's profile currently in force, or ``None``."""
    return (
        db.query(PermissionProfile)
        .filter(
            PermissionProfile.organization_id == organization_id,
            PermissionProfile.subject_id == subject_id,
            PermissionProfile.status == PermissionProfileStatus.ACTIVE.value,
        )
        .order_by(PermissionProfile.version.desc())
        .first()
    )


# --- Lifecycle ------------------------------------------------------------


def create_profile_draft(
    db: Session,
    *,
    subject: PermissionSubjectBearer,
    name: str,
    capabilities: list[str],
    prepared_by_user_id: int | None = None,
    note: str | None = None,
) -> PermissionProfile:
    """Prepare a bounded capability set for a person to approve."""
    cleaned = _validate_capabilities(capabilities)
    if not name.strip():
        raise PermissionProfileValidationError("A permission profile needs a name.")

    latest = (
        db.query(PermissionProfile)
        .filter(
            PermissionProfile.organization_id == subject.organization_id,
            PermissionProfile.subject_id == subject.permission_subject_id,
        )
        .order_by(PermissionProfile.version.desc())
        .first()
    )
    profile = PermissionProfile(
        organization_id=subject.organization_id,
        subject_id=subject.permission_subject_id,
        name=name.strip(),
        capabilities=cleaned,
        status=PermissionProfileStatus.DRAFT.value,
        version=(latest.version + 1) if latest else 1,
        prepared_by_user_id=prepared_by_user_id,
        note=note,
    )
    db.add(profile)
    db.flush()
    append_audit_event(
        db,
        subject.organization_id,
        PROFILE_AUDIT_DRAFTED,
        actor_user_id=prepared_by_user_id,
        metadata=_metadata(profile),
    )
    return profile


def submit_profile(
    db: Session, profile: PermissionProfile, *, submitted_by_user_id: int | None = None
) -> PermissionProfile:
    if profile.status != PermissionProfileStatus.DRAFT.value:
        raise PermissionProfileValidationError(PROFILE_ERROR_NOT_DRAFT)
    profile.status = PermissionProfileStatus.AWAITING_APPROVAL.value
    profile.submitted_at = utcnow()
    db.add(profile)
    append_audit_event(
        db,
        profile.organization_id,
        PROFILE_AUDIT_SUBMITTED,
        actor_user_id=submitted_by_user_id,
        metadata=_metadata(profile),
    )
    return profile


def approve_profile(
    db: Session, profile: PermissionProfile, *, approved_by_user_id: int
) -> PermissionProfile:
    """Put a profile in force, superseding whatever it replaces.

    Deliberately does **not** grant Docker socket access, even when the profile
    contains container capabilities — that is its own decision, made separately.
    """
    if profile.status != PermissionProfileStatus.AWAITING_APPROVAL.value:
        raise PermissionProfileValidationError(PROFILE_ERROR_NOT_AWAITING_APPROVAL)

    predecessor = get_active_profile(
        db, organization_id=profile.organization_id, subject_id=profile.subject_id
    )
    profile.status = PermissionProfileStatus.ACTIVE.value
    profile.approved_by_user_id = approved_by_user_id
    profile.approved_at = utcnow()
    if predecessor is not None and predecessor.id != profile.id:
        predecessor.status = PermissionProfileStatus.SUPERSEDED.value
        predecessor.superseded_by_id = profile.id
        db.add(predecessor)
    db.add(profile)
    append_audit_event(
        db,
        profile.organization_id,
        PROFILE_AUDIT_APPROVED,
        actor_user_id=approved_by_user_id,
        metadata=_metadata(profile),
    )
    return profile


def reject_profile(
    db: Session, profile: PermissionProfile, *, rejected_by_user_id: int, rejection_reason: str
) -> PermissionProfile:
    if profile.status != PermissionProfileStatus.AWAITING_APPROVAL.value:
        raise PermissionProfileValidationError(PROFILE_ERROR_NOT_AWAITING_APPROVAL)
    if not rejection_reason.strip():
        raise PermissionProfileValidationError("A rejection reason is required.")
    profile.status = PermissionProfileStatus.WITHDRAWN.value
    profile.rejected_by_user_id = rejected_by_user_id
    profile.rejected_at = utcnow()
    profile.rejection_reason = rejection_reason.strip()
    db.add(profile)
    append_audit_event(
        db,
        profile.organization_id,
        PROFILE_AUDIT_REJECTED,
        actor_user_id=rejected_by_user_id,
        metadata=_metadata(profile),
    )
    return profile


def approve_docker_socket(
    db: Session,
    profile: PermissionProfile,
    connector: AccessConnector,
    *,
    approved_by_user_id: int,
) -> PermissionProfile:
    """The contract's separate, explicit approval for Docker socket access.

    Its own call, its own approver, its own audit event — so the trail can always
    distinguish "they approved the profile" from "they approved reaching the
    socket", which is the whole point of the rule.
    """
    if not connector.requires_docker_socket:
        raise PermissionProfileValidationError(PROFILE_ERROR_DOCKER_SOCKET_NOT_REQUIRED)
    profile.docker_socket_approved_by_user_id = approved_by_user_id
    profile.docker_socket_approved_at = utcnow()
    db.add(profile)
    append_audit_event(
        db,
        profile.organization_id,
        PROFILE_AUDIT_DOCKER_SOCKET_APPROVED,
        actor_user_id=approved_by_user_id,
        metadata=_metadata(profile),
    )
    return profile


def approve_service_config(
    db: Session,
    profile: PermissionProfile,
    *,
    approved_by_user_id: int,
) -> PermissionProfile:
    """CA-08.3 (#291) — the separate approval for reading deployed configuration.

    Søren, 2026-08-24, keeping ``read_service_config`` in CA-08's scope on the
    condition that it takes the Docker socket's treatment. Deployed configuration
    is where credentials live, so granting it must be its own decision and its
    own line in the audit trail.

    Unlike the socket, there is no "does this Connector declare it needs it?"
    precondition. The socket is a property of how a Connector is built; reading
    configuration is a choice about how far a person is willing to let deep
    verification look, and any Connector could be asked to do it.
    """
    profile.service_config_approved_by_user_id = approved_by_user_id
    profile.service_config_approved_at = utcnow()
    db.add(profile)
    append_audit_event(
        db,
        profile.organization_id,
        PROFILE_AUDIT_SERVICE_CONFIG_APPROVED,
        actor_user_id=approved_by_user_id,
        metadata=_metadata(profile),
    )
    return profile


def _metadata(profile: PermissionProfile) -> dict:
    return {
        "profile_id": profile.id,
        "subject_id": profile.subject_id,
        "version": profile.version,
        "status": profile.status,
        "capabilities": list(profile.capabilities or []),
    }


def list_profiles(
    db: Session, *, organization_id: int, subject_id: str
) -> list[PermissionProfile]:
    return (
        db.query(PermissionProfile)
        .filter(
            PermissionProfile.organization_id == organization_id,
            PermissionProfile.subject_id == subject_id,
        )
        .order_by(PermissionProfile.version.desc())
        .all()
    )
