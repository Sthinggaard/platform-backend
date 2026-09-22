"""CA-05.B — propose a discovery boundary, and let a human approve it.

The system proposes; a human decides. Three rules from the contract are enforced
here rather than left to callers, because each one is a way the boundary could
silently widen:

1. A proposal may never include a value a human has excluded.
2. A proposal may never grant a capability the scanner's own profile forbids —
   the permission profile narrows, never widens.
3. Only the Technical Setup Owner or the manager tier may approve (never a
   consultant — see _require_boundary_approver), and an approved proposal is
   immutable. Changing scope means proposing again and superseding the old row.

Proposing is not scanning and must not start one: nothing here creates a
DiscoveryRun or touches the Collector.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from src.core.constants.discovery_environment_enums import EnvironmentCoverageState
from src.core.constants.discovery_scope_proposal_enums import (
    ALLOWED_SCOPE_PROPOSAL_TRANSITIONS,
    CAPABILITY_PROFILE_KEYS,
    SCOPE_PROPOSAL_AUDIT_APPROVED,
    SCOPE_PROPOSAL_AUDIT_PROPOSED,
    SCOPE_PROPOSAL_AUDIT_REJECTED,
    SCOPE_PROPOSAL_AUDIT_SUPERSEDED,
    DiscoveryScopeProposalStatus,
)
from src.core.model_defs.common import utcnow
from src.core.model_defs.discovery_scope_proposal import DiscoveryScopeProposal
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.model_defs.tenant_identity import User
from src.core.model_defs.tenant_org import Organization
from src.core.roles import MANAGER_ROLES, UserRole
from src.core.services.discovery_environment_detection_service import detect_environment
from src.core.constants.permission_profile_enums import PermissionProfileStatus, PermissionSubjectKind
from src.core.services.permission_profile_service import (
    approve_profile,
    create_discovery_profile,
    reject_profile,
    submit_profile,
)
from src.core.services.permission_subject_service import register_permission_subject


class ScopeProposalError(Exception):
    """A proposal rule was violated. Distinct from ValueError so callers can
    map it to a 4xx without swallowing genuine programming errors."""


@dataclass(frozen=True)
class ProposalDecision:
    proposal_id: str
    status: str
    decided_by_user_id: int | None


def build_scope_proposal(
    db: Session,
    *,
    organization_id: int,
    evidence_source_id: str,
    profile_snapshot: dict,
    requested_capabilities: list[str] | None = None,
) -> DiscoveryScopeProposal:
    """Propose a boundary from what the organisation already has on record.

    Inclusions come from environment detection's *proposable* candidates only —
    anything already covered needs no decision, and anything explicitly excluded
    must never be re-offered (re-proposing it would let the system quietly
    overturn a human's exclusion).
    """
    environment = detect_environment(
        db, organization_id=organization_id, evidence_source_id=evidence_source_id
    )

    exclusions = sorted(
        {
            candidate.value
            for candidate in environment.candidates
            if candidate.coverage_state == EnvironmentCoverageState.EXPLICITLY_EXCLUDED.value
        }
    )
    inclusions = sorted({candidate.value for candidate in environment.proposable})

    # Belt and braces: detection already filters these out, but an exclusion
    # leaking into inclusions is the single most damaging failure this service
    # can have, so it is re-checked rather than assumed.
    overlap = set(inclusions) & set(exclusions)
    if overlap:
        raise ScopeProposalError(
            f"Refusing to propose values that are explicitly excluded: {sorted(overlap)}"
        )

    capabilities = _resolve_capabilities(profile_snapshot, requested_capabilities)

    rationale = {
        candidate.value: candidate.rationale
        for candidate in environment.proposable
    }

    _supersede_open_proposals(
        db, organization_id=organization_id, evidence_source_id=evidence_source_id
    )

    subject = register_permission_subject(
        db, organization_id=organization_id, subject_kind=PermissionSubjectKind.DISCOVERY_SCOPE_PROPOSAL
    )
    profile = create_discovery_profile(
        db,
        subject_id=subject.id,
        organization_id=organization_id,
        name="Discovery scope proposal",
        discovery_capabilities=capabilities,
    )
    submit_profile(db, profile)

    proposal = DiscoveryScopeProposal(
        organization_id=organization_id,
        evidence_source_id=evidence_source_id,
        permission_subject_id=subject.id,
        permission_profile_id=profile.id,
        status=DiscoveryScopeProposalStatus.AWAITING_APPROVAL.value,
        inclusions=inclusions,
        exclusions=exclusions,
        checks=capabilities,
        rationale=rationale,
        proposed_at=utcnow(),
    )
    db.add(proposal)
    db.flush()

    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=None,
            event_type=SCOPE_PROPOSAL_AUDIT_PROPOSED,
            metadata_json={
                "proposalId": proposal.id,
                "evidenceSourceId": evidence_source_id,
                "inclusionCount": len(inclusions),
                "exclusionCount": len(exclusions),
                "capabilities": capabilities,
            },
        )
    )
    return proposal


def approve_scope_proposal(
    db: Session,
    *,
    organization_id: int,
    proposal_id: str,
    actor_user_id: int,
    note: str | None = None,
) -> ProposalDecision:
    """Approve a proposed boundary. Technical Setup Owner or manager tier."""
    decision = _decide(
        db,
        organization_id=organization_id,
        proposal_id=proposal_id,
        actor_user_id=actor_user_id,
        note=note,
        target_status=DiscoveryScopeProposalStatus.APPROVED.value,
        audit_event=SCOPE_PROPOSAL_AUDIT_APPROVED,
    )
    proposal = db.get(DiscoveryScopeProposal, proposal_id)
    if proposal is not None:
        profile = db.get(PermissionProfile, proposal.permission_profile_id)
        if profile is not None:
            approve_profile(db, profile, approved_by_user_id=actor_user_id)

    # CA-06.5 — the boundary now binds the inventory, not just the next scan.
    # Applied here because this is the moment the answer changes for artefacts
    # nobody is about to re-scan: without it, approving an exclusion left every
    # already-discovered artefact inside it sitting in the inventory, and
    # lifting an exclusion never released the ones it had withdrawn.
    #
    # Imported locally to keep the boundary services free of an import cycle —
    # artefact_boundary_service reads this module's `get_approved_scope`.
    from src.core.services.artefact_boundary_service import apply_boundary_to_inventory

    proposal = db.get(DiscoveryScopeProposal, proposal_id)
    if proposal is not None and proposal.organization_id == organization_id:
        apply_boundary_to_inventory(
            db,
            organization_id=organization_id,
            evidence_source_id=proposal.evidence_source_id,
            actor_user_id=actor_user_id,
        )

    return decision


def reject_scope_proposal(
    db: Session,
    *,
    organization_id: int,
    proposal_id: str,
    actor_user_id: int,
    note: str | None = None,
) -> ProposalDecision:
    """Reject a proposed boundary. Technical Setup Owner or manager tier."""
    decision = _decide(
        db,
        organization_id=organization_id,
        proposal_id=proposal_id,
        actor_user_id=actor_user_id,
        note=note,
        target_status=DiscoveryScopeProposalStatus.REJECTED.value,
        audit_event=SCOPE_PROPOSAL_AUDIT_REJECTED,
    )
    proposal = db.get(DiscoveryScopeProposal, proposal_id)
    if proposal is not None:
        profile = db.get(PermissionProfile, proposal.permission_profile_id)
        if profile is not None:
            reject_profile(
                db,
                profile,
                rejected_by_user_id=actor_user_id,
                rejection_reason=note or "Discovery scope proposal rejected.",
            )
    return decision


def get_approved_scope(
    db: Session, *, organization_id: int, evidence_source_id: str
) -> DiscoveryScopeProposal | None:
    """The boundary currently in force, if any."""
    return (
        db.query(DiscoveryScopeProposal)
        .filter(
            DiscoveryScopeProposal.organization_id == organization_id,
            DiscoveryScopeProposal.evidence_source_id == evidence_source_id,
            DiscoveryScopeProposal.status == DiscoveryScopeProposalStatus.APPROVED.value,
        )
        .order_by(DiscoveryScopeProposal.decided_at.desc())
        .first()
    )


def get_current_scope_proposal(
    db: Session, *, organization_id: int, evidence_source_id: str
) -> DiscoveryScopeProposal | None:
    """The proposal the reviewer should currently be looking at.

    Returns an approved boundary if one is in force, otherwise one still
    awaiting a decision. Superseded and rejected rows are history and are never
    surfaced — but a *pending* proposal must be, or nobody can approve it.
    """
    return (
        db.query(DiscoveryScopeProposal)
        .filter(
            DiscoveryScopeProposal.organization_id == organization_id,
            DiscoveryScopeProposal.evidence_source_id == evidence_source_id,
            DiscoveryScopeProposal.status.in_(
                (
                    DiscoveryScopeProposalStatus.APPROVED.value,
                    DiscoveryScopeProposalStatus.AWAITING_APPROVAL.value,
                )
            ),
        )
        # Approved outranks pending: once a boundary is in force it is the one
        # that governs discovery, even if a newer proposal is open behind it.
        .order_by(
            (DiscoveryScopeProposal.status == DiscoveryScopeProposalStatus.APPROVED.value).desc(),
            DiscoveryScopeProposal.proposed_at.desc(),
        )
        .first()
    )


def _decide(
    db: Session,
    *,
    organization_id: int,
    proposal_id: str,
    actor_user_id: int,
    note: str | None,
    target_status: str,
    audit_event: str,
) -> ProposalDecision:
    proposal = (
        db.query(DiscoveryScopeProposal)
        .filter(
            DiscoveryScopeProposal.id == proposal_id,
            DiscoveryScopeProposal.organization_id == organization_id,
        )
        .first()
    )
    if proposal is None:
        raise ScopeProposalError("Scope proposal not found for this organisation.")

    _require_boundary_approver(db, organization_id=organization_id, actor_user_id=actor_user_id)

    allowed = ALLOWED_SCOPE_PROPOSAL_TRANSITIONS.get(proposal.status, frozenset())
    if target_status not in allowed:
        raise ScopeProposalError(
            f"Cannot move a {proposal.status} scope proposal to {target_status}."
        )

    proposal.status = target_status
    proposal.decided_by_user_id = actor_user_id
    proposal.decided_at = utcnow()
    proposal.decision_note = note
    db.add(proposal)

    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            event_type=audit_event,
            metadata_json={
                "proposalId": proposal.id,
                "evidenceSourceId": proposal.evidence_source_id,
                "note": note,
            },
        )
    )
    return ProposalDecision(
        proposal_id=proposal.id, status=target_status, decided_by_user_id=actor_user_id
    )


def _require_boundary_approver(
    db: Session, *, organization_id: int, actor_user_id: int
) -> None:
    """Who may sign off a discovery boundary.

    The Technical Setup Owner (the contract's named approver) or the
    manager tier — org_admin/admin/manager — so accountability is not a single
    point of failure when that person is away. Every decision records the actual
    approver in the audit event either way, which is what the audit story rests
    on.

    Consultants are excluded deliberately. DISC-44 defines the role as external,
    time-boxed and read-only, and an external party approving what may be
    scanned would weaken the audit argument rather than strengthen it. They can
    still see the boundary and advise on it.
    """
    organization = (
        db.query(Organization).filter(Organization.id == organization_id).first()
    )
    if organization is None:
        raise ScopeProposalError("Organisation not found.")

    if organization.technical_setup_owner_user_id == actor_user_id:
        return

    actor = (
        db.query(User)
        .filter(User.id == actor_user_id, User.organization_id == organization_id)
        .first()
    )
    if actor is None:
        raise ScopeProposalError("Approver not found in this organisation.")
    if actor.role == UserRole.CONSULTANT.value:
        raise ScopeProposalError(
            "Consultants have read-only access and cannot approve the discovery boundary."
        )
    if actor.role not in MANAGER_ROLES:
        raise ScopeProposalError(
            "Only the Technical Setup Owner or a manager, admin or organisation admin "
            "may decide the discovery boundary."
        )


def _resolve_capabilities(
    profile_snapshot: dict, requested: list[str] | None
) -> list[str]:
    """Intersect what was asked for with what the scanner profile permits.

    Omitting ``requested`` proposes everything the profile already allows. A
    request for something the profile forbids is refused outright rather than
    silently dropped — silently narrowing would leave the reviewer approving a
    boundary different from the one they were shown.
    """
    permitted = {
        capability
        for capability, profile_key in CAPABILITY_PROFILE_KEYS.items()
        if bool(profile_snapshot.get(profile_key))
    }
    if requested is None:
        return sorted(permitted)

    unknown = set(requested) - set(CAPABILITY_PROFILE_KEYS)
    if unknown:
        raise ScopeProposalError(f"Unknown discovery capabilities: {sorted(unknown)}")

    forbidden = set(requested) - permitted
    if forbidden:
        raise ScopeProposalError(
            "The scanner profile does not permit these capabilities: "
            f"{sorted(forbidden)}"
        )
    return sorted(set(requested))


def _supersede_open_proposals(
    db: Session, *, organization_id: int, evidence_source_id: str
) -> None:
    """Only one proposal may be open per evidence source — two competing
    boundaries awaiting approval is an ambiguous decision for the reviewer."""
    open_statuses = (
        DiscoveryScopeProposalStatus.DRAFT.value,
        DiscoveryScopeProposalStatus.AWAITING_APPROVAL.value,
    )
    for existing in (
        db.query(DiscoveryScopeProposal)
        .filter(
            DiscoveryScopeProposal.organization_id == organization_id,
            DiscoveryScopeProposal.evidence_source_id == evidence_source_id,
            DiscoveryScopeProposal.status.in_(open_statuses),
        )
        .all()
    ):
        existing.status = DiscoveryScopeProposalStatus.SUPERSEDED.value
        db.add(existing)
        profile = db.get(PermissionProfile, existing.permission_profile_id)
        if profile is not None and profile.status in {
            PermissionProfileStatus.DRAFT.value,
            PermissionProfileStatus.AWAITING_APPROVAL.value,
        }:
            profile.status = PermissionProfileStatus.SUPERSEDED.value
            db.add(profile)
        db.add(
            AuditEvent(
                organization_id=organization_id,
                actor_user_id=None,
                event_type=SCOPE_PROPOSAL_AUDIT_SUPERSEDED,
                metadata_json={"proposalId": existing.id},
            )
        )
