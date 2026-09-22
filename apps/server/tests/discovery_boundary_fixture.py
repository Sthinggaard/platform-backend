"""Shared test helper: give an evidence source an approved discovery boundary.

CA-05.B made an approved boundary a precondition for discovery, the same shape
as ``technical_owner_required``. Tests that exercise runs therefore have to
satisfy it, exactly as they already seed ``technical_setup_owner_user_id``.

Kept as one helper rather than copied into each suite so the fixture shape
follows the model if the boundary gains required fields.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.constants.discovery_scope_proposal_enums import DiscoveryScopeProposalStatus
from src.core.model_defs.common import utcnow
from src.core.model_defs.discovery_scope_proposal import DiscoveryScopeProposal
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.model_defs.permission_subject import PermissionSubject


def approve_test_boundary(
    db: Session,
    *,
    organization_id: int,
    evidence_source_id: str,
    exclusions: list[str] | None = None,
    decided_by_user_id: int = 1,
) -> DiscoveryScopeProposal:
    """Seed an already-approved boundary so discovery is not blocked.

    Empty exclusions by default: these suites are testing run mechanics, not the
    boundary, so the boundary should permit everything they set up. Pass
    ``exclusions`` to test the gate itself.
    """
    subject = PermissionSubject(organization_id=organization_id, subject_kind="discovery_scope_proposal")
    db.add(subject)
    db.flush()
    profile = PermissionProfile(
        organization_id=organization_id,
        subject_id=subject.id,
        name="Approved test discovery profile",
        capabilities=[],
        discovery_capabilities=[],
        status="active",
    )
    db.add(profile)
    db.flush()
    proposal = DiscoveryScopeProposal(
        organization_id=organization_id,
        evidence_source_id=evidence_source_id,
        status=DiscoveryScopeProposalStatus.APPROVED.value,
        inclusions=[],
        exclusions=exclusions or [],
        checks=[],
        permission_subject_id=subject.id,
        permission_profile_id=profile.id,
        rationale={},
        decided_by_user_id=decided_by_user_id,
        decided_at=utcnow(),
    )
    db.add(proposal)
    db.commit()
    return proposal
