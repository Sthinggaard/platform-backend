"""Request and response contracts for Business Process Owner acceptance."""

from pydantic import BaseModel, Field

from src.api.schemas.timestamps import UtcTimestamp

from src.core.constants.process_ownership_enums import (
    ProcessOwnerProposalSource,
    ProcessOwnerProposalStatus,
    ProcessOwnershipRejectionReason,
    ProcessOwnershipStatus,
)


class ProcessOwnerCandidateResponse(BaseModel):
    user_id: int
    name: str
    email: str
    title: str | None = None
    source: ProcessOwnerProposalSource


class ProcessOwnerProposalResponse(BaseModel):
    process_id: str
    status: ProcessOwnerProposalStatus
    recommended_user_id: int | None = None
    current_owner_user_id: int | None = None
    acceptance_status: ProcessOwnershipStatus | None = None
    candidates: list[ProcessOwnerCandidateResponse] = Field(default_factory=list)


class ProcessOwnershipInvitationRequest(BaseModel):
    scope_binding_id: str = Field(min_length=1, max_length=36)


class ProcessOwnershipRejectionRequest(BaseModel):
    reason: ProcessOwnershipRejectionReason


class ProcessOwnershipResponse(BaseModel):
    id: str
    process_id: str
    scope_binding_id: str
    owner_user_id: int
    status: ProcessOwnershipStatus
    rejection_reason: ProcessOwnershipRejectionReason | None = None


class PendingOwnerInvitationResponse(BaseModel):
    """An invitation awaiting this candidate's answer.

    Carries enough to decide, not merely enough to identify: what the process
    is, the outcome it delivers, and how many services depend on it.
    """

    process_id: str
    process_name: str
    outcome_statement: str | None = None
    service_count: int = 0
    invited_at: UtcTimestamp
    invited_by_user_id: int | None = None


class PendingOwnerInvitationsResponse(BaseModel):
    invitations: list[PendingOwnerInvitationResponse] = Field(default_factory=list)
