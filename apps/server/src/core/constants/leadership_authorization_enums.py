"""Lifecycle values for leadership's authorisation of the onboarding programme."""

from enum import StrEnum


class LeadershipAuthorizationStatus(StrEnum):
    DRAFT = "draft"
    LEADERSHIP_REVIEW = "leadership_review"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    WITHDRAWN = "withdrawn"


# The governing body sponsoring the onboarding programme. Reuses the same
# authority vocabulary as risk appetite approval (a structured choice, per
# the governance contract's "use structured choices" rule) — the body that
# sponsors operational resilience onboarding is the same kind of body that
# approves the risk appetite it produces.
class LeadershipApprovingBody(StrEnum):
    BOARD_RISK_COMMITTEE = "board_risk_committee"
    SENIOR_MANAGEMENT = "senior_management"
    CISO = "ciso"
    CRO = "cro"


LEADERSHIP_AUTHORIZATION_AUDIT_DRAFT_CREATED = "leadership_authorization_draft_created"
LEADERSHIP_AUTHORIZATION_AUDIT_SUBMITTED = "leadership_authorization_submitted_for_review"
LEADERSHIP_AUTHORIZATION_AUDIT_APPROVED = "leadership_authorization_approved"
LEADERSHIP_AUTHORIZATION_AUDIT_REJECTED = "leadership_authorization_rejected"
LEADERSHIP_AUTHORIZATION_AUDIT_BACKFILLED = "leadership_authorization_backfilled"
# Distinct from APPROVED: the same admin who is also the accountable leader
# authorised the programme themselves in one step during onboarding, rather
# than an admin drafting it for a separately-named sponsor to later review.
# Kept as its own audit event so the trail never blurs a self-authorisation
# with a delegated approval.
LEADERSHIP_AUTHORIZATION_AUDIT_SELF_AUTHORIZED = "leadership_authorization_self_authorized"

LEADERSHIP_AUTHORIZATION_ERROR_ADMIN_REQUIRED = (
    "Organisation administrator access is required to prepare a leadership authorisation"
)
LEADERSHIP_AUTHORIZATION_ERROR_SPONSOR_MUST_APPROVE = (
    "Only the named sponsor can approve or reject their own leadership authorisation"
)
LEADERSHIP_AUTHORIZATION_ERROR_NOT_FOUND = "Leadership authorisation not found"
LEADERSHIP_AUTHORIZATION_ERROR_OWNER_INVITE_REQUIRES_AUTHORIZATION = (
    "Leadership must authorise the onboarding programme before Process Owners can be invited"
)
