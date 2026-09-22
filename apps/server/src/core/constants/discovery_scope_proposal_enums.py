"""CA-05.B — scope proposal vocabulary.

A proposal is the system saying "here is the boundary I suggest, and why";
approving it is the Technical Setup Owner's decision alone. The contract is
explicit: the Collector never chooses its own boundary, and access configuration
must not automatically start scanning.

Permission profile scope note (deliberate, agreed with Søren 2026-08-11): the
capability set here is intentionally minimal and discovery-run-shaped, not a
general Collector permission system. That larger model is **Epic C4**, which the
programme roadmap already owns and rates High security. This carries only the
four capability toggles a discovery boundary needs, and every one of them is
already expressed by ``ScannerProfile`` — a proposal may never grant a capability
the scanner's own profile does not permit, so this narrows, never widens. When
C4 lands it should absorb this rather than sit beside it.
"""

from enum import StrEnum


class DiscoveryScopeProposalStatus(StrEnum):
    DRAFT = "draft"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    # A newer proposal replaced this one. Kept rather than deleted so the
    # boundary's history stays auditable.
    SUPERSEDED = "superseded"


TERMINAL_SCOPE_PROPOSAL_STATUSES: frozenset[str] = frozenset(
    {
        DiscoveryScopeProposalStatus.APPROVED.value,
        DiscoveryScopeProposalStatus.REJECTED.value,
        DiscoveryScopeProposalStatus.SUPERSEDED.value,
    }
)

ALLOWED_SCOPE_PROPOSAL_TRANSITIONS: dict[str, frozenset[str]] = {
    DiscoveryScopeProposalStatus.DRAFT.value: frozenset(
        {
            DiscoveryScopeProposalStatus.AWAITING_APPROVAL.value,
            DiscoveryScopeProposalStatus.SUPERSEDED.value,
        }
    ),
    DiscoveryScopeProposalStatus.AWAITING_APPROVAL.value: frozenset(
        {
            DiscoveryScopeProposalStatus.APPROVED.value,
            DiscoveryScopeProposalStatus.REJECTED.value,
            DiscoveryScopeProposalStatus.SUPERSEDED.value,
        }
    ),
    # An approved boundary is immutable — changing scope means proposing again,
    # never editing what a human already signed off.
    DiscoveryScopeProposalStatus.APPROVED.value: frozenset(),
    DiscoveryScopeProposalStatus.REJECTED.value: frozenset(),
    DiscoveryScopeProposalStatus.SUPERSEDED.value: frozenset(),
}


class DiscoveryCapability(StrEnum):
    """What a run may do inside its boundary.

    One-to-one with ``ScannerProfile``'s existing capability flags
    (``allowsExternalDiscovery`` etc. in ``build_profile_snapshot``) rather than
    a parallel vocabulary — a second, diverging capability model is exactly the
    duplicate the programme's reuse-first rule forbids.
    """

    EXTERNAL_DISCOVERY = "external_discovery"
    INTERNAL_DISCOVERY = "internal_discovery"
    SERVICE_FINGERPRINTING = "service_fingerprinting"
    VULNERABILITY_CHECKS = "vulnerability_checks"


# Maps each capability to the profile-snapshot key that authorises it. A
# capability with no authorising profile flag can never be proposed.
CAPABILITY_PROFILE_KEYS: dict[str, str] = {
    DiscoveryCapability.EXTERNAL_DISCOVERY.value: "allowsExternalDiscovery",
    DiscoveryCapability.INTERNAL_DISCOVERY.value: "allowsInternalDiscovery",
    DiscoveryCapability.SERVICE_FINGERPRINTING.value: "allowsFingerprinting",
    DiscoveryCapability.VULNERABILITY_CHECKS.value: "allowsVulnerabilityChecks",
}

SCOPE_PROPOSAL_AUDIT_PROPOSED = "discovery_scope_proposal.proposed"
SCOPE_PROPOSAL_AUDIT_APPROVED = "discovery_scope_proposal.approved"
SCOPE_PROPOSAL_AUDIT_REJECTED = "discovery_scope_proposal.rejected"
SCOPE_PROPOSAL_AUDIT_SUPERSEDED = "discovery_scope_proposal.superseded"
