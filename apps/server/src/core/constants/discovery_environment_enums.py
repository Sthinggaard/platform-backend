"""CA-05.A — Environment detection vocabulary.

Detection observes what an organisation *already has on record* and proposes it
as candidate discovery scope. It never approves, never writes scope, and never
lets the Collector widen its own boundary — the Technical Setup Owner does that
in CA-05.B. This module therefore carries only the vocabulary a *proposal*
needs: where a candidate came from, what kind of thing it is, and whether an
approved target already covers it.
"""

from enum import StrEnum


class EnvironmentCandidateKind(StrEnum):
    """What the detected candidate is, in Collector-target terms."""

    DOMAIN = "domain"
    NETWORK_RANGE = "network_range"
    HOST = "host"
    SERVICE = "service"


class EnvironmentDetectionSource(StrEnum):
    """Which record the candidate was observed from. Kept explicit so a
    reviewer can always answer "why is this being proposed to me?" — the
    contract requires the proposal be explainable, not merely correct."""

    SCANNER_DOMAIN_TARGET = "scanner_domain_target"
    SCANNER_NETWORK_TARGET = "scanner_network_target"
    ASSET_REGISTRY = "asset_registry"
    ORGANIZATION_SCOPE = "organization_scope"


class EnvironmentCoverageState(StrEnum):
    """Relationship between a candidate and the already-approved boundary.

    COVERED         already inside an approved Collector target
    NOT_COVERED     known to the organisation, outside any approved target
    EXPLICITLY_EXCLUDED  a human has already excluded it; never re-propose
                    silently, surface it as excluded so the exclusion stays
                    visible and auditable
    """

    COVERED = "covered"
    NOT_COVERED = "not_covered"
    EXPLICITLY_EXCLUDED = "explicitly_excluded"


# Candidates a proposal may suggest adding. An explicitly-excluded candidate is
# never proposable — re-proposing something a human already excluded would let
# the system quietly overturn a human decision.
PROPOSABLE_COVERAGE_STATES: frozenset[str] = frozenset(
    {EnvironmentCoverageState.NOT_COVERED.value}
)
