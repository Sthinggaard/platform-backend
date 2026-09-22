"""CA-05.A — Environment detection.

Answers one question for the Technical Setup Owner: *what does this organisation
already have on record that a discovery run could cover, and what of it is not
covered today?*

Deliberately read-only. It opens no socket, contacts no host, and writes no row.
Everything it reports is already in the tenant's own database — approved
Collector targets, the asset registry, and the declared organisation scope. Live
probing of an environment is the Collector's job and only ever happens inside an
approved boundary via Step 4.2; proposing a boundary from evidence the
organisation already holds is not scanning and must not become a back door to it.

The Collector never chooses its own boundary (contract, CA-05 rules), so nothing
here approves, persists or widens scope. It produces a proposal for a human.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from src.core.constants.discovery_environment_enums import (
    PROPOSABLE_COVERAGE_STATES,
    EnvironmentCandidateKind,
    EnvironmentCoverageState,
    EnvironmentDetectionSource,
)
from src.core.constants.evidence_scanner_enums import ScannerTargetStatus
from src.core.model_defs.assets_runtime import Asset
from src.core.model_defs.evidence_scanner import ScannerDomainTarget, ScannerNetworkTarget
from src.core.model_defs.organization_identity import OrganizationScope
from src.core.services.discovery_boundary_matching import (
    is_scannable_identifier,
)
from src.core.services.discovery_boundary_matching import (
    matches_domain as _matches_domain,
)
from src.core.services.discovery_boundary_matching import (
    matches_network as _matches_network,
)
from src.core.services.discovery_boundary_matching import (
    parse_networks as _parse_networks,
)


@dataclass(frozen=True)
class EnvironmentCandidate:
    """One thing the organisation knows about that discovery could cover."""

    kind: str
    value: str
    display_name: str
    detected_from: str
    coverage_state: str
    # Why this candidate exists, in the reviewer's terms. The contract requires
    # the proposal be explainable, so this travels with the candidate rather
    # than being reconstructed in the UI.
    rationale: str
    source_record_id: str | None = None

    @property
    def is_proposable(self) -> bool:
        return self.coverage_state in PROPOSABLE_COVERAGE_STATES


@dataclass(frozen=True)
class EnvironmentDetectionResult:
    candidates: tuple[EnvironmentCandidate, ...] = field(default=())

    @property
    def proposable(self) -> tuple[EnvironmentCandidate, ...]:
        return tuple(c for c in self.candidates if c.is_proposable)

    @property
    def covered(self) -> tuple[EnvironmentCandidate, ...]:
        return tuple(
            c for c in self.candidates if c.coverage_state == EnvironmentCoverageState.COVERED.value
        )

    @property
    def excluded(self) -> tuple[EnvironmentCandidate, ...]:
        return tuple(
            c
            for c in self.candidates
            if c.coverage_state == EnvironmentCoverageState.EXPLICITLY_EXCLUDED.value
        )


def detect_environment(
    db: Session, *, organization_id: int, evidence_source_id: str
) -> EnvironmentDetectionResult:
    """Observe this tenant's recorded environment and classify each candidate
    against the already-approved Collector boundary.

    Every query filters on ``organization_id`` — an evidence_source_id alone is
    not a tenant boundary, and detection must never surface another tenant's
    hosts into this organisation's scope proposal.
    """
    domain_targets = (
        db.query(ScannerDomainTarget)
        .filter(
            ScannerDomainTarget.organization_id == organization_id,
            ScannerDomainTarget.evidence_source_id == evidence_source_id,
        )
        .all()
    )
    network_targets = (
        db.query(ScannerNetworkTarget)
        .filter(
            ScannerNetworkTarget.organization_id == organization_id,
            ScannerNetworkTarget.evidence_source_id == evidence_source_id,
        )
        .all()
    )

    approved_domains = {
        t.domain.strip().lower()
        for t in domain_targets
        if t.status == ScannerTargetStatus.APPROVED.value
    }
    excluded_domains = {
        t.domain.strip().lower()
        for t in domain_targets
        if t.status == ScannerTargetStatus.EXCLUDED.value
    }
    approved_networks = _parse_networks(
        t.cidr for t in network_targets if t.status == ScannerTargetStatus.APPROVED.value
    )

    candidates: list[EnvironmentCandidate] = []
    candidates.extend(_domain_candidates(domain_targets))
    candidates.extend(_network_candidates(network_targets))
    candidates.extend(
        _asset_candidates(
            db,
            organization_id=organization_id,
            approved_domains=approved_domains,
            excluded_domains=excluded_domains,
            approved_networks=approved_networks,
        )
    )
    candidates.extend(
        _organization_scope_candidates(
            db, organization_id=organization_id, excluded_domains=excluded_domains
        )
    )

    return EnvironmentDetectionResult(candidates=tuple(_deduplicate(candidates)))


def _domain_candidates(targets: list[ScannerDomainTarget]) -> list[EnvironmentCandidate]:
    out: list[EnvironmentCandidate] = []
    for target in targets:
        state = _target_coverage_state(target.status)
        if state is None:
            continue
        out.append(
            EnvironmentCandidate(
                kind=EnvironmentCandidateKind.DOMAIN.value,
                value=target.domain.strip().lower(),
                display_name=target.domain,
                detected_from=EnvironmentDetectionSource.SCANNER_DOMAIN_TARGET.value,
                coverage_state=state,
                rationale=f"Registered domain target ({target.ownership_status}).",
                source_record_id=target.id,
            )
        )
    return out


def _network_candidates(targets: list[ScannerNetworkTarget]) -> list[EnvironmentCandidate]:
    out: list[EnvironmentCandidate] = []
    for target in targets:
        state = _target_coverage_state(target.status)
        if state is None:
            continue
        out.append(
            EnvironmentCandidate(
                kind=EnvironmentCandidateKind.NETWORK_RANGE.value,
                value=target.cidr,
                display_name=target.name,
                detected_from=EnvironmentDetectionSource.SCANNER_NETWORK_TARGET.value,
                coverage_state=state,
                rationale=f"Registered {target.network_type} network range.",
                source_record_id=target.id,
            )
        )
    return out


def _asset_candidates(
    db: Session,
    *,
    organization_id: int,
    approved_domains: set[str],
    excluded_domains: set[str],
    approved_networks: list,
) -> list[EnvironmentCandidate]:
    """Hosts the organisation already has in its asset registry.

    An asset lands here because a human or an earlier approved run put it on
    record — so it is legitimate to *show* it. Whether discovery may touch it
    still depends entirely on the approved boundary, which is what
    ``coverage_state`` reports.
    """
    assets = (
        db.query(Asset)
        .filter(Asset.organization_id == organization_id)
        .all()
    )

    out: list[EnvironmentCandidate] = []
    for asset in assets:
        host = (asset.display_name or "").strip()
        if not host or not is_scannable_identifier(host):
            # The asset registry holds business names ("Main firewall", "AWS
            # production"), not addresses — there is no hostname/IP column on
            # Asset. Proposing a business name as a discovery target would ask
            # a human to approve scanning something that cannot be scanned, so
            # only genuine hosts/addresses are offered. Fails closed.
            continue
        normalized = host.lower()
        state = _asset_coverage_state(
            normalized,
            approved_domains=approved_domains,
            excluded_domains=excluded_domains,
            approved_networks=approved_networks,
        )
        out.append(
            EnvironmentCandidate(
                kind=EnvironmentCandidateKind.HOST.value,
                value=normalized,
                display_name=host,
                detected_from=EnvironmentDetectionSource.ASSET_REGISTRY.value,
                coverage_state=state,
                rationale=f"Known {asset.type} asset on the {asset.layer} layer.",
                source_record_id=str(asset.id),
            )
        )
    return out


def _organization_scope_candidates(
    db: Session, *, organization_id: int, excluded_domains: set[str]
) -> list[EnvironmentCandidate]:
    """Exclusions the organisation declared at org level.

    Only exclusions are read here. Org-level *inclusions* are entity ids, not
    scannable targets, and turning them into targets would be the system
    widening its own boundary — exactly what the contract forbids.
    """
    scopes = (
        db.query(OrganizationScope)
        .filter(OrganizationScope.organization_id == organization_id)
        .all()
    )

    out: list[EnvironmentCandidate] = []
    for scope in scopes:
        for excluded in scope.excluded_entity_ids or []:
            value = str(excluded).strip().lower()
            if not value:
                continue
            out.append(
                EnvironmentCandidate(
                    kind=EnvironmentCandidateKind.HOST.value,
                    value=value,
                    display_name=str(excluded),
                    detected_from=EnvironmentDetectionSource.ORGANIZATION_SCOPE.value,
                    coverage_state=EnvironmentCoverageState.EXPLICITLY_EXCLUDED.value,
                    rationale=f"Excluded by organisation scope '{scope.name}'.",
                    source_record_id=scope.id,
                )
            )
    return out


def _target_coverage_state(status: str) -> str | None:
    if status == ScannerTargetStatus.APPROVED.value:
        return EnvironmentCoverageState.COVERED.value
    if status == ScannerTargetStatus.EXCLUDED.value:
        return EnvironmentCoverageState.EXPLICITLY_EXCLUDED.value
    if status == ScannerTargetStatus.DRAFT.value:
        return EnvironmentCoverageState.NOT_COVERED.value
    # DISABLED targets are intentionally dormant, not candidates.
    return None


def _asset_coverage_state(
    value: str, *, approved_domains: set[str], excluded_domains: set[str], approved_networks: list
) -> str:
    if _matches_domain(value, excluded_domains):
        return EnvironmentCoverageState.EXPLICITLY_EXCLUDED.value
    if _matches_domain(value, approved_domains):
        return EnvironmentCoverageState.COVERED.value
    if _matches_network(value, approved_networks):
        return EnvironmentCoverageState.COVERED.value
    return EnvironmentCoverageState.NOT_COVERED.value








# Higher wins when the same value is observed from several records. An explicit
# exclusion outranks everything: if a human excluded it anywhere, the proposal
# must not offer it, whichever other record also mentions it.
_COVERAGE_PRECEDENCE: dict[str, int] = {
    EnvironmentCoverageState.NOT_COVERED.value: 0,
    EnvironmentCoverageState.COVERED.value: 1,
    EnvironmentCoverageState.EXPLICITLY_EXCLUDED.value: 2,
}


def _deduplicate(candidates: list[EnvironmentCandidate]) -> list[EnvironmentCandidate]:
    """Collapse on value, not on (kind, value).

    A domain target and an asset row carrying the same name are one thing to the
    reviewer being asked "may discovery touch this?" — listing it twice under
    two kinds is noise that makes an exclusion easy to miss.
    """
    best: dict[str, EnvironmentCandidate] = {}
    for candidate in candidates:
        existing = best.get(candidate.value)
        if existing is None or (
            _COVERAGE_PRECEDENCE[candidate.coverage_state]
            > _COVERAGE_PRECEDENCE[existing.coverage_state]
        ):
            best[candidate.value] = candidate
    return list(best.values())
