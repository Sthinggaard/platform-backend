"""CA-05.C — what a discovery run actually found.

Reports the hosts and services a completed run produced, plus how that result
sits against the approved boundary: what was covered, and what the organisation
had explicitly excluded.

Reads only already-normalised output. It never re-parses provider evidence — the
raw payload is `EvidencePackage`'s business and normalisation already turned it
into `Asset` rows via `artefact_identity_service`. Re-parsing here would be a
second, silently-diverging interpretation of the same evidence.

Provenance note: there is no foreign key from `Asset` back to the run that
discovered it. The persisted link is the ``evidence_package.normalized`` audit
event, which records ``evidencePackageId`` alongside the matched/created asset
ids. Audit is this system's provenance ledger (Epic A3), so reading it for
provenance is its purpose rather than a workaround — but it does mean this
service depends on that event's metadata shape. If run-to-asset lineage ever
needs to be queried at scale or joined in SQL, a real link column is the right
answer; that is a schema change and deliberately not made here.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from src.core.constants.discovery_environment_enums import EnvironmentCoverageState
from src.core.constants.discovery_execution_enums import (
    EVIDENCE_PACKAGE_AUDIT_NORMALIZED,
    EvidenceNormalizationStatus,
)
from src.core.constants.artefact_identity_enums import ArtefactReviewState
from src.core.constants.osi import layer_short_label
from src.core.services.asset_scan_findings_service import scan_findings_by_asset
from src.core.services.artefact_classification_service import (
    ObservedService,
    derive_candidacy,
    stored_service_names,
)
from src.core.services.artefact_identity_evidence_service import stored_identity
from src.core.model_defs.assets_runtime import Asset, AssetLifecycleState
from src.core.model_defs.discovery_execution import EvidencePackage
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.services.discovery_environment_detection_service import detect_environment


@dataclass(frozen=True)
class DiscoveredAsset:
    asset_id: int
    display_name: str
    asset_type: str
    #: The canonical OSILayer id as stored (L1–L7), or "Unknown".
    layer: str
    #: That layer's name, resolved once here so no view has to know how to turn
    #: an id into words — and so a legacy free-text value still renders.
    layer_label: str
    #: Service names actually observed on this host. The reviewer's real
    #: evidence when the class itself is generic.
    observed_services: tuple[str, ...]
    #: The same ports, with what is actually known about each. `observed_services`
    #: above cannot say whether a name was probed or read from nmap's port-number
    #: table, so `http-proxy` (a restatement of "port 8080") rendered exactly like
    #: `https` (something that answered and identified itself). A guess shown in
    #: the same voice as a finding is the defect #249 was raised for.
    #:
    #: Facts only. Which of these deserves a word, and what word, is the tenant's
    #: call — this module composes no sentences.
    observed_service_evidence: tuple[ObservedService, ...]
    #: What the scan concluded this artefact is, and where it sits — the same
    #: answer the standing inventory gives, from the same reader. A reviewer
    #: deciding "is this ours?" was shown `192.168.1.20` and a row of chips,
    #: which is the least useful form of every fact the platform holds.
    identity_name: str | None
    #: Which evidence produced the name. Carried for the same reason the
    #: inventory carries it: "read off its TLS certificate" and "guessed from a
    #: port number" are not the same claim.
    identity_basis: str | None
    identity_undetermined_reason: str | None
    identity_explanation: str | None
    network_address: str | None
    # Whether this run created the asset or matched one already on record.
    # A reviewer reading "42 hosts" needs to know how many are genuinely new.
    is_new: bool
    # The reviewer's own decision on this artefact, so the list can show what
    # has already been decided rather than asking again (#150). Carried as the
    # raw lifecycle value; naming it for the user is the caller's job.
    lifecycle_state: str
    # The decision as one value, derived once here rather than re-derived in
    # every view. Confirming is usually not a state change (rows are created
    # ACTIVE), so this reads reviewed_at as well — without it a confirmed row
    # was indistinguishable from an untouched one and the screen looked broken.
    review_state: str
    # Whether a business service could depend on this at all: service_bearing /
    # endpoint / undetermined. Derived here from the observed evidence rather
    # than stored on the asset, deliberately — it is a platform observation, not
    # a decision, so it must improve as the rules do instead of being frozen at
    # whatever the first scan concluded. That is the same mistake that left
    # every artefact classified by code that no longer existed (BUG-DISC-15).
    candidacy: str

    #: Open findings the vulnerability scanner has recorded against this
    #: artefact. The reviewer is deciding whether to keep this thing, and what a
    #: scan already found on it bears on that.
    #:
    #: ⚠️ ``0`` means no scanner finding is on record — **not** "scanned and
    #: clean". Nothing yet records whether a host was scanned and matched
    #: nothing, cut at the time budget, or never reached, so the surface says
    #: what was found and stays silent about what was not.
    scan_finding_count: int = 0


@dataclass(frozen=True)
class DiscoveryResultsSummary:
    discovery_run_id: str
    evidence_package_count: int
    discovered: tuple[DiscoveredAsset, ...]
    excluded_values: tuple[str, ...]
    # Providers that ran and observed nothing, by provider id. "We looked and
    # found nothing" is a real outcome a reviewer needs to see — it used to be
    # shown by fabricating a placeholder asset for the scan itself
    # (BUG-DISC-14), which put a non-existent thing in the inventory.
    empty_result_providers: tuple[str, ...] = ()

    @property
    def new_count(self) -> int:
        return sum(1 for asset in self.discovered if asset.is_new)

    @property
    def matched_count(self) -> int:
        return sum(1 for asset in self.discovered if not asset.is_new)


def get_discovery_results(
    db: Session, *, organization_id: int, discovery_run_id: str
) -> DiscoveryResultsSummary:
    """Summarise a run's normalised output.

    Tenant-filtered at every step: the run itself, its evidence packages, the
    audit events carrying lineage, and the asset rows. An asset id read out of
    audit metadata is never trusted on its own — it is re-fetched under this
    organisation's filter, so a stale or tampered id cannot surface another
    tenant's asset.
    """
    run = (
        db.query(DiscoveryRun)
        .filter(
            DiscoveryRun.id == discovery_run_id,
            DiscoveryRun.organization_id == organization_id,
        )
        .first()
    )
    if run is None:
        raise ValueError(
            f"No DiscoveryRun found for organization_id={organization_id!r}, id={discovery_run_id!r}"
        )

    package_ids = {
        package.id
        for package in db.query(EvidencePackage).filter(
            EvidencePackage.discovery_run_id == discovery_run_id,
            EvidencePackage.organization_id == organization_id,
        )
    }

    matched_ids, created_ids = _asset_ids_from_audit(
        db, organization_id=organization_id, package_ids=package_ids
    )

    # created wins over matched: an asset both created and later re-matched
    # within one run is still new to the organisation.
    matched_ids -= created_ids

    discovered = _load_assets(
        db, organization_id=organization_id, created_ids=created_ids, matched_ids=matched_ids
    )

    empty_result_providers = _providers_that_found_nothing(
        db, organization_id=organization_id, discovery_run_id=discovery_run_id
    )

    environment = detect_environment(
        db, organization_id=organization_id, evidence_source_id=run.evidence_source_id
    )
    excluded_values = tuple(
        sorted(
            candidate.value
            for candidate in environment.candidates
            if candidate.coverage_state == EnvironmentCoverageState.EXPLICITLY_EXCLUDED.value
        )
    )

    return DiscoveryResultsSummary(
        discovery_run_id=discovery_run_id,
        evidence_package_count=len(package_ids),
        discovered=discovered,
        excluded_values=excluded_values,
        empty_result_providers=empty_result_providers,
    )


def _observed_service_evidence(asset: Asset) -> tuple[ObservedService, ...]:
    """Per-port evidence, or nothing when this artefact predates it being kept.

    Deliberately **not** reconstructed from `observedServices` when absent. That
    list holds names only, so inventing `probed=False` entries for it would look
    like a positive statement that nothing was probed — which is exactly the
    downward guess #249 removed. An artefact with no evidence recorded says so
    by having none, and the reader falls back to the plain names.
    """
    intent = asset.intent if isinstance(asset.intent, dict) else {}
    recorded = intent.get("observedServiceEvidence")
    if not isinstance(recorded, list):
        return ()
    evidence: list[ObservedService] = []
    for item in recorded:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        port = item.get("port")
        evidence.append(
            ObservedService(
                name=name.strip(),
                port=port if isinstance(port, int) else None,
                probed=item.get("probed") is True,
            )
        )
    return tuple(evidence)


def _observed_services(asset: Asset) -> tuple[str, ...]:
    # The reader itself lives beside ``derive_candidacy``, which is the rule it
    # feeds; the inventory reads the same key and must not have its own copy.
    return stored_service_names(asset.intent)


def _review_state(asset: Asset) -> str:
    if asset.lifecycle_state == AssetLifecycleState.REMOVED:
        return ArtefactReviewState.REJECTED.value
    # Checked before reviewed_at, which every decision stamps — otherwise
    # "ours but not depended on" would read back as a plain confirmation and the
    # reviewer's actual answer would be lost the moment they gave it.
    if asset.lifecycle_state == AssetLifecycleState.NOT_USED:
        return ArtefactReviewState.NOT_USED.value
    if asset.reviewed_at is not None:
        return ArtefactReviewState.CONFIRMED.value
    if asset.lifecycle_state == AssetLifecycleState.UNCONFIRMED:
        return ArtefactReviewState.NEEDS_DECISION.value
    return ArtefactReviewState.UNDECIDED.value


def _providers_that_found_nothing(
    db: Session, *, organization_id: int, discovery_run_id: str
) -> tuple[str, ...]:
    """Providers whose packages normalised without producing any artefact.

    Read from the packages themselves rather than from the absence of an audit
    entry, so a provider that genuinely scanned and found nothing is reported as
    such instead of looking like it never ran.
    """
    packages = (
        db.query(EvidencePackage)
        .filter(
            EvidencePackage.discovery_run_id == discovery_run_id,
            EvidencePackage.organization_id == organization_id,
            EvidencePackage.normalization_status == EvidenceNormalizationStatus.NORMALIZED.value,
        )
        .all()
    )
    if not packages:
        return ()

    produced: set[str] = set()
    events = db.query(AuditEvent).filter(
        AuditEvent.organization_id == organization_id,
        AuditEvent.event_type == EVIDENCE_PACKAGE_AUDIT_NORMALIZED,
    )
    by_id = {package.id: package for package in packages}
    for event in events:
        metadata = event.metadata_json or {}
        package = by_id.get(metadata.get("evidencePackageId"))
        if package is None:
            continue
        if _int_ids(metadata.get("createdAssetIds")) or _int_ids(metadata.get("matchedAssetIds")):
            produced.add(package.provider_id)

    return tuple(sorted({p.provider_id for p in packages} - produced))


def _asset_ids_from_audit(
    db: Session, *, organization_id: int, package_ids: set[str]
) -> tuple[set[int], set[int]]:
    if not package_ids:
        return set(), set()

    matched: set[int] = set()
    created: set[int] = set()
    events = db.query(AuditEvent).filter(
        AuditEvent.organization_id == organization_id,
        AuditEvent.event_type == EVIDENCE_PACKAGE_AUDIT_NORMALIZED,
    )
    for event in events:
        metadata = event.metadata_json or {}
        if metadata.get("evidencePackageId") not in package_ids:
            continue
        matched.update(_int_ids(metadata.get("matchedAssetIds")))
        created.update(_int_ids(metadata.get("createdAssetIds")))
    return matched, created


def _int_ids(raw) -> set[int]:
    if not isinstance(raw, (list, tuple, set)):
        return set()
    out: set[int] = set()
    for value in raw:
        try:
            out.add(int(value))
        except (TypeError, ValueError):
            # Audit metadata is free-form JSON; a malformed id is skipped rather
            # than crashing a read-only summary.
            continue
    return out


def _load_assets(
    db: Session, *, organization_id: int, created_ids: set[int], matched_ids: set[int]
) -> tuple[DiscoveredAsset, ...]:
    all_ids = created_ids | matched_ids
    if not all_ids:
        return ()

    rows = (
        db.query(Asset)
        .filter(Asset.organization_id == organization_id, Asset.id.in_(all_ids))
        .all()
    )
    # The same aggregate the standing inventory reads, so one artefact cannot
    # report a different number of findings on two pages.
    scan_findings = scan_findings_by_asset(
        db, organization_id=organization_id, asset_ids=[row.id for row in rows]
    )
    discovered = [
        DiscoveredAsset(
            asset_id=row.id,
            display_name=row.display_name,
            asset_type=row.type,
            layer=row.layer,
            layer_label=layer_short_label(row.layer),
            observed_services=_observed_services(row),
            observed_service_evidence=_observed_service_evidence(row),
            **stored_identity(row.intent),
            is_new=row.id in created_ids,
            lifecycle_state=row.lifecycle_state.value,
            review_state=_review_state(row),
            candidacy=derive_candidacy(_observed_services(row)).value,
            scan_finding_count=scan_findings.get(row.id, (0, None))[0],
        )
        for row in rows
    ]
    discovered.sort(key=lambda asset: (not asset.is_new, asset.display_name.lower()))
    return tuple(discovered)
