from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.asset_monitoring.service import record_status
from src.core.constants.artefact_identity_enums import (
    ARTEFACT_AUDIT_DISCOVERED,
    ARTEFACT_AUDIT_IDENTIFIER_OBSERVED,
    ARTEFACT_AUDIT_IDENTITY_CONFLICT,
    ARTEFACT_AUDIT_IDENTITY_MATCHED,
    OBSERVATION_AUDIT_RECORDED,
    ArtefactIdentityMatchType,
    AssetEvidenceSignalKind,
    TechnicalObservationStatus,
    TechnicalObservationType,
)
from src.core.constants.risk_intelligence_ingestion import (
    FINDING_DOMAIN_RISK_INTELLIGENCE,
    INGESTION_BATCH_NORMALIZED_EVENT,
)
from src.core.logging_config import get_logger
from src.core.model_defs.common import SeverityLevel, utcnow
from src.core.models import (
    Asset,
    AssetEvidenceSignal,
    AssetFinding,
    AssetFindingStatus,
    AssetLifecycleState,
    AssetStatus,
    AuditEvent,
    ConnectivityStatus,
    Criticality,
    Environment,
    RiskIngestionBatch,
    RiskIngestionBatchStatus,
    ScanStartMode,
    SetupConfidence,
)
from src.core.model_defs.discovery_execution import EvidencePackage
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.services.artefact_boundary_service import evaluate_boundary, withdraw_artefact
from src.core.services.artefact_classification_service import classify_host_record
from src.core.constants.artefact_identity_evidence_enums import ArtefactIdentityUndetermined
from src.core.services.artefact_identity_evidence_service import determine_identity
from src.core.services.artefact_reconciliation_service import raise_identity_conflict
from src.core.services.discovery_scope_proposal_service import get_approved_scope
from src.core.services.artefact_observation_service import (
    extract_observed_ports,
    record_observed_ports,
)
from src.core.services.artefact_identity_service import (
    ArtefactIdentityCandidate,
    record_observed_identifiers,
    resolve_identity,
)
from src.core.services.asset_context_service import build_asset_business_context
from src.core.services.risk_intelligence_ingestion_service import get_ingestion_batch

logger = get_logger(__name__)

_HOST_KEYS = ("hosts", "assets", "nodes", "targets", "results", "observations")
_FINDING_KEYS = ("findings", "vulnerabilities", "issues", "alerts")
_SIGNAL_KIND = AssetEvidenceSignalKind.RISK_INTELLIGENCE_INGESTION.value
_FINDING_DOMAIN = FINDING_DOMAIN_RISK_INTELLIGENCE


def _write_audit(db: Session, *, organization_id: int, actor_user_id: int | None, event_type: str, metadata: dict) -> None:
    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            event_type=event_type,
            metadata_json=metadata,
        )
    )


@dataclass(frozen=True)
class NormalizedAssetContextSummary:
    asset_id: int
    asset_name: str
    matched_by: str
    created: bool
    linked_service_names: list[str]
    linked_process_names: list[str]
    crown_jewel_candidate: bool
    blast_radius_service_count: int
    blast_radius_mission_critical_count: int
    has_financial_exposure: bool


@dataclass(frozen=True)
class NormalizedFindingSummary:
    finding_id: int
    asset_id: int
    severity: str
    title: str
    status: str
    evidence_refs: list[str]
    risk_score: float | None


@dataclass(frozen=True)
class NormalizationResult:
    ingestion_batch_id: int
    organization_id: int
    batch_status: RiskIngestionBatchStatus
    normalized_at: datetime
    technical_summary: str
    human_decision_required: bool
    signal_count: int
    finding_count: int
    matched_asset_ids: list[int]
    created_asset_ids: list[int]
    business_contexts: list[NormalizedAssetContextSummary]
    findings: list[NormalizedFindingSummary]


def _empty_normalization_result(
    db: Session, batch: RiskIngestionBatch, *, organization_id: int
) -> NormalizationResult:
    """A batch that observed nothing: normalised, zero assets, zero signals."""
    batch.status = RiskIngestionBatchStatus.NORMALIZED
    db.add(batch)
    db.commit()
    db.refresh(batch)
    return NormalizationResult(
        ingestion_batch_id=batch.id,
        organization_id=organization_id,
        batch_status=batch.status,
        normalized_at=utcnow(),
        technical_summary=f"No hosts or findings were observed from {batch.source_name}.",
        human_decision_required=False,
        signal_count=0,
        finding_count=0,
        matched_asset_ids=[],
        created_asset_ids=[],
        business_contexts=[],
        findings=[],
    )


def normalize_ingestion_batch(
    db: Session,
    *,
    organization_id: int,
    actor_user_id: int | None,
    batch_id: int,
) -> NormalizationResult:
    batch = get_ingestion_batch(db, organization_id=organization_id, batch_id=batch_id)
    raw_payload = batch.raw_payload
    host_records = _extract_host_records(raw_payload)
    if not host_records:
        global_findings = _extract_global_findings(raw_payload)
        if not global_findings:
            # Nothing observed and nothing found. Inventing a host here named
            # after the batch source created an asset for something that does
            # not exist (BUG-DISC-14, second fabrication point — removing only
            # the adapter's left this one producing "discovery_execution:
            # subfinder" instead). An empty scan is a valid outcome, recorded by
            # the batch itself, not by fabricating inventory.
            return _empty_normalization_result(db, batch, organization_id=organization_id)
        # Findings with no host still need something to hang from — keep the
        # synthetic anchor for that case only.
        host_records = [{"hostname": batch.source_name, "findings": global_findings}]

    existing_signal_fingerprints, existing_finding_fingerprints = _load_existing_fingerprints(
        db,
        organization_id=organization_id,
        batch_id=batch.id,
    )

    signal_count = 0
    finding_count = 0
    matched_asset_ids: list[int] = []
    created_asset_ids: list[int] = []
    business_contexts: list[NormalizedAssetContextSummary] = []
    findings: list[NormalizedFindingSummary] = []
    summarized_asset_ids: set[int] = set()

    now = utcnow()
    provenance = _resolve_signal_provenance(db, batch)
    for host_index, host_record in enumerate(host_records, start=1):
        host_label = _host_label(host_record, fallback=f"{batch.source_name}-{host_index}")
        try:
            asset, matched_by, created = _resolve_or_create_asset(
                db,
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                batch=batch,
                host_record=host_record,
                host_label=host_label,
            )
        except _UnknownVulnerabilityHost as exc:
            # One host the inventory no longer recognises must not cost the
            # batch its other findings — the same per-item isolation the
            # normalisation hand-off and the scan runner both keep. Logged
            # loudly because the platform chose this address itself.
            logger.warning(
                "vulnerability_finding_for_unknown_host",
                organization_id=organization_id,
                ingestion_batch_id=batch.id,
                host=exc.host_label,
            )
            continue

        if asset.id not in matched_asset_ids:
            matched_asset_ids.append(asset.id)
        if created and asset.id not in created_asset_ids:
            created_asset_ids.append(asset.id)

        finding_records = _host_findings(host_record, raw_payload)
        signal_payload = _build_signal_payload(
            batch=batch,
            host_record=host_record,
            host_label=host_label,
            asset=asset,
            matched_by=matched_by,
            created=created,
            finding_records=finding_records,
        )
        signal_fingerprint = signal_payload["signalFingerprint"]
        if signal_fingerprint not in existing_signal_fingerprints:
            observation_type = _classify_observation(host_record, finding_records)
            severity = _signal_severity(finding_records)
            signal = AssetEvidenceSignal(
                organization_id=organization_id,
                asset_id=asset.id,
                kind=_SIGNAL_KIND,
                payload_json=signal_payload,
                observed_at=now,
                confidence=_signal_confidence(matched_by, created),
                risk_score=_risk_score_from_findings(finding_records),
                observation_type=observation_type.value,
                status=TechnicalObservationStatus.OBSERVED.value,
                severity=severity.value if severity else None,
                evidence_package_id=provenance.evidence_package_id,
                provider_execution_id=provenance.provider_execution_id,
                scanner_instance_id=provenance.scanner_instance_id,
            )
            db.add(signal)
            db.flush()
            signal_count += 1
            existing_signal_fingerprints.add(signal_fingerprint)
            _write_audit(
                db,
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                event_type=OBSERVATION_AUDIT_RECORDED,
                metadata={
                    "assetId": asset.id,
                    "signalId": signal.id,
                    "observationType": observation_type.value,
                    "ingestionBatchId": batch.id,
                },
            )

        # CA-06.2 — the technical detail of what answered, kept structurally
        # instead of only inside the signal payload. Recorded per host record
        # rather than only when a new signal is written: a replayed batch
        # produces no new signal, but the ports it reports were still observed,
        # and their last-seen dates are the whole point.
        record_observed_ports(
            db,
            asset=asset,
            ports=extract_observed_ports(host_record),
            observed_at=now,
        )

        asset_findings_created = 0
        for finding_index, finding_record in enumerate(finding_records, start=1):
            finding_payload = _build_finding_payload(
                batch=batch,
                host_label=host_label,
                host_record=host_record,
                finding_record=finding_record,
                finding_index=finding_index,
                asset=asset,
            )
            finding_fingerprint = finding_payload["findingFingerprint"]
            if finding_fingerprint in existing_finding_fingerprints:
                continue

            severity = _severity_from_value(finding_payload["severity"])
            asset_finding = AssetFinding(
                organization_id=organization_id,
                asset_id=asset.id,
                domain=_FINDING_DOMAIN,
                severity=severity,
                title=finding_payload["title"],
                description=finding_payload["description"],
                evidence_refs=finding_payload["evidenceRefs"],
                risk_score=finding_payload["riskScore"],
                first_seen_at=now,
                last_seen_at=now,
                status=AssetFindingStatus.NEEDS_REVIEW
                if severity in {SeverityLevel.CRITICAL, SeverityLevel.HIGH}
                else AssetFindingStatus.OPEN,
            )
            db.add(asset_finding)
            db.flush()
            finding_count += 1
            asset_findings_created += 1
            existing_finding_fingerprints.add(finding_fingerprint)
            findings.append(
                NormalizedFindingSummary(
                    finding_id=asset_finding.id,
                    asset_id=asset.id,
                    severity=asset_finding.severity.value,
                    title=asset_finding.title,
                    status=asset_finding.status.value,
                    evidence_refs=list(asset_finding.evidence_refs or []),
                    risk_score=asset_finding.risk_score,
                )
            )

        total_findings = _current_finding_count(asset) + asset_findings_created
        recent_findings = findings[-asset_findings_created:] if asset_findings_created else []
        status = (
            AssetStatus.AT_RISK
            if asset_findings_created and _has_high_severity(recent_findings)
            else AssetStatus.PARTIALLY_OBSERVED
        )
        record_status(
            db,
            asset,
            status,
            risk_score=_asset_risk_score(finding_records),
            observation_level="collector_import",
            findings_count=total_findings,
            confidence=_signal_confidence(matched_by, created),
            observed_at=now,
        )

        context = build_asset_business_context(asset, organization_id, db)
        if context.asset_id not in summarized_asset_ids:
            summarized_asset_ids.add(context.asset_id)
            business_contexts.append(
                NormalizedAssetContextSummary(
                    asset_id=context.asset_id,
                    asset_name=context.display_name,
                    matched_by=matched_by,
                    created=created,
                    linked_service_names=[service.service_name for service in context.linked_services],
                    linked_process_names=[process.process_name for process in context.linked_processes],
                    crown_jewel_candidate=context.crown_jewel_candidate,
                    blast_radius_service_count=context.blast_radius.service_count,
                    blast_radius_mission_critical_count=context.blast_radius.mission_critical_count,
                    has_financial_exposure=context.blast_radius.has_financial_exposure,
                )
            )

    batch.status = RiskIngestionBatchStatus.NEEDS_REVIEW
    batch.updated_at = now
    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            event_type=INGESTION_BATCH_NORMALIZED_EVENT,
            metadata_json={
                "ingestionBatchId": batch.id,
                "signalCount": signal_count,
                "findingCount": finding_count,
                "matchedAssetIds": matched_asset_ids,
                "createdAssetIds": created_asset_ids,
                "businessContextCount": len(business_contexts),
                "status": batch.status.value,
            },
        )
    )
    db.commit()
    db.refresh(batch)
    logger.info(
        "risk_intelligence_ingestion_batch_normalized",
        organization_id=organization_id,
        ingestion_batch_id=batch.id,
        signal_count=signal_count,
        finding_count=finding_count,
        matched_asset_ids=matched_asset_ids,
        created_asset_ids=created_asset_ids,
    )

    technical_summary = (
        f"Normalized {len(host_records)} host observations from {batch.source_name} "
        f"into {signal_count} signals and {finding_count} findings."
    )
    return NormalizationResult(
        ingestion_batch_id=batch.id,
        organization_id=organization_id,
        batch_status=batch.status,
        normalized_at=now,
        technical_summary=technical_summary,
        human_decision_required=True,
        signal_count=signal_count,
        finding_count=finding_count,
        matched_asset_ids=matched_asset_ids,
        created_asset_ids=created_asset_ids,
        business_contexts=business_contexts,
        findings=findings,
    )


def serialize_normalization_result(result: NormalizationResult) -> dict[str, Any]:
    return {
        "ingestionBatchId": result.ingestion_batch_id,
        "organizationId": result.organization_id,
        "batchStatus": result.batch_status.value,
        "normalizedAt": result.normalized_at.isoformat(),
        "technicalSummary": result.technical_summary,
        "humanDecisionRequired": result.human_decision_required,
        "signalCount": result.signal_count,
        "findingCount": result.finding_count,
        "matchedAssetIds": result.matched_asset_ids,
        "createdAssetIds": result.created_asset_ids,
        "businessContexts": [
            {
                "assetId": context.asset_id,
                "assetName": context.asset_name,
                "matchedBy": context.matched_by,
                "created": context.created,
                "linkedServiceNames": context.linked_service_names,
                "linkedProcessNames": context.linked_process_names,
                "crownJewelCandidate": context.crown_jewel_candidate,
                "blastRadiusServiceCount": context.blast_radius_service_count,
                "blastRadiusMissionCriticalCount": context.blast_radius_mission_critical_count,
                "hasFinancialExposure": context.has_financial_exposure,
            }
            for context in result.business_contexts
        ],
        "findings": [
            {
                "findingId": finding.finding_id,
                "assetId": finding.asset_id,
                "severity": finding.severity,
                "title": finding.title,
                "status": finding.status,
                "evidenceRefs": finding.evidence_refs,
                "riskScore": finding.risk_score,
            }
            for finding in result.findings
        ],
    }


def _extract_host_records(raw_payload: dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
    if isinstance(raw_payload, list):
        return [item for item in raw_payload if isinstance(item, dict)]
    if not isinstance(raw_payload, dict):
        return []

    for key in _HOST_KEYS:
        value = raw_payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]

    if any(key in raw_payload for key in ("hostname", "fqdn", "ip", "services", "findings")):
        return [raw_payload]

    return []


def _extract_global_findings(raw_payload: dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
    if not isinstance(raw_payload, dict):
        return []
    for key in _FINDING_KEYS:
        value = raw_payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _host_findings(host_record: dict[str, Any], raw_payload: dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
    for key in _FINDING_KEYS:
        value = host_record.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return _extract_global_findings(raw_payload)


#: Keys that carry a *name* someone gave this host — a resolved hostname, an
#: FQDN, a label a source already chose. Separated from the address keys below
#: because CA-07.1 needs to know whether a host is already named: a name the
#: organisation's own DNS supplies beats anything a scan can infer about it.
_HOST_NAME_KEYS = ("hostname", "fqdn", "host", "name", "displayName", "assetName", "target")
_HOST_ADDRESS_KEYS = ("ip", "address")


def _network_address(host_record: dict[str, Any]) -> str | None:
    """Where the artefact lives, and only that.

    Deliberately **not** `_host_label`, which searches names before addresses
    because a hostname is the better handle for identity matching. The two
    questions are different — *what do we call it* and *where is it* — and one
    function answering both is what let a hostname be stored as an address
    (#323).
    """
    return _first_string(host_record, _HOST_ADDRESS_KEYS)


def _first_string(host_record: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = host_record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, list):
            for candidate in value:
                if isinstance(candidate, str) and candidate.strip():
                    return candidate.strip()
    return None


def _host_label(host_record: dict[str, Any], *, fallback: str) -> str:
    """The stable identifier this host is matched and keyed on.

    Unchanged by CA-07.1 on purpose. It feeds `_identity_candidate` and the
    canonical identity key, so it must keep answering "which artefact is this?"
    with a network identifier. What a person *reads* is chosen separately, in
    `_display_name` — an application being renamed must not read as a new
    artefact arriving.
    """
    return _first_string(host_record, _HOST_NAME_KEYS + _HOST_ADDRESS_KEYS) or fallback


#: Reasons that mean *"this run did not look properly"* rather than *"we looked
#: and it is not there"*. A stored name survives these and is cleared by the
#: others, which is what lets a name be withdrawn by evidence instead of only
#: ever being added to.
_SHALLOW_LOOK_REASONS = frozenset(
    {
        ArtefactIdentityUndetermined.NOT_PROBED.value,
        ArtefactIdentityUndetermined.NOTHING_LISTENING.value,
        # CA-09A.2 — the most shallow look of all: the Collector could not see
        # hardware addresses, so a silent device could not be named however
        # carefully it was scanned. Without this, a Collector that loses the
        # capability would *withdraw* names a privileged scan had established,
        # and the estate would get quietly worse on a re-scan.
        ArtefactIdentityUndetermined.HARDWARE_NOT_VISIBLE.value,
    }
)


def _refresh_identity(
    asset: Asset, intent: dict[str, Any], *, host_record: dict[str, Any], host_label: str
) -> None:
    """Re-read what this artefact is, on every re-observation.

    **The defect this fixes**, seen on a real inventory (Søren, 2026-08-25):
    `192.168.1.20` had an open HTTP proxy port and its row read *"Nothing
    answered on this address, so there was nothing to identify it by."* The
    artefact had been created by an earlier sweep that found nothing, and
    identity was written once at creation and never again — so a later scan that
    did find something updated the classification, the type and the layer, and
    left the identity frozen at the first run's verdict.

    That is precisely what the classification branch above refuses to do, in its
    own words: *"the row improves as the classifier does instead of being frozen
    at the first scan's verdict."* The reasoning was right and was only ever
    applied to half the record.

    **A name is never lost to a shallower look.** A safe-discovery sweep that
    skips version detection is not evidence that yesterday's deep scan was
    wrong, so its silence leaves an existing name alone.

    **But a run that genuinely looked and found nothing does clear it.**
    Otherwise a name can never be withdrawn once written, and the first bad one
    outlives every scan that disagrees. That is not hypothetical: two artefacts
    were carrying "Site doesn't have a title (text/html)" as their name, and a
    rule that only ever protected stored names would have preserved exactly the
    values this change exists to get rid of.
    """
    fresh = determine_identity(host_record)
    stored = intent.get("identity") if isinstance(intent.get("identity"), dict) else {}

    if fresh.name is None and stored.get("name") and fresh.undetermined_reason in _SHALLOW_LOOK_REASONS:
        return

    intent["identity"] = {
        "name": fresh.name,
        "basis": fresh.basis,
        "evidence": fresh.evidence,
        "undeterminedReason": fresh.undetermined_reason,
        # Every basis that independently produced a name, not only the one
        # that won. Two readings that agree are a better claim than either
        # alone (Søren, 2026-08-27), and the matcher cannot weigh that if
        # only the winner survives into storage.
        "corroboratingBases": list(fresh.corroborating_bases),
        "explanation": fresh.explanation,
    }
    asset.intent = intent

    # The row's title follows the same ladder it was first built from, because a
    # title derived from a rejected identity otherwise outlives it. Two artefacts
    # on the live inventory were **named** "Site doesn't have a title
    # (text/html)" — nmap reporting the absence of a title. Correcting the filter
    # stops that being read as a name again, and this is what lets the rows
    # already carrying it recover on their next scan instead of keeping it for
    # ever.
    #
    # Safe to recompute because nothing else can write it: no route sets
    # `display_name`, so it has only ever come from the scan. The day a person
    # can rename an artefact, this needs the same guard `classificationSetByHuman`
    # gives the class.
    asset.display_name = _display_name(host_record, identity_name=fresh.name, host_label=host_label)


def _display_name(host_record: dict[str, Any], *, identity_name: str | None, host_label: str) -> str:
    """What a person reads on the row.

    Order, strongest first:

    1. **A name the organisation already gave it.** A resolved hostname is their
       own vocabulary, and a scan has no business overriding it — replacing
       `app.example.com` with `nginx 1.24.0` tells a reader what software serves
       the host and loses what the host *is*.
    2. **What the scan determined it to be.** This is the case the story exists
       for: a bare `192.168.1.33` with no DNS behind it becomes `Plane`.
    3. The address, as before.
    """
    return _first_string(host_record, _HOST_NAME_KEYS) or identity_name or host_label


@dataclass(frozen=True)
class _SignalProvenance:
    """CA-06.2 — where a batch's observations came from.

    Resolved once per batch rather than per host: every signal in one batch
    shares the same package, job and Collector, and a batch with 400 hosts
    should not ask the database the same question 400 times.

    Every field is ``None`` for a hand-uploaded batch, and stays ``None``. An
    absent reference reads as absent — the alternative is inventing a
    provenance chain for evidence that never had one.
    """

    evidence_package_id: str | None = None
    provider_execution_id: str | None = None
    scanner_instance_id: str | None = None


def _resolve_signal_provenance(db: Session, batch: RiskIngestionBatch) -> _SignalProvenance:
    if batch.evidence_package_id is None:
        return _SignalProvenance()

    package = (
        db.query(EvidencePackage)
        .filter(
            EvidencePackage.id == batch.evidence_package_id,
            EvidencePackage.organization_id == batch.organization_id,
        )
        .first()
    )
    if package is None:
        return _SignalProvenance()

    # The Collector is a property of the run, not of the package, so it is the
    # one hop that has to be walked. Recorded onto the signal afterwards so the
    # question does not need walking again.
    scanner_instance_id = (
        db.query(DiscoveryRun.scanner_instance_id)
        .filter(
            DiscoveryRun.id == package.discovery_run_id,
            DiscoveryRun.organization_id == batch.organization_id,
        )
        .scalar()
    )
    return _SignalProvenance(
        evidence_package_id=package.id,
        provider_execution_id=package.provider_execution_id,
        scanner_instance_id=scanner_instance_id,
    )


class _UnknownVulnerabilityHost(Exception):
    """A vulnerability observation whose host is not on record.

    Not an error in the evidence — it is a statement about the inventory. The
    scan was sent to an address this platform chose from its own artefacts, so
    being unable to find that artefact again means something moved, merged or
    was removed between the command and the result. The finding is skipped and
    said out loud rather than hung on a new row nobody asked for.
    """

    def __init__(self, host_label: str) -> None:
        super().__init__(host_label)
        self.host_label = host_label


def _resolve_or_create_asset(
    db: Session,
    *,
    organization_id: int,
    actor_user_id: int | None,
    batch: RiskIngestionBatch,
    host_record: dict[str, Any],
    host_label: str,
) -> tuple[Asset, str, bool]:
    candidate = _identity_candidate(organization_id, host_record, host_label)
    resolution = resolve_identity(db, candidate)

    # Only a *decided* match links this observation to an existing artefact.
    # Branching on `matched_asset is not None` instead — as this did before
    # CA-06.1 — merged POSSIBLE_MATCHes too, because the identity service
    # returns the candidate row it is unsure about rather than hiding it. That
    # silently merged artefacts on a display-name collision alone, against the
    # standing rule that uncertain records are never silently merged, and left
    # the UNCONFIRMED branch below unreachable.
    is_decided_match = resolution.match_type in (
        ArtefactIdentityMatchType.EXACT_MATCH,
        ArtefactIdentityMatchType.STRONG_MATCH,
    )

    # An observation that cannot establish identity is one that never discovered
    # anything — a vulnerability scan is pointed at hosts discovery already
    # found, and its targets are built from `asset_identifiers`. So its host is
    # by construction already on record, and the address it reports came *from*
    # that artefact.
    #
    # That makes a lone address match a return to source rather than the open
    # question it is for a discovery provider. "IP alone is not identity" holds
    # where an address is the only thing connecting two observations; here the
    # address is why the scan went to that host at all.
    #
    # Two addresses matching two artefacts is still a real question and is left
    # to a person.
    if not host_record.get("establishesIdentity", True):
        if is_decided_match and resolution.matched_asset is not None:
            pass
        elif (
            resolution.match_type == ArtefactIdentityMatchType.POSSIBLE_MATCH
            and resolution.matched_asset is not None
            and len(resolution.conflicting_asset_ids) <= 1
        ):
            is_decided_match = True
        else:
            # Nothing to hang this on, and inventing an artefact from a
            # vulnerability match is the fabrication BUG-DISC-14 removed from two
            # other paths. Raised rather than swallowed: the scan was sent to an
            # address the platform chose, so failing to find it again is a real
            # discrepancy and not a routine miss.
            raise _UnknownVulnerabilityHost(host_label)

    if is_decided_match and resolution.matched_asset is not None:
        asset = resolution.matched_asset
        # Backfill: this asset predates identity keys (STRONG_MATCH) — set
        # it now so the *next* run of the same source resolves EXACT_MATCH
        # instead of re-deriving the same inference every time.
        if asset.canonical_identity_key is None and resolution.canonical_identity_key is not None:
            asset.canonical_identity_key = resolution.canonical_identity_key
            db.add(asset)
        # Re-derive from the evidence this run actually observed — but never over
        # a person's own answer about what this thing is. That is marked
        # specifically, not inferred from `reviewed_at`: confirming an artefact
        # means "yes, this is ours" and says nothing about the label, so keying
        # on it would freeze a machine guess the moment someone confirmed the
        # row. Where no human has classified it, the platform's earlier guess
        # carries no more authority than today's, so the row improves as the
        # classifier does instead of being frozen at the first scan's verdict.
        rescan = classify_host_record(host_record)
        intent = dict(asset.intent) if isinstance(asset.intent, dict) else {}

        # #323 — refreshed on every scan, not written once at creation. Two
        # reasons, and the second is why the fix above is not enough on its own:
        #
        # An address is an *observation* and it moves — DHCP reassigns, a host
        # is renumbered — so a value frozen at first sight quietly becomes a
        # claim about where something used to be.
        #
        # And every artefact already on the estate carries the old, wrong value:
        # the hostname, stored as an address. Without this they would keep it
        # forever however many times they were rescanned, which is exactly the
        # "written once and never again" failure this file already had to fix
        # for identity.
        observed_address = _network_address(host_record)
        if observed_address:
            intent["networkAddress"] = observed_address
            asset.intent = intent

        if rescan.observed:
            intent["observedServices"] = list(rescan.observed)
            intent["observedServiceEvidence"] = [
                {"name": item.name, "port": item.port, "probed": item.probed}
                for item in rescan.observed_evidence
            ]
            asset.intent = intent
            db.add(asset)
        if not intent.get("classificationSetByHuman"):
            asset.type = rescan.asset_type
            asset.layer = rescan.layer
            db.add(asset)
        _refresh_identity(asset, intent, host_record=host_record, host_label=host_label)
        db.add(asset)
        # CA-06.1 — grow the identifier set. This is what keeps the artefact
        # linked next time: an address seen today is what the *following* run
        # matches on if the hostname stops resolving.
        newly_observed = record_observed_identifiers(
            db,
            asset=asset,
            identifiers=resolution.observed_identifiers,
            observed_by_source=batch.source_name,
        )
        _write_audit(
            db,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            event_type=ARTEFACT_AUDIT_IDENTITY_MATCHED,
            metadata={
                "assetId": asset.id,
                "matchType": resolution.match_type.value,
                "reason": resolution.reason,
                "ingestionBatchId": batch.id,
            },
        )
        if newly_observed:
            # An artefact answering to something it has not answered to before
            # is a fact worth its own audit line — this is the trail that
            # explains why the inventory did *not* grow a row.
            _write_audit(
                db,
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                event_type=ARTEFACT_AUDIT_IDENTIFIER_OBSERVED,
                metadata={
                    "assetId": asset.id,
                    "identifiers": [
                        {"type": identifier.identifier_type.value, "value": identifier.value}
                        for identifier in newly_observed
                    ],
                    "ingestionBatchId": batch.id,
                },
            )
        return asset, f"matched:{resolution.match_type.value}:{host_label}", False

    # DISTINCT, or a POSSIBLE_MATCH the identity service deliberately
    # refused to auto-merge (spec: ambiguous matches never silently merge —
    # preserve both records rather than destroying evidence). A possible
    # match still creates its own new row, just flagged UNCONFIRMED instead
    # of ACTIVE so it's queryable as a reviewable candidate.
    lifecycle_state = (
        AssetLifecycleState.UNCONFIRMED
        if resolution.match_type == ArtefactIdentityMatchType.POSSIBLE_MATCH
        else AssetLifecycleState.ACTIVE
    )
    classification = classify_host_record(host_record)
    # CA-07.1 — what the host called itself, where the evidence supports it.
    # Deliberately *not* folded into `host_label`: that value feeds identity
    # matching and the canonical identity key, and it must stay a stable network
    # identifier. A name is what a person reads; an identifier is what the
    # platform matches on, and the two changing together would make renaming an
    # application look like the arrival of a new artefact.
    identity = determine_identity(host_record)
    asset = Asset(
        organization_id=organization_id,
        # BUG-DISC-15: this read a key nmap never emits, so every discovered
        # artefact was a "Service". Both fields now come from the observed
        # evidence, or say Unknown.
        type=classification.asset_type,
        provider="collector",
        provider_display_name=batch.source_name,
        display_name=_display_name(host_record, identity_name=identity.name, host_label=host_label),
        layer=classification.layer,
        environment=Environment.PROD,
        criticality=Criticality.MEDIUM,
        status=AssetStatus.PARTIALLY_OBSERVED,
        connectivity_status=ConnectivityStatus.PENDING_VERIFICATION,
        setup_confidence=SetupConfidence.LOW,
        scan_start_mode=ScanStartMode.AUDIT_ONLY,
        observation_level="collector_import",
        findings_count=0,
        risk_score=0.0,
        confidence=0.4,
        canonical_identity_key=resolution.canonical_identity_key,
        lifecycle_state=lifecycle_state,
        intent={
            "ingestionBatchId": batch.id,
            "sourceName": batch.source_name,
            "collectorProfile": batch.collector_profile,
            # What was actually seen on this host. Kept so the review list can
            # show it: a generic class plus the observed services is far more
            # use to a reviewer than a confident-sounding class alone.
            "observedServices": list(classification.observed),
            # Per *port*, with whether nmap actually probed it. `observedServices`
            # above is a de-duplicated list of names and stays exactly as it was —
            # older rows have only that, and the reading side falls back to it.
            "observedServiceEvidence": [
                {"name": item.name, "port": item.port, "probed": item.probed}
                for item in classification.observed_evidence
            ],
            # CA-07.1 — how the name above was arrived at, or why there isn't
            # one. `networkAddress` is kept alongside because the address stops
            # being the display name the moment an identity is determined, and a
            # reviewer still needs to know where the thing lives.
            #
            # #323 — the **address**, not the host label. `_host_label` prefers a
            # hostname (it is the better handle for matching), so on any host
            # that announced one this stored the hostname and called it an
            # address. That made `display_name` and `networkAddress` identical,
            # and the surfaces read that as "the name is only the address
            # wearing a name's clothes" — so a device called `iPad`, with `iPad`
            # in both fields, was titled **"Unidentified device"** while showing
            # `iPad` on a chip beside it. The row contradicted itself, and it did
            # so because this field was not what it claimed to be.
            "networkAddress": _network_address(host_record) or host_label,
            "identity": {
                "name": identity.name,
                "basis": identity.basis,
                "evidence": identity.evidence,
                "undeterminedReason": identity.undetermined_reason,
                "corroboratingBases": list(identity.corroborating_bases),
                "explanation": identity.explanation,
            },
        },
    )
    db.add(asset)
    db.flush()
    record_observed_identifiers(
        db,
        asset=asset,
        identifiers=resolution.observed_identifiers,
        observed_by_source=batch.source_name,
    )
    _write_audit(
        db,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        event_type=ARTEFACT_AUDIT_DISCOVERED,
        metadata={
            "assetId": asset.id,
            "matchType": resolution.match_type.value,
            "lifecycleState": lifecycle_state.value,
            "ingestionBatchId": batch.id,
        },
    )
    if resolution.conflicting_asset_ids:
        # Recorded as its own event, and on the row itself, so the question
        # survives the run that raised it. Resolving it is CA-06.4's job; all
        # this does is refuse to answer it by guessing.
        intent = dict(asset.intent) if isinstance(asset.intent, dict) else {}
        intent["possibleDuplicateOfAssetIds"] = list(resolution.conflicting_asset_ids)
        intent["possibleDuplicateReason"] = resolution.reason
        asset.intent = intent
        db.add(asset)
        # And as a record a person can actually act on. The intent field and the
        # audit event state the question; neither can be answered. `raise_...`
        # refuses to reopen a pair someone already decided, which is what makes
        # "keep separate" durable across scans (CA-06.4).
        for other_asset_id in resolution.conflicting_asset_ids:
            raise_identity_conflict(
                db,
                organization_id=organization_id,
                left_asset_id=asset.id,
                right_asset_id=other_asset_id,
                reason=resolution.reason,
                evidence={
                    "ingestionBatchId": batch.id,
                    "matchType": resolution.match_type.value,
                    "observedIdentifiers": [
                        {"identifierType": observed.identifier_type.value, "identifierValue": observed.value}
                        for observed in resolution.observed_identifiers
                    ],
                },
            )
        _write_audit(
            db,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            event_type=ARTEFACT_AUDIT_IDENTITY_CONFLICT,
            metadata={
                "assetId": asset.id,
                "conflictingAssetIds": list(resolution.conflicting_asset_ids),
                "reason": resolution.reason,
                "ingestionBatchId": batch.id,
            },
        )
    # CA-06.5 — the approved boundary binds the inventory, not only the scan.
    # A target inside an exclusion can still be reached (another source, a
    # broader sweep), and a new row for it would put the organisation back to
    # looking at something it explicitly agreed not to look at.
    _withdraw_if_outside_boundary(
        db, asset=asset, batch=batch, organization_id=organization_id, actor_user_id=actor_user_id
    )
    return asset, "created", True


def _withdraw_if_outside_boundary(
    db: Session,
    *,
    asset: Asset,
    batch: RiskIngestionBatch,
    organization_id: int,
    actor_user_id: int | None,
) -> None:
    """Apply the boundary this batch came through, if it can be established.

    Silent when the evidence source cannot be resolved — a batch with no
    discovery run behind it has no boundary to apply, and withdrawing on a guess
    would take an artefact out of the inventory with nothing to point at as the
    reason.
    """
    evidence_source_id = _batch_evidence_source_id(db, batch)
    if evidence_source_id is None:
        return

    boundary = get_approved_scope(
        db, organization_id=organization_id, evidence_source_id=evidence_source_id
    )
    if boundary is None:
        return

    exclusions = [str(value) for value in (boundary.exclusions or [])]
    verdict = evaluate_boundary(db, asset=asset, exclusions=exclusions)
    if verdict.excluded:
        withdraw_artefact(db, asset=asset, verdict=verdict, actor_user_id=actor_user_id)


def _batch_evidence_source_id(db: Session, batch: RiskIngestionBatch) -> str | None:
    if batch.evidence_package_id is None:
        return None
    package = (
        db.query(EvidencePackage)
        .filter(
            EvidencePackage.id == batch.evidence_package_id,
            EvidencePackage.organization_id == batch.organization_id,
        )
        .first()
    )
    if package is None:
        return None
    return (
        db.query(DiscoveryRun.evidence_source_id)
        .filter(
            DiscoveryRun.id == package.discovery_run_id,
            DiscoveryRun.organization_id == batch.organization_id,
        )
        .scalar()
    )


def _identity_candidate(
    organization_id: int, host_record: dict[str, Any], host_label: str
) -> ArtefactIdentityCandidate:
    def _str(key: str) -> str | None:
        value = host_record.get(key)
        return value.strip() if isinstance(value, str) and value.strip() else None

    hostname = _str("hostname") or _str("fqdn") or _str("host") or _str("target")
    domain = _str("domain")
    ip_address = _str("ip") or _str("address")
    provider = _str("provider")
    provider_resource_id = _str("resourceId") or _str("resource_id") or _str("providerResourceId")

    return ArtefactIdentityCandidate(
        organization_id=organization_id,
        normalized_type=str(host_record.get("type") or "Service"),
        provider=provider,
        provider_resource_id=provider_resource_id,
        hostname=hostname,
        domain=domain,
        ip_address=ip_address,
        display_name=host_label,
    )


def _build_signal_payload(
    *,
    batch: RiskIngestionBatch,
    host_record: dict[str, Any],
    host_label: str,
    asset: Asset,
    matched_by: str,
    created: bool,
    finding_records: list[dict[str, Any]],
) -> dict[str, Any]:
    # Fingerprint only the stable observation data — never the resolution
    # outcome (matchedBy/created/assetId), which can legitimately differ
    # between two runs over the *identical* payload (e.g. "created" the
    # first time, "matched:..." once that asset exists) without the
    # observation itself being new. Fingerprinting the outcome would break
    # idempotent replay (Step 4.1A acceptance criterion).
    fingerprint_basis = {
        "ingestionBatchId": batch.id,
        "sourceName": batch.source_name,
        "collectorProfile": batch.collector_profile,
        "hostLabel": host_label,
        "host": _select_host_identity(host_record),
        "services": host_record.get("services") if isinstance(host_record.get("services"), list) else [],
        "findingTitles": [_finding_title(finding) for finding in finding_records],
    }
    payload = {
        **fingerprint_basis,
        "asset": {
            "assetId": asset.id,
            "assetName": asset.display_name,
            "matchedBy": matched_by,
            "created": created,
        },
        "signalFingerprint": _fingerprint(fingerprint_basis),
    }
    return payload


def _build_finding_payload(
    *,
    batch: RiskIngestionBatch,
    host_label: str,
    host_record: dict[str, Any],
    finding_record: dict[str, Any],
    finding_index: int,
    asset: Asset,
) -> dict[str, Any]:
    finding = {
        "ingestionBatchId": batch.id,
        "hostLabel": host_label,
        "findingIndex": finding_index,
        "finding": finding_record,
        "assetId": asset.id,
    }
    title = _finding_title(finding_record)
    severity = _severity_string(finding_record)
    description = _finding_description(finding_record)
    evidence_refs = [
        f"ingestion-batch:{batch.id}",
        f"host:{host_label}",
        f"finding-fingerprint:{_fingerprint(finding)}",
    ]
    payload = {
        "title": title,
        "severity": severity,
        "description": description,
        "evidenceRefs": evidence_refs,
        "riskScore": _finding_risk_score(severity),
        "findingFingerprint": _fingerprint(finding),
        "source": batch.source_name,
        "collectorProfile": batch.collector_profile,
        "rawFinding": finding_record,
        "host": _select_host_identity(host_record),
    }
    return payload


def _load_existing_fingerprints(
    db: Session,
    *,
    organization_id: int,
    batch_id: int,
) -> tuple[set[str], set[str]]:
    # BUG-DISC-12: both filters below used to run in Python over every row the
    # organisation had ever produced, loaded as full ORM entities. The batch
    # filter in particular threw almost all of them away again. On a real
    # database that is not a slow path, it is a wall: 14.1 million signal rows
    # (3.5 GB) took the worker past 100% CPU and 5 GB resident without ever
    # finishing, so no evidence could be normalised at all.
    #
    # Both queries now select a single column and let the database do the
    # filtering. Semantics are unchanged: signal fingerprints are scoped to
    # this batch, finding fingerprints to the whole organisation.
    existing_signal_payloads = db.execute(
        select(AssetEvidenceSignal.payload_json).where(
            AssetEvidenceSignal.organization_id == organization_id,
            # as_integer, not as_string: the two backends disagree on what a
            # JSON number extracts to (Postgres ->> gives text, SQLite gives an
            # integer), and a string comparison silently matches nothing on
            # SQLite — which breaks replay idempotency rather than erroring.
            # ingestionBatchId is always written from batch.id by this module,
            # so it is always numeric.
            AssetEvidenceSignal.payload_json["ingestionBatchId"].as_integer() == batch_id,
        )
    ).scalars().all()
    existing_finding_refs = db.execute(
        select(AssetFinding.evidence_refs).where(AssetFinding.organization_id == organization_id)
    ).scalars().all()

    signal_fingerprints = {
        str(payload.get("signalFingerprint"))
        for payload in existing_signal_payloads
        if isinstance(payload, dict) and payload.get("signalFingerprint")
    }
    finding_fingerprints = set()
    for refs in existing_finding_refs:
        refs = refs or []
        for ref in refs:
            if isinstance(ref, str) and ref.startswith("finding-fingerprint:"):
                finding_fingerprints.add(ref.removeprefix("finding-fingerprint:"))
    return signal_fingerprints, finding_fingerprints


def _fingerprint(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _select_host_identity(host_record: dict[str, Any]) -> dict[str, Any]:
    identity: dict[str, Any] = {}
    for key in ("hostname", "fqdn", "host", "name", "ip", "address"):
        value = host_record.get(key)
        if isinstance(value, str) and value.strip():
            identity[key] = value.strip()
    if isinstance(host_record.get("services"), list):
        identity["services"] = host_record["services"]
    return identity


def _finding_title(finding_record: dict[str, Any]) -> str:
    for key in ("title", "name", "id", "finding", "summary"):
        value = finding_record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "Collector finding"


def _finding_description(finding_record: dict[str, Any]) -> str | None:
    for key in ("description", "detail", "details", "message", "output"):
        value = finding_record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _severity_string(finding_record: dict[str, Any]) -> str:
    value = finding_record.get("severity")
    if isinstance(value, str) and value.strip():
        return value.strip().lower()
    return SeverityLevel.MEDIUM.value


def _severity_from_value(value: str) -> SeverityLevel:
    normalized = value.strip().lower()
    mapping = {
        "critical": SeverityLevel.CRITICAL,
        "high": SeverityLevel.HIGH,
        "medium": SeverityLevel.MEDIUM,
        "moderate": SeverityLevel.MEDIUM,
        "low": SeverityLevel.LOW,
        "info": SeverityLevel.INFO,
        "informational": SeverityLevel.INFO,
    }
    return mapping.get(normalized, SeverityLevel.MEDIUM)


def _finding_risk_score(severity: str) -> float:
    mapping = {
        SeverityLevel.CRITICAL.value: 95.0,
        SeverityLevel.HIGH.value: 80.0,
        SeverityLevel.MEDIUM.value: 55.0,
        SeverityLevel.LOW.value: 25.0,
        SeverityLevel.INFO.value: 5.0,
    }
    return mapping.get(severity, 50.0)


def _risk_score_from_findings(finding_records: list[dict[str, Any]]) -> float:
    if not finding_records:
        return 5.0
    scores = [_finding_risk_score(_severity_string(record)) for record in finding_records]
    return max(scores) if scores else 5.0


def _asset_risk_score(finding_records: list[dict[str, Any]]) -> float:
    if not finding_records:
        return 5.0
    severity_weight = {
        SeverityLevel.CRITICAL.value: 95.0,
        SeverityLevel.HIGH.value: 80.0,
        SeverityLevel.MEDIUM.value: 55.0,
        SeverityLevel.LOW.value: 25.0,
        SeverityLevel.INFO.value: 5.0,
    }
    weighted_scores = [severity_weight.get(_severity_string(record), 50.0) for record in finding_records]
    return max(weighted_scores) if weighted_scores else 5.0


def _signal_confidence(matched_by: str, created: bool) -> float:
    if created:
        return 0.4
    if matched_by.startswith("matched:"):
        label = matched_by.removeprefix("matched:")
        return 0.95 if label else 0.85
    return 0.7


def _classify_observation(
    host_record: dict[str, Any], finding_records: list[dict[str, Any]]
) -> TechnicalObservationType:
    """One signal per host record today, not one per discrete technical
    fact (Step 4.2's real per-stage execution loop would enable that) — so
    classify by the single most significant fact present: a finding
    outranks a service outranks bare reachability."""
    if finding_records:
        return TechnicalObservationType.VULNERABILITY_OBSERVED
    if isinstance(host_record.get("services"), list) and host_record["services"]:
        return TechnicalObservationType.SERVICE_EXPOSED
    return TechnicalObservationType.HOST_REACHABLE


def _signal_severity(finding_records: list[dict[str, Any]]) -> SeverityLevel | None:
    if not finding_records:
        return None
    severities = [_severity_from_value(_severity_string(record)) for record in finding_records]
    order = [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO]
    for level in order:
        if level in severities:
            return level
    return None


def _current_finding_count(asset: Asset) -> int:
    if isinstance(asset.findings_count, int):
        return asset.findings_count
    return 0


def _has_high_severity(findings: list[NormalizedFindingSummary]) -> bool:
    return any(finding.severity in {SeverityLevel.HIGH.value, SeverityLevel.CRITICAL.value} for finding in findings)
