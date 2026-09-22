"""Step 4.1A/4.1B — Discovery normalisation into the shared organisation
inventory (``Asset``) and the structured observations recorded against it
(``AssetEvidenceSignal``).

Vocabulary only: how a normalized signal is classified by pipeline
(``kind``, 4.1A) and by what it actually observed (``observation_type``,
4.1B), how confidently two candidate observations were matched to the same
real-world artefact, and the audit event names this domain writes.
Deliberately does not model business criticality, Business Service
assignment, or dependency mapping — that stays Step 4.1C's job
(``SlotInstance``, already built under the BSP ticket series).
"""

from enum import StrEnum


class AssetEvidenceSignalKind(StrEnum):
    """Controlled taxonomy for ``AssetEvidenceSignal.kind`` (a plain
    ``String(100)`` column — no DB-level enum, to avoid a disruptive
    migration on live data; validated here at the service layer instead).
    Extends, never replaces, the existing ``COLLECTOR_HOST_OBSERVATION``
    value written by ``assets_service.py``'s manual connector path.
    """

    COLLECTOR_HOST_OBSERVATION = "collector_host_observation"
    RISK_INTELLIGENCE_INGESTION = "risk_intelligence_ingestion"


class ArtefactIdentityMatchType(StrEnum):
    """Result of comparing a normalization candidate against the org's
    existing Asset registry (skill: confidence = verification, never
    fabricated — a POSSIBLE_MATCH never auto-merges)."""

    EXACT_MATCH = "exact_match"
    STRONG_MATCH = "strong_match"
    POSSIBLE_MATCH = "possible_match"
    DISTINCT = "distinct"


class ArtefactIdentifierType(StrEnum):
    """CA-06.1 — the kinds of identifier an artefact can be observed under.

    An artefact is not one identifier; it is the set of identifiers it has ever
    been seen as. This vocabulary names the members of that set so identity can
    survive one of them changing (a DHCP lease) or a second source contributing
    a different one (nmap sees a hostname, AWS sees an instance id).
    """

    PROVIDER_RESOURCE = "provider_resource"
    HOSTNAME = "hostname"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    ENDPOINT = "endpoint"


#: Identifiers that name a *thing*. An overlap on one of these is enough to say
#: two observations are the same artefact.
STRONG_ARTEFACT_IDENTIFIER_TYPES: frozenset[ArtefactIdentifierType] = frozenset(
    {
        ArtefactIdentifierType.PROVIDER_RESOURCE,
        ArtefactIdentifierType.HOSTNAME,
        ArtefactIdentifierType.DOMAIN,
        ArtefactIdentifierType.ENDPOINT,
    }
)

#: Identifiers that name a *location*, which today's occupant may not be
#: tomorrow's. The CA-06 rule "IP alone is not identity" lives here: an overlap
#: on one of these raises a conflict for a person to resolve (CA-06.4) and never
#: merges on its own.
WEAK_ARTEFACT_IDENTIFIER_TYPES: frozenset[ArtefactIdentifierType] = frozenset(
    {ArtefactIdentifierType.IP_ADDRESS}
)

#: Ordering used to pick which identifier a canonical key is derived from —
#: strongest first. Deliberately the same precedence the pre-CA-06.1 single-signal
#: key used, so keys already stored keep resolving to the same artefact.
ARTEFACT_IDENTIFIER_STRENGTH_ORDER: tuple[ArtefactIdentifierType, ...] = (
    ArtefactIdentifierType.PROVIDER_RESOURCE,
    ArtefactIdentifierType.HOSTNAME,
    ArtefactIdentifierType.DOMAIN,
    ArtefactIdentifierType.IP_ADDRESS,
    ArtefactIdentifierType.ENDPOINT,
)

#: An identifier set changed in a way a person may need to look at.
ARTEFACT_AUDIT_IDENTIFIER_OBSERVED = "artefact.identifier_observed"
#: Two artefacts overlap, but only on a weak identifier — never merged here.
ARTEFACT_AUDIT_IDENTITY_CONFLICT = "artefact.identity_conflict"


class ArtefactIdentityConflictState(StrEnum):
    """CA-06.4 — where a person has got to with an uncertain match.

    The platform raises the question and never answers it. Both resolutions are
    real decisions, recorded as such: ``RESOLVED_SEPARATE`` is not "nothing
    happened", it is a person stating these are genuinely different things, and
    it has to be durable or the next scan asks them again.
    """

    OPEN = "open"
    RESOLVED_MERGED = "resolved_merged"
    RESOLVED_SEPARATE = "resolved_separate"


#: A person decided two records are the same thing, or are not.
ARTEFACT_AUDIT_KEPT_SEPARATE = "artefact.kept_separate"
#: A merge was undone. Its own event, never a second `artefact.merged`.
ARTEFACT_AUDIT_MERGE_REVERSED = "artefact.merge_reversed"

#: CA-06.5 — the approved boundary took an artefact out of the inventory, and
#: gave it back. Distinct from the human review events: nobody decided this
#: artefact is not theirs, the agreed scope simply stopped covering it.
ARTEFACT_AUDIT_BOUNDARY_WITHDRAWN = "artefact.boundary_withdrawn"
ARTEFACT_AUDIT_BOUNDARY_RESTORED = "artefact.boundary_restored"


class TechnicalObservationType(StrEnum):
    """What was actually observed — distinct from AssetEvidenceSignalKind
    (which pipeline produced the row). The current ingestion pipeline
    writes one signal per host record rather than one per discrete
    technical fact, so a signal covering several services/findings is
    classified by its single most significant fact (findings outrank
    services outrank bare reachability) — an honest simplification of the
    current one-signal-per-host granularity, not fabricated precision."""

    HOST_REACHABLE = "host_reachable"
    SERVICE_EXPOSED = "service_exposed"
    PORT_OPEN = "port_open"
    SOFTWARE_VERSION_OBSERVED = "software_version_observed"
    CERTIFICATE_EXPIRY_OBSERVED = "certificate_expiry_observed"
    ENCRYPTION_CONFIGURATION_OBSERVED = "encryption_configuration_observed"
    AUTHENTICATION_MECHANISM_OBSERVED = "authentication_mechanism_observed"
    BACKUP_STATE_OBSERVED = "backup_state_observed"
    MONITORING_SIGNAL_OBSERVED = "monitoring_signal_observed"
    LOGGING_STATE_OBSERVED = "logging_state_observed"
    VULNERABILITY_OBSERVED = "vulnerability_observed"
    CONFIGURATION_WEAKNESS_OBSERVED = "configuration_weakness_observed"
    DEPENDENCY_ENDPOINT_OBSERVED = "dependency_endpoint_observed"
    PROVIDER_RESOURCE_STATE_OBSERVED = "provider_resource_state_observed"
    CONTROL_ENABLED = "control_enabled"
    CONTROL_DISABLED = "control_disabled"


class TechnicalObservationStatus(StrEnum):
    """Result of comparing what was observed against what was expected —
    distinct from AssetFindingStatus (a finding's own open/resolved
    lifecycle). UNKNOWN/omitted (nullable column) both mean "no comparison
    was possible," never fabricated as COMPLIANT."""

    OBSERVED = "observed"
    EXPECTED = "expected"
    MISMATCH = "mismatch"
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"
    INCONCLUSIVE = "inconclusive"
    RESOLVED = "resolved"


# Audit event names — dot-separated snake_case values, written via a local
# ``_write_audit`` wrapper (matching discovery_run.py/evidence_scanner.py),
# never the shared ``log_audit_event`` directly (established convention).
ARTEFACT_AUDIT_DISCOVERED = "artefact.discovered"
ARTEFACT_AUDIT_IDENTITY_MATCHED = "artefact.identity_matched"
ARTEFACT_AUDIT_MERGED = "artefact.merged"
# Human decisions on a discovered artefact (#150). The platform proposes an
# inventory; a person decides what is actually theirs and what it is.
class ArtefactReviewState(StrEnum):
    """What a reviewer has decided about a discovered artefact, as one value the
    UI can render. Derived, never stored: it is a reading of lifecycle_state plus
    reviewed_at, kept here so the vocabulary has one definition rather than being
    re-derived in every view."""

    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    # "Ours, but we will never depend on it." Distinct from REJECTED because it
    # is a different statement: one denies ownership, the other accepts it and
    # declines the dependency.
    NOT_USED = "not_used"
    # Identity matching could not decide; a person must (never silently merged).
    NEEDS_DECISION = "needs_decision"
    # Discovered and no one has looked at it yet.
    UNDECIDED = "undecided"


ARTEFACT_AUDIT_CONFIRMED = "artefact.confirmed"
ARTEFACT_AUDIT_REJECTED = "artefact.rejected"
#: "Ours, but we will never depend on it" — a decision in its own right, so
#: it is recorded as one rather than being inferred from a lifecycle value.
ARTEFACT_AUDIT_NOT_USED = "artefact.marked_not_used"
ARTEFACT_AUDIT_CLASSIFICATION_CORRECTED = "artefact.classification_corrected"
ARTEFACT_AUDIT_DEPENDENCY_CATEGORY_SET = "artefact.dependency_category_set"
ARTEFACT_AUDIT_SERVICE_LINKED = "artefact.service_linked"
ARTEFACT_AUDIT_NORMALIZATION_COMPLETED = "artefact.normalization_completed"
ARTEFACT_AUDIT_NORMALIZATION_FAILED = "artefact.normalization_failed"

OBSERVATION_AUDIT_RECORDED = "technical_observation.recorded"
