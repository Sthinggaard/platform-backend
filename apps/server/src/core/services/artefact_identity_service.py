"""Step 4.1A — deterministic artefact identity resolution.

Single source of truth for "is this normalization candidate the same
real-world artefact as an existing Asset row." Replaces the previous
case-insensitive-display-name-only match (``resolve_asset_by_label`` in
``asset_context_service.py``, still used elsewhere and left untouched) for
any caller that wants the stronger, spec-required guarantee: identity must
never rely on display name alone.

Priority order for the canonical identity key mirrors the strength of the
signal (skill: confidence = verification, never fabricated) — a bare
display-name match is deliberately never enough to produce an EXACT_MATCH
or STRONG_MATCH; at best it produces a POSSIBLE_MATCH, which this service
never auto-merges.

**CA-06.1 — an artefact is an identifier *set*, not one identifier.**
Originally identity was one signal: the strongest available field, hashed.
That made an artefact's identity only as durable as that one field, with two
consequences the CA-06 checklist names directly — a host keyed on its IP became
a *new* artefact the next time DHCP moved it, and the same host seen by nmap
(``hostname:…``) and by a cloud provider (``provider:aws:i-…``) produced two
keys that could never converge.

So resolution now matches on the set of identifiers an artefact has ever been
observed under (``AssetIdentifier``), and the canonical key is derived from that
set. The key itself is unchanged in form and still computed by the same
precedence, so keys already stored keep resolving to the same artefact — and
once an artefact has a key it keeps it, even if a stronger identifier turns up
later. A key that moved would not be an identity.

What did *not* change: which overlaps are allowed to mean "same artefact." A
strong identifier (provider resource, hostname, domain, endpoint) names a thing.
An IP names a location, and today's occupant may not be tomorrow's — so an
IP-only overlap raises a conflict for a person to resolve (CA-06.4) and is never
merged here.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, tuple_
from sqlalchemy.orm import Session

from src.core.constants.artefact_identity_enums import (
    ARTEFACT_IDENTIFIER_STRENGTH_ORDER,
    STRONG_ARTEFACT_IDENTIFIER_TYPES,
    ArtefactIdentifierType,
    ArtefactIdentityMatchType,
)
from src.core.model_defs.assets_runtime import Asset, AssetIdentifier, AssetLifecycleState
from src.core.model_defs.common import utcnow


@dataclass(frozen=True)
class ArtefactIdentityCandidate:
    organization_id: int
    normalized_type: str

    provider: str | None = None
    provider_resource_id: str | None = None

    hostname: str | None = None
    domain: str | None = None
    ip_address: str | None = None
    endpoint: str | None = None

    environment: str | None = None
    # Weakest signal — never used to build a canonical_identity_key on its
    # own, only as a POSSIBLE_MATCH fallback when nothing stronger exists.
    display_name: str | None = None


@dataclass(frozen=True)
class ObservedIdentifier:
    """One member of an artefact's identifier set, as observed right now."""

    identifier_type: ArtefactIdentifierType
    value: str

    @property
    def is_strong(self) -> bool:
        return self.identifier_type in STRONG_ARTEFACT_IDENTIFIER_TYPES


@dataclass(frozen=True)
class ArtefactIdentityResolution:
    match_type: ArtefactIdentityMatchType
    canonical_identity_key: str | None
    matched_asset: Asset | None
    reason: str
    #: The identifier set this candidate was observed under. The caller records
    #: it against whichever artefact the candidate resolves to, which is how the
    #: set grows and how the *next* observation stays linked.
    observed_identifiers: tuple[ObservedIdentifier, ...] = ()
    #: Populated when more than one existing artefact overlaps this candidate,
    #: or when the only overlap is a weak one. These are the pairs CA-06.4 asks
    #: a person to resolve — never merged here.
    conflicting_asset_ids: tuple[int, ...] = ()


def _normalize(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    return normalized or None


#: The string each identifier type contributes to a canonical key. **Frozen.**
#: These exact prefixes are inside a sha256 that is already stored on live rows,
#: so changing one silently orphans every artefact keyed under it. They are not
#: the enum's own values for the same reason — ``ip_address`` would not hash to
#: what ``ip`` hashed to.
_CANONICAL_KEY_PREFIX: dict[ArtefactIdentifierType, str] = {
    ArtefactIdentifierType.PROVIDER_RESOURCE: "provider",
    ArtefactIdentifierType.HOSTNAME: "hostname",
    ArtefactIdentifierType.DOMAIN: "domain",
    ArtefactIdentifierType.IP_ADDRESS: "ip",
    ArtefactIdentifierType.ENDPOINT: "endpoint",
}


def build_identifier_set(candidate: ArtefactIdentityCandidate) -> tuple[ObservedIdentifier, ...]:
    """Every identifier this observation carries, normalised, strongest first.

    A provider resource id is only an identifier together with its provider —
    ``i-0abc`` means nothing without ``aws`` in front of it, and two providers
    could legitimately issue the same string.
    """
    identifiers: list[ObservedIdentifier] = []

    provider = _normalize(candidate.provider)
    provider_resource_id = _normalize(candidate.provider_resource_id)
    if provider and provider_resource_id:
        identifiers.append(
            ObservedIdentifier(ArtefactIdentifierType.PROVIDER_RESOURCE, f"{provider}:{provider_resource_id}")
        )

    for identifier_type, raw in (
        (ArtefactIdentifierType.HOSTNAME, candidate.hostname),
        (ArtefactIdentifierType.DOMAIN, candidate.domain),
        (ArtefactIdentifierType.IP_ADDRESS, candidate.ip_address),
        (ArtefactIdentifierType.ENDPOINT, candidate.endpoint),
    ):
        value = _normalize(raw)
        if value:
            identifiers.append(ObservedIdentifier(identifier_type, value))

    order = {identifier_type: index for index, identifier_type in enumerate(ARTEFACT_IDENTIFIER_STRENGTH_ORDER)}
    identifiers.sort(key=lambda identifier: order[identifier.identifier_type])
    return tuple(identifiers)


def build_canonical_identity_key(candidate: ArtefactIdentityCandidate) -> str | None:
    """The strongest identifier in the candidate's set wins — never a
    combination that could silently drift if only one field changes, and
    never display_name (see module docstring).

    Derived from the identifier set rather than from the candidate's fields
    directly, so precedence has one definition. The hash is byte-identical to
    the pre-CA-06.1 form for the same input.
    """
    identifiers = build_identifier_set(candidate)
    if not identifiers:
        return None

    strongest = identifiers[0]
    prefix = _CANONICAL_KEY_PREFIX[strongest.identifier_type]
    normalized_type = _normalize(candidate.normalized_type) or "unknown"
    raw = f"org:{candidate.organization_id}|type:{normalized_type}|{prefix}:{strongest.value}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _resolvable_assets(db: Session, organization_id: int):
    """Artefacts in this organisation that a new observation may resolve to.

    One definition, used by every lookup below, because an exclusion that only
    some paths apply is not an exclusion. A merged artefact is deliberately not
    a candidate: it has already been decided to be the same thing as another
    record, and re-linking to it would undo that decision silently. Reversing a
    merge is CA-06.4's job, made by a person.
    """
    return db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.lifecycle_state != AssetLifecycleState.MERGED,
    )


def _assets_matching_identifiers(
    db: Session,
    *,
    organization_id: int,
    identifiers: tuple[ObservedIdentifier, ...],
) -> list[int]:
    """Artefacts in this organisation ever observed under any of these
    identifiers, oldest first. Tenant-scoped in the query itself, never by the
    caller filtering afterwards."""
    if not identifiers:
        return []

    rows = (
        db.query(AssetIdentifier.asset_id)
        .join(Asset, Asset.id == AssetIdentifier.asset_id)
        .filter(
            AssetIdentifier.organization_id == organization_id,
            Asset.organization_id == organization_id,
            # A withdrawn or already-merged artefact is not a match candidate;
            # resurrecting one is CA-06.4/CA-06.5's decision, not a side effect
            # of the next scan.
            Asset.lifecycle_state != AssetLifecycleState.MERGED,
            tuple_(AssetIdentifier.identifier_type, AssetIdentifier.identifier_value).in_(
                [(identifier.identifier_type.value, identifier.value) for identifier in identifiers]
            ),
        )
        .order_by(AssetIdentifier.asset_id.asc())
        .distinct()
        .all()
    )
    return [row[0] for row in rows]


def resolve_identity(db: Session, candidate: ArtefactIdentityCandidate) -> ArtefactIdentityResolution:
    identifiers = build_identifier_set(candidate)
    canonical_key = build_canonical_identity_key(candidate)
    strong_identifiers = tuple(identifier for identifier in identifiers if identifier.is_strong)

    # 1. The identifier set. This is what survives a changed IP and what lets a
    #    second provider's view of the same host converge on one artefact.
    if strong_identifiers:
        matched_ids = _assets_matching_identifiers(
            db, organization_id=candidate.organization_id, identifiers=strong_identifiers
        )
        if len(matched_ids) == 1:
            matched = db.get(Asset, matched_ids[0])
            if matched is not None:
                return ArtefactIdentityResolution(
                    match_type=ArtefactIdentityMatchType.EXACT_MATCH,
                    canonical_identity_key=matched.canonical_identity_key or canonical_key,
                    matched_asset=matched,
                    reason="Matched an existing artefact on a strong identifier it has been observed under before.",
                    observed_identifiers=identifiers,
                )
        elif len(matched_ids) > 1:
            # Two artefacts each legitimately claim one of this candidate's
            # strong identifiers. That is a real question about the world, not
            # something to resolve by picking one.
            return ArtefactIdentityResolution(
                match_type=ArtefactIdentityMatchType.POSSIBLE_MATCH,
                canonical_identity_key=canonical_key,
                matched_asset=db.get(Asset, matched_ids[0]),
                reason=(
                    "This observation's identifiers are spread across more than one existing artefact. "
                    "A person decides whether they are the same thing."
                ),
                observed_identifiers=identifiers,
                conflicting_asset_ids=tuple(matched_ids),
            )

    if canonical_key is not None:
        # 2. The stored canonical key. Artefacts created before CA-06.1 have a
        #    key but no identifier rows yet, so this is what keeps them matching
        #    until their first re-observation populates the set.
        existing = (
            _resolvable_assets(db, candidate.organization_id)
            .filter(Asset.canonical_identity_key == canonical_key)
            .order_by(Asset.id.asc())
            .first()
        )
        if existing is not None:
            return ArtefactIdentityResolution(
                match_type=ArtefactIdentityMatchType.EXACT_MATCH,
                canonical_identity_key=canonical_key,
                matched_asset=existing,
                reason="Matched an existing artefact by canonical identity key.",
                observed_identifiers=identifiers,
            )

        # 3. A same-org asset already carries a hostname/ip/domain-derived
        #    display name equal to the strongest signal we have, but was
        #    created before this service existed (no canonical_identity_key
        #    yet) — strong, not exact, since we're inferring the key rather
        #    than reading a stored one.
        strong_source = candidate.hostname or candidate.domain or candidate.ip_address or candidate.endpoint
        if strong_source:
            strong_match = (
                _resolvable_assets(db, candidate.organization_id)
                .filter(
                    Asset.canonical_identity_key.is_(None),
                    func.lower(Asset.display_name) == _normalize(strong_source),
                )
                .order_by(Asset.id.asc())
                .first()
            )
            if strong_match is not None:
                return ArtefactIdentityResolution(
                    match_type=ArtefactIdentityMatchType.STRONG_MATCH,
                    canonical_identity_key=canonical_key,
                    matched_asset=strong_match,
                    reason="Matched a pre-existing artefact (created before identity keys existed) by hostname/domain/ip.",
                    observed_identifiers=identifiers,
                )

        # 4. Nothing strong matched, but an existing artefact has been seen at
        #    this address. "IP alone is not identity" — so this is a question,
        #    not a match.
        weak_identifiers = tuple(identifier for identifier in identifiers if not identifier.is_strong)
        if weak_identifiers:
            weak_matches = _assets_matching_identifiers(
                db, organization_id=candidate.organization_id, identifiers=weak_identifiers
            )
            if weak_matches:
                return ArtefactIdentityResolution(
                    match_type=ArtefactIdentityMatchType.POSSIBLE_MATCH,
                    canonical_identity_key=canonical_key,
                    matched_asset=db.get(Asset, weak_matches[0]),
                    reason=(
                        "Another artefact has been observed at this address, but nothing stronger than the "
                        "address itself connects them. An address can be reassigned, so a person decides."
                    ),
                    observed_identifiers=identifiers,
                    conflicting_asset_ids=tuple(weak_matches),
                )

        return ArtefactIdentityResolution(
            match_type=ArtefactIdentityMatchType.DISTINCT,
            canonical_identity_key=canonical_key,
            matched_asset=None,
            reason="No existing artefact shares this identity key.",
            observed_identifiers=identifiers,
        )

    # 5. No strong identifier at all — display name is the only signal.
    #    Never EXACT/STRONG; at best a reviewable POSSIBLE_MATCH.
    if candidate.display_name:
        possible = (
            _resolvable_assets(db, candidate.organization_id)
            .filter(func.lower(Asset.display_name) == _normalize(candidate.display_name))
            .order_by(Asset.id.asc())
            .first()
        )
        if possible is not None:
            return ArtefactIdentityResolution(
                match_type=ArtefactIdentityMatchType.POSSIBLE_MATCH,
                canonical_identity_key=None,
                matched_asset=possible,
                reason="Display name matches an existing artefact, but no strong identifier confirms it is the same artefact.",
                observed_identifiers=identifiers,
                conflicting_asset_ids=(possible.id,) if possible.id is not None else (),
            )

    return ArtefactIdentityResolution(
        match_type=ArtefactIdentityMatchType.DISTINCT,
        canonical_identity_key=None,
        matched_asset=None,
        reason="No identifier strong enough to match any existing artefact.",
        observed_identifiers=identifiers,
    )


def record_observed_identifiers(
    db: Session,
    *,
    asset: Asset,
    identifiers: tuple[ObservedIdentifier, ...],
    observed_by_source: str | None = None,
    observed_at: datetime | None = None,
) -> tuple[ObservedIdentifier, ...]:
    """Add this observation's identifiers to the artefact's set.

    Returns the identifiers that were *new* to this artefact, so the caller can
    say what changed rather than re-deriving it.

    An identifier is never removed here. A host that has moved keeps the address
    it used to answer on, with the date it was last seen there — that is how
    "where was this in March" stays answerable, and deleting it would destroy
    the only evidence that the move happened.
    """
    if asset.id is None:
        db.flush()

    now = observed_at or utcnow()
    existing_rows = {
        (row.identifier_type, row.identifier_value): row
        for row in db.query(AssetIdentifier).filter(
            AssetIdentifier.organization_id == asset.organization_id,
            AssetIdentifier.asset_id == asset.id,
        )
    }

    newly_observed: list[ObservedIdentifier] = []
    for identifier in identifiers:
        key = (identifier.identifier_type.value, identifier.value)
        row = existing_rows.get(key)
        if row is None:
            db.add(
                AssetIdentifier(
                    organization_id=asset.organization_id,
                    asset_id=asset.id,
                    identifier_type=identifier.identifier_type.value,
                    identifier_value=identifier.value,
                    observed_by_source=observed_by_source,
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            newly_observed.append(identifier)
        else:
            row.last_seen_at = now
            if observed_by_source and not row.observed_by_source:
                row.observed_by_source = observed_by_source
            db.add(row)

    return tuple(newly_observed)
