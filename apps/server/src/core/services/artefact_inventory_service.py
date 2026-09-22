"""CA-06.6 — the organisation's artefact inventory, independent of any run.

Artefacts were only reachable *inside a discovery run*: the list belonged to the
scan that produced it, so "what do we have?" could only be answered as "what did
this scan find?". Everything CA-06 built — stable identity across IP changes,
observation history, relationships, resolved matches, boundary withdrawals —
describes an inventory that outlives every run, and nothing could read it.

This module answers the standing question. It reports facts and composes no
sentences: which artefacts exist, what each is, how much evidence stands behind
it, and what is still waiting on a person. The words a reader sees are the
tenant app's to write, because business language is a product decision, not a
database one.

Two rules hold throughout:

* **Every query is tenant-scoped.** Not "usually" — an inventory read that
  forgets `organization_id` hands one organisation another's estate, and the
  filters below are the exact place a missing clause would hide.
* **Nothing here decides.** Certainty is reported as the evidence behind it —
  how many identifiers, how many sources, when it was last seen — rather than
  as a verdict the platform reached on its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from src.core.constants.artefact_access_lifecycle_enums import ACCESS_STATES_AWAITING_A_PERSON
from src.core.constants.artefact_identity_enums import ArtefactIdentityConflictState
from src.core.model_defs.artefact_access_lifecycle import ArtefactAccessLifecycle
from src.core.model_defs.artefact_reconciliation import ArtefactIdentityConflict
from src.core.model_defs.assets_runtime import (
    Asset,
    AssetIdentifier,
    AssetLifecycleState,
    AssetObservedPort,
)
from src.core.services.artefact_classification_service import derive_candidacy, stored_service_names
from src.core.services.artefact_identity_evidence_service import stored_identity
from src.core.services.asset_scan_findings_service import scan_findings_by_asset


@dataclass(frozen=True)
class InventoryFilters:
    """What the caller asked to see. Every field narrows; none widens.

    An empty filter set means "the whole inventory", which is the honest default
    for a standing list — hiding rows by default would make the inventory look
    smaller than it is, and the count is the first thing anyone checks.
    """

    lifecycle_states: tuple[AssetLifecycleState, ...] = ()
    asset_type: str | None = None
    layer: str | None = None
    #: "reviewed" — a person has ruled on it; "unreviewed" — nobody has yet.
    review_status: str | None = None
    #: Matches display name or any identifier the artefact has been seen under.
    query: str | None = None
    #: One ``ArtefactCandidacy`` value — narrows to artefacts a business service
    #: could depend on, or to the addresses that answered and expose nothing.
    #: The estate is mostly the latter (253 of 254 rows on org 7), so without
    #: this the inventory's own count answers a question nobody asked.
    candidacy: str | None = None


@dataclass(frozen=True)
class InventoryEntry:
    """One artefact, with the evidence a reader needs to judge it.

    Deliberately facts, not phrasing: ``identifier_count`` and ``source_names``
    rather than "seen by two sources", because the sentence belongs to whoever
    is writing for the reader.
    """

    asset_id: int
    display_name: str
    asset_type: str
    layer: str
    dependency_category: str | None
    lifecycle_state: str
    #: Whether a person has ruled on this artefact, and when.
    reviewed_at: datetime | None
    reviewed_by_user_id: int | None
    first_observed_at: datetime | None
    last_observed_at: datetime | None
    #: The size of the identity the artefact has accumulated. More identifiers
    #: seen under more sources is the platform's *evidence*, which is what
    #: "how sure are we" should be answered with.
    identifier_count: int
    source_names: tuple[str, ...]
    observed_port_count: int
    #: What the last vulnerability scan found on this artefact, and when it last
    #: saw it. ``0`` and ``None`` mean no scanner finding is on record — which is
    #: **not** the same as "scanned and clean", and the row must not say it is.
    #: Telling those apart needs a per-host coverage record the platform does not
    #: keep yet; until it does, the row says what was found and stays silent
    #: about what was not.
    scan_finding_count: int
    scan_last_finding_at: datetime | None
    #: Whether a business service could depend on this at all — the only
    #: question that makes a 500-row estate reviewable (CA-09A.1).
    #:
    #: The discovery review surface has carried this since CA-05; the standing
    #: inventory never did, so 253 addresses that answered a ping and one real
    #: service rendered identically and counted the same. Derived here rather
    #: than stored, exactly as `discovery_results_service` derives it, so the
    #: two surfaces cannot disagree and no migration is needed.
    candidacy: str
    #: Waiting on a person (CA-06.4). A row with an open match is not a settled
    #: record, however confident everything else about it looks.
    open_conflict_count: int
    #: Which approved exclusion took it out of the inventory (CA-06.5), if any.
    withdrawn_by_exclusion: str | None
    #: The record this one was merged into (CA-06.4), if any.
    merged_into_asset_id: int | None
    # ── CA-07.6 (#240) — the access journey, deliberately separate ───────────
    #: The artefact's *access* state (CA-07.5), which is a second and
    #: independent fact from ``lifecycle_state`` above. An artefact can be
    #: confirmed in the inventory with no access configured, or unconfirmed
    #: with access already approved. Carried in its own field for exactly that
    #: reason: one field holding both would make two questions look like one
    #: answer. ``None`` means no access has ever been requested for it, which
    #: is not the same as a journey that stalled at its first step.
    access_state: str | None
    #: Which Connector the access runs through, so a reader can tell *this host
    #: is reached through the one in the datacentre* apart from *through the
    #: one on a laptop*. Never a credential — ``AccessConnector`` holds none.
    access_connector_id: str | None
    #: Whether the access journey is waiting on a person right now. Computed
    #: from the state rather than stored, so it cannot disagree with it.
    access_awaiting_person: bool
    # ── CA-07.1 / #249 — what the scan concluded this thing is ───────────────
    #: Determining identity has been stored on the asset since CA-07.1 and was
    #: never exposed, so every row read "192.168.1.36 · Web service · L5" no
    #: matter what the scan had established. Søren, 2026-08-25: *"the last
    #: implement was supposed to add context to the artefacts. However it
    #: didn't."* It was determined and recorded; it simply never left the server.
    #:
    #: Deliberately four fields rather than one sentence. ``display_name`` may
    #: already *be* the identity, or may be a hostname the organisation gave it,
    #: and a reader needs to know which — a name the platform inferred and a name
    #: its owner chose carry different weight.
    identity_name: str | None
    #: Which evidence produced the name (``ArtefactIdentityBasis``). "Read off
    #: its TLS certificate" and "guessed from the port number" are not the same
    #: claim and must not render identically.
    identity_basis: str | None
    #: Why there is no name (``ArtefactIdentityUndetermined``). Only
    #: ``probed_nothing_identifying`` is an honest argument for deeper access.
    identity_undetermined_reason: str | None
    #: The reason in business language, composed server-side from the single
    #: source in ``IDENTITY_UNDETERMINED_EXPLANATION`` so the tenant does not
    #: restate the model.
    identity_explanation: str | None
    #: Where this artefact sits, as against what it is. Søren, 2026-08-25: the
    #: address is "too arbitrary" to be a name — an executive reads
    #: ``192.168.1.36`` and learns nothing. The two were always separate ideas
    #: in the model (normalisation keeps ``networkAddress`` precisely because
    #: "the address stops being the display name the moment an identity is
    #: determined, and a reviewer still needs to know where the thing lives"),
    #: and the inventory simply had one field doing both jobs.
    #:
    #: Sent as its own field so the surface can put the description in the title
    #: and the address where it belongs. **Not** derived from ``display_name``:
    #: that value also feeds ``resolve_identity``'s legacy display-name match,
    #: so it stays exactly what it is.
    network_address: str | None


@dataclass(frozen=True)
class InventoryPage:
    entries: tuple[InventoryEntry, ...]
    #: The total matching the filters, not the number returned — a reader
    #: paging through 400 artefacts needs to know there are 400.
    total: int
    #: Every distinct value present in this organisation's inventory, so the
    #: caller can offer filters that lead somewhere. Computed from the estate
    #: rather than from a hardcoded list, which would offer types nobody has and
    #: hide types the classifier learned to emit.
    asset_types: tuple[str, ...]
    layers: tuple[str, ...]


def _ids_with_candidacy(query, wanted: str) -> list[int]:
    """The ids, within an already tenant-scoped query, whose candidacy matches.

    Derived through the same ``derive_candidacy`` the discovery review uses, so
    a row cannot be set aside on one surface and carried on the other.
    """
    return [
        asset_id
        for asset_id, intent in query.with_entities(Asset.id, Asset.intent).all()
        if derive_candidacy(stored_service_names(intent)).value == wanted
    ]


def _base_query(db: Session, organization_id: int):
    """Every inventory read starts here. One definition, so a filter cannot be
    added on a path that forgot the tenant clause."""
    return db.query(Asset).filter(Asset.organization_id == organization_id)


def _apply_filters(query, filters: InventoryFilters):
    if filters.lifecycle_states:
        query = query.filter(Asset.lifecycle_state.in_(filters.lifecycle_states))
    if filters.asset_type:
        query = query.filter(func.lower(Asset.type) == filters.asset_type.strip().lower())
    if filters.layer:
        query = query.filter(func.lower(Asset.layer) == filters.layer.strip().lower())
    if filters.review_status == "reviewed":
        query = query.filter(Asset.reviewed_at.isnot(None))
    elif filters.review_status == "unreviewed":
        query = query.filter(Asset.reviewed_at.is_(None))
    return query


def list_inventory(
    db: Session,
    *,
    organization_id: int,
    filters: InventoryFilters | None = None,
    limit: int = 100,
    offset: int = 0,
) -> InventoryPage:
    """The organisation's inventory, filtered as asked."""
    filters = filters or InventoryFilters()

    query = _apply_filters(_base_query(db, organization_id), filters)

    if filters.query:
        needle = f"%{filters.query.strip().lower()}%"
        # An artefact is findable by anything it has been seen under, not only
        # by the name it happens to display today — that is the whole point of
        # CA-06.1's identifier set, and searching the display name alone would
        # lose a host the moment its name changed.
        matching_ids = (
            db.query(AssetIdentifier.asset_id)
            .filter(AssetIdentifier.organization_id == organization_id)
            .filter(func.lower(AssetIdentifier.identifier_value).like(needle))
            .scalar_subquery()
        )
        query = query.filter(
            or_(func.lower(Asset.display_name).like(needle), Asset.id.in_(matching_ids))
        )

    if filters.candidacy:
        # Candidacy is derived from the stored service names, not held in a
        # column, so it cannot be written as a SQL clause. The matching ids are
        # resolved first and the query constrained by them, which keeps `total`
        # and the page slice answering the same question — a filter applied
        # after the slice would report a count for one set and rows for another.
        #
        # This reads every row's `intent` for the organisation once per filtered
        # request. Correct, and fine at estate sizes seen so far; if it ever is
        # not, the fix is to persist candidacy on the asset rather than to make
        # the filter approximate.
        query = query.filter(Asset.id.in_(_ids_with_candidacy(query, filters.candidacy)))

    total = query.count()
    assets = query.order_by(Asset.display_name.asc(), Asset.id.asc()).limit(limit).offset(offset).all()
    asset_ids = [asset.id for asset in assets]

    identifiers = _identifiers_by_asset(db, organization_id=organization_id, asset_ids=asset_ids)
    port_counts = _port_counts_by_asset(db, organization_id=organization_id, asset_ids=asset_ids)
    conflict_counts = _open_conflict_counts(db, organization_id=organization_id, asset_ids=asset_ids)
    scan_findings = scan_findings_by_asset(db, organization_id=organization_id, asset_ids=asset_ids)
    access = _access_by_asset(db, organization_id=organization_id, asset_ids=asset_ids)

    entries = tuple(
        InventoryEntry(
            asset_id=asset.id,
            display_name=asset.display_name,
            asset_type=asset.type,
            layer=asset.layer,
            dependency_category=asset.dependency_category,
            lifecycle_state=asset.lifecycle_state.value,
            reviewed_at=asset.reviewed_at,
            reviewed_by_user_id=asset.reviewed_by_user_id,
            first_observed_at=_earliest_identifier(identifiers.get(asset.id, ())),
            last_observed_at=asset.last_observed_at,
            identifier_count=len(identifiers.get(asset.id, ())),
            source_names=_source_names(identifiers.get(asset.id, ())),
            observed_port_count=port_counts.get(asset.id, 0),
            scan_finding_count=scan_findings.get(asset.id, (0, None))[0],
            scan_last_finding_at=scan_findings.get(asset.id, (0, None))[1],
            candidacy=derive_candidacy(stored_service_names(asset.intent)).value,
            open_conflict_count=conflict_counts.get(asset.id, 0),
            withdrawn_by_exclusion=asset.withdrawn_by_exclusion,
            merged_into_asset_id=asset.merged_into_asset_id,
            access_state=access[asset.id].state if asset.id in access else None,
            access_connector_id=access[asset.id].connector_id if asset.id in access else None,
            access_awaiting_person=(
                access[asset.id].state in ACCESS_STATES_AWAITING_A_PERSON if asset.id in access else False
            ),
            **_identity_fields(asset),
        )
        for asset in assets
    )

    return InventoryPage(
        entries=entries,
        total=total,
        asset_types=_distinct_values(db, organization_id=organization_id, column=Asset.type),
        layers=_distinct_values(db, organization_id=organization_id, column=Asset.layer),
    )


def _access_by_asset(
    db: Session, *, organization_id: int, asset_ids: list[int]
) -> dict[int, ArtefactAccessLifecycle]:
    """CA-07.6 — one query for the page, on the precedent the loaders below set.

    Scoped by ``organization_id`` as well as by ``asset_id``: the asset ids come
    from a query already scoped to this organisation, so filtering on them alone
    would be correct today and silently wrong the first time a caller passes ids
    from anywhere else. Tenant scoping is not something to infer from context.
    """
    if not asset_ids:
        return {}
    rows = (
        db.query(ArtefactAccessLifecycle)
        .filter(
            ArtefactAccessLifecycle.organization_id == organization_id,
            ArtefactAccessLifecycle.asset_id.in_(asset_ids),
        )
        .all()
    )
    return {row.asset_id: row for row in rows}


def _identifiers_by_asset(
    db: Session, *, organization_id: int, asset_ids: list[int]
) -> dict[int, tuple[AssetIdentifier, ...]]:
    """One query for the whole page rather than one per row — an inventory of
    400 artefacts would otherwise issue 400 queries to answer "how sure"."""
    if not asset_ids:
        return {}
    rows = (
        db.query(AssetIdentifier)
        .filter(AssetIdentifier.organization_id == organization_id)
        .filter(AssetIdentifier.asset_id.in_(asset_ids))
        .all()
    )
    grouped: dict[int, list[AssetIdentifier]] = {}
    for row in rows:
        grouped.setdefault(row.asset_id, []).append(row)
    return {asset_id: tuple(values) for asset_id, values in grouped.items()}


def _port_counts_by_asset(db: Session, *, organization_id: int, asset_ids: list[int]) -> dict[int, int]:
    if not asset_ids:
        return {}
    rows = (
        db.query(AssetObservedPort.asset_id, func.count(AssetObservedPort.id))
        .filter(AssetObservedPort.organization_id == organization_id)
        .filter(AssetObservedPort.asset_id.in_(asset_ids))
        .group_by(AssetObservedPort.asset_id)
        .all()
    )
    return {asset_id: count for asset_id, count in rows}




def _open_conflict_counts(db: Session, *, organization_id: int, asset_ids: list[int]) -> dict[int, int]:
    """Open matches touching each artefact, counted from either side of the
    pair — a conflict is as much the higher artefact's business as the lower's,
    and counting one side would leave half the estate looking settled."""
    if not asset_ids:
        return {}
    conflicts = (
        db.query(ArtefactIdentityConflict)
        .filter(ArtefactIdentityConflict.organization_id == organization_id)
        .filter(ArtefactIdentityConflict.state == ArtefactIdentityConflictState.OPEN.value)
        .filter(
            or_(
                ArtefactIdentityConflict.lower_asset_id.in_(asset_ids),
                ArtefactIdentityConflict.higher_asset_id.in_(asset_ids),
            )
        )
        .all()
    )
    counts: dict[int, int] = {}
    wanted = set(asset_ids)
    for conflict in conflicts:
        for side in (conflict.lower_asset_id, conflict.higher_asset_id):
            if side in wanted:
                counts[side] = counts.get(side, 0) + 1
    return counts


def _distinct_values(db: Session, *, organization_id: int, column) -> tuple[str, ...]:
    rows = (
        db.query(column)
        .filter(Asset.organization_id == organization_id)
        .distinct()
        .order_by(column.asc())
        .all()
    )
    return tuple(value for (value,) in rows if value)


def _identity_fields(asset: Asset) -> dict[str, str | None]:
    """What the scan concluded this artefact is, plus where it sits.

    Delegates to ``stored_identity`` rather than reading ``intent`` here. The
    discovery review list asks the identical question, and an artefact that
    reads "Unidentified device" on one page and ``192.168.1.20`` on the other is
    one record contradicting itself.
    """
    return stored_identity(asset.intent)


def _source_names(identifiers: tuple[AssetIdentifier, ...]) -> tuple[str, ...]:
    """Who has seen this artefact. Sorted and de-duplicated, because "seen by
    two sources" is the claim — not "seen eleven times by the same one"."""
    return tuple(sorted({row.observed_by_source for row in identifiers if row.observed_by_source}))


def _earliest_identifier(identifiers: tuple[AssetIdentifier, ...]) -> datetime | None:
    """When this artefact was first seen under anything at all. Read from the
    identifier set rather than the asset row, because an artefact that changed
    address keeps the earlier identifier and its date — which is exactly the
    history CA-06.1 exists to preserve."""
    dates = [row.first_seen_at for row in identifiers if row.first_seen_at]
    return min(dates) if dates else None


__all__ = ["InventoryEntry", "InventoryFilters", "InventoryPage", "list_inventory"]
