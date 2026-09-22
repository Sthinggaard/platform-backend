"""CA-06.4 — a person resolves an uncertain match: same thing, or genuinely separate.

Identity resolution already refuses to guess: when a candidate's identifiers are
spread across more than one existing artefact, or the only overlap is an address,
it returns ``POSSIBLE_MATCH`` with the ids it could not separate
(``artefact_identity_service``). Until this module, that refusal had nowhere to
go — the question was written into ``Asset.intent`` and an audit event, and no
code path could ever answer it. ``AssetLifecycleState.MERGED`` and
``Asset.merged_into_asset_id`` had existed since the July migration with nothing
in the codebase writing either one.

Four operations, and the reasoning that shapes them:

* **Raise** — reconciliation states the question, ordered so A-vs-B and B-vs-A
  are one conflict rather than two. Re-observing the same ambiguity refreshes an
  open conflict instead of stacking another, and **never reopens one a person
  resolved as separate**: asking again every scan would make "keep separate"
  meaningless.
* **Merge** — a person says the records are one artefact. Nothing is destroyed:
  identifiers, ports, relationships and evidence move to the survivor, and
  anything the survivor already held is collapsed *with a full snapshot* so the
  merge can be undone. The merged row stays, in ``MERGED``, pointing at the
  survivor.
* **Keep separate** — a person says they are different things. A real decision,
  recorded as one, and durable.
* **Reverse** — undoes a merge from its snapshot. The record of the merge stays:
  "merged on the 3rd, undone on the 5th" is precisely what an audit asks about.

The platform never merges on its own, at any confidence. That is a rule of the
product, not a threshold to tune.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from src.core.constants.artefact_identity_enums import (
    ARTEFACT_AUDIT_KEPT_SEPARATE,
    ARTEFACT_AUDIT_MERGE_REVERSED,
    ARTEFACT_AUDIT_MERGED,
    ArtefactIdentityConflictState,
)
from src.core.model_defs.artefact_reconciliation import (
    ArtefactIdentityConflict,
    ArtefactMergeRecord,
)
from src.core.model_defs.artefact_relationships import ArtefactRelationship
from src.core.model_defs.assets_runtime import (
    Asset,
    AssetEvidenceSignal,
    AssetFinding,
    AssetIdentifier,
    AssetLifecycleState,
    AssetObservedPort,
)
from src.core.model_defs.common import utcnow
from src.core.models import AuditEvent
from src.core.services.artefact_relationship_service import (
    repoint_relationships,
    restore_relationship_snapshot,
)


class ArtefactReconciliationError(RuntimeError):
    """Raised when a reconciliation decision cannot be applied as asked."""


@dataclass(frozen=True)
class ConflictSide:
    """One artefact in a conflict, with enough on it to decide without leaving
    the screen. A reviewer asked "are these the same?" needs to see what each
    side actually is and what it was seen under — sending them to another page
    to find out is how a question goes unanswered."""

    asset_id: int
    display_name: str
    asset_type: str
    layer: str
    lifecycle_state: str
    identifiers: tuple[dict, ...]
    last_observed_at: datetime | None


@dataclass(frozen=True)
class ConflictView:
    conflict_id: int
    reason: str
    state: str
    raised_at: datetime
    last_raised_at: datetime
    left: ConflictSide
    right: ConflictSide
    shared_identifiers: tuple[dict, ...]


# ─── Shared helpers ──────────────────────────────────────────────────────────


def _require_artefact(db: Session, *, organization_id: int, asset_id: int) -> Asset:
    """Tenant-scoped, and deliberately indistinguishable from "not found" for
    another organisation's row — the same rule the rest of artefact review
    follows, because a permission error would confirm the row exists."""
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id)
        .filter(Asset.organization_id == organization_id)
        .first()
    )
    if asset is None:
        raise ArtefactReconciliationError("That artefact does not exist in this organisation.")
    return asset


def _write_audit(
    db: Session,
    *,
    organization_id: int,
    actor_user_id: int | None,
    event_type: str,
    metadata: dict,
) -> None:
    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            event_type=event_type,
            metadata_json=metadata,
        )
    )


def _ordered(left_asset_id: int, right_asset_id: int) -> tuple[int, int]:
    """One conflict per unordered pair. Without this, dismissing A-vs-B would
    leave B-vs-A open and the reviewer would be asked the same question twice."""
    return (left_asset_id, right_asset_id) if left_asset_id < right_asset_id else (right_asset_id, left_asset_id)


def _identifier_rows(db: Session, asset_id: int) -> list[AssetIdentifier]:
    return (
        db.query(AssetIdentifier)
        .filter(AssetIdentifier.asset_id == asset_id)
        .order_by(AssetIdentifier.identifier_type.asc(), AssetIdentifier.identifier_value.asc())
        .all()
    )


def _identifier_payload(row: AssetIdentifier) -> dict:
    return {
        "identifierType": row.identifier_type,
        "identifierValue": row.identifier_value,
        "observedBySource": row.observed_by_source,
        "firstSeenAt": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "lastSeenAt": row.last_seen_at.isoformat() if row.last_seen_at else None,
    }


# ─── Raising the question ────────────────────────────────────────────────────


def raise_identity_conflict(
    db: Session,
    *,
    organization_id: int,
    left_asset_id: int,
    right_asset_id: int,
    reason: str,
    evidence: dict | None = None,
) -> ArtefactIdentityConflict | None:
    """State an uncertain match, or refresh one already open.

    Returns ``None`` when there is nothing to ask: the pair is the same row, or
    a person already answered it. **Both resolutions suppress re-raising.** A
    merged pair is settled by construction; a pair kept separate is settled by
    someone's judgement, and re-asking would quietly overrule them — the exact
    failure the acceptance criteria call out as "keep separate is durable".
    """
    if left_asset_id == right_asset_id:
        return None

    lower, higher = _ordered(left_asset_id, right_asset_id)
    existing = (
        db.query(ArtefactIdentityConflict)
        .filter(ArtefactIdentityConflict.organization_id == organization_id)
        .filter(ArtefactIdentityConflict.lower_asset_id == lower)
        .filter(ArtefactIdentityConflict.higher_asset_id == higher)
        .first()
    )

    if existing is not None:
        if existing.state != ArtefactIdentityConflictState.OPEN.value:
            return None
        # Still live, and seen again. The question is not new, but a reviewer
        # deserves to know it has not gone stale either.
        existing.last_raised_at = utcnow()
        existing.reason = reason
        if evidence is not None:
            existing.evidence = evidence
        db.add(existing)
        db.flush()
        return existing

    conflict = ArtefactIdentityConflict(
        organization_id=organization_id,
        lower_asset_id=lower,
        higher_asset_id=higher,
        state=ArtefactIdentityConflictState.OPEN.value,
        reason=reason,
        evidence=evidence,
    )
    db.add(conflict)
    db.flush()
    return conflict


def list_open_conflicts(db: Session, *, organization_id: int) -> list[ConflictView]:
    """The conflict surface's data: each pair, both sides, and why the platform
    is unsure. Composed here rather than in the route so the reason and the
    evidence travel together with the pair they belong to."""
    conflicts = (
        db.query(ArtefactIdentityConflict)
        .filter(ArtefactIdentityConflict.organization_id == organization_id)
        .filter(ArtefactIdentityConflict.state == ArtefactIdentityConflictState.OPEN.value)
        .order_by(ArtefactIdentityConflict.last_raised_at.desc())
        .all()
    )

    views: list[ConflictView] = []
    for conflict in conflicts:
        left = db.get(Asset, conflict.lower_asset_id)
        right = db.get(Asset, conflict.higher_asset_id)
        if left is None or right is None:
            # One side is gone. Nothing to decide, and showing half a pair would
            # be worse than showing nothing.
            continue

        left_ids = _identifier_rows(db, left.id)
        right_ids = _identifier_rows(db, right.id)
        shared_keys = {(row.identifier_type, row.identifier_value) for row in left_ids} & {
            (row.identifier_type, row.identifier_value) for row in right_ids
        }

        views.append(
            ConflictView(
                conflict_id=conflict.id,
                reason=conflict.reason,
                state=conflict.state,
                raised_at=conflict.raised_at,
                last_raised_at=conflict.last_raised_at,
                left=_side(left, left_ids),
                right=_side(right, right_ids),
                # What they actually have in common, called out rather than left
                # for the reviewer to spot by comparing two lists by eye.
                shared_identifiers=tuple(
                    _identifier_payload(row) for row in left_ids if (row.identifier_type, row.identifier_value) in shared_keys
                ),
            )
        )
    return views


def _side(asset: Asset, identifiers: list[AssetIdentifier]) -> ConflictSide:
    return ConflictSide(
        asset_id=asset.id,
        display_name=asset.display_name,
        asset_type=asset.type,
        layer=asset.layer,
        lifecycle_state=asset.lifecycle_state.value,
        identifiers=tuple(_identifier_payload(row) for row in identifiers),
        last_observed_at=asset.last_observed_at,
    )


# ─── Answering it ────────────────────────────────────────────────────────────


def keep_artefacts_separate(
    db: Session,
    *,
    organization_id: int,
    conflict_id: int,
    actor_user_id: int | None,
    reason: str | None = None,
) -> ArtefactIdentityConflict:
    """"These are genuinely different things."

    Neither record changes — which is the point, and why this has to be recorded
    explicitly. "Nothing happened" and "a person looked at this and decided it
    was two artefacts" are indistinguishable in the data unless the decision is
    written down, and the next scan would raise the same question forever.
    """
    conflict = _require_conflict(db, organization_id=organization_id, conflict_id=conflict_id)
    if conflict.state != ArtefactIdentityConflictState.OPEN.value:
        raise ArtefactReconciliationError("That match has already been resolved.")

    conflict.state = ArtefactIdentityConflictState.RESOLVED_SEPARATE.value
    conflict.resolved_at = utcnow()
    conflict.resolved_by_user_id = actor_user_id
    conflict.resolution_reason = reason
    db.add(conflict)
    _write_audit(
        db,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        event_type=ARTEFACT_AUDIT_KEPT_SEPARATE,
        metadata={
            "conflictId": conflict.id,
            "assetIds": [conflict.lower_asset_id, conflict.higher_asset_id],
            "reason": reason,
        },
    )
    db.flush()
    return conflict


def merge_artefacts(
    db: Session,
    *,
    organization_id: int,
    survivor_asset_id: int,
    merged_asset_id: int,
    actor_user_id: int | None,
    conflict_id: int | None = None,
    reason: str | None = None,
) -> ArtefactMergeRecord:
    """"These are one artefact." Everything the merged record knew moves to the
    survivor, and what moved is written down so the merge can be undone.

    The survivor is the caller's choice, never the platform's — "which of these
    is the real record" is exactly the judgement being asked for.
    """
    if survivor_asset_id == merged_asset_id:
        raise ArtefactReconciliationError("An artefact cannot be merged into itself.")

    survivor = _require_artefact(db, organization_id=organization_id, asset_id=survivor_asset_id)
    merged = _require_artefact(db, organization_id=organization_id, asset_id=merged_asset_id)

    if merged.lifecycle_state == AssetLifecycleState.MERGED:
        raise ArtefactReconciliationError("That artefact has already been merged into another record.")
    if survivor.lifecycle_state == AssetLifecycleState.MERGED:
        raise ArtefactReconciliationError(
            "That artefact was itself merged into another record — merge into the surviving record instead."
        )

    moved = {
        "identifiers": _move_identifiers(db, survivor=survivor, merged=merged),
        "observedPorts": _move_observed_ports(db, survivor=survivor, merged=merged),
        "relationships": _move_relationships(db, survivor=survivor, merged=merged),
        "evidenceSignals": _move_evidence_signals(db, survivor=survivor, merged=merged),
        "findings": _move_findings(db, survivor=survivor, merged=merged),
    }

    previous_lifecycle_state = merged.lifecycle_state.value
    merged.lifecycle_state = AssetLifecycleState.MERGED
    merged.merged_into_asset_id = survivor.id
    merged.reviewed_at = utcnow()
    merged.reviewed_by_user_id = actor_user_id
    db.add(merged)

    # The survivor now stands for both observations, so it was last seen
    # whenever the *later* of the two was seen. Leaving this alone would make a
    # merge look like the artefact went quiet.
    if merged.last_observed_at is not None and (
        survivor.last_observed_at is None or merged.last_observed_at > survivor.last_observed_at
    ):
        survivor.last_observed_at = merged.last_observed_at
    db.add(survivor)

    conflict = None
    if conflict_id is not None:
        conflict = _require_conflict(db, organization_id=organization_id, conflict_id=conflict_id)
        conflict.state = ArtefactIdentityConflictState.RESOLVED_MERGED.value
        conflict.resolved_at = utcnow()
        conflict.resolved_by_user_id = actor_user_id
        conflict.resolution_reason = reason
        db.add(conflict)

    record = ArtefactMergeRecord(
        organization_id=organization_id,
        survivor_asset_id=survivor.id,
        merged_asset_id=merged.id,
        conflict_id=conflict.id if conflict is not None else None,
        decided_by_user_id=actor_user_id,
        reason=reason,
        previous_lifecycle_state=previous_lifecycle_state,
        moved=moved,
    )
    db.add(record)
    db.flush()

    _write_audit(
        db,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        event_type=ARTEFACT_AUDIT_MERGED,
        metadata={
            "mergeRecordId": record.id,
            "survivorAssetId": survivor.id,
            "mergedAssetId": merged.id,
            "conflictId": conflict.id if conflict is not None else None,
            "reason": reason,
            "moved": {key: len(value) for key, value in moved.items()},
        },
    )
    return record


def reverse_merge(
    db: Session,
    *,
    organization_id: int,
    merge_record_id: int,
    actor_user_id: int | None,
    reason: str | None = None,
) -> ArtefactMergeRecord:
    """Undo a merge, from what the merge itself recorded.

    Rows that were re-pointed go back; rows that were collapsed as duplicates
    are rebuilt from their snapshots, which is why the snapshots are stored at
    all — the row is gone, so its id would restore nothing.

    The merge record is kept and stamped as reversed rather than deleted. A
    decision that was taken and then undone is two facts an auditor is entitled
    to, and deleting the record would erase both.
    """
    record = (
        db.query(ArtefactMergeRecord)
        .filter(ArtefactMergeRecord.id == merge_record_id)
        .filter(ArtefactMergeRecord.organization_id == organization_id)
        .first()
    )
    if record is None:
        raise ArtefactReconciliationError("That merge does not exist in this organisation.")
    if record.reversed_at is not None:
        raise ArtefactReconciliationError("That merge has already been undone.")

    merged = _require_artefact(db, organization_id=organization_id, asset_id=record.merged_asset_id)
    moved = record.moved or {}

    _restore_identifiers(db, merged_asset_id=merged.id, entries=moved.get("identifiers", []))
    _restore_observed_ports(db, merged_asset_id=merged.id, entries=moved.get("observedPorts", []))
    _restore_relationships(
        db,
        merged_asset_id=merged.id,
        survivor_asset_id=record.survivor_asset_id,
        entries=moved.get("relationships", []),
    )
    _restore_evidence_signals(db, merged_asset_id=merged.id, entries=moved.get("evidenceSignals", []))
    # `.get` with a default, so reversing a merge recorded before findings were
    # moved still works — those records have no "findings" key at all.
    _restore_findings(db, merged_asset_id=merged.id, entries=moved.get("findings", []))

    merged.lifecycle_state = AssetLifecycleState(record.previous_lifecycle_state)
    merged.merged_into_asset_id = None
    db.add(merged)

    record.reversed_at = utcnow()
    record.reversed_by_user_id = actor_user_id
    record.reversal_reason = reason
    db.add(record)

    # The question is open again. It was a real uncertainty before someone
    # answered it, and undoing the answer does not make it certain.
    if record.conflict_id is not None:
        conflict = db.get(ArtefactIdentityConflict, record.conflict_id)
        if conflict is not None and conflict.organization_id == organization_id:
            conflict.state = ArtefactIdentityConflictState.OPEN.value
            conflict.resolved_at = None
            conflict.resolved_by_user_id = None
            conflict.resolution_reason = None
            conflict.last_raised_at = utcnow()
            db.add(conflict)

    _write_audit(
        db,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        event_type=ARTEFACT_AUDIT_MERGE_REVERSED,
        metadata={
            "mergeRecordId": record.id,
            "survivorAssetId": record.survivor_asset_id,
            "mergedAssetId": record.merged_asset_id,
            "reason": reason,
        },
    )
    db.flush()
    return record


def _require_conflict(db: Session, *, organization_id: int, conflict_id: int) -> ArtefactIdentityConflict:
    conflict = (
        db.query(ArtefactIdentityConflict)
        .filter(ArtefactIdentityConflict.id == conflict_id)
        .filter(ArtefactIdentityConflict.organization_id == organization_id)
        .first()
    )
    if conflict is None:
        raise ArtefactReconciliationError("That match does not exist in this organisation.")
    return conflict


# ─── Moving what the merged record knew ──────────────────────────────────────
#
# Each mover returns a list of entries the reversal reads back. An entry is
# either {"id": n} — the row was re-pointed and moving it back is enough — or
# {"collapsed": {...}} — the survivor already held the equivalent row, so this
# one was removed and its contents are the only way back.


def _move_identifiers(db: Session, *, survivor: Asset, merged: Asset) -> list[dict]:
    existing = {
        (row.identifier_type, row.identifier_value): row for row in _identifier_rows(db, survivor.id)
    }
    entries: list[dict] = []

    for row in _identifier_rows(db, merged.id):
        twin = existing.get((row.identifier_type, row.identifier_value))
        if twin is None:
            row.asset_id = survivor.id
            db.add(row)
            entries.append({"id": row.id})
            continue

        # The survivor has been seen under this identifier too. Keep the widest
        # true window across both rows — the identifier was genuinely first seen
        # at the earlier of the two, whichever record happened to hold it.
        if row.first_seen_at and (twin.first_seen_at is None or row.first_seen_at < twin.first_seen_at):
            twin.first_seen_at = row.first_seen_at
        if row.last_seen_at and (twin.last_seen_at is None or row.last_seen_at > twin.last_seen_at):
            twin.last_seen_at = row.last_seen_at
        db.add(twin)
        entries.append({"collapsed": _identifier_payload(row) | {"organizationId": row.organization_id}})
        db.delete(row)

    db.flush()
    return entries


def _move_observed_ports(db: Session, *, survivor: Asset, merged: Asset) -> list[dict]:
    existing = {
        (row.port, row.protocol): row
        for row in db.query(AssetObservedPort).filter(AssetObservedPort.asset_id == survivor.id).all()
    }
    entries: list[dict] = []

    for row in db.query(AssetObservedPort).filter(AssetObservedPort.asset_id == merged.id).all():
        twin = existing.get((row.port, row.protocol))
        if twin is None:
            row.asset_id = survivor.id
            db.add(row)
            entries.append({"id": row.id})
            continue

        if row.first_seen_at and (twin.first_seen_at is None or row.first_seen_at < twin.first_seen_at):
            twin.first_seen_at = row.first_seen_at
        if row.last_seen_at and (twin.last_seen_at is None or row.last_seen_at > twin.last_seen_at):
            twin.last_seen_at = row.last_seen_at
        db.add(twin)
        entries.append(
            {
                "collapsed": {
                    "organizationId": row.organization_id,
                    "port": row.port,
                    "protocol": row.protocol,
                    "serviceName": row.service_name,
                    "product": row.product,
                    "productVersion": row.product_version,
                    "firstSeenAt": row.first_seen_at.isoformat() if row.first_seen_at else None,
                    "lastSeenAt": row.last_seen_at.isoformat() if row.last_seen_at else None,
                }
            }
        )
        db.delete(row)

    db.flush()
    return entries


def _move_relationships(db: Session, *, survivor: Asset, merged: Asset) -> list[dict]:
    """Delegated to ``repoint_relationships``, which already owns this rule.

    The relationship service knows things a merge should not have to restate:
    that an edge between the two merged records becomes a self-edge the table's
    check constraint forbids, that a duplicate keeps the widest true window, and
    that a human-authored claim outranks an observed one when the two collapse
    together. Reimplementing any of that here would be a second, worse copy.
    """
    result = repoint_relationships(
        db, organization_id=merged.organization_id, from_asset_id=merged.id, into_asset_id=survivor.id
    )
    return [{"id": edge_id} for edge_id in result.moved_ids] + [
        {"collapsed": snapshot} for snapshot in result.collapsed
    ]


def _move_evidence_signals(db: Session, *, survivor: Asset, merged: Asset) -> list[dict]:
    """Straight re-point: signals are an append-only stream with no uniqueness
    to collide on, and every one of them is evidence that was genuinely observed
    against the artefact the survivor now stands for."""
    entries: list[dict] = []
    for row in db.query(AssetEvidenceSignal).filter(AssetEvidenceSignal.asset_id == merged.id).all():
        row.asset_id = survivor.id
        db.add(row)
        entries.append({"id": row.id})
    db.flush()
    return entries


def _move_findings(db: Session, *, survivor: Asset, merged: Asset) -> list[dict]:
    """Straight re-point, exactly like the evidence signals above.

    🐞 **These were left behind until 2026-09-07**, and the merge's own docstring
    said "everything the merged record knew moves to the survivor" while this was
    the one thing that did not. It is the most consequential omission of the four:
    a finding *is* the product's output, and stranding it on a tombstoned record
    means the platform holds the evidence and shows it against a row nobody
    reads.

    What it looked like on organisation 7: 22 of 25 findings sat on `MERGED`
    artefacts. `192.168.50.152` carried 13 — including SSH and RPC results —
    while `pi-local`, the surviving record for the same machine, showed **zero**.
    The tombstone rendered as *"Unidentified device · Nothing answered on this
    address · Nothing listening"* beside a control offering 13 findings, which is
    a card contradicting itself in three places.

    Findings have no uniqueness constraint to collide on, so this is a re-point
    rather than a merge of two sets. A duplicate title across the two records is
    left as two rows deliberately: they were observed separately, and collapsing
    them here would be this function deciding they are the same finding, which is
    not a judgement it is entitled to make.
    """
    entries: list[dict] = []
    for row in db.query(AssetFinding).filter(AssetFinding.asset_id == merged.id).all():
        row.asset_id = survivor.id
        db.add(row)
        entries.append({"id": row.id})
    db.flush()
    return entries


# ─── Putting it back ─────────────────────────────────────────────────────────


def _parse_time(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _restore_identifiers(db: Session, *, merged_asset_id: int, entries: list[dict]) -> None:
    for entry in entries:
        if "id" in entry:
            row = db.get(AssetIdentifier, entry["id"])
            if row is not None:
                row.asset_id = merged_asset_id
                db.add(row)
            continue

        snapshot = entry["collapsed"]
        db.add(
            AssetIdentifier(
                organization_id=snapshot["organizationId"],
                asset_id=merged_asset_id,
                identifier_type=snapshot["identifierType"],
                identifier_value=snapshot["identifierValue"],
                observed_by_source=snapshot.get("observedBySource"),
                first_seen_at=_parse_time(snapshot.get("firstSeenAt")) or utcnow(),
                last_seen_at=_parse_time(snapshot.get("lastSeenAt")) or utcnow(),
            )
        )
    db.flush()


def _restore_observed_ports(db: Session, *, merged_asset_id: int, entries: list[dict]) -> None:
    for entry in entries:
        if "id" in entry:
            row = db.get(AssetObservedPort, entry["id"])
            if row is not None:
                row.asset_id = merged_asset_id
                db.add(row)
            continue

        snapshot = entry["collapsed"]
        db.add(
            AssetObservedPort(
                organization_id=snapshot["organizationId"],
                asset_id=merged_asset_id,
                port=snapshot["port"],
                protocol=snapshot["protocol"],
                service_name=snapshot.get("serviceName"),
                product=snapshot.get("product"),
                product_version=snapshot.get("productVersion"),
                first_seen_at=_parse_time(snapshot.get("firstSeenAt")) or utcnow(),
                last_seen_at=_parse_time(snapshot.get("lastSeenAt")) or utcnow(),
            )
        )
    db.flush()


def _restore_relationships(
    db: Session, *, merged_asset_id: int, survivor_asset_id: int, entries: list[dict]
) -> None:
    """Put back only the end the merge moved.

    Exactly one end of a re-pointed edge is the survivor: an edge with the
    survivor on its *other* end would have become a self-edge and been collapsed
    instead, never re-pointed. So "the end that is the survivor" identifies the
    moved end without having to record it, and leaves any unrelated change made
    since the merge alone.
    """
    for entry in entries:
        if "id" in entry:
            edge = db.get(ArtefactRelationship, entry["id"])
            if edge is None:
                continue
            if edge.source_asset_id == survivor_asset_id:
                edge.source_asset_id = merged_asset_id
            elif edge.target_asset_id == survivor_asset_id:
                edge.target_asset_id = merged_asset_id
            db.add(edge)
            continue

        restore_relationship_snapshot(db, entry["collapsed"])
    db.flush()


def _restore_evidence_signals(db: Session, *, merged_asset_id: int, entries: list[dict]) -> None:
    for entry in entries:
        row = db.get(AssetEvidenceSignal, entry.get("id"))
        if row is not None:
            row.asset_id = merged_asset_id
            db.add(row)
    db.flush()


def _restore_findings(db: Session, *, merged_asset_id: int, entries: list[dict]) -> None:
    for entry in entries:
        row = db.get(AssetFinding, entry.get("id"))
        if row is not None:
            row.asset_id = merged_asset_id
            db.add(row)
    db.flush()


__all__ = [
    "ArtefactReconciliationError",
    "ConflictSide",
    "ConflictView",
    "keep_artefacts_separate",
    "list_open_conflicts",
    "merge_artefacts",
    "raise_identity_conflict",
    "reverse_merge",
]
