"""CA-06.3 — recording and maintaining the edges between artefacts.

Owns every rule about relationships so no caller has to know them:

* **A person outranks a scan.** Once someone has asserted a relationship, a
  later scan may confirm it but never quietly rewrites or withdraws it. The
  platform recommends and documents; it does not overrule a human decision on
  its own.
* **Nothing is deleted.** A relationship that stops being observed is withdrawn
  with a date. "These two were connected until the 14th" is a fact worth
  keeping, and deleting the row destroys the only evidence it ever existed.
* **An inference is never stated as fact.** Origin and confidence are recorded
  on every row and are not defaultable, so any surface showing a relationship
  can always say who claimed it and how sure they were.
* **Reconciliation re-points, it does not orphan.** When CA-06.4 merges two
  artefacts, the loser's relationships move to the survivor rather than being
  destroyed with it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import or_
from sqlalchemy.orm import Session

from src.core.constants.artefact_relationship_enums import (
    HUMAN_AUTHORED_ORIGINS,
    ArtefactRelationshipConfidence,
    ArtefactRelationshipOrigin,
    ArtefactRelationshipState,
    ArtefactRelationshipType,
)
from src.core.model_defs.artefact_relationships import ArtefactRelationship
from src.core.model_defs.assets_runtime import Asset
from src.core.model_defs.common import utcnow


class ArtefactRelationshipError(ValueError):
    """A relationship that cannot be recorded as asked."""


@dataclass(frozen=True)
class RepointResult:
    """What re-pointing did, in enough detail to undo it (CA-06.4).

    ``collapsed`` holds full snapshots rather than ids, because a collapsed edge
    no longer exists as a row — restoring it needs its contents, not a pointer
    to where it used to be.
    """

    moved_ids: tuple[int, ...] = ()
    collapsed: tuple[dict, ...] = ()

    @property
    def moved(self) -> int:
        return len(self.moved_ids)

    @property
    def collapsed_count(self) -> int:
        return len(self.collapsed)

    def __iter__(self):
        """Kept unpackable as ``moved, collapsed`` — the counts are what most
        callers want, and reading them should not require knowing this became a
        richer object for the merge's benefit."""
        return iter((self.moved, self.collapsed_count))


def _snapshot_relationship(edge: ArtefactRelationship) -> dict:
    """Everything needed to recreate this edge exactly, as JSON-safe values."""
    return {
        "organizationId": edge.organization_id,
        "sourceAssetId": edge.source_asset_id,
        "targetAssetId": edge.target_asset_id,
        "relationshipType": edge.relationship_type,
        "origin": edge.origin,
        "confidence": edge.confidence,
        "state": edge.state,
        "reason": edge.reason,
        "evidencePackageId": edge.evidence_package_id,
        "scannerInstanceId": edge.scanner_instance_id,
        "observedBySource": edge.observed_by_source,
        "assertedByUserId": edge.asserted_by_user_id,
        "firstSeenAt": edge.first_seen_at.isoformat() if edge.first_seen_at else None,
        "lastSeenAt": edge.last_seen_at.isoformat() if edge.last_seen_at else None,
        "withdrawnAt": edge.withdrawn_at.isoformat() if edge.withdrawn_at else None,
    }


def restore_relationship_snapshot(db: Session, snapshot: dict) -> ArtefactRelationship | None:
    """Recreate an edge collapsed by a merge, when that merge is undone.

    Returns ``None`` when the edge already exists again — undoing a merge must
    not fail because reconciliation re-observed the relationship in the
    meantime.
    """
    existing = (
        db.query(ArtefactRelationship)
        .filter(
            ArtefactRelationship.organization_id == snapshot["organizationId"],
            ArtefactRelationship.source_asset_id == snapshot["sourceAssetId"],
            ArtefactRelationship.target_asset_id == snapshot["targetAssetId"],
            ArtefactRelationship.relationship_type == snapshot["relationshipType"],
        )
        .first()
    )
    if existing is not None:
        return None

    def _time(value: str | None) -> datetime | None:
        return datetime.fromisoformat(value) if value else None

    restored = ArtefactRelationship(
        organization_id=snapshot["organizationId"],
        source_asset_id=snapshot["sourceAssetId"],
        target_asset_id=snapshot["targetAssetId"],
        relationship_type=snapshot["relationshipType"],
        origin=snapshot["origin"],
        confidence=snapshot["confidence"],
        state=snapshot["state"],
        reason=snapshot.get("reason"),
        evidence_package_id=snapshot.get("evidencePackageId"),
        scanner_instance_id=snapshot.get("scannerInstanceId"),
        observed_by_source=snapshot.get("observedBySource"),
        asserted_by_user_id=snapshot.get("assertedByUserId"),
        first_seen_at=_time(snapshot.get("firstSeenAt")) or utcnow(),
        last_seen_at=_time(snapshot.get("lastSeenAt")) or utcnow(),
        withdrawn_at=_time(snapshot.get("withdrawnAt")),
    )
    db.add(restored)
    db.flush()
    return restored


def _require_same_organization(db: Session, organization_id: int, *asset_ids: int) -> None:
    """Both ends must belong to the organisation the caller is acting for.

    Checked here rather than trusted from the caller: a relationship is the one
    place in this domain where two artefact ids meet, and an unchecked pair is
    how one tenant's artefact ends up pointing at another's.
    """
    found = {
        asset_id
        for (asset_id,) in db.query(Asset.id).filter(
            Asset.organization_id == organization_id, Asset.id.in_(asset_ids)
        )
    }
    missing = set(asset_ids) - found
    if missing:
        raise ArtefactRelationshipError(
            f"Artefact(s) {sorted(missing)} do not belong to organization {organization_id}."
        )


def record_relationship(
    db: Session,
    *,
    organization_id: int,
    source_asset_id: int,
    target_asset_id: int,
    relationship_type: ArtefactRelationshipType,
    origin: ArtefactRelationshipOrigin,
    confidence: ArtefactRelationshipConfidence,
    reason: str | None = None,
    evidence_package_id: str | None = None,
    scanner_instance_id: str | None = None,
    observed_by_source: str | None = None,
    asserted_by_user_id: int | None = None,
    observed_at: datetime | None = None,
) -> ArtefactRelationship:
    """Record that two artefacts are related, or refresh an existing claim.

    Re-observing an existing relationship advances ``last_seen_at`` rather than
    inserting a second row, which is what makes a repeated scan idempotent.
    """
    if source_asset_id == target_asset_id:
        raise ArtefactRelationshipError("An artefact cannot be related to itself.")
    if origin == ArtefactRelationshipOrigin.ASSERTED_BY_PERSON and asserted_by_user_id is None:
        # "A person said so" with no person named is not attribution.
        raise ArtefactRelationshipError(
            "A person-asserted relationship must record which person asserted it."
        )

    _require_same_organization(db, organization_id, source_asset_id, target_asset_id)

    now = observed_at or utcnow()
    existing = (
        db.query(ArtefactRelationship)
        .filter(
            ArtefactRelationship.organization_id == organization_id,
            ArtefactRelationship.source_asset_id == source_asset_id,
            ArtefactRelationship.target_asset_id == target_asset_id,
            ArtefactRelationship.relationship_type == relationship_type.value,
        )
        .first()
    )

    if existing is None:
        created = ArtefactRelationship(
            organization_id=organization_id,
            source_asset_id=source_asset_id,
            target_asset_id=target_asset_id,
            relationship_type=relationship_type.value,
            origin=origin.value,
            confidence=confidence.value,
            state=ArtefactRelationshipState.ACTIVE.value,
            reason=reason,
            evidence_package_id=evidence_package_id,
            scanner_instance_id=scanner_instance_id,
            observed_by_source=observed_by_source,
            asserted_by_user_id=asserted_by_user_id,
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(created)
        db.flush()
        return created

    existing.last_seen_at = now

    # A person's claim is not downgraded by a machine seeing the same thing more
    # weakly. The scan is still recorded (last_seen_at above), it just does not
    # get to restate what the relationship *is*.
    incoming_is_human = origin in HUMAN_AUTHORED_ORIGINS
    stored_is_human = ArtefactRelationshipOrigin(existing.origin) in HUMAN_AUTHORED_ORIGINS
    if incoming_is_human or not stored_is_human:
        existing.origin = origin.value
        existing.confidence = confidence.value
        if reason:
            existing.reason = reason
        if asserted_by_user_id is not None:
            existing.asserted_by_user_id = asserted_by_user_id

    # Provenance is additive: a later observation fills gaps, and never blanks
    # out what an earlier one established.
    if evidence_package_id:
        existing.evidence_package_id = evidence_package_id
    if scanner_instance_id:
        existing.scanner_instance_id = scanner_instance_id
    if observed_by_source:
        existing.observed_by_source = observed_by_source

    # Seeing it again revives a withdrawn relationship — but never one a person
    # rejected, which stays rejected until a person says otherwise.
    if existing.state == ArtefactRelationshipState.WITHDRAWN.value:
        existing.state = ArtefactRelationshipState.ACTIVE.value
        existing.withdrawn_at = None

    db.add(existing)
    db.flush()
    return existing


def withdraw_relationship(
    db: Session,
    *,
    relationship: ArtefactRelationship,
    reason: str | None = None,
    withdrawn_at: datetime | None = None,
) -> ArtefactRelationship:
    """Mark a relationship as no longer held true, without destroying it.

    A person's assertion is not withdrawn here — the platform does not retract
    someone else's statement because a scan stopped seeing it. Removing one is a
    human decision, recorded as ``REJECTED``.
    """
    if ArtefactRelationshipOrigin(relationship.origin) in HUMAN_AUTHORED_ORIGINS:
        raise ArtefactRelationshipError(
            "A person-asserted relationship cannot be withdrawn by the platform; "
            "it takes a person's decision to reject it."
        )

    relationship.state = ArtefactRelationshipState.WITHDRAWN.value
    relationship.withdrawn_at = withdrawn_at or utcnow()
    if reason:
        relationship.reason = reason
    db.add(relationship)
    db.flush()
    return relationship


def relationships_for_asset(
    db: Session,
    *,
    organization_id: int,
    asset_id: int,
    include_withdrawn: bool = False,
) -> list[ArtefactRelationship]:
    """Every relationship this artefact is either end of, tenant-scoped."""
    query = db.query(ArtefactRelationship).filter(
        ArtefactRelationship.organization_id == organization_id,
        or_(
            ArtefactRelationship.source_asset_id == asset_id,
            ArtefactRelationship.target_asset_id == asset_id,
        ),
    )
    if not include_withdrawn:
        query = query.filter(ArtefactRelationship.state == ArtefactRelationshipState.ACTIVE.value)
    return query.order_by(ArtefactRelationship.id.asc()).all()


def repoint_relationships(
    db: Session,
    *,
    organization_id: int,
    from_asset_id: int,
    into_asset_id: int,
    repointed_at: datetime | None = None,
) -> RepointResult:
    """Move one artefact's relationships onto another. Used when two artefacts
    are merged (CA-06.4).

    Returns a :class:`RepointResult`: the ids that were re-pointed, and full
    snapshots of the edges that had to be collapsed. It still unpacks as
    ``moved, collapsed`` counts for callers that only want the tally — the
    snapshots exist so the merge that called this can be undone, which counts
    alone could never support.

    Written here rather than inside the merge because the rule belongs to
    relationships: a merge says two records are one thing, and everything that
    pointed at either must end up pointing at the survivor. Orphaning them
    instead would silently delete structure a person never agreed to lose.
    """
    if from_asset_id == into_asset_id:
        raise ArtefactRelationshipError("Cannot re-point an artefact's relationships onto itself.")

    _require_same_organization(db, organization_id, from_asset_id, into_asset_id)
    now = repointed_at or utcnow()

    survivor_edges = {
        (row.source_asset_id, row.target_asset_id, row.relationship_type): row
        for row in db.query(ArtefactRelationship).filter(
            ArtefactRelationship.organization_id == organization_id,
            or_(
                ArtefactRelationship.source_asset_id == into_asset_id,
                ArtefactRelationship.target_asset_id == into_asset_id,
            ),
        )
    }

    moved_ids: list[int] = []
    collapsed: list[dict] = []
    for edge in (
        db.query(ArtefactRelationship)
        .filter(
            ArtefactRelationship.organization_id == organization_id,
            or_(
                ArtefactRelationship.source_asset_id == from_asset_id,
                ArtefactRelationship.target_asset_id == from_asset_id,
            ),
        )
        .order_by(ArtefactRelationship.id.asc())
        .all()
    ):
        new_source = into_asset_id if edge.source_asset_id == from_asset_id else edge.source_asset_id
        new_target = into_asset_id if edge.target_asset_id == from_asset_id else edge.target_asset_id

        if new_source == new_target:
            # The merge turned "A runs on B" into "A runs on A". The two ends
            # were the same artefact all along, so the edge was never real
            # structure — it was a symptom of the duplicate being merged.
            collapsed.append(_snapshot_relationship(edge))
            db.delete(edge)
            continue

        key = (new_source, new_target, edge.relationship_type)
        duplicate = survivor_edges.get(key)
        if duplicate is not None:
            # The survivor already holds this exact claim. Keep the earliest
            # first-seen and the latest last-seen, so merging never shortens the
            # history of a relationship.
            duplicate.first_seen_at = min(duplicate.first_seen_at, edge.first_seen_at)
            duplicate.last_seen_at = max(duplicate.last_seen_at, edge.last_seen_at)
            if ArtefactRelationshipOrigin(edge.origin) in HUMAN_AUTHORED_ORIGINS and (
                ArtefactRelationshipOrigin(duplicate.origin) not in HUMAN_AUTHORED_ORIGINS
            ):
                duplicate.origin = edge.origin
                duplicate.confidence = edge.confidence
                duplicate.asserted_by_user_id = edge.asserted_by_user_id
            db.add(duplicate)
            collapsed.append(_snapshot_relationship(edge))
            db.delete(edge)
            continue

        edge.source_asset_id = new_source
        edge.target_asset_id = new_target
        edge.updated_at = now
        db.add(edge)
        survivor_edges[key] = edge
        moved_ids.append(edge.id)

    db.flush()
    return RepointResult(moved_ids=tuple(moved_ids), collapsed=tuple(collapsed))
