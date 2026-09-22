"""CA-06.5 — an excluded target leaves the inventory, and says why.

``DiscoveryScopeProposal.exclusions`` is the boundary a human explicitly signed
off: "never look at this". Discovery already refuses to *scan* an excluded target
(``discovery_run_service._evaluate_approved_boundary``), but nothing ever applied
the same boundary to the **inventory**. An artefact discovered before an
exclusion existed — or found through a source that reached it another way — stayed
in the inventory indefinitely, so approving an exclusion changed what would be
scanned next and nothing about what the organisation was looking at.

Three properties shape this module:

* **Withdrawn, not deleted.** The artefact keeps its evidence, its identifiers
  and its history. It was genuinely observed; an exclusion is a decision about
  scope, not a claim that the observation never happened.
* **It says which exclusion, and when.** "This disappeared" is not an
  explanation. The pattern that caught it is recorded on the row, so a reviewer
  asking why something left the inventory gets an answer rather than an absence.
* **Restoring returns it to review, never straight to active.** An exclusion
  being lifted does not mean the artefact is confirmed — it means the question
  is open again, and a person answers it.

Withdrawal is deliberately its own lifecycle state. ``REMOVED`` is a person
saying "not ours"; reusing it would let a boundary change silently overwrite a
human decision, and lifting the exclusion would then hand back a record whose
rejection had been erased.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from src.core.constants.artefact_identity_enums import (
    ARTEFACT_AUDIT_BOUNDARY_RESTORED,
    ARTEFACT_AUDIT_BOUNDARY_WITHDRAWN,
)
from src.core.model_defs.assets_runtime import Asset, AssetIdentifier, AssetLifecycleState
from src.core.model_defs.common import utcnow
from src.core.models import AuditEvent
from src.core.services.discovery_boundary_matching import is_within
from src.core.services.discovery_scope_proposal_service import get_approved_scope


@dataclass(frozen=True)
class BoundaryVerdict:
    """Whether an artefact falls outside the approved boundary, and on what."""

    excluded: bool
    #: The exclusion pattern that caught it. Recorded on the row, because a
    #: withdrawal a reviewer cannot explain is indistinguishable from a bug.
    matched_exclusion: str | None = None
    #: The value of the artefact's own that matched — an address, a hostname.
    matched_value: str | None = None


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


def _artefact_values(db: Session, asset: Asset) -> list[str]:
    """Everything about this artefact a boundary could be written against.

    The identifier set, not just the display name: an exclusion is normally
    written as an address or a domain, and an artefact whose display name has
    since become a hostname would otherwise slip past a boundary it plainly
    falls inside.
    """
    values = [asset.display_name] if asset.display_name else []
    values.extend(
        row.identifier_value
        for row in db.query(AssetIdentifier).filter(AssetIdentifier.asset_id == asset.id).all()
        if row.identifier_value
    )
    return values


def evaluate_boundary(db: Session, *, asset: Asset, exclusions: list[str]) -> BoundaryVerdict:
    """Does the approved boundary exclude this artefact, and on which pattern?

    Matching is delegated to ``is_within``, which discovery already uses to
    enforce the same boundary at scan time. Two different notions of "inside the
    boundary" is exactly how a target gets scanned but never withdrawn, or the
    reverse.
    """
    if not exclusions:
        return BoundaryVerdict(excluded=False)

    for value in _artefact_values(db, asset):
        for exclusion in exclusions:
            if is_within(value, [exclusion]):
                return BoundaryVerdict(excluded=True, matched_exclusion=str(exclusion), matched_value=value)
    return BoundaryVerdict(excluded=False)


def withdraw_artefact(
    db: Session,
    *,
    asset: Asset,
    verdict: BoundaryVerdict,
    actor_user_id: int | None,
) -> Asset:
    """Take an artefact out of the inventory because the boundary excludes it.

    Idempotent: an artefact already withdrawn is not re-stamped, so a scan that
    sees it again does not keep moving the date on which it left.
    """
    if asset.lifecycle_state == AssetLifecycleState.WITHDRAWN:
        return asset

    previous = asset.lifecycle_state
    asset.lifecycle_state = AssetLifecycleState.WITHDRAWN
    asset.withdrawn_by_exclusion = verdict.matched_exclusion
    asset.withdrawn_at = utcnow()
    db.add(asset)
    _write_audit(
        db,
        organization_id=asset.organization_id,
        actor_user_id=actor_user_id,
        event_type=ARTEFACT_AUDIT_BOUNDARY_WITHDRAWN,
        metadata={
            "assetId": asset.id,
            "displayName": asset.display_name,
            "previousLifecycleState": previous.value,
            "matchedExclusion": verdict.matched_exclusion,
            "matchedValue": verdict.matched_value,
        },
    )
    db.flush()
    return asset


def restore_artefact_to_review(db: Session, *, asset: Asset, actor_user_id: int | None) -> Asset:
    """The exclusion no longer applies, so the question is open again.

    Returned to ``UNCONFIRMED`` rather than ``ACTIVE``. Nobody ever said this
    artefact belongs in the inventory — a boundary stopped being applied to it,
    which is not the same statement, and quietly activating it would put a
    record into the dependency picture that no person ever confirmed.
    """
    if asset.lifecycle_state != AssetLifecycleState.WITHDRAWN:
        return asset

    exclusion = asset.withdrawn_by_exclusion
    asset.lifecycle_state = AssetLifecycleState.UNCONFIRMED
    asset.withdrawn_by_exclusion = None
    asset.withdrawn_at = None
    db.add(asset)
    _write_audit(
        db,
        organization_id=asset.organization_id,
        actor_user_id=actor_user_id,
        event_type=ARTEFACT_AUDIT_BOUNDARY_RESTORED,
        metadata={
            "assetId": asset.id,
            "displayName": asset.display_name,
            "previousExclusion": exclusion,
            "lifecycleState": asset.lifecycle_state.value,
        },
    )
    db.flush()
    return asset


def apply_boundary_to_inventory(
    db: Session,
    *,
    organization_id: int,
    evidence_source_id: str,
    actor_user_id: int | None,
) -> tuple[int, int]:
    """Reconcile the whole inventory against the boundary currently in force.

    Called when a boundary is approved, because that is the moment the answer
    changes for artefacts nobody is about to re-scan. Returns
    ``(withdrawn, restored)``.

    Both directions, deliberately. Applying only new exclusions would let a
    lifted exclusion leave its artefacts withdrawn forever, with no event ever
    coming to release them — the decision would be reversible in the boundary
    and irreversible in the inventory.
    """
    boundary = get_approved_scope(
        db, organization_id=organization_id, evidence_source_id=evidence_source_id
    )
    exclusions = [str(value) for value in (boundary.exclusions or [])] if boundary is not None else []

    withdrawn = 0
    restored = 0
    for asset in db.query(Asset).filter(Asset.organization_id == organization_id).all():
        # A person's own decision is not the boundary's to overturn in either
        # direction: REMOVED, NOT_USED and MERGED are answers someone already
        # gave about this record.
        if asset.lifecycle_state in _HUMAN_DECIDED_STATES:
            continue

        verdict = evaluate_boundary(db, asset=asset, exclusions=exclusions)
        if verdict.excluded:
            if asset.lifecycle_state != AssetLifecycleState.WITHDRAWN:
                withdraw_artefact(db, asset=asset, verdict=verdict, actor_user_id=actor_user_id)
                withdrawn += 1
        elif asset.lifecycle_state == AssetLifecycleState.WITHDRAWN:
            restore_artefact_to_review(db, asset=asset, actor_user_id=actor_user_id)
            restored += 1

    db.flush()
    return withdrawn, restored


#: States that record a person's answer about the artefact. A boundary change
#: must not overwrite one.
_HUMAN_DECIDED_STATES = frozenset(
    {
        AssetLifecycleState.REMOVED,
        AssetLifecycleState.NOT_USED,
        AssetLifecycleState.MERGED,
    }
)


__all__ = [
    "BoundaryVerdict",
    "apply_boundary_to_inventory",
    "evaluate_boundary",
    "restore_artefact_to_review",
    "withdraw_artefact",
]
