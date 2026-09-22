"""Human decisions on a discovered artefact (#150).

Discovery proposes an inventory; a person decides what is actually theirs and
what each thing is. Until this existed, nothing in the codebase could move an
``Asset`` out of ``UNCONFIRMED`` and nothing could remove one that should never
have been created — the review half of CA-06's "uncertainty/conflict review"
contract was missing, so a screen could ask for a confirmation the user had no
way to give.

Two properties matter more than the writes themselves, and both are proven by
tests rather than assumed:

* **A decision survives the next scan.** ``resolve_identity`` matches on
  ``canonical_identity_key`` without filtering by lifecycle state, so a rejected
  artefact is re-matched and stays rejected instead of being recreated. A
  corrected classification survives too, but by an explicit marker rather than
  by normalisation leaving every existing row alone: a correction sets
  ``intent.classificationSetByHuman``, and re-derivation defers to it. The
  distinction matters — confirming an artefact says "this is ours" and nothing
  about the label, so keying re-derivation off ``reviewed_at`` would freeze a
  machine guess on exactly the rows a person had already looked at.
* **Every decision is attributable.** This is a human decision about the
  organisation's own inventory, so it belongs in the audit trail exactly like a
  risk decision does — who, when, and what changed.

This module owns artefact review only. Identity resolution lives in
``artefact_identity_service``; creating artefacts from evidence lives in
``risk_intelligence_normalization_service``.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.constants.artefact_identity_enums import (
    ARTEFACT_AUDIT_CLASSIFICATION_CORRECTED,
    ARTEFACT_AUDIT_CONFIRMED,
    ARTEFACT_AUDIT_DEPENDENCY_CATEGORY_SET,
    ARTEFACT_AUDIT_NOT_USED,
    ARTEFACT_AUDIT_REJECTED,
)
from src.core.constants.dependency_category_enums import DependencyCategory
from src.core.model_defs.assets_runtime import Asset, AssetLifecycleState
from src.core.model_defs.common import utcnow
from src.core.models import AuditEvent


class ArtefactReviewError(RuntimeError):
    """Raised when a review decision cannot be applied as asked."""


def _require_artefact(db: Session, *, organization_id: int, asset_id: str) -> Asset:
    """Tenant-scoped lookup. The organization_id filter is not optional — an
    artefact id from another organisation must read as "not found", never as a
    permission error that confirms the row exists."""
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id)
        .filter(Asset.organization_id == organization_id)
        .first()
    )
    if asset is None:
        raise ArtefactReviewError("That artefact does not exist in this organisation.")
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


def confirm_artefact(
    db: Session, *, organization_id: int, asset_id: str, actor_user_id: int | None
) -> Asset:
    """"Yes, this is ours." Moves an artefact to ``ACTIVE``.

    Deliberately allowed on an already-``ACTIVE`` artefact: most discovered rows
    are created ACTIVE, and a reviewer confirming one is still a real decision
    worth recording — the audit trail is the point, not the state change.
    """
    asset = _require_artefact(db, organization_id=organization_id, asset_id=asset_id)
    if asset.lifecycle_state == AssetLifecycleState.MERGED:
        raise ArtefactReviewError(
            "This artefact was merged into another record and cannot be confirmed on its own."
        )

    previous = asset.lifecycle_state
    asset.lifecycle_state = AssetLifecycleState.ACTIVE
    # Stamped even when the state does not move — which is the usual case, since
    # discovered rows are created ACTIVE. Without this the reviewer's decision
    # left no mark on the record and their own screen could not show it.
    asset.reviewed_at = utcnow()
    asset.reviewed_by_user_id = actor_user_id
    db.add(asset)
    _write_audit(
        db,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        event_type=ARTEFACT_AUDIT_CONFIRMED,
        metadata={
            "assetId": asset.id,
            "displayName": asset.display_name,
            "previousLifecycleState": previous.value,
            "lifecycleState": asset.lifecycle_state.value,
        },
    )
    db.flush()
    return asset


def reject_artefact(
    db: Session,
    *,
    organization_id: int,
    asset_id: str,
    actor_user_id: int | None,
    reason: str | None = None,
) -> Asset:
    """"This is not ours." Moves an artefact to ``REMOVED``.

    Not a delete: the evidence that produced it is real and stays on record, and
    an auditor is entitled to see that something was observed and deliberately
    excluded, plus who excluded it. A later scan re-matches this row by identity
    key and leaves it rejected rather than creating a duplicate.
    """
    asset = _require_artefact(db, organization_id=organization_id, asset_id=asset_id)

    previous = asset.lifecycle_state
    asset.lifecycle_state = AssetLifecycleState.REMOVED
    asset.reviewed_at = utcnow()
    asset.reviewed_by_user_id = actor_user_id
    db.add(asset)
    _write_audit(
        db,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        event_type=ARTEFACT_AUDIT_REJECTED,
        metadata={
            "assetId": asset.id,
            "displayName": asset.display_name,
            "previousLifecycleState": previous.value,
            "lifecycleState": asset.lifecycle_state.value,
            "reason": reason,
        },
    )
    db.flush()
    return asset


def correct_artefact_classification(
    db: Session,
    *,
    organization_id: int,
    asset_id: str,
    actor_user_id: int | None,
    asset_type: str | None = None,
    layer: str | None = None,
) -> Asset:
    """"That is not what this is." Corrects an artefact's type and/or layer.

    The scanner's classification is a guess derived from open ports
    (BUG-DISC-15); a reviewer looking at their own network knows better. Both
    fields are optional so a caller can fix one without restating the other, and
    the previous values are recorded so the correction itself is reviewable.
    """
    if asset_type is None and layer is None:
        raise ArtefactReviewError("A correction must change the type, the layer, or both.")

    asset = _require_artefact(db, organization_id=organization_id, asset_id=asset_id)
    changed: dict[str, dict[str, str | None]] = {}

    if asset_type is not None and asset_type != asset.type:
        changed["type"] = {"from": asset.type, "to": asset_type}
        asset.type = asset_type
    if layer is not None and layer != asset.layer:
        changed["layer"] = {"from": asset.layer, "to": layer}
        asset.layer = layer

    if not changed:
        return asset  # nothing to record — the values already say this

    # Saying what something *is* is as much a decision about the artefact as
    # saying it is ours, so it stamps the same fields. Without this a correction
    # left no mark at all, and anything reasoning about "has a human looked at
    # this?" could not see it.
    asset.reviewed_at = utcnow()
    asset.reviewed_by_user_id = actor_user_id
    # And separately: *this class* is now a person's answer. `reviewed_at` alone
    # cannot say that — confirming an artefact means "yes, this is ours" and
    # says nothing about whether the label is right — so treating it as approval
    # of the classification would freeze a machine guess the moment someone
    # confirmed the artefact.
    intent = dict(asset.intent) if isinstance(asset.intent, dict) else {}
    intent["classificationSetByHuman"] = True
    asset.intent = intent
    db.add(asset)
    _write_audit(
        db,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        event_type=ARTEFACT_AUDIT_CLASSIFICATION_CORRECTED,
        metadata={
            "assetId": asset.id,
            "displayName": asset.display_name,
            "changed": changed,
        },
    )
    db.flush()
    return asset


def set_dependency_category(
    db: Session, *, organization_id: int, asset_id: str, actor_user_id: int | None, category: DependencyCategory
) -> Asset:
    """Record a reviewer's explicit library label; scanner evidence never supplies it."""
    asset = _require_artefact(db, organization_id=organization_id, asset_id=asset_id)
    if asset.lifecycle_state != AssetLifecycleState.ACTIVE or asset.reviewed_at is None:
        raise ArtefactReviewError("Confirm this active artefact in the library before assigning a dependency category.")
    previous = asset.dependency_category
    asset.dependency_category = category.value
    db.add(asset)
    _write_audit(db, organization_id=organization_id, actor_user_id=actor_user_id,
        event_type=ARTEFACT_AUDIT_DEPENDENCY_CATEGORY_SET,
        metadata={"assetId": asset.id, "from": previous, "to": category.value})
    db.flush()
    return asset


def mark_artefact_not_used(
    db: Session,
    *,
    organization_id: int,
    asset_id: str,
    actor_user_id: int | None,
    reason: str | None = None,
) -> Asset:
    """"This is ours, but we will never depend on it."

    The third disposition, and the one the other two could not express. A phone
    or a laptop on the office WiFi is genuinely the organisation's, so rejecting
    it as "not ours" is a false statement about it — but confirming it puts a
    device nothing can depend on into the dependency picture. Reviewers had no
    honest way to deal with those rows, so they stayed undecided run after run.

    Distinct from ``reject_artefact`` on purpose: both take the artefact out of
    the dependency picture, but they say different things, and an auditor asking
    "what is on your network that you have chosen not to model, and who decided
    that?" is entitled to the difference. Reversible through ``confirm_artefact``
    like any other decision.
    """
    asset = _require_artefact(db, organization_id=organization_id, asset_id=asset_id)
    if asset.lifecycle_state == AssetLifecycleState.MERGED:
        raise ArtefactReviewError(
            "This artefact was merged into another record, so this decision belongs on the record it was merged into."
        )

    previous = asset.lifecycle_state
    asset.lifecycle_state = AssetLifecycleState.NOT_USED
    asset.reviewed_at = utcnow()
    asset.reviewed_by_user_id = actor_user_id
    db.add(asset)
    _write_audit(
        db,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        event_type=ARTEFACT_AUDIT_NOT_USED,
        metadata={
            "assetId": asset.id,
            "displayName": asset.display_name,
            "previousLifecycleState": previous.value,
            "lifecycleState": asset.lifecycle_state.value,
            "reason": reason,
        },
    )
    db.flush()
    return asset
