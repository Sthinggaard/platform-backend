"""Step 4.2 Part 3 (DISC-39) — technical-readiness / downstream-readiness.

The spec's own "non-negotiable" distinction (§43-45): three independently
true/false layers, never collapsed into one status, so nothing can ever
read "execution finished" as "onboarding is ready." This concept does not
exist anywhere else in the codebase today (confirmed by DISC-36's
repository inspection) — this module is its first and only home.

``technical_foundation_ready`` is still never derived from the other two
layers — "evidence processed" must never imply "foundation ready". It is
now derived from real state instead (BUG-DISC-16).

It previously returned a hardcoded ``False``, which was the right call
while nothing downstream existed to measure. It stopped being right the
moment the layer was rendered to users as a live progress indicator: a
deliberate "not computed yet" was shown as work underway, spinning
forever, with no action that could ever complete it.

The rule now: the organisation has a technical foundation once discovery
has produced artefacts. That is deliberately *not* gated on every
ambiguous artefact having been confirmed by a human, even though the
first version of this fix was — because **no confirm action exists**.
Nothing anywhere writes an ``Asset`` out of ``UNCONFIRMED``: no route, no
service, no screen. Gating on it would have reproduced the exact defect
this ticket exists to remove — a step the user is told to complete and
cannot — just with narrower wording. BUG-DISC-16's own acceptance
criterion forbids it: "a user is never shown a step that no available
action can advance."

Unconfirmed artefacts are therefore *surfaced, not blocking*: the label
states how many are uncertain, without pretending the user can act on it
yet. Building that review surface is CA-06's job ("uncertainty/conflict
review"), and when it exists this rule should tighten to require it.
"""

from __future__ import annotations

from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.core.constants.discovery_execution_enums import (
    TERMINAL_EXECUTION_PLAN_STATUSES,
    EvidenceNormalizationStatus,
)
from src.core.model_defs.assets_runtime import Asset, AssetLifecycleState
from src.core.model_defs.discovery_execution import DiscoveryExecutionPlan, EvidencePackage
from src.core.model_defs.discovery_run import DiscoveryRun

_PENDING_NORMALIZATION_STATUSES = frozenset(
    {EvidenceNormalizationStatus.PENDING.value, EvidenceNormalizationStatus.QUEUED.value}
)


class DiscoveryReadinessLayers(BaseModel):
    execution_complete: bool
    evidence_processing_complete: bool
    technical_foundation_ready: bool
    next_step_label: str | None


def _artefact_counts(db: Session, organization_id: int) -> tuple[int, int]:
    """(total artefacts, artefacts still awaiting a human identity decision).

    Organisation-scoped, not run-scoped: an Asset carries no ``discovery_run_id``
    — its link to a run exists only inside audit metadata — and the technical
    foundation is a property of the organisation's inventory, not of one run.
    A second run therefore correctly re-opens the layer if it turns up something
    ambiguous.
    """
    total = (
        db.query(Asset)
        .filter(Asset.organization_id == organization_id)
        .filter(Asset.lifecycle_state != AssetLifecycleState.REMOVED)
        .count()
    )
    unconfirmed = (
        db.query(Asset)
        .filter(Asset.organization_id == organization_id)
        .filter(Asset.lifecycle_state == AssetLifecycleState.UNCONFIRMED)
        .count()
    )
    return total, unconfirmed


def resolve_discovery_readiness_layers(
    db: Session, run: DiscoveryRun, plan: DiscoveryExecutionPlan | None
) -> DiscoveryReadinessLayers:
    execution_complete = plan is not None and plan.status in TERMINAL_EXECUTION_PLAN_STATUSES

    packages = db.query(EvidencePackage).filter(EvidencePackage.discovery_run_id == run.id).all()
    # Vacuously complete when a run produced zero packages (e.g. nothing
    # discoverable in scope) — there is nothing left pending.
    evidence_processing_complete = execution_complete and not any(
        package.normalization_status in _PENDING_NORMALIZATION_STATUSES for package in packages
    )

    asset_count, unconfirmed_count = _artefact_counts(db, run.organization_id)
    technical_foundation_ready = evidence_processing_complete and asset_count > 0

    if not execution_complete:
        next_step_label = "Discovery is still running."
    elif not evidence_processing_complete:
        next_step_label = "Risklence is processing the evidence collected during discovery."
    elif asset_count == 0:
        # Evidence arrived and was processed, but nothing in it described
        # anything ownable. That is a real outcome, not a pending step.
        next_step_label = (
            "Discovery finished without finding anything in the approved boundary. "
            "Widen the boundary or check the Collector's network access."
        )
    elif unconfirmed_count > 0:
        # Stated, not demanded: these are recorded rather than silently merged,
        # and there is no review surface yet to act on them (CA-06). Saying so
        # is honest; asking the user to "confirm" them would not be.
        thing = "item" if unconfirmed_count == 1 else "items"
        next_step_label = (
            f"{asset_count} assets are recorded. {unconfirmed_count} {thing} could not be "
            "matched with confidence and are kept separate rather than merged — Risklence "
            "will ask you to resolve them once identity review is available."
        )
    else:
        next_step_label = None

    return DiscoveryReadinessLayers(
        execution_complete=execution_complete,
        evidence_processing_complete=evidence_processing_complete,
        technical_foundation_ready=technical_foundation_ready,
        next_step_label=next_step_label,
    )
