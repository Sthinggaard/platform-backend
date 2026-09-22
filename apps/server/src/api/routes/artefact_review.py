"""Human decisions on a discovered artefact (#150).

Separate router rather than more endpoints on ``discovery_run.py``: reviewing
the inventory is not part of running a discovery, and these decisions outlive
the run that surfaced them. Adding this file touches no existing route.

Read access to discovery results is already granted to every active org member
(``can_view_diagnostics``); *deciding* what the organisation owns is a stronger
authority, so these routes require **manager or above** (``MANAGER_ROLES``).

Manager is the right floor rather than admin: a manager can already manage
assets, and saying what an asset *is* — or that it is not ours at all — is the
same kind of authority, not a governance decision like approving the discovery
boundary. ``MANAGER_ROLES`` is inclusive upward by construction
(manager/admin/org_admin), so no separate rule is needed for senior roles.

This is org-wide inventory triage. It is deliberately **not** the same question
as who may approve something scoped to one Business Process — where an accepted
owner holds the mandate for their own process. Nothing here is process-scoped
yet, so no owner check applies.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.dependency_category_enums import DependencyCategory
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.tenant_identity import User
from src.core.repository import TenantRepository
from src.core.roles import MANAGER_ROLES
from src.core.services.artefact_reconciliation_service import (
    ArtefactReconciliationError,
    keep_artefacts_separate,
    list_open_conflicts,
    merge_artefacts,
    reverse_merge,
)
from src.core.services.artefact_review_service import (
    ArtefactReviewError,
    confirm_artefact,
    correct_artefact_classification,
    mark_artefact_not_used,
    reject_artefact,
    set_dependency_category,
)

router = APIRouter(prefix="/api/v1/artefacts", tags=["Artefact review"])


class ArtefactDecisionResponse(BaseModel):
    asset_id: int
    display_name: str
    asset_type: str
    layer: str
    lifecycle_state: str


class RejectArtefactRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=500)


class CorrectClassificationRequest(BaseModel):
    asset_type: str | None = Field(default=None, min_length=1, max_length=100)
    layer: str | None = Field(default=None, min_length=1, max_length=100)


class SetDependencyCategoryRequest(BaseModel):
    dependency_category: DependencyCategory


def _require_reviewer(db: Session, ctx: TenantContext) -> int:
    """Manager and above. Reuses the shared role set and the `_require_org_admin`
    shape used by evidence_source/evidence_scanner rather than a local check —
    the first version hardcoded `role != "org_admin"`, which silently excluded
    `admin` and refused a legitimate reviewer."""
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active or user.role not in MANAGER_ROLES:
        raise AuthorizationError(
            "Deciding what belongs in the inventory requires a manager or administrator role."
        )
    return user.id


def _response(asset) -> ArtefactDecisionResponse:
    return ArtefactDecisionResponse(
        asset_id=asset.id,
        display_name=asset.display_name,
        asset_type=asset.type,
        layer=asset.layer,
        lifecycle_state=asset.lifecycle_state.value,
    )


# ─── CA-06.4 — uncertain matches ─────────────────────────────────────────────
#
# Same authority floor as the decisions above, and for the same reason: saying
# two records are one artefact is a statement about what the organisation owns.
# Deliberately *not* a lower bar than confirming a single artefact — a merge
# changes more, not less.


class ConflictSideResponse(BaseModel):
    asset_id: int
    display_name: str
    asset_type: str
    layer: str
    lifecycle_state: str
    identifiers: list[dict]
    last_observed_at: str | None


class ConflictResponse(BaseModel):
    conflict_id: int
    reason: str
    state: str
    raised_at: str
    last_raised_at: str
    left: ConflictSideResponse
    right: ConflictSideResponse
    shared_identifiers: list[dict]


class MergeArtefactsRequest(BaseModel):
    #: Which record remains the artefact. The caller's judgement, never
    #: inferred here — "which of these is the real one" is the question.
    survivor_asset_id: int
    merged_asset_id: int
    conflict_id: int | None = None
    reason: str | None = Field(default=None, max_length=500)


class KeepSeparateRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=500)


class MergeRecordResponse(BaseModel):
    merge_record_id: int
    survivor_asset_id: int
    merged_asset_id: int
    reversed: bool


class ConflictResolutionResponse(BaseModel):
    conflict_id: int
    state: str


def _reconciliation_error(exc: ArtefactReconciliationError):
    if "does not exist" in str(exc):
        return ResourceNotFoundError(str(exc))
    return ValidationError(str(exc))


@router.get("/conflicts", response_model=list[ConflictResponse])
def list_artefact_conflicts_route(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[ConflictResponse]:
    """The uncertain matches waiting on a person, each with both sides and why
    the platform is unsure."""
    _require_reviewer(db, ctx)
    return [
        ConflictResponse(
            conflict_id=view.conflict_id,
            reason=view.reason,
            state=view.state,
            raised_at=view.raised_at.isoformat(),
            last_raised_at=view.last_raised_at.isoformat(),
            left=ConflictSideResponse(
                asset_id=view.left.asset_id,
                display_name=view.left.display_name,
                asset_type=view.left.asset_type,
                layer=view.left.layer,
                lifecycle_state=view.left.lifecycle_state,
                identifiers=list(view.left.identifiers),
                last_observed_at=view.left.last_observed_at.isoformat() if view.left.last_observed_at else None,
            ),
            right=ConflictSideResponse(
                asset_id=view.right.asset_id,
                display_name=view.right.display_name,
                asset_type=view.right.asset_type,
                layer=view.right.layer,
                lifecycle_state=view.right.lifecycle_state,
                identifiers=list(view.right.identifiers),
                last_observed_at=view.right.last_observed_at.isoformat() if view.right.last_observed_at else None,
            ),
            shared_identifiers=list(view.shared_identifiers),
        )
        for view in list_open_conflicts(db, organization_id=ctx.organization_id)
    ]


@router.post("/merge", response_model=MergeRecordResponse)
def merge_artefacts_route(
    payload: MergeArtefactsRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> MergeRecordResponse:
    """"These are one artefact." Nothing is destroyed and the merge is
    reversible — what moved is recorded so it can be put back."""
    actor_user_id = _require_reviewer(db, ctx)
    try:
        record = merge_artefacts(
            db,
            organization_id=ctx.organization_id,
            survivor_asset_id=payload.survivor_asset_id,
            merged_asset_id=payload.merged_asset_id,
            actor_user_id=actor_user_id,
            conflict_id=payload.conflict_id,
            reason=payload.reason,
        )
    except ArtefactReconciliationError as exc:
        raise _reconciliation_error(exc) from exc
    db.commit()
    return MergeRecordResponse(
        merge_record_id=record.id,
        survivor_asset_id=record.survivor_asset_id,
        merged_asset_id=record.merged_asset_id,
        reversed=record.reversed_at is not None,
    )


@router.post("/merges/{merge_record_id}/reverse", response_model=MergeRecordResponse)
def reverse_merge_route(
    merge_record_id: int,
    payload: KeepSeparateRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> MergeRecordResponse:
    """Undo a merge. The record of it stays, stamped as reversed."""
    actor_user_id = _require_reviewer(db, ctx)
    try:
        record = reverse_merge(
            db,
            organization_id=ctx.organization_id,
            merge_record_id=merge_record_id,
            actor_user_id=actor_user_id,
            reason=payload.reason,
        )
    except ArtefactReconciliationError as exc:
        raise _reconciliation_error(exc) from exc
    db.commit()
    return MergeRecordResponse(
        merge_record_id=record.id,
        survivor_asset_id=record.survivor_asset_id,
        merged_asset_id=record.merged_asset_id,
        reversed=record.reversed_at is not None,
    )


@router.post("/conflicts/{conflict_id}/keep-separate", response_model=ConflictResolutionResponse)
def keep_artefacts_separate_route(
    conflict_id: int,
    payload: KeepSeparateRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ConflictResolutionResponse:
    """"These are genuinely different things." Durable: a later scan does not
    re-raise a match a person has already dismissed."""
    actor_user_id = _require_reviewer(db, ctx)
    try:
        conflict = keep_artefacts_separate(
            db,
            organization_id=ctx.organization_id,
            conflict_id=conflict_id,
            actor_user_id=actor_user_id,
            reason=payload.reason,
        )
    except ArtefactReconciliationError as exc:
        raise _reconciliation_error(exc) from exc
    db.commit()
    return ConflictResolutionResponse(conflict_id=conflict.id, state=conflict.state)


@router.post("/{asset_id}/confirm", response_model=ArtefactDecisionResponse)
def confirm_artefact_route(
    asset_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ArtefactDecisionResponse:
    """"Yes, this is ours." """
    actor_user_id = _require_reviewer(db, ctx)
    try:
        asset = confirm_artefact(
            db,
            organization_id=ctx.organization_id,
            asset_id=asset_id,
            actor_user_id=actor_user_id,
        )
    except ArtefactReviewError as exc:
        # "does not exist" covers both a missing row and another tenant's row —
        # the service deliberately does not distinguish them, and neither does
        # this response.
        if "does not exist" in str(exc):
            raise ResourceNotFoundError(str(exc)) from exc
        raise ValidationError(str(exc)) from exc
    db.commit()
    return _response(asset)


@router.post("/{asset_id}/reject", response_model=ArtefactDecisionResponse)
def reject_artefact_route(
    asset_id: str,
    payload: RejectArtefactRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ArtefactDecisionResponse:
    """"This is not ours." Removes it from the inventory without destroying the
    evidence that produced it."""
    actor_user_id = _require_reviewer(db, ctx)
    try:
        asset = reject_artefact(
            db,
            organization_id=ctx.organization_id,
            asset_id=asset_id,
            actor_user_id=actor_user_id,
            reason=payload.reason,
        )
    except ArtefactReviewError as exc:
        if "does not exist" in str(exc):
            raise ResourceNotFoundError(str(exc)) from exc
        raise ValidationError(str(exc)) from exc
    db.commit()
    return _response(asset)


@router.post("/{asset_id}/not-used", response_model=ArtefactDecisionResponse)
def mark_artefact_not_used_route(
    asset_id: str,
    payload: RejectArtefactRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ArtefactDecisionResponse:
    """"Ours, but we will never depend on it." Keeps the artefact on record and
    out of the dependency picture, which "not ours" could not say honestly."""
    actor_user_id = _require_reviewer(db, ctx)
    try:
        asset = mark_artefact_not_used(
            db,
            organization_id=ctx.organization_id,
            asset_id=asset_id,
            actor_user_id=actor_user_id,
            reason=payload.reason,
        )
    except ArtefactReviewError as exc:
        if "does not exist" in str(exc):
            raise ResourceNotFoundError(str(exc)) from exc
        raise ValidationError(str(exc)) from exc
    db.commit()
    return _response(asset)


@router.post("/{asset_id}/classification", response_model=ArtefactDecisionResponse)
def correct_artefact_classification_route(
    asset_id: str,
    payload: CorrectClassificationRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ArtefactDecisionResponse:
    """"That is not what this is." Corrects the type and/or layer."""
    actor_user_id = _require_reviewer(db, ctx)
    try:
        asset = correct_artefact_classification(
            db,
            organization_id=ctx.organization_id,
            asset_id=asset_id,
            actor_user_id=actor_user_id,
            asset_type=payload.asset_type,
            layer=payload.layer,
        )
    except ArtefactReviewError as exc:
        if "does not exist" in str(exc):
            raise ResourceNotFoundError(str(exc)) from exc
        raise ValidationError(str(exc)) from exc
    db.commit()
    return _response(asset)


@router.post("/{asset_id}/dependency-category", response_model=ArtefactDecisionResponse)
def set_dependency_category_route(asset_id: str, payload: SetDependencyCategoryRequest,
    ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)) -> ArtefactDecisionResponse:
    actor_user_id = _require_reviewer(db, ctx)
    try:
        asset = set_dependency_category(db, organization_id=ctx.organization_id, asset_id=asset_id,
            actor_user_id=actor_user_id, category=payload.dependency_category)
    except ArtefactReviewError as exc:
        if "does not exist" in str(exc):
            raise ResourceNotFoundError(str(exc)) from exc
        raise ValidationError(str(exc)) from exc
    db.commit()
    return _response(asset)
