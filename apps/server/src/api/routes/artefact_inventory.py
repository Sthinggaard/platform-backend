"""CA-06.6 — the organisation's artefact inventory, independent of any run.

Artefacts were only reachable *inside a discovery run*, so "what do we have?"
could only be answered as "what did this scan find?". This router answers the
standing question: the inventory as it is now, whichever run last touched it.

**Reading is not deciding.** Any active member of the organisation may see what
the organisation has — it is their own estate, and an inventory nobody can look
at cannot be checked. Changing it stays where it already is: the artefact-review
routes, behind ``MANAGER_ROLES``. This file adds no way to change anything.

Its own prefix rather than more paths under ``/api/v1/artefacts``: that router
already owns ``/{asset_id}/...`` decision routes, and a new list endpoint sharing
that namespace would sit one careless path segment away from being shadowed by
them.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.schemas.timestamps import UtcTimestamp
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ValidationError
from src.core.model_defs.assets_runtime import AssetLifecycleState
from src.core.model_defs.tenant_identity import User
from src.core.repository import TenantRepository
from src.core.services.artefact_classification_service import ArtefactCandidacy
from src.core.services.artefact_inventory_service import InventoryFilters, list_inventory
from src.core.services.auth_service import is_access_expired

router = APIRouter(prefix="/api/v1/artefact-inventory", tags=["Artefact inventory"])

_REVIEW_STATUSES = frozenset({"reviewed", "unreviewed"})

#: Derived from the enum, so a new candidacy is accepted by the filter the
#: moment the classifier can produce it.
_CANDIDACIES = frozenset(value.value for value in ArtefactCandidacy)


class InventoryEntryResponse(BaseModel):
    asset_id: int
    display_name: str
    asset_type: str
    layer: str
    dependency_category: str | None
    lifecycle_state: str
    reviewed_at: UtcTimestamp | None
    reviewed_by_user_id: int | None
    first_observed_at: UtcTimestamp | None
    last_observed_at: UtcTimestamp | None
    identifier_count: int
    source_names: list[str]
    observed_port_count: int
    #: What the last vulnerability scan found on this artefact, and when.
    #:
    #: ⚠️ ``0`` means **no scanner finding is on record**, which is not the same
    #: as "scanned and found nothing" — the platform keeps no per-host coverage
    #: record yet, so those two and "never scanned" are indistinguishable here.
    #: The row must therefore say what *was* found and stay silent about what was
    #: not; a badge claiming a clean scan on this field would be an assertion
    #: posing as an observation.
    scan_finding_count: int
    scan_last_finding_at: UtcTimestamp | None
    #: Whether a business service could depend on this at all. The reading side
    #: needs it to tell an address that merely answered from a thing that runs
    #: something (CA-09A.1).
    candidacy: str
    open_conflict_count: int
    withdrawn_by_exclusion: str | None
    merged_into_asset_id: int | None
    # CA-07.6 (#240) — the access journey, in its own fields. Never merged into
    # `lifecycle_state`: an artefact can be confirmed in the inventory with no
    # access configured, or unconfirmed with access already approved, and one
    # field holding both would make two questions look like one answer.
    #
    # There is deliberately no credential-shaped field here, and there is no
    # room for one: `AccessConnector` holds no secret material, so the surface
    # cannot leak what the model cannot store.
    access_state: str | None
    access_connector_id: str | None
    access_awaiting_person: bool

    # CA-07.1 / #249 — what the scan concluded this artefact is. Determined and
    # stored since CA-07.1, and never sent to anybody until now: the row showed
    # an address and a generic class however much the scan had established.
    #
    # `identity_name` is what the scan concluded, which is *not* always
    # `display_name`: a hostname the organisation gave the host outranks it, and
    # a reader is entitled to tell an inferred name from a chosen one.
    identity_name: str | None
    identity_basis: str | None
    identity_undetermined_reason: str | None
    identity_explanation: str | None
    # Where it sits, as against what it is. The address was doing both jobs and
    # is arbitrary as a name — an executive reads 192.168.1.36 and learns
    # nothing. Its own field so the surface can title the row with a description.
    network_address: str | None


class InventoryResponse(BaseModel):
    entries: list[InventoryEntryResponse]
    total: int
    asset_types: list[str]
    layers: list[str]


def _require_member(db: Session, ctx: TenantContext) -> User:
    """An active member of this organisation, and nothing more.

    Deliberately a lower bar than the review routes: seeing the inventory is
    reading a list of your own organisation's things, while deciding what
    belongs in it is an authority. Expired access is still access denied — a
    lapsed account keeps its role, so checking the role alone would let it read
    on indefinitely.
    """
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active or is_access_expired(user):
        raise AuthorizationError("You do not have access to this organisation's inventory.")
    return user


@router.get("", response_model=InventoryResponse)
def list_artefact_inventory_route(
    lifecycle_state: list[str] = Query(default=[]),
    asset_type: str | None = Query(default=None),
    layer: str | None = Query(default=None),
    review_status: str | None = Query(default=None),
    q: str | None = Query(default=None),
    candidacy: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> InventoryResponse:
    """The organisation's inventory, filtered as asked."""
    _require_member(db, ctx)

    states: list[AssetLifecycleState] = []
    for value in lifecycle_state:
        try:
            states.append(AssetLifecycleState(value.strip().upper()))
        except ValueError as exc:
            # Named back to the caller rather than silently dropped: a filter
            # that quietly does nothing shows a full inventory to someone who
            # asked for a slice of it, which reads as data they do not have.
            raise ValidationError(f"'{value}' is not a lifecycle state.") from exc

    if review_status is not None and review_status not in _REVIEW_STATUSES:
        raise ValidationError("Review status must be 'reviewed' or 'unreviewed'.")

    if candidacy is not None and candidacy not in _CANDIDACIES:
        # Named back for the same reason as a bad lifecycle state: a filter that
        # quietly does nothing returns the whole estate to someone who asked for
        # the part of it that can carry a dependency.
        raise ValidationError(f"'{candidacy}' is not a candidacy.")

    page = list_inventory(
        db,
        organization_id=ctx.organization_id,
        filters=InventoryFilters(
            lifecycle_states=tuple(states),
            asset_type=asset_type,
            layer=layer,
            review_status=review_status,
            query=q,
            candidacy=candidacy,
        ),
        limit=limit,
        offset=offset,
    )

    return InventoryResponse(
        entries=[
            InventoryEntryResponse(
                asset_id=entry.asset_id,
                display_name=entry.display_name,
                asset_type=entry.asset_type,
                layer=entry.layer,
                dependency_category=entry.dependency_category,
                lifecycle_state=entry.lifecycle_state,
                reviewed_at=entry.reviewed_at.isoformat() if entry.reviewed_at else None,
                reviewed_by_user_id=entry.reviewed_by_user_id,
                first_observed_at=entry.first_observed_at.isoformat() if entry.first_observed_at else None,
                last_observed_at=entry.last_observed_at.isoformat() if entry.last_observed_at else None,
                identifier_count=entry.identifier_count,
                source_names=list(entry.source_names),
                observed_port_count=entry.observed_port_count,
                scan_finding_count=entry.scan_finding_count,
                scan_last_finding_at=(
                    entry.scan_last_finding_at.isoformat() if entry.scan_last_finding_at else None
                ),
                candidacy=entry.candidacy,
                open_conflict_count=entry.open_conflict_count,
                withdrawn_by_exclusion=entry.withdrawn_by_exclusion,
                merged_into_asset_id=entry.merged_into_asset_id,
                access_state=entry.access_state,
                access_connector_id=entry.access_connector_id,
                access_awaiting_person=entry.access_awaiting_person,
                identity_name=entry.identity_name,
                identity_basis=entry.identity_basis,
                identity_undetermined_reason=entry.identity_undetermined_reason,
                identity_explanation=entry.identity_explanation,
                network_address=entry.network_address,
            )
            for entry in page.entries
        ],
        total=page.total,
        asset_types=list(page.asset_types),
        layers=list(page.layers),
    )
