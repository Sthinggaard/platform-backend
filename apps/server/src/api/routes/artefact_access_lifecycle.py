"""CA-07.5 — the access lifecycle surface, and the two endpoints that stay apart.

`POST /{asset_id}/verification-ready` and `POST /{asset_id}/approve-verification`
are separate calls with different authorities, and that separation *is* the
contract's rule. One endpoint that marked an artefact ready and approved it would
make being ready and being allowed the same act, which is precisely what *"access
does not start verification"* forbids. CA-07.3 drew the same line between
approving a profile and approving Docker socket access, for the same reason.

Approving verification belongs to the organisation's named leadership sponsor —
the authority CA-07.0, the risk appetite and the permission profile already use.
Everything before it is operational and belongs to an org admin: preparing access
is not permitting it.

There is no endpoint that starts a verification run. CA-08 owns that, and
`mark_running` refuses any artefact that is not already `APPROVED`.
"""

from __future__ import annotations


import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.routes.access_connectors import require_connector, require_org_admin
from src.core.constants.artefact_access_lifecycle_enums import (
    ACCESS_LIFECYCLE_ERROR_APPROVER_REQUIRED,
    ACCESS_LIFECYCLE_ERROR_ARTEFACT_NOT_FOUND,
    ACCESS_LIFECYCLE_ERROR_NOT_FOUND,
    ARTEFACT_ACCESS_TRANSITIONS,
    ArtefactAccessState,
)
from src.core.constants.connector_access_test_enums import TEST_ERROR_NOT_FOUND
from src.core.constants.contextual_access_enums import ArtefactAccessChoice
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.artefact_access_lifecycle import ArtefactAccessLifecycle
from src.core.model_defs.assets_runtime import Asset
from src.core.model_defs.connector_access_test import ConnectorAccessTest
from src.core.repository import TenantRepository
from src.core.services.artefact_access_decision_service import (
    ArtefactAccessDecisionError,
    describe_access_question,
    get_current_decision,
    list_decisions,
    record_decision,
)
from src.core.services.artefact_access_lifecycle_service import (
    ArtefactAccessLifecycleError,
    approve_verification,
    get_lifecycle,
    inherit_standing_approval,
    mark_configured,
    mark_tested,
    mark_verification_ready,
)
from src.core.services.leadership_authorization_service import (
    get_active_leadership_authorization,
)
from src.api.schemas.timestamps import UtcTimestamp

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/artefact-access", tags=["Artefact access"])


class AccessRequestBody(BaseModel):
    """All five choices are accepted, and all five are recorded.

    Two of them additionally start CA-07.5's access lifecycle. The other three
    used to be refused by name; since CA-07.1 slice 2 they are recorded as the
    answers they are — "network-only" is a decision somebody made, not the
    absence of one.
    """

    choice: ArtefactAccessChoice
    deviation_reason: str | None = None


class ConfigureAccessBody(BaseModel):
    connector_id: str


class MarkTestedBody(BaseModel):
    access_test_id: str


class ArtefactAccessResponse(BaseModel):
    id: str
    asset_id: int
    state: str
    requested_choice: str
    deviation_reason: str | None = None
    requested_at: UtcTimestamp
    requested_by_user_id: int | None = None
    connector_id: str | None = None
    configured_at: UtcTimestamp | None = None
    access_test_id: str | None = None
    tested_at: UtcTimestamp | None = None
    # Two fields, never collapsed. A reader must be able to see that an artefact
    # is ready and has not been approved — that gap is the contract's rule made
    # visible rather than merely obeyed.
    verification_ready_at: UtcTimestamp | None = None
    verification_approved_at: UtcTimestamp | None = None
    verification_approved_by_user_id: int | None = None
    verification_approved_source: str | None = None
    verification_approval_policy_id: str | None = None
    running_at: UtcTimestamp | None = None
    completed_at: UtcTimestamp | None = None


class ArtefactAccessStateCatalogueResponse(BaseModel):
    """The seven states and their legal successors, published rather than implied.

    So a surface renders the journey from one source instead of hard-coding an
    order that could drift from the server's.
    """

    states: list[str]
    transitions: dict[str, list[str]]


def _response(lifecycle: ArtefactAccessLifecycle) -> ArtefactAccessResponse:
    return ArtefactAccessResponse(
        id=lifecycle.id,
        asset_id=lifecycle.asset_id,
        state=lifecycle.state,
        requested_choice=lifecycle.requested_choice,
        deviation_reason=lifecycle.deviation_reason,
        requested_at=lifecycle.requested_at,
        requested_by_user_id=lifecycle.requested_by_user_id,
        connector_id=lifecycle.connector_id,
        configured_at=lifecycle.configured_at,
        access_test_id=lifecycle.access_test_id,
        tested_at=lifecycle.tested_at,
        verification_ready_at=lifecycle.verification_ready_at,
        verification_approved_at=lifecycle.verification_approved_at,
        verification_approved_by_user_id=lifecycle.verification_approved_by_user_id,
        verification_approved_source=lifecycle.verification_approved_source,
        verification_approval_policy_id=lifecycle.verification_approval_policy_id,
        running_at=lifecycle.running_at,
        completed_at=lifecycle.completed_at,
    )


class ArtefactAccessChoiceOptionResponse(BaseModel):
    """One of the five, with what it would *answer* — never what it would run."""

    choice: str
    answers: str
    #: True when this choice is the organisation's standing answer. The surface
    #: marks it rather than removing the others: CLAUDE.md:217 requires that
    #: decision options stay available and the user is never locked out.
    is_standing_default: bool
    #: True when picking it owes a recorded reason, so the surface can ask for
    #: one at the moment of choosing rather than refusing afterwards.
    requires_reason: bool


class ArtefactAccessQuestionResponse(BaseModel):
    """What a person is being asked about one artefact, and on what evidence."""

    asset_id: int
    display_name: str
    identity_undetermined_reason: str | None
    #: The gap in the reader's own words. Present whatever the standing policy
    #: answers — a default must never turn a real gap into an invisible one.
    unknown_statement: str | None
    #: True only where deeper access would genuinely resolve the gap. The other
    #: undetermined reasons are not arguments for credentials, and saying so is
    #: the difference between asking for access and asking for it honestly.
    deeper_access_would_help: bool
    standing_default: str | None
    current_choice: str | None
    choices: list[ArtefactAccessChoiceOptionResponse]


class ArtefactAccessDecisionResponse(BaseModel):
    """One recorded answer. Present for all five choices, including the three
    that start no access journey — they are answers, not the absence of one."""

    id: str
    asset_id: int
    choice: str
    standing_default: str | None
    deviation_reason: str | None
    identity_undetermined_reason: str | None
    decided_at: UtcTimestamp
    decided_by_user_id: int | None
    #: The access journey this answer started, or null when the answer sought no
    #: access. Two fields rather than one, so "no journey" is never mistaken for
    #: "no answer".
    access_state: str | None


def _decision_response(
    db: Session, decision, *, organization_id: int
) -> ArtefactAccessDecisionResponse:
    lifecycle = get_lifecycle(db, organization_id=organization_id, asset_id=decision.asset_id)
    return ArtefactAccessDecisionResponse(
        id=decision.id,
        asset_id=decision.asset_id,
        choice=decision.choice,
        standing_default=decision.standing_default,
        deviation_reason=decision.deviation_reason,
        identity_undetermined_reason=decision.identity_undetermined_reason,
        decided_at=decision.decided_at,
        decided_by_user_id=decision.decided_by_user_id,
        access_state=lifecycle.state if lifecycle else None,
    )


def _require_approver(db: Session, ctx: TenantContext) -> None:
    """Approving verification is a leadership act, not an operational one.

    Deeper access reads inside a host. Saying that may now happen is the same
    class of decision as approving the permission profile that bounds it, so it
    is held by the same named sponsor rather than by whoever prepared it.
    """
    authorization = get_active_leadership_authorization(db, ctx.organization_id)
    if authorization is None or ctx.user_id != authorization.sponsor_user_id:
        raise AuthorizationError(ACCESS_LIFECYCLE_ERROR_APPROVER_REQUIRED)


def _require_artefact(db: Session, *, ctx: TenantContext, asset_id: int) -> Asset:
    asset = TenantRepository(db, Asset, ctx.organization_id).get_by_id(asset_id)
    if asset is None:
        raise ResourceNotFoundError(ACCESS_LIFECYCLE_ERROR_ARTEFACT_NOT_FOUND)
    return asset


def _require_lifecycle(
    db: Session, *, ctx: TenantContext, asset_id: int
) -> ArtefactAccessLifecycle:
    _require_artefact(db, ctx=ctx, asset_id=asset_id)
    lifecycle = get_lifecycle(db, organization_id=ctx.organization_id, asset_id=asset_id)
    if lifecycle is None:
        raise ResourceNotFoundError(ACCESS_LIFECYCLE_ERROR_NOT_FOUND)
    return lifecycle


@router.get("/states", response_model=ArtefactAccessStateCatalogueResponse)
def get_states() -> ArtefactAccessStateCatalogueResponse:
    return ArtefactAccessStateCatalogueResponse(
        states=[state.value for state in ArtefactAccessState],
        transitions={
            state: list(targets) for state, targets in ARTEFACT_ACCESS_TRANSITIONS.items()
        },
    )


@router.get("/{asset_id}", response_model=ArtefactAccessResponse)
def get_one(
    asset_id: int,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ArtefactAccessResponse:
    return _response(_require_lifecycle(db, ctx=ctx, asset_id=asset_id))


@router.get("/{asset_id}/question", response_model=ArtefactAccessQuestionResponse)
def question(
    asset_id: int,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ArtefactAccessQuestionResponse:
    """What to put in front of a person for this artefact (CA-07.1).

    A read, so it is open to any member of the organisation. Being shown what is
    unknown is not the authority to act on it — that split is CA-07.6's own
    criterion, and gating the question behind admin would mean the person who has
    to chase a decision cannot see that one is outstanding.
    """
    asset = _require_artefact(db, ctx=ctx, asset_id=asset_id)
    resolved = describe_access_question(db, organization_id=ctx.organization_id, asset=asset)
    return ArtefactAccessQuestionResponse(
        asset_id=resolved.asset_id,
        display_name=resolved.display_name,
        identity_undetermined_reason=resolved.identity_undetermined_reason,
        unknown_statement=resolved.unknown_statement,
        deeper_access_would_help=resolved.deeper_access_would_help,
        standing_default=resolved.standing_default,
        current_choice=resolved.current_choice,
        choices=[
            ArtefactAccessChoiceOptionResponse(
                choice=choice,
                answers=resolved.choice_answers[choice],
                is_standing_default=choice == resolved.standing_default,
                # Accepting the standing answer is a single confirm; deviating
                # owes a reason. The same idiom the intervention flow already
                # uses for the recommended route versus any other.
                requires_reason=(
                    resolved.standing_default is not None and choice != resolved.standing_default
                ),
            )
            for choice in resolved.choices
        ],
    )


@router.get("/{asset_id}/decisions", response_model=list[ArtefactAccessDecisionResponse])
def decisions(
    asset_id: int,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[ArtefactAccessDecisionResponse]:
    """Every answer ever given about this artefact, newest first."""
    _require_artefact(db, ctx=ctx, asset_id=asset_id)
    return [
        _decision_response(db, decision, organization_id=ctx.organization_id)
        for decision in list_decisions(db, organization_id=ctx.organization_id, asset_id=asset_id)
    ]


@router.post("/{asset_id}/request", response_model=ArtefactAccessDecisionResponse)
def request(
    asset_id: int,
    body: AccessRequestBody,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ArtefactAccessDecisionResponse:
    """Record a person's answer to "what should we do about this artefact?".

    CA-07.1 slice 2 — routed through ``record_decision`` rather than straight to
    ``request_access``, so **all five** choices land here. Three of them start no
    access journey and previously could not be recorded at all, which made
    "we decided network-only" and "nobody has looked" the same absence of data.
    """
    require_org_admin(db, ctx)
    asset = _require_artefact(db, ctx=ctx, asset_id=asset_id)
    try:
        decision = record_decision(
            db,
            organization_id=ctx.organization_id,
            asset=asset,
            choice=body.choice.value,
            decided_by_user_id=ctx.user_id,
            deviation_reason=body.deviation_reason,
        )
    except (ArtefactAccessDecisionError, ArtefactAccessLifecycleError) as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(decision)
    return _decision_response(db, decision, organization_id=ctx.organization_id)


@router.post("/{asset_id}/configure", response_model=ArtefactAccessResponse)
def configure(
    asset_id: int,
    body: ConfigureAccessBody,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ArtefactAccessResponse:
    """Name the Connector that reaches this artefact."""
    require_org_admin(db, ctx)
    lifecycle = _require_lifecycle(db, ctx=ctx, asset_id=asset_id)
    connector = require_connector(db, ctx=ctx, connector_id=body.connector_id)
    try:
        mark_configured(db, lifecycle, connector, actor_user_id=ctx.user_id)
    except ArtefactAccessLifecycleError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(lifecycle)
    return _response(lifecycle)


@router.post("/{asset_id}/tested", response_model=ArtefactAccessResponse)
def tested(
    asset_id: int,
    body: MarkTestedBody,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ArtefactAccessResponse:
    """Point at the connection test that proved access works."""
    require_org_admin(db, ctx)
    lifecycle = _require_lifecycle(db, ctx=ctx, asset_id=asset_id)
    test = TenantRepository(db, ConnectorAccessTest, ctx.organization_id).get_by_id(
        body.access_test_id
    )
    if test is None:
        raise ResourceNotFoundError(TEST_ERROR_NOT_FOUND)
    try:
        mark_tested(db, lifecycle, test, actor_user_id=ctx.user_id)
    except ArtefactAccessLifecycleError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(lifecycle)
    return _response(lifecycle)


@router.post("/{asset_id}/verification-ready", response_model=ArtefactAccessResponse)
def verification_ready(
    asset_id: int,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ArtefactAccessResponse:
    """Everything access can establish is established. **Nothing is started.**

    Deliberately an org-admin act rather than a leadership one: saying "there is
    nothing more to prepare" is operational. Saying "you may now go and read
    inside that host" is the next endpoint, and it is somebody else's decision.
    """
    require_org_admin(db, ctx)
    lifecycle = _require_lifecycle(db, ctx=ctx, asset_id=asset_id)
    try:
        mark_verification_ready(db, lifecycle, actor_user_id=ctx.user_id)
    except ArtefactAccessLifecycleError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(lifecycle)
    return _response(lifecycle)


@router.post("/{asset_id}/approve-verification", response_model=ArtefactAccessResponse)
def approve(
    asset_id: int,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ArtefactAccessResponse:
    """A person authorises verification of this artefact. Nothing runs yet.

    Approving is not starting either — CA-08 reports that a run began, and it can
    only do so for an artefact that reached this state first.
    """
    lifecycle = _require_lifecycle(db, ctx=ctx, asset_id=asset_id)
    _require_approver(db, ctx)
    try:
        approve_verification(db, lifecycle, approved_by_user_id=ctx.user_id)
    except ArtefactAccessLifecycleError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(lifecycle)
    return _response(lifecycle)


@router.post("/{asset_id}/inherit-standing-approval", response_model=ArtefactAccessResponse)
def inherit(
    asset_id: int,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ArtefactAccessResponse:
    """Take the approval from the organisation's Mode A decision, if it has one.

    Its own endpoint rather than a flag on `/approve-verification`, so the two
    kinds of human "yes" cannot be confused for one another — and so an
    organisation without a live Mode A decision is told that plainly instead of
    quietly getting an approval nobody gave.
    """
    require_org_admin(db, ctx)
    lifecycle = _require_lifecycle(db, ctx=ctx, asset_id=asset_id)
    try:
        inherit_standing_approval(db, lifecycle)
    except ArtefactAccessLifecycleError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(lifecycle)
    return _response(lifecycle)


__all__ = ["router"]
