"""CA-07.1 (#235) slice 2 — the five choices, recorded, starting nothing.

Slice 1 built the *no-access baseline*: an artefact is named from evidence already
within reach, so that "unknown" means the genuine remainder rather than everything
nobody looked at. This slice is the story itself — a person is shown what is not
known and what each choice would answer, and every answer is recorded.

The criterion that drove the design is the fourth: *the choice is recorded as a
decision with attribution — including network-only and review later, which are
answers, not absence of one.* Before this, three of the five could not be stored
anywhere, so "we decided network-only" and "nobody has looked" were the same
absence of data.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.artefact_identity_evidence_enums import ArtefactIdentityUndetermined
from src.core.constants.contextual_access_enums import (
    ArtefactAccessChoice,
    ContextualAccessDecision,
    ContextualAccessPolicyStatus,
)
from src.core.database import Base
from src.core.model_defs.artefact_access_decision import ArtefactAccessDecision
from src.core.model_defs.artefact_access_lifecycle import ArtefactAccessLifecycle
from src.core.model_defs.assets_runtime import (
    Asset,
    AssetLifecycleState,
    AssetStatus,
    ConnectivityStatus,
    Criticality,
    Environment,
    ScanStartMode,
    SetupConfidence,
)
from src.core.model_defs.common import utcnow
from src.core.model_defs.contextual_access_policy import ContextualAccessPolicy
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.model_defs.tenant_org import Organization
from src.core.services.artefact_access_decision_service import (
    ACCESS_CHOICE_ANSWERS,
    ArtefactAccessDecisionError,
    describe_access_question,
    get_current_decision,
    list_decisions,
    record_decision,
)


@pytest.fixture(scope="function")
def db():
    engine = create_engine("sqlite:///:memory:")
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(bind=engine)
    session = Session(bind=engine)
    session.add_all(
        [
            Organization(id=1, name="Org One", slug="org-one"),
            Organization(id=2, name="Org Two", slug="org-two"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _asset(
    db: Session,
    *,
    organization_id: int = 1,
    display_name: str = "10.0.0.15",
    undetermined: str | None = None,
) -> Asset:
    identity = {"name": None, "basis": None, "undeterminedReason": undetermined}
    asset = Asset(
        organization_id=organization_id,
        type="Observed host",
        provider="collector",
        display_name=display_name,
        layer="Infrastructure",
        environment=Environment.PROD,
        criticality=Criticality.MEDIUM,
        status=AssetStatus.PARTIALLY_OBSERVED,
        connectivity_status=ConnectivityStatus.PENDING_VERIFICATION,
        setup_confidence=SetupConfidence.LOW,
        scan_start_mode=ScanStartMode.AUDIT_ONLY,
        findings_count=0,
        risk_score=0.0,
        confidence=0.4,
        lifecycle_state=AssetLifecycleState.ACTIVE,
        intent={"identity": identity} if undetermined is not None else {},
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def _standing_default(db: Session, choice: str, *, organization_id: int = 1) -> None:
    db.add(
        ContextualAccessPolicy(
            organization_id=organization_id,
            decision=ContextualAccessDecision.DEEPER_ACCESS_DEFAULT.value,
            choice=choice,
            status=ContextualAccessPolicyStatus.ACTIVE.value,
            version=1,
            consequence_statement="Recorded in a test.",
            consequence_acknowledged=True,
            prepared_by="Preparer",
            approved_by="Sponsor",
            approved_at=utcnow(),
            effective_from=utcnow(),
        )
    )
    db.commit()


# --- All five are recordable -------------------------------------------------


@pytest.mark.parametrize("choice", [member.value for member in ArtefactAccessChoice])
def test_every_one_of_the_five_choices_can_be_recorded(db: Session, choice: str):
    """The gap this slice closes. `request_access` refuses three of them by name,
    correctly — but that left the platform unable to say anybody had answered."""
    asset = _asset(db)

    decision = record_decision(db, organization_id=1, asset=asset, choice=choice, decided_by_user_id=4)
    db.commit()

    assert decision.choice == choice
    assert decision.decided_by_user_id == 4
    assert get_current_decision(db, organization_id=1, asset_id=asset.id).choice == choice


def test_an_answer_that_asks_for_nothing_is_still_an_answer(db: Session):
    """"We decided network-only in August" and "nobody has looked at this" must
    never be the same absence of data — the standing-policy amendment's own
    warning, applied to the record rather than to the surface."""
    asset = _asset(db)

    record_decision(db, organization_id=1, asset=asset, choice=ArtefactAccessChoice.REVIEW_LATER.value)
    db.commit()

    current = get_current_decision(db, organization_id=1, asset_id=asset.id)
    assert current is not None
    assert current.choice == ArtefactAccessChoice.REVIEW_LATER.value


def test_an_unknown_choice_is_refused_by_name(db: Session):
    asset = _asset(db)
    with pytest.raises(ArtefactAccessDecisionError, match="not one of the five"):
        record_decision(db, organization_id=1, asset=asset, choice="ssh_as_root")


# --- Choosing starts nothing -------------------------------------------------


@pytest.mark.parametrize(
    "choice",
    [
        ArtefactAccessChoice.NETWORK_ONLY.value,
        ArtefactAccessChoice.EXCLUDE.value,
        ArtefactAccessChoice.REVIEW_LATER.value,
    ],
)
def test_a_choice_that_seeks_no_access_starts_no_lifecycle(db: Session, choice: str):
    """Starting a journey for one would say access was sought when the answer
    was that it was not."""
    asset = _asset(db)

    record_decision(db, organization_id=1, asset=asset, choice=choice)
    db.commit()

    assert db.query(ArtefactAccessLifecycle).count() == 0


@pytest.mark.parametrize(
    "choice",
    [ArtefactAccessChoice.CONNECT_HOST.value, ArtefactAccessChoice.GRANT_ACCESS.value],
)
def test_an_access_seeking_choice_starts_the_lifecycle_at_its_first_state(db: Session, choice: str):
    """And no further. `access_requested` is a recorded intent, not a scan —
    nothing is scheduled, queued or dispatched by answering."""
    asset = _asset(db)

    record_decision(db, organization_id=1, asset=asset, choice=choice, decided_by_user_id=9)
    db.commit()

    lifecycle = db.query(ArtefactAccessLifecycle).one()
    assert lifecycle.state == "access_requested"
    assert lifecycle.requested_choice == choice
    assert lifecycle.connector_id is None
    assert lifecycle.tested_at is None
    assert lifecycle.verification_ready_at is None
    assert lifecycle.verification_approved_at is None
    assert lifecycle.running_at is None


def test_excluding_records_the_decision_but_does_not_withdraw_the_artefact(db: Session):
    """The checklist says exclusion routes through CA-06.5 rather than a second
    mechanism — and stamping WITHDRAWN from here would *be* that second
    mechanism. CA-06.5 withdraws because an **approved boundary** excludes, and
    that boundary needs the Technical Setup Owner or manager tier. One person
    clicking "exclude" on one row is not that approval.
    """
    asset = _asset(db)

    record_decision(db, organization_id=1, asset=asset, choice=ArtefactAccessChoice.EXCLUDE.value)
    db.commit()
    db.refresh(asset)

    assert asset.lifecycle_state == AssetLifecycleState.ACTIVE
    assert asset.withdrawn_by_exclusion is None
    assert get_current_decision(db, organization_id=1, asset_id=asset.id).choice == "exclude"


# --- The standing default, and deviation -------------------------------------


def test_accepting_the_standing_default_needs_no_reason(db: Session):
    """The platform's existing idiom: the recommended route is a single confirm."""
    _standing_default(db, ArtefactAccessChoice.NETWORK_ONLY.value)
    asset = _asset(db)

    decision = record_decision(
        db, organization_id=1, asset=asset, choice=ArtefactAccessChoice.NETWORK_ONLY.value
    )
    db.commit()

    assert decision.deviation_reason is None
    assert decision.standing_default == ArtefactAccessChoice.NETWORK_ONLY.value


def test_deviating_from_the_standing_default_is_refused_without_a_reason(db: Session):
    _standing_default(db, ArtefactAccessChoice.NETWORK_ONLY.value)
    asset = _asset(db)

    with pytest.raises(ArtefactAccessDecisionError, match="recorded reason"):
        record_decision(
            db, organization_id=1, asset=asset, choice=ArtefactAccessChoice.CONNECT_HOST.value
        )


def test_deviating_with_a_reason_is_recorded_with_it(db: Session):
    _standing_default(db, ArtefactAccessChoice.NETWORK_ONLY.value)
    asset = _asset(db)

    decision = record_decision(
        db,
        organization_id=1,
        asset=asset,
        choice=ArtefactAccessChoice.CONNECT_HOST.value,
        deviation_reason="This host carries the payments database and we need to know what it runs.",
        decided_by_user_id=7,
    )
    db.commit()

    assert decision.deviation_reason.startswith("This host carries")
    assert decision.standing_default == ArtefactAccessChoice.NETWORK_ONLY.value


def test_the_standing_default_is_snapshotted_not_looked_up_later(db: Session):
    """The policy is versioned and can be superseded. "Was this a deviation?"
    must be answered as it was on the day, not as it would be today."""
    _standing_default(db, ArtefactAccessChoice.NETWORK_ONLY.value)
    asset = _asset(db)
    record_decision(
        db,
        organization_id=1,
        asset=asset,
        choice=ArtefactAccessChoice.CONNECT_HOST.value,
        deviation_reason="Needed at the time.",
    )
    db.commit()

    # The organisation later changes its mind about the default.
    db.query(ContextualAccessPolicy).update(
        {ContextualAccessPolicy.status: ContextualAccessPolicyStatus.SUPERSEDED.value}
    )
    db.commit()

    assert get_current_decision(db, organization_id=1, asset_id=asset.id).standing_default == (
        ArtefactAccessChoice.NETWORK_ONLY.value
    )


def test_with_no_standing_policy_every_choice_is_free_and_none_owes_a_reason(db: Session):
    """`None` means more clicks, not fewer options."""
    asset = _asset(db)
    decision = record_decision(
        db, organization_id=1, asset=asset, choice=ArtefactAccessChoice.CONNECT_HOST.value
    )
    db.commit()
    assert decision.standing_default is None
    assert decision.deviation_reason is None


# --- What is unknown, and what each choice would answer ----------------------


def test_the_question_offers_all_five_choices_even_with_a_standing_default(db: Session):
    """CLAUDE.md:217 — decision options stay available and the user is never
    locked out. The default pre-answers; it does not withdraw."""
    _standing_default(db, ArtefactAccessChoice.NETWORK_ONLY.value)
    asset = _asset(db)

    question = describe_access_question(db, organization_id=1, asset=asset)

    assert set(question.choices) == {member.value for member in ArtefactAccessChoice}
    assert question.standing_default == ArtefactAccessChoice.NETWORK_ONLY.value


def test_every_choice_is_explained_by_what_it_would_answer(db: Session):
    """The second criterion. Not what it would *run* — a reader deciding whether
    to grant credentials needs to know what they would learn."""
    asset = _asset(db)
    question = describe_access_question(db, organization_id=1, asset=asset)

    for choice in ArtefactAccessChoice:
        answer = question.choice_answers[choice.value]
        assert answer, choice.value
        # Vocabulary check: the explanations speak about knowledge, never tools.
        assert not any(word in answer.lower() for word in ("nmap", "ssh", "scan profile", "port 22"))

    assert question.choice_answers == ACCESS_CHOICE_ANSWERS


def test_what_is_unknown_is_stated_even_when_a_standing_default_answers_the_question(db: Session):
    """The amendment's third criterion, and the one it exists to protect: a
    standing default must never turn a real gap into an invisible one."""
    _standing_default(db, ArtefactAccessChoice.NETWORK_ONLY.value)
    asset = _asset(
        db, undetermined=ArtefactIdentityUndetermined.PROBED_NOTHING_IDENTIFYING.value
    )

    question = describe_access_question(db, organization_id=1, asset=asset)

    assert question.unknown_statement is not None
    assert "nothing it returned identified what it is" in question.unknown_statement
    assert question.standing_default == ArtefactAccessChoice.NETWORK_ONLY.value


@pytest.mark.parametrize(
    ("reason", "would_help"),
    [
        (ArtefactIdentityUndetermined.PROBED_NOTHING_IDENTIFYING.value, True),
        (ArtefactIdentityUndetermined.NOT_PROBED.value, False),
        (ArtefactIdentityUndetermined.NOTHING_LISTENING.value, False),
        (None, False),
    ],
)
def test_deeper_access_is_only_argued_for_where_it_would_actually_help(
    db: Session, reason: str | None, would_help: bool
):
    """Slice 1's whole reason for three undetermined reasons rather than one
    `unknown`. Asking for credentials to learn something an unauthenticated
    request would have answered is a least-privilege failure, and asking for
    them to reach a host with nothing listening is asking for nothing."""
    asset = _asset(db, undetermined=reason)

    question = describe_access_question(db, organization_id=1, asset=asset)

    assert question.deeper_access_would_help is would_help


def test_a_named_artefact_states_no_gap(db: Session):
    asset = _asset(db)
    question = describe_access_question(db, organization_id=1, asset=asset)
    assert question.identity_undetermined_reason is None
    assert question.unknown_statement is None


def test_the_question_reports_the_answer_already_standing(db: Session):
    asset = _asset(db)
    record_decision(db, organization_id=1, asset=asset, choice=ArtefactAccessChoice.REVIEW_LATER.value)
    db.commit()

    question = describe_access_question(db, organization_id=1, asset=asset)

    assert question.current_choice == ArtefactAccessChoice.REVIEW_LATER.value


# --- History and attribution -------------------------------------------------


def test_a_change_of_mind_is_history_not_an_overwrite(db: Session):
    """"We said network-only in August and changed our minds in October" is the
    fact an auditor is looking for, and a mutable column cannot hold it."""
    asset = _asset(db)
    record_decision(
        db, organization_id=1, asset=asset, choice=ArtefactAccessChoice.REVIEW_LATER.value,
        decided_by_user_id=1,
    )
    db.commit()
    record_decision(
        db, organization_id=1, asset=asset, choice=ArtefactAccessChoice.CONNECT_HOST.value,
        decided_by_user_id=2,
    )
    db.commit()

    history = list_decisions(db, organization_id=1, asset_id=asset.id)

    assert [row.choice for row in history] == ["connect_host", "review_later"]
    assert [row.decided_by_user_id for row in history] == [2, 1]
    assert get_current_decision(db, organization_id=1, asset_id=asset.id).choice == "connect_host"


def test_every_answer_writes_one_audit_event_whatever_it_was(db: Session):
    """A trail recording only the choices that sought access would show a
    reviewer a history of requests and none of the refusals."""
    asset = _asset(db)
    record_decision(db, organization_id=1, asset=asset, choice=ArtefactAccessChoice.EXCLUDE.value)
    db.commit()

    events = db.query(AuditEvent).filter(
        AuditEvent.event_type == "artefact_access_decision_recorded"
    ).all()
    assert len(events) == 1
    assert events[0].metadata_json["choice"] == "exclude"
    assert events[0].metadata_json["assetId"] == asset.id


# --- Isolation ---------------------------------------------------------------


def test_decisions_do_not_leak_between_organisations(db: Session):
    theirs = _asset(db, organization_id=2, display_name="their-host")
    record_decision(db, organization_id=2, asset=theirs, choice=ArtefactAccessChoice.EXCLUDE.value)
    db.commit()

    assert get_current_decision(db, organization_id=1, asset_id=theirs.id) is None
    assert list_decisions(db, organization_id=1, asset_id=theirs.id) == ()
    assert db.query(ArtefactAccessDecision).count() == 1
