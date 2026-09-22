"""#242 — a recurrence that is visible, pausable, honest about misses, and never
outlives the approval it runs under.

One test per acceptance criterion, plus the boundary the non-goals name:
recurrence creates work, it does not execute it.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.contextual_access_enums import (
    AccessOperatingMode,
    ContextualAccessDecision,
    ContextualAccessPolicyStatus,
)
from src.core.constants.recurrence_enums import (
    RecurrenceCadenceType,
    RECURRENCE_AUDIT_OCCURRENCE_DUE,
    RECURRENCE_AUDIT_OCCURRENCE_MISSED,
    RECURRENCE_AUDIT_SCHEDULE_LAPSED,
    RecurrenceOccurrenceStatus,
    RecurrenceScheduleStatus,
)
from src.core.database import Base
from src.core.model_defs.common import naive_utc, utcnow
from src.core.constants.evidence_source_enums import EvidenceSourceType
from src.core.model_defs.contextual_access_policy import ContextualAccessPolicy
from src.core.model_defs.evidence_scanner import ScannerInstance
from src.core.model_defs.evidence_source import EvidenceSource
from src.core.model_defs.recurrence_schedule import RecurrenceOccurrence, RecurrenceSchedule
from src.core.models import AuditEvent, Organization, User
from src.core.services.recurrence_occurrence_service import (
    claim_due_occurrences,
    count_occurrences,
    list_occurrences,
    materialize_due_occurrences,
    record_occurrence_claimed,
    record_occurrence_failed,
)
from src.core.services.recurrence_schedule_service import (
    RecurrenceScheduleValidationError,
    cancel_schedule,
    create_schedule,
    pause_schedule,
    resume_schedule,
    supersede_schedule,
)

ORG_ID = 1
OTHER_ORG_ID = 2
ADMIN_USER_ID = 1
CADENCE = 30


@pytest.fixture()
def db() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            User.__table__,
            ContextualAccessPolicy.__table__,
            # #260 — a schedule now names the Collector it runs, so the FK
            # target has to exist here.
            EvidenceSource.__table__,
            ScannerInstance.__table__,
            RecurrenceSchedule.__table__,
            RecurrenceOccurrence.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=ORG_ID, name="Org", slug="org"),
            Organization(id=OTHER_ORG_ID, name="Other", slug="other"),
            User(id=ADMIN_USER_ID, organization_id=ORG_ID, email="admin@example.com", role="org_admin"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _policy(
    db: Session,
    *,
    organization_id: int = ORG_ID,
    status: str = ContextualAccessPolicyStatus.ACTIVE.value,
    effective_to=None,
) -> ContextualAccessPolicy:
    policy = ContextualAccessPolicy(
        organization_id=organization_id,
        decision=ContextualAccessDecision.ACCESS_OPERATING_MODE.value,
        choice=AccessOperatingMode.SCHEDULED_AUTONOMOUS.value,
        status=status,
        version=1,
        consequence_statement="Runs with nobody watching.",
        consequence_acknowledged=True,
        approved_by=str(ADMIN_USER_ID),
        approved_at=utcnow(),
        effective_from=utcnow(),
        effective_to=effective_to,
    )
    db.add(policy)
    db.commit()
    return policy


def _collector(db: Session, *, organization_id: int = ORG_ID) -> ScannerInstance:
    """#260 — a schedule is made for a Collector, so every schedule needs one."""
    source = EvidenceSource(
        organization_id=organization_id,
        name="Primary collector source",
        type=EvidenceSourceType.SCANNER.value,
        mode="pull",
    )
    db.add(source)
    db.flush()
    instance = ScannerInstance(
        organization_id=organization_id,
        evidence_source_id=source.id,
        name="Primary collector",
        installation_method="docker",
        # Only the hash is ever persisted; the raw token is returned once at
        # install time and never stored.
        activation_token_hash="hash-for-test",
        status="online",
    )
    db.add(instance)
    db.commit()
    return instance


def _schedule(db: Session, policy: ContextualAccessPolicy, **kwargs) -> RecurrenceSchedule:
    """Create a schedule, optionally already due.

    #267 refuses a start in the past, so `starts_at` can no longer be used to
    fabricate a schedule the sweep will pick up immediately. Being *due* is a
    state a schedule reaches, not something it can be created as — so a test
    that needs one sets `next_occurrence_at` directly and says so, rather than
    going through a creation path that now, correctly, refuses it.
    """
    due_at = kwargs.pop("starts_at", None)
    schedule = create_schedule(
        db,
        organization_id=policy.organization_id,
        authorizing_policy=policy,
        cadence_interval=kwargs.pop("cadence_interval", CADENCE),
        scanner_instance_id=kwargs.pop(
            "scanner_instance_id", _collector(db, organization_id=policy.organization_id).id
        ),
        created_by_user_id=ADMIN_USER_ID,
        **kwargs,
    )
    if due_at is not None:
        schedule.next_occurrence_at = naive_utc(due_at)
        db.add(schedule)
    db.commit()
    return schedule


def _events(db: Session) -> list[str]:
    return [event.event_type for event in db.query(AuditEvent).all()]


# --- Criterion 1: a first-class, auditable schedule, not a beat entry -------


def test_a_schedule_is_a_record_the_organisation_owns(db: Session):
    policy = _policy(db)
    schedule = _schedule(db, policy, purpose="Deeper access every 30 days")

    stored = db.query(RecurrenceSchedule).filter_by(id=schedule.id).one()
    assert stored.organization_id == ORG_ID
    assert stored.cadence_interval == CADENCE
    assert stored.status == RecurrenceScheduleStatus.ACTIVE.value
    assert stored.created_by_user_id == ADMIN_USER_ID
    assert stored.purpose == "Deeper access every 30 days"
    assert "recurrence_schedule_created" in _events(db)


def test_the_beat_entry_is_the_mechanism_and_the_schedule_is_the_record(db: Session):
    """Criterion 1 rules out a recurrence that exists *only* as a beat entry."""
    from src.core.celery_app import celery_app

    entry = celery_app.conf.beat_schedule["materialize-due-recurrence-occurrences"]
    assert entry["task"].endswith("materialize_due_recurrence_occurrences")
    # The sweep carries no organisation, cadence or authority of its own — all
    # of that lives on rows, which is what makes it visible to whoever approved it.
    assert set(entry) == {"task", "schedule"}


def test_one_organisations_schedule_is_invisible_to_another(db: Session):
    _schedule(db, _policy(db))

    from src.core.services.recurrence_schedule_service import list_schedules

    assert len(list_schedules(db, organization_id=ORG_ID)) == 1
    assert list_schedules(db, organization_id=OTHER_ORG_ID) == []


# --- Criterion 2: the next occurrence is visible, and pausable --------------


def test_the_next_occurrence_is_known_before_it_happens(db: Session):
    policy = _policy(db)
    schedule = _schedule(db, policy)

    assert schedule.next_occurrence_at is not None
    assert schedule.next_occurrence_at > naive_utc(utcnow())
    assert schedule.last_occurrence_at is None


def test_pausing_stops_occurrences_without_touching_the_access_underneath(db: Session):
    policy = _policy(db)
    schedule = _schedule(db, policy, starts_at=naive_utc(utcnow()) - timedelta(minutes=1))

    pause_schedule(db, schedule, paused_by_user_id=ADMIN_USER_ID)
    db.commit()

    assert materialize_due_occurrences(db) == []
    db.refresh(policy)
    # The approval is entirely untouched — pausing a cadence is not revoking access.
    assert policy.status == ContextualAccessPolicyStatus.ACTIVE.value
    assert policy.effective_to is None


def test_resuming_does_not_backfill_the_occurrences_a_pause_skipped(db: Session):
    policy = _policy(db)
    schedule = _schedule(db, policy, starts_at=naive_utc(utcnow()) - timedelta(days=90))
    pause_schedule(db, schedule)
    db.commit()

    resume_schedule(db, schedule, resumed_by_user_id=ADMIN_USER_ID)
    db.commit()

    assert schedule.status == RecurrenceScheduleStatus.ACTIVE.value
    # Moved forward from now, not replayed from the past.
    assert schedule.next_occurrence_at > naive_utc(utcnow())
    assert materialize_due_occurrences(db) == []


def test_cancelling_ends_the_cadence_and_leaves_the_approval_alone(db: Session):
    policy = _policy(db)
    schedule = _schedule(db, policy, starts_at=naive_utc(utcnow()) - timedelta(minutes=1))

    cancel_schedule(db, schedule, cancelled_by_user_id=ADMIN_USER_ID)
    db.commit()

    assert materialize_due_occurrences(db) == []
    db.refresh(policy)
    assert policy.status == ContextualAccessPolicyStatus.ACTIVE.value


# --- Criterion 3: a missed occurrence is reported, not skipped --------------


def test_an_unclaimed_occurrence_is_reported_as_missed_rather_than_overtaken(db: Session):
    policy = _policy(db)
    schedule = _schedule(db, policy, starts_at=naive_utc(utcnow()) - timedelta(days=1))

    first = materialize_due_occurrences(db)
    db.commit()
    assert len(first) == 1

    # Nobody claimed it; the next window comes round.
    later = naive_utc(utcnow()) + timedelta(days=CADENCE + 1)
    second = materialize_due_occurrences(db, now=later)
    db.commit()
    assert len(second) == 1

    occurrences = list_occurrences(db, organization_id=ORG_ID, schedule_id=schedule.id)
    statuses = {o.id: o.status for o in occurrences}
    assert statuses[first[0].id] == RecurrenceOccurrenceStatus.MISSED.value
    assert statuses[second[0].id] == RecurrenceOccurrenceStatus.DUE.value
    # It is still there to be reported — not deleted, not overwritten.
    assert len(occurrences) == 2
    assert first[0].failure_reason
    assert RECURRENCE_AUDIT_OCCURRENCE_MISSED in _events(db)


def test_a_failed_occurrence_is_recorded_with_its_reason(db: Session):
    policy = _policy(db)
    _schedule(db, policy, starts_at=naive_utc(utcnow()) - timedelta(minutes=1))
    occurrence = materialize_due_occurrences(db)[0]
    db.commit()

    record_occurrence_failed(db, occurrence, failure_reason="The Collector was unreachable.")
    db.commit()

    assert occurrence.status == RecurrenceOccurrenceStatus.FAILED.value
    assert occurrence.failure_reason == "The Collector was unreachable."
    assert "recurrence_occurrence_failed" in _events(db)


def test_a_failure_without_a_reason_is_refused(db: Session):
    policy = _policy(db)
    _schedule(db, policy, starts_at=naive_utc(utcnow()) - timedelta(minutes=1))
    occurrence = materialize_due_occurrences(db)[0]
    db.commit()

    with pytest.raises(RecurrenceScheduleValidationError, match="reason is required"):
        record_occurrence_failed(db, occurrence, failure_reason="   ")


def test_the_occurrence_records_when_it_was_due_not_when_the_sweep_noticed(db: Session):
    policy = _policy(db)
    due_at = naive_utc(utcnow()) - timedelta(days=3)
    _schedule(db, policy, starts_at=due_at)

    noticed_at = naive_utc(utcnow())
    occurrence = materialize_due_occurrences(db, now=noticed_at)[0]
    db.commit()

    assert occurrence.scheduled_for == due_at
    assert occurrence.materialized_at == noticed_at


# --- Criterion 4: the schedule never outlives its approval ------------------


def test_a_schedule_lapses_when_its_approval_expires_and_produces_nothing(db: Session):
    policy = _policy(db, effective_to=naive_utc(utcnow()) + timedelta(days=45))
    schedule = _schedule(db, policy)

    # Past the approval's expiry, and past the cadence — both due and unauthorised.
    after_expiry = naive_utc(utcnow()) + timedelta(days=60)
    created = materialize_due_occurrences(db, now=after_expiry)
    db.commit()

    assert created == []
    assert schedule.status == RecurrenceScheduleStatus.LAPSED.value
    assert schedule.lapsed_at is not None
    assert "expired" in schedule.lapsed_reason
    assert list_occurrences(db, organization_id=ORG_ID, schedule_id=schedule.id) == []
    assert RECURRENCE_AUDIT_SCHEDULE_LAPSED in _events(db)
    assert RECURRENCE_AUDIT_OCCURRENCE_DUE not in _events(db)


def test_a_schedule_lapses_when_its_approval_is_superseded(db: Session):
    policy = _policy(db)
    schedule = _schedule(db, policy, starts_at=naive_utc(utcnow()) - timedelta(minutes=1))

    policy.status = ContextualAccessPolicyStatus.SUPERSEDED.value
    db.commit()

    assert materialize_due_occurrences(db) == []
    assert schedule.status == RecurrenceScheduleStatus.LAPSED.value
    assert "no longer active" in schedule.lapsed_reason


def test_a_paused_schedule_cannot_be_resumed_onto_an_expired_approval(db: Session):
    policy = _policy(db, effective_to=naive_utc(utcnow()) + timedelta(days=45))
    schedule = _schedule(db, policy)
    pause_schedule(db, schedule)
    db.commit()

    policy.effective_to = naive_utc(utcnow()) - timedelta(days=1)
    db.commit()

    resume_schedule(db, schedule)
    db.commit()

    assert schedule.status == RecurrenceScheduleStatus.LAPSED.value


def test_a_schedule_cannot_be_created_under_an_inactive_approval(db: Session):
    policy = _policy(db, status=ContextualAccessPolicyStatus.DRAFT.value)

    with pytest.raises(RecurrenceScheduleValidationError, match="active approval"):
        create_schedule(
            db,
            organization_id=ORG_ID,
            authorizing_policy=policy,
            scanner_instance_id=_collector(db).id,
            cadence_interval=CADENCE,
        )


def test_a_schedule_requires_the_scheduled_autonomous_operating_mode(db: Session):
    policy = _policy(db)
    policy.choice = AccessOperatingMode.PROCESS_TRIGGERED.value
    db.commit()

    with pytest.raises(RecurrenceScheduleValidationError, match="unattended-access approval"):
        create_schedule(
            db,
            organization_id=ORG_ID,
            authorizing_policy=policy,
            scanner_instance_id=_collector(db).id,
            cadence_interval=CADENCE,
        )


def test_replacing_a_schedule_keeps_the_old_ledger_and_links_both_records(db: Session):
    policy = _policy(db)
    old = _schedule(db, policy, purpose="Old cadence")
    old_occurrence = RecurrenceOccurrence(
        organization_id=ORG_ID,
        schedule_id=old.id,
        scheduled_for=old.next_occurrence_at,
        materialized_at=utcnow(),
        status=RecurrenceOccurrenceStatus.COMPLETED.value,
    )
    db.add(old_occurrence)
    db.commit()

    replacement = supersede_schedule(
        db,
        old,
        authorizing_policy=policy,
        cadence_interval=14,
        cadence_type=RecurrenceCadenceType.INTERVAL_DAYS.value,
        cadence_weekdays=None,
        purpose="New cadence",
        superseded_by_user_id=ADMIN_USER_ID,
    )
    db.commit()

    assert old.status == RecurrenceScheduleStatus.SUPERSEDED.value
    assert old.superseded_by_id == replacement.id
    assert replacement.supersedes_schedule_id == old.id
    assert db.query(RecurrenceOccurrence).filter_by(id=old_occurrence.id).one().schedule_id == old.id


def test_a_schedule_whose_first_run_falls_after_the_approval_expires_is_refused(db: Session):
    policy = _policy(db, effective_to=naive_utc(utcnow()) + timedelta(days=10))

    with pytest.raises(RecurrenceScheduleValidationError, match="expires before the first"):
        create_schedule(
            db,
            organization_id=ORG_ID,
            authorizing_policy=policy,
            scanner_instance_id=_collector(db).id,
            cadence_interval=CADENCE,
        )


def test_a_schedule_cannot_borrow_another_organisations_approval(db: Session):
    foreign = _policy(db, organization_id=OTHER_ORG_ID)

    with pytest.raises(RecurrenceScheduleValidationError):
        create_schedule(
            db,
            organization_id=ORG_ID,
            authorizing_policy=foreign,
            scanner_instance_id=_collector(db).id,
            cadence_interval=CADENCE,
        )


def test_a_cadence_outside_the_permitted_range_is_refused(db: Session):
    policy = _policy(db)
    for cadence in (0, 366):
        with pytest.raises(RecurrenceScheduleValidationError, match="outside what this cadence allows"):
            create_schedule(
                db,
                organization_id=ORG_ID,
                authorizing_policy=policy,
                scanner_instance_id=_collector(db).id,
                cadence_interval=cadence,
            )


# --- The non-goal: recurrence creates work, it does not execute it ----------


def test_a_due_occurrence_waits_to_be_claimed_and_nothing_runs(db: Session):
    policy = _policy(db)
    _schedule(db, policy, starts_at=naive_utc(utcnow()) - timedelta(minutes=1))

    created = materialize_due_occurrences(db)
    db.commit()

    assert len(created) == 1
    assert created[0].status == RecurrenceOccurrenceStatus.DUE.value
    # Nothing was dispatched, executed or referenced — a consumer has to come
    # and take it.
    assert created[0].created_work_ref is None
    assert created[0].claimed_at is None
    assert claim_due_occurrences(db, organization_id=ORG_ID) == created


def test_a_claim_records_what_work_it_created(db: Session):
    policy = _policy(db)
    _schedule(db, policy, starts_at=naive_utc(utcnow()) - timedelta(minutes=1))
    occurrence = materialize_due_occurrences(db)[0]
    db.commit()

    record_occurrence_claimed(db, occurrence, created_work_ref="discovery-run-42")
    db.commit()

    assert occurrence.status == RecurrenceOccurrenceStatus.CLAIMED.value
    assert occurrence.created_work_ref == "discovery-run-42"
    assert claim_due_occurrences(db, organization_id=ORG_ID) == []
    assert "recurrence_occurrence_claimed" in _events(db)


def test_a_claim_that_cannot_say_what_it_created_is_refused(db: Session):
    policy = _policy(db)
    _schedule(db, policy, starts_at=naive_utc(utcnow()) - timedelta(minutes=1))
    occurrence = materialize_due_occurrences(db)[0]
    db.commit()

    with pytest.raises(RecurrenceScheduleValidationError, match="what work it created"):
        record_occurrence_claimed(db, occurrence, created_work_ref="  ")


def test_a_claimed_occurrence_is_not_reported_as_missed(db: Session):
    policy = _policy(db)
    _schedule(db, policy, starts_at=naive_utc(utcnow()) - timedelta(days=1))
    first = materialize_due_occurrences(db)[0]
    record_occurrence_claimed(db, first, created_work_ref="discovery-run-1")
    db.commit()

    materialize_due_occurrences(db, now=naive_utc(utcnow()) + timedelta(days=CADENCE + 1))
    db.commit()

    assert first.status == RecurrenceOccurrenceStatus.CLAIMED.value
    assert RECURRENCE_AUDIT_OCCURRENCE_MISSED not in _events(db)


# --- The sweep advances honestly -------------------------------------------


def test_the_sweep_advances_the_schedule_from_when_it_was_due(db: Session):
    """#246 — this test previously asserted the defect.

    It read `next_occurrence_at == swept_at + CADENCE`, which is the drift: the
    schedule advanced from when the sweep *noticed* rather than from when the
    occurrence was *due*, so every bit of lateness was folded in permanently. A
    worker down for two days moved a weekly schedule two days later forever.

    The assertion is now the anchor, and the old expression is kept below as the
    thing that must not come back.
    """
    policy = _policy(db)
    schedule = _schedule(db, policy, starts_at=naive_utc(utcnow()) - timedelta(minutes=1))
    original_next = schedule.next_occurrence_at

    swept_at = naive_utc(utcnow())
    materialize_due_occurrences(db, now=swept_at)
    db.commit()

    assert schedule.last_occurrence_at == original_next
    assert schedule.next_occurrence_at == original_next + timedelta(days=CADENCE)
    assert schedule.next_occurrence_at != swept_at + timedelta(days=CADENCE)


def test_a_schedule_that_is_not_yet_due_produces_nothing(db: Session):
    policy = _policy(db)
    _schedule(db, policy)

    assert materialize_due_occurrences(db) == []


# --- #246: the weekday cadence, through the service ---------------------------


def test_a_weekly_schedule_starts_on_the_weekday_it_names(db: Session):
    """"Every Monday" starts on a Monday, not a week from today whatever day
    that is. The first occurrence uses the same anchor function the sweep
    advances with, so the two cannot disagree."""
    policy = _policy(db)
    schedule = create_schedule(
        db,
        organization_id=ORG_ID,
        authorizing_policy=policy,
        scanner_instance_id=_collector(db).id,
        cadence_type=RecurrenceCadenceType.DAY_OF_WEEK.value,
        cadence_interval=1,
        cadence_weekdays=[0],
    )
    db.commit()

    assert schedule.next_occurrence_at.weekday() == 0
    assert schedule.cadence_type == RecurrenceCadenceType.DAY_OF_WEEK.value
    # #265 — the interval counts *weeks* for this shape, so "every 1 week on
    # Monday". The old model carried a meaningless 7 here.
    assert schedule.cadence_interval == 1


def test_a_weekly_schedule_must_say_which_day(db: Session):
    policy = _policy(db)
    with pytest.raises(RecurrenceScheduleValidationError):
        create_schedule(
            db,
            organization_id=ORG_ID,
            authorizing_policy=policy,
            scanner_instance_id=_collector(db).id,
            cadence_type=RecurrenceCadenceType.DAY_OF_WEEK.value,
            cadence_weekdays=None,
        )


def test_a_weekday_outside_monday_to_sunday_is_refused(db: Session):
    policy = _policy(db)
    with pytest.raises(RecurrenceScheduleValidationError):
        create_schedule(
            db,
            organization_id=ORG_ID,
            authorizing_policy=policy,
            scanner_instance_id=_collector(db).id,
            cadence_type=RecurrenceCadenceType.DAY_OF_WEEK.value,
            cadence_weekdays=[7],
        )


def test_a_cadence_shape_this_platform_does_not_offer_is_refused_by_name(db: Session):
    """Named rather than silently coerced to an interval — a schedule that runs
    on a cadence nobody chose is worse than one that refuses to be created."""
    policy = _policy(db)
    with pytest.raises(RecurrenceScheduleValidationError, match="not a cadence"):
        create_schedule(
            db,
            organization_id=ORG_ID,
            authorizing_policy=policy,
            scanner_instance_id=_collector(db).id,
            cadence_type="0 9 * * 1",
        )


def test_a_weekday_on_an_interval_schedule_is_dropped_not_kept(db: Session):
    """It would be a second, silent opinion about when the schedule runs."""
    policy = _policy(db)
    schedule = create_schedule(
        db,
        organization_id=ORG_ID,
        authorizing_policy=policy,
        scanner_instance_id=_collector(db).id,
        cadence_interval=30,
        cadence_weekdays=[3],
    )
    db.commit()

    assert schedule.cadence_weekdays == []
    assert schedule.cadence_interval == 30


def test_an_existing_interval_schedule_is_unchanged_by_the_new_shape(db: Session):
    """Additive: a schedule created the old way still reads as an interval."""
    policy = _policy(db)
    schedule = create_schedule(
        db,
        organization_id=ORG_ID,
        authorizing_policy=policy,
        scanner_instance_id=_collector(db).id,
        cadence_interval=CADENCE,
    )
    db.commit()

    assert schedule.cadence_type == RecurrenceCadenceType.INTERVAL_DAYS.value
    assert schedule.cadence_weekdays == []


def test_a_schedule_without_a_collector_is_refused(db: Session):
    """#260 (Søren, 2026-08-19): *"the schedule is made for the scanner, not the
    other way around, so having a schedule with no collector makes no sense."*

    It was nullable, on the reasoning that the recurrence *primitive* did not
    require a Collector. True of the primitive, false of the product: such a
    schedule runs nothing, and since the list lives on the Collector's own page
    it would also have nowhere to be read — the defect #245 exists to fix.
    """
    policy = _policy(db)
    with pytest.raises(RecurrenceScheduleValidationError, match="which one"):
        create_schedule(
            db,
            organization_id=ORG_ID,
            authorizing_policy=policy,
            scanner_instance_id="",
            cadence_interval=CADENCE,
        )


# --- #267: the start anchor, at the service boundary -------------------------


def test_a_start_in_the_past_is_refused_with_a_reason_a_person_can_act_on(db: Session):
    """The decision this story forced, taken explicitly: refuse rather than
    quietly move the start forward. Starting somewhere the person did not choose
    is the system deciding; saying so lets them choose again."""
    policy = _policy(db)

    with pytest.raises(RecurrenceScheduleValidationError, match="cannot start in the past"):
        create_schedule(
            db,
            organization_id=ORG_ID,
            authorizing_policy=policy,
            scanner_instance_id=_collector(db).id,
            cadence_interval=CADENCE,
            starts_at=naive_utc(utcnow()) - timedelta(minutes=1),
        )


def test_the_first_occurrence_reported_is_the_one_it_will_actually_produce(db: Session):
    """Criterion 3, and the defect underneath it. A Thursday start on an "every
    Monday" cadence used to be stored verbatim, so the record promised a Thursday
    run that would never happen again."""
    policy = _policy(db)
    thursday = naive_utc(utcnow()) + timedelta(days=(3 - naive_utc(utcnow()).weekday()) % 7 + 7)
    thursday = thursday.replace(hour=9, minute=0, second=0, microsecond=0)

    schedule = create_schedule(
        db,
        organization_id=ORG_ID,
        authorizing_policy=policy,
        scanner_instance_id=_collector(db).id,
        cadence_type=RecurrenceCadenceType.DAY_OF_WEEK.value,
        cadence_interval=1,
        cadence_weekdays=[0],
        starts_at=thursday,
        anchor_timezone="UTC",
    )
    db.commit()

    assert schedule.next_occurrence_at.weekday() == 0, "a Monday, not the Thursday asked for"
    assert schedule.next_occurrence_at > thursday


def test_a_start_already_on_the_cadence_is_kept_exactly(db: Session):
    policy = _policy(db)
    now = naive_utc(utcnow())
    monday = (now + timedelta(days=(0 - now.weekday()) % 7 + 7)).replace(
        hour=9, minute=0, second=0, microsecond=0
    )

    schedule = create_schedule(
        db,
        organization_id=ORG_ID,
        authorizing_policy=policy,
        scanner_instance_id=_collector(db).id,
        cadence_type=RecurrenceCadenceType.DAY_OF_WEEK.value,
        cadence_interval=1,
        cadence_weekdays=[0],
        starts_at=monday,
        anchor_timezone="UTC",
    )
    db.commit()

    assert schedule.next_occurrence_at == monday


@pytest.mark.parametrize(
    "cadence_kwargs",
    [
        {"cadence_type": "interval_days", "cadence_interval": 30},
        {"cadence_type": "day_of_week", "cadence_interval": 1, "cadence_weekdays": [0]},
        {"cadence_type": "monthly", "cadence_interval": 1, "cadence_day_of_month": 15},
        {"cadence_type": "yearly", "cadence_interval": 1, "cadence_day_of_month": 1,
         "cadence_month": 6},
        {"cadence_type": "every_weekday"},
    ],
)
def test_an_approval_expiring_before_the_first_run_still_refuses_every_shape(
    db: Session, cadence_kwargs: dict
):
    """Criterion 4. The guard predates the new shapes, and a schedule created
    only to lapse untouched is the thing it exists to prevent."""
    policy = _policy(db)
    policy.effective_to = naive_utc(utcnow()) + timedelta(hours=1)
    db.add(policy)
    db.commit()

    with pytest.raises(RecurrenceScheduleValidationError):
        create_schedule(
            db,
            organization_id=ORG_ID,
            authorizing_policy=policy,
            scanner_instance_id=_collector(db).id,
            **cadence_kwargs,
        )


def test_a_replacement_can_move_its_anchor_as_well_as_its_cadence(db: Session):
    """#272 — the editor collects a start date on a replacement too, and the
    supersede path used to drop it silently. A person moved the start and
    nothing happened."""
    policy = _policy(db)
    original = _schedule(db, policy)
    now = naive_utc(utcnow())
    monday = (now + timedelta(days=(0 - now.weekday()) % 7 + 7)).replace(
        hour=9, minute=0, second=0, microsecond=0
    )

    replacement = supersede_schedule(
        db,
        original,
        authorizing_policy=policy,
        cadence_type=RecurrenceCadenceType.DAY_OF_WEEK.value,
        cadence_interval=1,
        cadence_weekdays=[0],
        purpose="Moved to Mondays",
        starts_at=monday,
        superseded_by_user_id=ADMIN_USER_ID,
    )
    db.commit()

    assert replacement.next_occurrence_at == monday
    assert replacement.cadence_type == RecurrenceCadenceType.DAY_OF_WEEK.value
    # The old row is kept and linked, never deleted — its ledger hangs off it.
    assert original.status == RecurrenceScheduleStatus.SUPERSEDED.value
    assert original.superseded_by_id == replacement.id
    assert replacement.supersedes_schedule_id == original.id


def test_a_replacement_without_a_start_takes_the_next_time_the_cadence_comes_round(
    db: Session,
):
    policy = _policy(db)
    original = _schedule(db, policy)

    replacement = supersede_schedule(
        db,
        original,
        authorizing_policy=policy,
        cadence_type=RecurrenceCadenceType.INTERVAL_DAYS.value,
        cadence_interval=14,
        purpose=None,
        superseded_by_user_id=ADMIN_USER_ID,
    )
    db.commit()

    assert replacement.next_occurrence_at > naive_utc(utcnow())


# --- #276: the ledger never presents a truncated list as a complete one ------


def test_the_ledger_reports_its_true_size_not_the_page_it_returned(db: Session):
    """A weekly schedule crosses fifty occurrences inside a year. Until now the
    screen showed the fifty most recent with no sign anything was missing."""
    policy = _policy(db)
    schedule = _schedule(db, policy)
    for day in range(55):
        db.add(
            RecurrenceOccurrence(
                organization_id=ORG_ID,
                schedule_id=schedule.id,
                scheduled_for=naive_utc(utcnow()) - timedelta(days=day),
                materialized_at=naive_utc(utcnow()),
                status=RecurrenceOccurrenceStatus.COMPLETED.value,
            )
        )
    db.commit()

    page = list_occurrences(db, organization_id=ORG_ID, schedule_id=schedule.id)
    total = count_occurrences(db, organization_id=ORG_ID, schedule_id=schedule.id)

    assert len(page) == 50, "the page stays modest"
    assert total == 55, "and the reader can be told there are more"
    assert total > len(page)


def test_every_occurrence_is_reachable_by_paging(db: Session):
    policy = _policy(db)
    schedule = _schedule(db, policy)
    for day in range(55):
        db.add(
            RecurrenceOccurrence(
                organization_id=ORG_ID,
                schedule_id=schedule.id,
                scheduled_for=naive_utc(utcnow()) - timedelta(days=day),
                materialized_at=naive_utc(utcnow()),
                status=RecurrenceOccurrenceStatus.COMPLETED.value,
            )
        )
    db.commit()

    first = list_occurrences(db, organization_id=ORG_ID, schedule_id=schedule.id)
    second = list_occurrences(
        db, organization_id=ORG_ID, schedule_id=schedule.id, offset=50
    )

    assert len(second) == 5
    seen = {o.id for o in first} | {o.id for o in second}
    assert len(seen) == 55, "no occurrence is unreachable, and none is served twice"


def test_the_ledger_stays_newest_first_across_pages(db: Session):
    policy = _policy(db)
    schedule = _schedule(db, policy)
    for day in range(55):
        db.add(
            RecurrenceOccurrence(
                organization_id=ORG_ID,
                schedule_id=schedule.id,
                scheduled_for=naive_utc(utcnow()) - timedelta(days=day),
                materialized_at=naive_utc(utcnow()),
                status=RecurrenceOccurrenceStatus.COMPLETED.value,
            )
        )
    db.commit()

    first = list_occurrences(db, organization_id=ORG_ID, schedule_id=schedule.id)
    second = list_occurrences(
        db, organization_id=ORG_ID, schedule_id=schedule.id, offset=50
    )

    assert first[0].scheduled_for > first[-1].scheduled_for
    assert first[-1].scheduled_for > second[0].scheduled_for
