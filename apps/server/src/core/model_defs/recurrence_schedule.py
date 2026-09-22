"""#242 — a recurrence an organisation can see, pause, and outlive its approval by never.

Two tables, because a schedule and its occurrences answer different questions.
The schedule answers *"what is meant to happen, and when next?"*. The occurrence
ledger answers *"what actually came due, and what became of it?"* — including the
ones nobody picked up, which is the answer a single ``last_run_at`` column on the
schedule could never give.

**Recurrence creates work; it does not execute it.** An occurrence is
materialised as ``DUE`` and waits to be claimed. Nothing here dispatches, runs,
or verifies anything — Step 4.2 is untouched, which is #242's own non-goal.

The FK to ``contextual_access_policies`` is the point of the story rather than a
convenience: the schedule reads its authority live instead of copying
``effective_to`` onto itself, so the two cannot drift and a schedule cannot keep
running on permission that has lapsed.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import JSON, Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped

from src.core.constants.recurrence_enums import (
    RECURRENCE_LEGACY_ANCHOR_TIMEZONE,
    RecurrenceCadenceType,
    RecurrenceOccurrenceStatus,
    RecurrenceScheduleStatus,
)
from src.core.database import Base
from src.core.model_defs.common import utcnow


class RecurrenceSchedule(Base):
    """A cadence an organisation approved, in a record it can actually read."""

    __tablename__ = "recurrence_schedules"
    __table_args__ = (
        Index("ix_recurrence_schedules_org_status", "organization_id", "status"),
        # The sweep's own query: every active schedule whose next occurrence is
        # due. Ordered so the sweep never scans schedules that cannot be due.
        Index("ix_recurrence_schedules_due", "status", "next_occurrence_at"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # The approval this schedule runs under. NOT NULL and read live: a schedule
    # with no authority is exactly the thing this must not permit.
    authorizing_policy_id: Mapped[str] = Column(
        String(36),
        ForeignKey("contextual_access_policies.id", ondelete="CASCADE"),
        nullable=False,
    )
    # The Collector this cadence runs. NOT NULL (#260, Søren 2026-08-19):
    # *"the schedule is made for the scanner, not the other way around, so having
    # a schedule with no collector makes no sense."*
    #
    # It was nullable, on the reasoning that the recurrence primitive did not
    # require a Collector to exist. That was true of the primitive and false of
    # the product: a schedule with no Collector runs nothing, and — since #260
    # put the schedule on the Collector's own page — it would also have nowhere
    # to be read, which is the defect #245 exists to fix.
    #
    # ON DELETE RESTRICT, not CASCADE and no longer SET NULL. SET NULL is
    # impossible against NOT NULL, and CASCADE would take the occurrence ledger
    # with it — the audit record of everything this cadence ever did. RESTRICT
    # follows the instinct CA-07.5 already recorded ("a completed access journey
    # must outlive the Connector it went through") and costs nothing in practice:
    # a Collector is *retired*, which is a status change, never a row deletion.
    scanner_instance_id: Mapped[str] = Column(
        String(36), ForeignKey("scanner_instances.id", ondelete="RESTRICT"), nullable=False
    )
    supersedes_schedule_id: Mapped[str | None] = Column(
        String(36), ForeignKey("recurrence_schedules.id", ondelete="SET NULL"), nullable=True
    )
    superseded_by_id: Mapped[str | None] = Column(
        String(36), ForeignKey("recurrence_schedules.id", ondelete="SET NULL"), nullable=True
    )
    superseded_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    superseded_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # #265 — the N in "every N days/weeks/months/years". The *unit* comes from
    # `cadence_type` rather than being stored, which is what removes the
    # meaningless 7 a weekday schedule used to carry in `cadence_days`.
    #
    # `cadence_days` is gone rather than kept alongside this: the criterion was
    # that it keep one meaning or be migrated with every caller, and two columns
    # that both look like "how often" is exactly the second meaning it must not
    # acquire.
    cadence_interval: Mapped[int] = Column(Integer, nullable=False, server_default="1")
    # #246 — which *shape* the cadence is. Defaulted rather than nullable so
    # every schedule created before this column existed reads as what it was:
    # an interval. Additive migration, no backfill needed.
    cadence_type: Mapped[str] = Column(
        String(20), nullable=False, server_default=RecurrenceCadenceType.INTERVAL_DAYS.value
    )
    # #265 — a *set*, because "every Monday and Thursday" is one cadence and not
    # two schedules a reader has to notice are related. Monday is 0, matching
    # datetime.weekday(). Empty for the shapes that do not name weekdays;
    # EVERY_WEEKDAY leaves it empty too, since Monday-to-Friday is what that
    # shape *means* rather than a set somebody could edit a day out of.
    cadence_weekdays: Mapped[list[int]] = Column(
        JSON, nullable=False, server_default="[]"
    )
    # Monthly and yearly only. Accepts 31 for every month; a shorter month
    # clamps to its last day — see `clamp_day_of_month`, where that rule is
    # decided rather than discovered.
    cadence_day_of_month: Mapped[int | None] = Column(Integer, nullable=True)
    # Yearly only. A monthly cadence recurs in every month and so names none.
    cadence_month: Mapped[int | None] = Column(Integer, nullable=True)
    # #285 — the IANA zone the cadence is computed in, captured from its creator
    # at creation and never resolved against whoever is reading. A recurring job
    # happens at a single moment; resolved per reader, "every Monday at 14:30"
    # would mean a different instant for each of them.
    #
    # Defaulted to UTC rather than to a place, because that is what schedules
    # created before this column existed actually did — the arithmetic ran on
    # naive UTC. Naming a city here would be inventing an intent nobody recorded.
    anchor_timezone: Mapped[str] = Column(
        String(64), nullable=False, server_default=RECURRENCE_LEGACY_ANCHOR_TIMEZONE
    )
    status: Mapped[str] = Column(
        String(20), nullable=False, default=RecurrenceScheduleStatus.ACTIVE.value
    )
    # Visible before it happens — criterion 2. Always populated for an active
    # schedule, so "when is this next due?" never needs to be recomputed by a
    # reader who might compute it differently.
    next_occurrence_at: Mapped[datetime] = Column(DateTime, nullable=False)
    last_occurrence_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    purpose: Mapped[str | None] = Column(Text, nullable=True)
    created_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    paused_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    paused_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    cancelled_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    cancelled_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # Set by the sweep, never by a person — the schedule stopped because the
    # permission ran out, and the record says so in its own words.
    lapsed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    lapsed_reason: Mapped[str | None] = Column(Text, nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(
        DateTime, nullable=False, default=utcnow, onupdate=utcnow
    )


class RecurrenceOccurrence(Base):
    """One time the schedule came round, and what became of it.

    Kept even when nothing claimed it. "A missed or failed occurrence is
    reported rather than silently skipped to the next window" is only possible
    if the occurrence that was skipped still exists to be reported.
    """

    __tablename__ = "recurrence_occurrences"
    __table_args__ = (
        Index("ix_recurrence_occurrences_schedule", "schedule_id", "status"),
        Index("ix_recurrence_occurrences_org_status", "organization_id", "status"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    schedule_id: Mapped[str] = Column(
        String(36), ForeignKey("recurrence_schedules.id", ondelete="CASCADE"), nullable=False
    )
    # When it was *due*, not when the sweep noticed. A sweep that runs late must
    # not make an occurrence look punctual.
    scheduled_for: Mapped[datetime] = Column(DateTime, nullable=False)
    materialized_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    status: Mapped[str] = Column(
        String(20), nullable=False, default=RecurrenceOccurrenceStatus.DUE.value
    )
    claimed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    # What the claimant created, in its own vocabulary. A plain reference rather
    # than a FK: recurrence creates work without knowing what kind of work it is,
    # and a foreign key here would make it know.
    created_work_ref: Mapped[str | None] = Column(String(255), nullable=True)
    resolved_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    failure_reason: Mapped[str | None] = Column(Text, nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)


__all__ = ["RecurrenceSchedule", "RecurrenceOccurrence"]
