"""#463: migration `20260915_service_bia_exceptions` against a real Postgres.

The clean-up is JSONB SQL, so a mocked or SQLite database would prove nothing (AGENTS.md §11.2).
Runs inside the conftest transaction and rolls back.

Søren, 2026-09-15 (option B): an answer identical to the process's reads as inherited, an answer that
differs stays as an exception marked as recorded before reasons were required, and a service in
several processes is compared with each one separately.
"""

from __future__ import annotations

import importlib.util
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.core.models import (
    BusinessService,
    Organization,
    OrganizationBiaBaseline,
    ProcessBiaAssessment,
    ServiceBiaException,
    ValueStream,
)

MIGRATION_PATH = (
    Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "20260915_service_bia_exceptions.py"
)


def _load_migration():
    spec = importlib.util.spec_from_file_location(
        "service_bia_exceptions_migration", MIGRATION_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MIGRATION = _load_migration()

PROCESS_ANSWERS = {
    "impact1h": "high",
    "impact4h": "high",
    "impact24h": "medium",
    "mtd": "short",
    "dataSensitivity": "high",
    "workaround": "manual",
    "alternativeChannel": "none",
}
EARLIER = datetime(2026, 9, 1)
LATER = EARLIER + timedelta(days=1)


def _process(db: Session, org: Organization, *, legacy: dict | None = None) -> ValueStream:
    row = ValueStream(
        id=str(uuid4()), organization_id=org.id, name="Order to Cash", bia_answers=legacy
    )
    db.add(row)
    db.flush()
    return row


def _assessment(
    db: Session,
    process: ValueStream,
    answers: dict,
    *,
    status: str = "attested",
    created_at: datetime = EARLIER,
) -> None:
    db.add(
        ProcessBiaAssessment(
            organization_id=process.organization_id,
            process_id=process.id,
            status=status,
            answers=answers,
            source="test",
            confidence="high",
            assumption_state="confirmed",
            created_at=created_at,
        )
    )
    db.flush()


def _baseline(db: Session, org: Organization, answers: dict, *, status: str = "active") -> None:
    db.add(OrganizationBiaBaseline(organization_id=org.id, status=status, answers=answers))
    db.flush()


def _service(
    db: Session, org: Organization, processes: list[ValueStream], answers: dict | None
) -> BusinessService:
    row = BusinessService(
        id=str(uuid4()),
        organization_id=org.id,
        name="Order processing",
        value_stream_ids=[process.id for process in processes],
        bia_answers=answers,
    )
    db.add(row)
    db.flush()
    return row


def _run(db: Session) -> int:
    recorded = db.execute(MIGRATION.BACKFILL_SERVICE_BIA_EXCEPTIONS).rowcount
    db.flush()
    return recorded


def _exceptions(db: Session, service: BusinessService) -> dict[tuple[str, str], tuple]:
    rows = db.execute(
        text(
            "SELECT process_id, field, value, previous_value, reason_code, recorded_by_user_id, "
            "recorded_before_reasons FROM service_bia_exceptions WHERE service_id = :s"
        ),
        {"s": service.id},
    )
    return {(row[0], row[1]): tuple(row[2:]) for row in rows}


def _report(db: Session, org: Organization) -> tuple[int, int, int] | None:
    for organization_id, inherited, exceptions, kept in db.execute(
        MIGRATION.REPORT_BY_ORGANIZATION
    ):
        if organization_id == org.id:
            return inherited, exceptions, kept
    return None


def test_an_answer_identical_to_the_process_reads_as_inherited(
    db_session: Session, sample_organization: Organization
) -> None:
    process = _process(db_session, sample_organization)
    _assessment(db_session, process, PROCESS_ANSWERS)
    service = _service(db_session, sample_organization, [process], dict(PROCESS_ANSWERS))

    assert _run(db_session) == 0
    assert _exceptions(db_session, service) == {}
    assert _report(db_session, sample_organization) == (7, 0, 0)


def test_a_differing_answer_stays_marked_as_recorded_before_reasons(
    db_session: Session, sample_organization: Organization
) -> None:
    process = _process(db_session, sample_organization)
    _assessment(db_session, process, PROCESS_ANSWERS)
    service = _service(
        db_session, sample_organization, [process], {**PROCESS_ANSWERS, "impact1h": "low"}
    )

    assert _run(db_session) == 1
    assert _exceptions(db_session, service) == {
        (process.id, "impact1h"): ("low", "high", None, None, True)
    }
    assert _report(db_session, sample_organization) == (6, 1, 0)


def test_a_service_in_two_processes_is_compared_with_each(
    db_session: Session, sample_organization: Organization
) -> None:
    """The same answer is inherited in one process and an exception in the other."""
    matching = _process(db_session, sample_organization)
    _assessment(db_session, matching, PROCESS_ANSWERS)
    differing = _process(db_session, sample_organization)
    _assessment(db_session, differing, {**PROCESS_ANSWERS, "mtd": "long"})
    service = _service(
        db_session, sample_organization, [matching, differing], dict(PROCESS_ANSWERS)
    )

    _run(db_session)

    assert _exceptions(db_session, service) == {
        (differing.id, "mtd"): ("short", "long", None, None, True)
    }


def test_an_attested_assessment_is_compared_before_the_organisation_baseline(
    db_session: Session, sample_organization: Organization
) -> None:
    _baseline(db_session, sample_organization, {**PROCESS_ANSWERS, "workaround": "none"})
    process = _process(db_session, sample_organization)
    _assessment(db_session, process, PROCESS_ANSWERS)
    service = _service(db_session, sample_organization, [process], dict(PROCESS_ANSWERS))

    _run(db_session)

    assert _exceptions(db_session, service) == {}


def test_an_unattested_assessment_falls_back_to_the_organisation_baseline(
    db_session: Session, sample_organization: Organization
) -> None:
    _baseline(db_session, sample_organization, PROCESS_ANSWERS)
    process = _process(db_session, sample_organization)
    _assessment(db_session, process, {**PROCESS_ANSWERS, "mtd": "long"}, status="in_progress")
    service = _service(db_session, sample_organization, [process], dict(PROCESS_ANSWERS))

    _run(db_session)

    assert _exceptions(db_session, service) == {}


def test_a_superseded_assessment_is_ignored(
    db_session: Session, sample_organization: Organization
) -> None:
    process = _process(db_session, sample_organization)
    _assessment(db_session, process, PROCESS_ANSWERS, created_at=EARLIER)
    _assessment(
        db_session,
        process,
        {**PROCESS_ANSWERS, "mtd": "long"},
        status="superseded",
        created_at=LATER,
    )
    service = _service(db_session, sample_organization, [process], dict(PROCESS_ANSWERS))

    _run(db_session)

    assert _exceptions(db_session, service) == {}


def test_the_latest_assessment_counts_even_when_it_is_not_attested(
    db_session: Session, sample_organization: Organization
) -> None:
    """An older attested assessment behind a newer one still in progress, and no baseline: the
    process has no BIA in force, so the service's answers are kept."""
    process = _process(db_session, sample_organization)
    _assessment(db_session, process, PROCESS_ANSWERS, created_at=EARLIER)
    _assessment(db_session, process, PROCESS_ANSWERS, status="in_progress", created_at=LATER)
    service = _service(db_session, sample_organization, [process], dict(PROCESS_ANSWERS))

    _run(db_session)

    assert len(_exceptions(db_session, service)) == 7
    assert _report(db_session, sample_organization) == (0, 0, 7)


def test_a_process_with_no_bia_keeps_every_answer_with_nothing_to_depart_from(
    db_session: Session, sample_organization: Organization
) -> None:
    process = _process(db_session, sample_organization)
    _assessment(db_session, process, {}, status="prepared")
    service = _service(db_session, sample_organization, [process], dict(PROCESS_ANSWERS))

    _run(db_session)

    kept = _exceptions(db_session, service)
    assert len(kept) == 7
    assert {previous for _, previous, *_ in kept.values()} == {None}


def test_the_legacy_process_answers_are_used_when_nothing_else_exists(
    db_session: Session, sample_organization: Organization
) -> None:
    process = _process(db_session, sample_organization, legacy=PROCESS_ANSWERS)
    service = _service(
        db_session, sample_organization, [process], {**PROCESS_ANSWERS, "dataSensitivity": "low"}
    )

    _run(db_session)

    assert _exceptions(db_session, service) == {
        (process.id, "dataSensitivity"): ("low", "high", None, None, True)
    }


def test_owner_title_and_impact_path_never_become_exceptions_and_answers_are_untouched(
    db_session: Session, sample_organization: Organization
) -> None:
    process = _process(db_session, sample_organization)
    _assessment(db_session, process, PROCESS_ANSWERS)
    answers = {
        **PROCESS_ANSWERS,
        "serviceOwnerTitle": "Head of Billing",
        "impactPath": ["revenue_stop"],
    }
    service = _service(db_session, sample_organization, [process], answers)

    _run(db_session)
    db_session.refresh(service)

    assert _exceptions(db_session, service) == {}
    assert service.bia_answers == answers


def test_an_empty_answer_is_not_an_exception(
    db_session: Session, sample_organization: Organization
) -> None:
    process = _process(db_session, sample_organization)
    _assessment(db_session, process, PROCESS_ANSWERS)
    service = _service(
        db_session, sample_organization, [process], {**PROCESS_ANSWERS, "workaround": "  "}
    )

    _run(db_session)

    assert _exceptions(db_session, service) == {}


def test_a_second_run_changes_nothing(
    db_session: Session, sample_organization: Organization
) -> None:
    process = _process(db_session, sample_organization)
    _assessment(db_session, process, PROCESS_ANSWERS)
    service = _service(
        db_session, sample_organization, [process], {**PROCESS_ANSWERS, "impact4h": "low"}
    )

    assert _run(db_session) == 1
    assert _run(db_session) == 0
    assert len(_exceptions(db_session, service)) == 1


def test_a_withdrawn_exception_does_not_block_the_carry_over(
    db_session: Session, sample_organization: Organization
) -> None:
    """Only an active exception counts as already recorded."""
    process = _process(db_session, sample_organization)
    _assessment(db_session, process, PROCESS_ANSWERS)
    service = _service(
        db_session, sample_organization, [process], {**PROCESS_ANSWERS, "impact4h": "low"}
    )
    db_session.add(
        ServiceBiaException(
            organization_id=sample_organization.id,
            service_id=service.id,
            process_id=process.id,
            field="impact4h",
            value="medium",
            withdrawn_at=EARLIER,
        )
    )
    db_session.flush()

    assert _run(db_session) == 1


def test_a_process_of_another_organisation_is_ignored(
    db_session: Session, sample_organization: Organization
) -> None:
    other = Organization(
        name="Other Org",
        slug=f"other-{uuid4().hex[:8]}",
        plan_tier="enterprise",
        subscription_status="active",
        onboarding_completed=False,
    )
    db_session.add(other)
    db_session.flush()
    foreign = _process(db_session, other)
    service = _service(db_session, sample_organization, [foreign], dict(PROCESS_ANSWERS))

    assert _run(db_session) == 0
    assert _exceptions(db_session, service) == {}
    counted = dict(db_session.execute(MIGRATION.COUNT_SERVICES_WITHOUT_PROCESS).all())
    assert counted.get(sample_organization.id) == 1


def test_the_revision_id_fits_and_the_table_matches_the_model() -> None:
    assert len(MIGRATION.revision) <= 32
    assert [column.name for column in MIGRATION.columns()] == [
        column.name for column in ServiceBiaException.__table__.columns
    ]
    for migrated in MIGRATION.columns():
        modelled = ServiceBiaException.__table__.columns[migrated.name]
        assert migrated.nullable == modelled.nullable, migrated.name
        assert str(migrated.type) == str(modelled.type), migrated.name


@pytest.mark.parametrize("field", MIGRATION.BIA_FIELD_KEYS)
def test_every_frozen_field_is_a_bia_field_today(field: str) -> None:
    """The migration's frozen copy of the seven fields, held against today's list."""
    from src.core.services.bia_inheritance_service import BIA_FIELD_KEYS

    assert field in BIA_FIELD_KEYS
