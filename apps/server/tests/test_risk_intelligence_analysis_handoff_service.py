"""The analysis sweep — the step that had no sweep at all.

``analyze_normalized_ingestion_batch`` was reachable only from
``POST /risk-intelligence/batches/{id}/analyze``. Normalisation had a periodic
sweep and a beat entry; analysis had neither, so a Collector's evidence became
an ``AssetFinding`` on its own and stopped there. Read from the running platform
on 2026-09-07: 61 batches ``NEEDS_REVIEW``, 20 ``NORMALIZED``, **0** ``ANALYZED``.

The selection rule is the part that is easy to get backwards, so it is asserted
from both sides: ``NEEDS_REVIEW`` is the state that carries findings, and
``NORMALIZED`` is the state of a batch that observed *nothing*.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.database import Base
from src.core.model_defs.risk_intelligence_ingestion import (
    RiskIngestionBatch,
    RiskIngestionBatchStatus,
)
from src.core.model_defs.tenant_org import Organization

_TABLES = (Organization.__table__, RiskIngestionBatch.__table__)


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in _TABLES:
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine, tables=list(_TABLES))
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Org", slug="org", country="DK"))
    session.add(Organization(id=2, name="Other", slug="other", country="DK"))
    session.commit()
    yield session
    session.close()


def _batch(
    db: Session,
    *,
    status: RiskIngestionBatchStatus,
    organization_id: int = 1,
    source_name: str = "discovery_execution:nuclei",
) -> RiskIngestionBatch:
    batch = RiskIngestionBatch(
        organization_id=organization_id,
        source_name=source_name,
        collector_profile="discovery_execution_pipeline",
        content_type="application/json",
        payload_checksum="checksum",
        raw_payload={"hosts": []},
        raw_payload_size_bytes=0,
        status=status,
    )
    db.add(batch)
    db.commit()
    return batch


def _capture(monkeypatch) -> list[dict]:
    """Replace the analysis call, recording exactly what the sweep selected."""
    from src.core.services import risk_intelligence_analysis_handoff_service as handoff

    calls: list[dict] = []

    def _fake_analyze(db_, *, organization_id, actor_user_id, batch_id):
        calls.append(
            {"organization_id": organization_id, "actor_user_id": actor_user_id, "batch_id": batch_id}
        )

    monkeypatch.setattr(handoff, "analyze_normalized_ingestion_batch", _fake_analyze)
    return calls


def test_a_batch_with_findings_is_analysed(db: Session, monkeypatch) -> None:
    """``NEEDS_REVIEW`` is what normalisation writes when it produced findings."""
    from src.core.services import risk_intelligence_analysis_handoff_service as handoff

    batch = _batch(db, status=RiskIngestionBatchStatus.NEEDS_REVIEW)
    calls = _capture(monkeypatch)

    analysed = handoff.process_pending_analysis_batches(db)

    assert [call["batch_id"] for call in calls] == [batch.id]
    assert [item.id for item in analysed] == [batch.id]


def test_an_empty_batch_is_not_analysed(db: Session, monkeypatch) -> None:
    """``NORMALIZED`` means the batch observed nothing.

    Sweeping it would re-analyse empty batches on every tick and never touch a
    real finding — the exact inversion the two status names invite.
    """
    from src.core.services import risk_intelligence_analysis_handoff_service as handoff

    _batch(db, status=RiskIngestionBatchStatus.NORMALIZED)
    calls = _capture(monkeypatch)

    assert handoff.process_pending_analysis_batches(db) == []
    assert calls == []


@pytest.mark.parametrize(
    "status",
    [
        RiskIngestionBatchStatus.RECEIVED,
        RiskIngestionBatchStatus.ANALYZED,
        RiskIngestionBatchStatus.REVIEWED,
        RiskIngestionBatchStatus.FAILED,
    ],
)
def test_batches_outside_the_analysable_state_are_left_alone(
    db: Session, monkeypatch, status: RiskIngestionBatchStatus
) -> None:
    """An un-normalised batch has no findings yet; an analysed one already has
    its threats, and re-running would rewrite a threat a person may already have
    decided on. ``REVIEWED`` carries that decision outright."""
    from src.core.services import risk_intelligence_analysis_handoff_service as handoff

    _batch(db, status=status)
    calls = _capture(monkeypatch)

    assert handoff.process_pending_analysis_batches(db) == []
    assert calls == []


def test_each_batch_is_analysed_in_its_own_organization(db: Session, monkeypatch) -> None:
    """The sweep is platform-wide, so the tenant boundary comes from the batch
    itself. Carrying one organisation's id into another's batch is how a
    platform sweep turns into a cross-tenant write."""
    from src.core.services import risk_intelligence_analysis_handoff_service as handoff

    own = _batch(db, status=RiskIngestionBatchStatus.NEEDS_REVIEW, organization_id=1)
    other = _batch(db, status=RiskIngestionBatchStatus.NEEDS_REVIEW, organization_id=2)
    calls = _capture(monkeypatch)

    handoff.process_pending_analysis_batches(db)

    by_batch = {call["batch_id"]: call["organization_id"] for call in calls}
    assert by_batch == {own.id: 1, other.id: 2}


def test_the_sweep_has_no_human_actor(db: Session, monkeypatch) -> None:
    """A platform sweep must not attribute its audit events to a person.

    ``analyze_normalized_ingestion_batch`` writes an ``AuditEvent`` with
    ``actor_user_id``; naming a user there would put a decision-shaped record
    against somebody who did nothing.
    """
    from src.core.services import risk_intelligence_analysis_handoff_service as handoff

    _batch(db, status=RiskIngestionBatchStatus.NEEDS_REVIEW)
    calls = _capture(monkeypatch)

    handoff.process_pending_analysis_batches(db)

    assert [call["actor_user_id"] for call in calls] == [None]


def test_one_failing_batch_does_not_stop_the_others(db: Session, monkeypatch) -> None:
    """Each batch commits its own work, so a later batch must still be analysed
    after an earlier one fails — and the failed batch is not reported as done."""
    from src.core.services import risk_intelligence_analysis_handoff_service as handoff

    first = _batch(db, status=RiskIngestionBatchStatus.NEEDS_REVIEW, source_name="first")
    second = _batch(db, status=RiskIngestionBatchStatus.NEEDS_REVIEW, source_name="second")

    seen: list[int] = []

    def _explode_on_first(db_, *, organization_id, actor_user_id, batch_id):
        seen.append(batch_id)
        if batch_id == first.id:
            raise RuntimeError("analysis blew up")

    monkeypatch.setattr(handoff, "analyze_normalized_ingestion_batch", _explode_on_first)

    analysed = handoff.process_pending_analysis_batches(db)

    assert seen == [first.id, second.id], "the sweep must continue past a failure"
    assert [item.id for item in analysed] == [second.id], "a failed batch is not analysed"


def test_a_failed_batch_keeps_its_status_and_is_retried(db: Session, monkeypatch) -> None:
    """No ``ANALYSIS_FAILED`` state exists, so a failure leaves the batch where
    it was and the next sweep picks it up again. A transient fault must not
    permanently strand a real finding."""
    from src.core.services import risk_intelligence_analysis_handoff_service as handoff

    batch = _batch(db, status=RiskIngestionBatchStatus.NEEDS_REVIEW)
    attempts: list[int] = []

    def _always_fails(db_, *, organization_id, actor_user_id, batch_id):
        attempts.append(batch_id)
        raise RuntimeError("still broken")

    monkeypatch.setattr(handoff, "analyze_normalized_ingestion_batch", _always_fails)

    handoff.process_pending_analysis_batches(db)
    db.refresh(batch)
    assert batch.status == RiskIngestionBatchStatus.NEEDS_REVIEW

    handoff.process_pending_analysis_batches(db)
    assert attempts == [batch.id, batch.id], "the batch is offered again on the next sweep"


def test_oldest_batch_is_analysed_first(db: Session, monkeypatch) -> None:
    """Ordered by arrival so a backlog drains predictably, rather than in
    whatever order the database happens to return rows."""
    from src.core.services import risk_intelligence_analysis_handoff_service as handoff

    first = _batch(db, status=RiskIngestionBatchStatus.NEEDS_REVIEW, source_name="first")
    second = _batch(db, status=RiskIngestionBatchStatus.NEEDS_REVIEW, source_name="second")
    first.received_at = first.received_at.replace(year=2020)
    db.commit()

    calls = _capture(monkeypatch)
    handoff.process_pending_analysis_batches(db)

    assert [call["batch_id"] for call in calls] == [first.id, second.id]


def test_an_empty_sweep_does_nothing(db: Session, monkeypatch) -> None:
    """The common case between scans: one indexed no-op query."""
    from src.core.services import risk_intelligence_analysis_handoff_service as handoff

    calls = _capture(monkeypatch)
    assert handoff.process_pending_analysis_batches(db) == []
    assert calls == []


# --- End to end -------------------------------------------------------------
#
# The tests above replace the analysis call to pin the *selection* rule. These
# run the real services against a real schema, because the claim that matters —
# "a Collector's finding becomes a threat a person can act on, with nobody
# pressing anything" — is exactly the claim a stubbed analysis cannot make.


@pytest.fixture()
def full_db() -> Session:
    """Every table, so normalisation and analysis can run for real."""
    from sqlalchemy.sql.sqltypes import ARRAY as _SqlArray

    engine = create_engine("sqlite:///:memory:")
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (_SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(bind=engine)
    session = Session(bind=engine)
    session.add(Organization(id=1, name="Test Org", slug="test-org", country="DK"))
    session.commit()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


def _nuclei_payload() -> dict:
    """The shape `_parse_nuclei_jsonl` produces: host records carrying findings."""
    return {
        "hosts": [
            {
                "hostname": "api.example.com",
                "ip": "203.0.113.10",
                "findings": [
                    {
                        "id": "nuclei-tls-001",
                        "severity": "high",
                        "title": "Outdated TLS configuration",
                        "description": "TLS 1.0 remains enabled on the public endpoint.",
                    }
                ],
            }
        ]
    }


def test_a_scan_finding_becomes_a_threat_with_nobody_pressing_anything(full_db: Session) -> None:
    """The whole point, end to end.

    Before this sweep existed the batch stopped at ``NEEDS_REVIEW`` and no
    ``Threat`` was ever created, so the finding never reached a process, an
    intervention feed or a decision.
    """
    from src.core.models import Threat
    from src.core.services.risk_intelligence_ingestion_service import create_ingestion_batch
    from src.core.services.risk_intelligence_normalization_service import normalize_ingestion_batch
    from src.core.services import risk_intelligence_analysis_handoff_service as handoff

    batch = create_ingestion_batch(
        full_db,
        organization_id=1,
        actor_user_id=7,
        source_name="discovery_execution:nuclei",
        collector_profile="discovery_execution_pipeline",
        raw_payload=_nuclei_payload(),
        file_name=None,
    )
    normalize_ingestion_batch(full_db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    full_db.refresh(batch)
    assert batch.status == RiskIngestionBatchStatus.NEEDS_REVIEW
    assert full_db.query(Threat).count() == 0, "the state this sweep was built to end"

    analysed = handoff.process_pending_analysis_batches(full_db)

    assert [item.id for item in analysed] == [batch.id]
    full_db.refresh(batch)
    assert batch.status == RiskIngestionBatchStatus.ANALYZED

    threats = full_db.query(Threat).all()
    assert len(threats) == 1
    threat = threats[0]
    assert threat.organization_id == 1
    assert threat.severity == "high"
    # `detected` is the first state of the lifecycle, not a decision: the sweep
    # surfaces the threat, a person still chooses what to do about it.
    assert threat.status == "detected"
    assert threat.what_it_means, "a threat with no business meaning is not a product output"
    assert threat.recommendation, "the platform recommends; it never decides"


def test_a_second_sweep_does_not_analyse_the_same_batch_again(full_db: Session) -> None:
    """Once analysed the batch leaves the selectable state, so a threat a person
    may already have decided on is not rewritten every 90 seconds."""
    from src.core.models import Threat
    from src.core.services.risk_intelligence_ingestion_service import create_ingestion_batch
    from src.core.services.risk_intelligence_normalization_service import normalize_ingestion_batch
    from src.core.services import risk_intelligence_analysis_handoff_service as handoff

    batch = create_ingestion_batch(
        full_db,
        organization_id=1,
        actor_user_id=7,
        source_name="discovery_execution:nuclei",
        collector_profile="discovery_execution_pipeline",
        raw_payload=_nuclei_payload(),
        file_name=None,
    )
    normalize_ingestion_batch(full_db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    assert len(handoff.process_pending_analysis_batches(full_db)) == 1
    assert handoff.process_pending_analysis_batches(full_db) == []
    assert full_db.query(Threat).count() == 1


def test_a_batch_that_observed_nothing_never_reaches_analysis(full_db: Session) -> None:
    """An empty scan is a valid outcome. It must not manufacture a threat, and
    the empty path's ``NORMALIZED`` status is what keeps the sweep off it."""
    from src.core.models import Threat
    from src.core.services.risk_intelligence_ingestion_service import create_ingestion_batch
    from src.core.services.risk_intelligence_normalization_service import normalize_ingestion_batch
    from src.core.services import risk_intelligence_analysis_handoff_service as handoff

    batch = create_ingestion_batch(
        full_db,
        organization_id=1,
        actor_user_id=7,
        source_name="discovery_execution:nuclei",
        collector_profile="discovery_execution_pipeline",
        raw_payload={"hosts": []},
        file_name=None,
    )
    normalize_ingestion_batch(full_db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    full_db.refresh(batch)
    assert batch.status == RiskIngestionBatchStatus.NORMALIZED

    assert handoff.process_pending_analysis_batches(full_db) == []
    assert full_db.query(Threat).count() == 0
