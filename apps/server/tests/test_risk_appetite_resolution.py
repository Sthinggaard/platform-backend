"""Dashboard slice 2 — appetite resolution precedence, expiry, supersede, validation."""

from datetime import datetime, timedelta, timezone

import pytest

from src.core.model_defs.risk_appetite_policy import (
    APPETITE_POLICY_ACTIVE,
    APPETITE_POLICY_DRAFT,
    APPETITE_POLICY_LEADERSHIP_REVIEW,
    APPETITE_POLICY_SUPERSEDED,
    RiskAppetitePolicy,
)
from src.core.services import risk_appetite_resolution_service as svc

NOW = datetime(2026, 7, 12, 12, 0, 0)


class DummyQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def first(self):
        return self._rows[0] if self._rows else None

    def all(self):
        return list(self._rows)


class DummyDB:
    def __init__(self, policies=None):
        self.policies = list(policies or [])
        self.added: list[object] = []

    def query(self, _model):
        return DummyQuery(self.policies)

    def add(self, row):
        if row not in self.added:
            self.added.append(row)

    def flush(self):
        pass


def _policy(scope, *, process_id=None, answers=None, version=1, effective_to=None, review_at=None, decision_reference=None, status=APPETITE_POLICY_ACTIVE):
    return RiskAppetitePolicy(
        id=f"pol-{scope}-{process_id or 'org'}-{version}",
        organization_id=7,
        scope=scope,
        process_id=process_id,
        answers=answers or {"downtime": 2},
        status=status,
        version=version,
        approved_by="2",
        approved_at=NOW,
        effective_from=NOW - timedelta(days=30),
        effective_to=effective_to,
        review_at=review_at,
        decision_reference=decision_reference,
    )


def test_org_policy_resolves_when_nothing_more_specific_exists():
    db = DummyDB([_policy("organisation", answers={"downtime": 1})])

    resolved = svc.resolve_process_appetite(db, organization_id=7, process_id="proc-1", at=NOW)

    assert resolved is not None
    assert resolved.source_scope == "organisation"
    assert resolved.answers == {"downtime": 1}


def test_process_override_beats_org_policy():
    db = DummyDB([
        _policy("organisation", answers={"downtime": 1}),
        _policy("business_process", process_id="proc-1", answers={"downtime": 3}),
    ])

    resolved = svc.resolve_process_appetite(db, organization_id=7, process_id="proc-1", at=NOW)

    assert resolved.source_scope == "business_process"
    assert resolved.answers == {"downtime": 3}
    # A different process still resolves from the org policy.
    other = svc.resolve_process_appetite(db, organization_id=7, process_id="proc-2", at=NOW)
    assert other.source_scope == "organisation"


def test_valid_decision_exception_beats_everything_and_carries_its_window():
    expiry = NOW + timedelta(days=14)
    db = DummyDB([
        _policy("organisation"),
        _policy("business_process", process_id="proc-1"),
        _policy(
            "decision_exception",
            process_id="proc-1",
            answers={"downtime": 4},
            effective_to=expiry,
            review_at=expiry,
            decision_reference="decision-42",
        ),
    ])

    resolved = svc.resolve_process_appetite(db, organization_id=7, process_id="proc-1", at=NOW)

    assert resolved.source_scope == "decision_exception"
    assert resolved.effective_to == expiry
    assert resolved.decision_reference == "decision-42"


def test_expired_exception_is_ignored_but_surfaced():
    db = DummyDB([
        _policy("organisation", answers={"downtime": 1}),
        _policy(
            "decision_exception",
            process_id="proc-1",
            effective_to=NOW - timedelta(days=1),
            review_at=NOW - timedelta(days=1),
            decision_reference="decision-lapsed",
        ),
    ])

    resolved = svc.resolve_process_appetite(db, organization_id=7, process_id="proc-1", at=NOW)

    # Resolution falls back to the org policy; the lapse is not silent.
    assert resolved.source_scope == "organisation"
    assert resolved.expired_exception_reference == "decision-lapsed"


def test_missing_appetite_resolves_to_nothing_never_inferred():
    assert svc.resolve_process_appetite(DummyDB(), organization_id=7, process_id="proc-1", at=NOW) is None


def test_write_supersedes_previous_active_version():
    predecessor = _policy("business_process", process_id="proc-1", version=3)
    db = DummyDB([predecessor])

    policy = svc.set_appetite_policy(
        db,
        organization_id=7,
        scope="business_process",
        process_id="proc-1",
        answers={"downtime": 2},
        approved_by="2",
    )

    assert policy.version == 4
    assert predecessor.status == APPETITE_POLICY_SUPERSEDED
    assert predecessor.superseded_by_id == policy.id


def test_organisation_appetite_requires_the_draft_and_leadership_review_lifecycle():
    predecessor = _policy("organisation", version=3)
    db = DummyDB([predecessor])
    review_at = datetime.now(timezone.utc) + timedelta(days=90)

    draft = svc.create_appetite_draft(
        db,
        organization_id=7,
        scope="organisation",
        answers={"downtime": 2},
        prepared_by="1",
        review_at=review_at,
    )

    assert draft.status == APPETITE_POLICY_DRAFT
    assert draft.approved_by is None
    assert draft.version == 4
    assert svc.resolve_process_appetite(db, organization_id=7, process_id="proc-1", at=NOW)
    with pytest.raises(svc.AppetitePolicyValidationError):
        svc.approve_appetite_draft(
            db,
            draft,
            approved_by="2",
            approval_reference="governance-record-1",
        )

    svc.submit_appetite_draft(db, draft, submitted_by="1")
    assert draft.status == APPETITE_POLICY_LEADERSHIP_REVIEW
    svc.approve_appetite_draft(
        db,
        draft,
        approved_by="2",
        approval_reference="governance-record-1",
    )

    assert draft.status == APPETITE_POLICY_ACTIVE
    assert draft.approved_by == "2"
    assert predecessor.status == APPETITE_POLICY_SUPERSEDED


def test_direct_organisation_appetite_write_is_rejected():
    with pytest.raises(svc.AppetitePolicyValidationError):
        svc.set_appetite_policy(
            DummyDB(),
            organization_id=7,
            scope="organisation",
            answers={"downtime": 2},
            approved_by="2",
        )


def test_exception_requires_expiry_and_review_date():
    with pytest.raises(svc.AppetitePolicyValidationError):
        svc.set_appetite_policy(
            DummyDB(),
            organization_id=7,
            scope="decision_exception",
            process_id="proc-1",
            answers={"downtime": 4},
            approved_by="2",
        )


def test_scope_invariants_are_enforced():
    with pytest.raises(svc.AppetitePolicyValidationError):
        svc.set_appetite_policy(
            DummyDB(), organization_id=7, scope="business_process", answers={"downtime": 2}, approved_by="2",
        )
    with pytest.raises(svc.AppetitePolicyValidationError):
        svc.set_appetite_policy(
            DummyDB(), organization_id=7, scope="organisation", process_id="proc-1",
            answers={"downtime": 2}, approved_by="2",
        )
    with pytest.raises(svc.AppetitePolicyValidationError):
        svc.set_appetite_policy(
            DummyDB(), organization_id=7, scope="organisation", answers={}, approved_by="2",
        )
