"""Dashboard slice 4 — lapsed reviews reopen the Business Process evaluation."""

from datetime import datetime
from types import SimpleNamespace

from src.core.model_defs.risk_appetite_policy import RiskAppetitePolicy
from src.core.services import review_reopening_service as svc
from src.core.services.risk_appetite_resolution_service import ResolvedProcessAppetite
from src.core.services.risk_evaluation_service import evaluate_process

NOW = datetime(2026, 7, 12, 12, 0, 0)


def test_parse_review_date_tolerates_common_formats():
    assert svc._parse_review_date("2026-07-01") == datetime(2026, 7, 1)
    assert svc._parse_review_date("2026-07-01T09:30:00") is not None
    assert svc._parse_review_date(None) is None
    assert svc._parse_review_date("not-a-date") is None


def _appetite(answers=None):
    return ResolvedProcessAppetite(
        answers=answers or {"downtime": 2},
        source_scope="organisation",
        policy_id="pol-1",
        version=1,
        approved_by="2",
        effective_from=datetime(2026, 1, 1),
        effective_to=None,
        review_at=None,
        decision_reference=None,
    )


COMPLETE_BIA = {
    "impact1h": "medium",
    "impact4h": "high",
    "impact24h": "severe",
    "mtd": "le_4h",
    "dataSensitivity": "medium",
    "workaround": "partial",
    "alternativeChannel": "partial",
}


def test_overdue_review_removes_within_appetite_and_prepared_claims():
    process = SimpleNamespace(
        id="proc-1", organization_id=7, name="Billing", bia_answers=COMPLETE_BIA
    )
    service = SimpleNamespace(
        id="svc-1",
        name="Billing",
        bia_answers=None,
        value_stream_ids=["proc-1"],
        l1=["1"],
        l2=[],
        l3=[],
        archived_at=None,
    )
    threat = SimpleNamespace(id="t-1", status="kept-safe", severity="high", asset="Payment Gateway")
    verification = SimpleNamespace(verification_status="verified_successful", created_at=NOW)

    evaluation, _ = evaluate_process(
        process=process,
        services=[service],
        asset_name_by_id={"1": "payment gateway"},
        threats=[threat],
        decisions_by_threat_id={"t-1": [SimpleNamespace(id="d-1")]},
        latest_verification_by_threat_id={"t-1": verification},
        published_bundle_service_ids={"svc-1"},
        resolved_appetite=_appetite(),
        process_bia_answers=COMPLETE_BIA,
        bia_exceptions={},
        overdue_reviews=[{"decision_reference": "d-9", "review_due_at": "2026-07-01"}],
    )

    # Without the lapse this would be within_appetite/prepared — the lapse removes both.
    assert evaluation.status == "approaching_appetite"
    assert evaluation.preparedness == "partially_prepared"
    assert evaluation.evidence_snapshot["overdue_review_count"] == 1
    assert "lapsed without verified evidence" in evaluation.residual["explanation"]
    assert "d-9" in evaluation.explanation[-1]["text"]


class _Query:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *_a, **_k):
        return self

    def all(self):
        return list(self._rows)


class _DB:
    """Routes model queries for find_overdue_reviews."""

    def __init__(
        self,
        *,
        decisions=(),
        verifications=(),
        threats=(),
        assets=(),
        services=(),
        policies=(),
        reopenings=(),
    ):
        self.rows = {
            "DecisionRecord": list(decisions),
            "VerificationRecord": list(verifications),
            "Threat": list(threats),
            "Asset": list(assets),
            "BusinessService": list(services),
            "RiskAppetitePolicy": list(policies),
            "ReviewReopening": list(reopenings),
        }
        self.added = []

    def query(self, model):
        return _Query(self.rows.get(model.__name__, []))

    def add(self, row):
        self.added.append(row)

    def flush(self):
        pass


def _decision(decision_id="d-1", review_date="2026-07-01", threat_id="t-1"):
    return SimpleNamespace(
        id=decision_id,
        review_date=review_date,
        threat_id=threat_id,
        selected_action="accepted",
        decided_by="coo@risklence.com",
    )


def _org_data(**overrides):
    data = dict(
        decisions=[_decision()],
        verifications=[],
        threats=[
            SimpleNamespace(id="t-1", asset="Payment Gateway", status="accepted", severity="high")
        ],
        assets=[SimpleNamespace(id=1, display_name="Payment Gateway")],
        services=[
            SimpleNamespace(
                id="svc-1",
                value_stream_ids=["proc-1"],
                l1=["1"],
                l2=[],
                l3=[],
                archived_at=None,
            )
        ],
        policies=[],
        reopenings=[],
    )
    data.update(overrides)
    return data


def test_finds_lapsed_decision_review_mapped_to_its_process():
    db = _DB(**_org_data())

    overdue = svc.find_overdue_reviews(db, organization_id=7, at=NOW)

    assert len(overdue) == 1
    item = overdue[0]
    assert item.source == "decision_review"
    assert item.process_id == "proc-1"
    assert item.decision_reference == "d-1"
    assert item.review_owner == "coo@risklence.com"


def test_verified_threats_do_not_reopen():
    db = _DB(
        **_org_data(
            verifications=[
                SimpleNamespace(threat_id="t-1", verification_status="verified_successful"),
            ]
        )
    )
    assert svc.find_overdue_reviews(db, organization_id=7, at=NOW) == []


def test_future_review_dates_do_not_reopen():
    db = _DB(**_org_data(decisions=[_decision(review_date="2026-08-01")]))
    assert svc.find_overdue_reviews(db, organization_id=7, at=NOW) == []


def test_already_reopened_references_are_idempotent():
    db = _DB(
        **_org_data(
            reopenings=[
                SimpleNamespace(
                    process_id="proc-1",
                    source="decision_review",
                    decision_reference="d-1",
                    review_due_at="2026-07-01",
                ),
            ]
        )
    )
    assert svc.find_overdue_reviews(db, organization_id=7, at=NOW) == []


def test_lapsed_appetite_exception_reopens_its_process():
    policy = RiskAppetitePolicy(
        id="pol-exc",
        organization_id=7,
        scope="decision_exception",
        process_id="proc-1",
        answers={"downtime": 3},
        status="active",
        version=1,
        approved_by="2",
        approved_at=NOW,
        effective_from=datetime(2026, 6, 1),
        effective_to=datetime(2026, 7, 1),
        review_at=datetime(2026, 6, 25),
        decision_reference="decision-migration-42",
    )
    db = _DB(**_org_data(decisions=[], policies=[policy]))

    overdue = svc.find_overdue_reviews(db, organization_id=7, at=NOW)

    assert len(overdue) == 1
    assert overdue[0].source == "appetite_exception"
    assert overdue[0].decision_reference == "decision-migration-42"
    assert "expired on" in overdue[0].description


def test_open_reopenings_remain_outstanding_until_verified_or_renewed():
    reopening = SimpleNamespace(
        process_id="proc-1",
        source="decision_review",
        decision_reference="d-1",
        review_due_at="2026-07-01",
        review_owner="coo@risklence.com",
    )
    # Already reopened, threat still unverified → stays outstanding.
    db = _DB(**_org_data(reopenings=[reopening]))
    outstanding = svc.find_outstanding_reviews(db, organization_id=7, at=NOW)
    assert len(outstanding) == 1
    assert "Reopened" in outstanding[0].description

    # Evidence arrived → resolved, disappears.
    db = _DB(
        **_org_data(
            reopenings=[reopening],
            verifications=[
                SimpleNamespace(threat_id="t-1", verification_status="verified_successful")
            ],
        )
    )
    assert svc.find_outstanding_reviews(db, organization_id=7, at=NOW) == []

    # A newer decision on the same threat with a future review date supersedes it.
    db = _DB(
        **_org_data(
            reopenings=[reopening],
            decisions=[_decision(), _decision(decision_id="d-2", review_date="2026-09-01")],
        )
    )
    outstanding = svc.find_outstanding_reviews(db, organization_id=7, at=NOW)
    assert all(
        o.decision_reference != "d-1" or "Reopened" not in o.description for o in outstanding
    )
