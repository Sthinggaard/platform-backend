from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import SecretStr
from starlette.requests import Request

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import template_governance


def _request(secret: str | None = None) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if secret is not None:
        headers.append(
            (
                template_governance.SCHEDULED_TRIGGER_SECRET_HEADER.encode("utf-8"),
                secret.encode("utf-8"),
            )
        )
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": template_governance.TEMPLATE_GOVERNANCE_SCHEDULED_RUN_PATH,
            "headers": headers,
        }
    )


def _org_admin_ctx(organization_id: int = 42) -> TenantContext:
    return TenantContext(
        user_id=1,
        organization_id=organization_id,
        email="admin@tenant.test",
        roles=["org_admin"],
        permissions=[],
    )


def _run(*, triggered_by: str) -> SimpleNamespace:
    return SimpleNamespace(
        id="run-1",
        status="completed",
        triggered_by=triggered_by,
        service_keys_analysed=["order_management"],
        candidates_generated=2,
        candidates_auto_staged=1,
        summary={"per_service": {"order_management": {"candidate_created": True}}},
        error=None,
        started_at=datetime(2026, 4, 13, 8, 0, tzinfo=timezone.utc),
        finished_at=datetime(2026, 4, 13, 8, 5, tzinfo=timezone.utc),
    )


def test_trigger_scheduled_learning_run_accepts_valid_secret(monkeypatch):
    monkeypatch.setattr(
        template_governance.settings.template_governance,
        "scheduled_trigger_secret",
        SecretStr("cron-secret"),
    )
    calls: list[dict[str, object]] = []

    def fake_run_learning_analysis(db, service_keys=None, triggered_by="manual"):
        calls.append(
            {
                "db": db,
                "service_keys": service_keys,
                "triggered_by": triggered_by,
            }
        )
        return _run(triggered_by=triggered_by)

    monkeypatch.setattr(template_governance, "run_learning_analysis", fake_run_learning_analysis)
    db = object()

    result = template_governance.trigger_scheduled_learning_run(_request("cron-secret"), db)

    assert result.triggered_by == "scheduled"
    assert calls == [
        {
            "db": db,
            "service_keys": None,
            "triggered_by": "scheduled",
        }
    ]


def test_trigger_scheduled_learning_run_rejects_invalid_secret(monkeypatch):
    monkeypatch.setattr(
        template_governance.settings.template_governance,
        "scheduled_trigger_secret",
        SecretStr("cron-secret"),
    )

    with pytest.raises(HTTPException) as exc_info:
        template_governance.trigger_scheduled_learning_run(_request("wrong-secret"), object())

    assert exc_info.value.status_code == 403


def test_trigger_scheduled_learning_run_requires_configured_secret(monkeypatch):
    monkeypatch.setattr(
        template_governance.settings.template_governance,
        "scheduled_trigger_secret",
        None,
    )

    with pytest.raises(HTTPException) as exc_info:
        template_governance.trigger_scheduled_learning_run(_request(None), object())

    assert exc_info.value.status_code == 503


# ── A1 security remediation regression tests ────────────────────────────────
#
# Newly-discovered Critical finding alongside H1/H2: every route below except
# list_upgrades is platform-wide (no organization_id on ServiceTemplate at
# all), but was gated only by ctx.is_admin() — satisfied by any paying
# customer's own org_admin — and the tenant Settings UI actually wired the
# whole surface into ordinary customer navigation (RiskTemplateGovernance,
# SettingsContainer.tsx). approve_candidate in particular published a new
# active ServiceTemplate version platform-wide, meaning any single tenant's
# admin could change what every other tenant saw as their "current" template.
# These tests prove an ordinary org_admin — from any organisation — can no
# longer reach any of these routes without the platform operator secret.

def test_trigger_learning_run_rejects_org_admin_without_operator_secret(monkeypatch):
    monkeypatch.setattr(
        template_governance.settings.template_governance, "scheduled_trigger_secret", None
    )

    with pytest.raises(HTTPException) as exc_info:
        template_governance.trigger_learning_run(
            request=_request(None),
            body=template_governance.TriggerRunRequest(),
            ctx=_org_admin_ctx(),
            db=object(),
        )

    assert exc_info.value.status_code == 503


def test_list_learning_runs_rejects_org_admin_without_operator_secret(monkeypatch):
    monkeypatch.setattr(
        template_governance.settings.template_governance, "scheduled_trigger_secret", None
    )

    with pytest.raises(HTTPException) as exc_info:
        template_governance.list_learning_runs(
            request=_request(None), ctx=_org_admin_ctx(), db=object()
        )

    assert exc_info.value.status_code == 503


def test_list_candidates_rejects_org_admin_without_operator_secret(monkeypatch):
    monkeypatch.setattr(
        template_governance.settings.template_governance, "scheduled_trigger_secret", None
    )

    with pytest.raises(HTTPException) as exc_info:
        template_governance.list_candidates(
            request=_request(None), ctx=_org_admin_ctx(), db=object()
        )

    assert exc_info.value.status_code == 503


def test_approve_candidate_rejects_org_admin_without_operator_secret(monkeypatch):
    """Direct regression test for the Critical finding: a customer admin
    could previously publish a new platform-wide active ServiceTemplate
    version via this route. Must now be denied before the candidate is
    even looked up, regardless of which organisation the caller belongs to.
    """
    monkeypatch.setattr(
        template_governance.settings.template_governance, "scheduled_trigger_secret", None
    )
    published: list[str] = []
    monkeypatch.setattr(
        template_governance,
        "publish_candidate",
        lambda *a, **k: published.append("published"),
    )

    with pytest.raises(HTTPException) as exc_info:
        template_governance.approve_candidate(
            request=_request(None),
            candidate_id="candidate-1",
            body=template_governance.ReviewRequest(),
            ctx=_org_admin_ctx(),
            db=object(),
        )

    assert exc_info.value.status_code == 503
    assert published == []


def test_reject_candidate_rejects_org_admin_without_operator_secret(monkeypatch):
    monkeypatch.setattr(
        template_governance.settings.template_governance, "scheduled_trigger_secret", None
    )

    with pytest.raises(HTTPException) as exc_info:
        template_governance.reject_candidate_endpoint(
            request=_request(None),
            candidate_id="candidate-1",
            body=template_governance.ReviewRequest(),
            ctx=_org_admin_ctx(),
            db=object(),
        )

    assert exc_info.value.status_code == 503


def test_approve_candidate_succeeds_with_correct_operator_secret(monkeypatch):
    """Confirms the fix denies by default but does not break the real
    platform-operator workflow when the secret is actually supplied."""
    monkeypatch.setattr(
        template_governance.settings.template_governance,
        "scheduled_trigger_secret",
        SecretStr("cron-secret"),
    )
    candidate = SimpleNamespace(id="candidate-1", status="pending")

    class FakeQuery:
        def filter(self, *a, **k):
            return self

        def first(self):
            return candidate

    class FakeDb:
        def query(self, *a, **k):
            return FakeQuery()

        def refresh(self, *a, **k):
            pass

    calls: list[str] = []
    monkeypatch.setattr(
        template_governance,
        "publish_candidate",
        lambda db, c, reviewed_by, review_note: calls.append(reviewed_by),
    )
    monkeypatch.setattr(
        template_governance,
        "_candidate_to_response",
        lambda c: SimpleNamespace(id=c.id),
    )

    response = template_governance.approve_candidate(
        request=_request("cron-secret"),
        candidate_id="candidate-1",
        body=template_governance.ReviewRequest(),
        ctx=_org_admin_ctx(),
        db=FakeDb(),
    )

    assert response.id == "candidate-1"
    assert calls == ["admin@tenant.test"]


def test_list_upgrades_unaffected_by_operator_secret_gate(monkeypatch):
    """list_upgrades is genuinely per-org (get_upgrades_for_org filters by
    ctx.organization_id) and is the one real customer-facing feature in this
    module — the security fix must not require the operator secret here."""
    monkeypatch.setattr(
        template_governance, "get_upgrades_for_org", lambda db, org_id: [
            {
                "service_id": "svc-1",
                "service_name": "Checkout",
                "service_key": "checkout",
                "current_version": 1,
                "latest_version": 2,
            }
        ]
    )

    result = template_governance.list_upgrades(ctx=_org_admin_ctx(), db=object())

    assert len(result) == 1
    assert result[0].service_key == "checkout"
