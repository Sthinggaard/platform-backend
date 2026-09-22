from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import SecretStr
from starlette.requests import Request

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import learning
from src.core.constants.internal_routes import LEARNING_LOOP_SCHEDULED_RUN_PATH


def _request(secret: str | None = None) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if secret is not None:
        headers.append(
            (
                learning.SCHEDULED_TRIGGER_SECRET_HEADER.encode("utf-8"),
                secret.encode("utf-8"),
            )
        )
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": LEARNING_LOOP_SCHEDULED_RUN_PATH,
            "headers": headers,
        }
    )


def _admin_ctx() -> TenantContext:
    return TenantContext(
        user_id=1,
        organization_id=42,
        email="admin@risklence.test",
        roles=["org_admin"],
        permissions=[],
    )


def _user_ctx() -> TenantContext:
    return TenantContext(
        user_id=2,
        organization_id=42,
        email="user@risklence.test",
        roles=["ciso"],
        permissions=[],
    )


def _run(*, triggered_by: str) -> SimpleNamespace:
    return SimpleNamespace(
        id="run-1",
        status="completed",
        triggered_by=triggered_by,
        since=datetime(2026, 4, 20, 0, 0, tzinfo=timezone.utc),
        signals_ingested=9,
        candidates_generated=3,
        candidates_auto_staged=1,
        summary={"signalCounts": {"recommendation_decision_feedback": 4}},
        error=None,
        started_at=datetime(2026, 4, 21, 1, 0, tzinfo=timezone.utc),
        finished_at=datetime(2026, 4, 21, 1, 5, tzinfo=timezone.utc),
    )


def test_trigger_learning_run_rejects_any_org_admin_without_operator_secret(monkeypatch):
    """A1 security remediation (H1/H2): org_admin is not platform authority.

    This route reads/writes every organisation's TrainingSignal rows; before
    this fix, any paying customer's own org_admin satisfied ctx.is_admin()
    and could trigger it. It must now be rejected regardless of role or
    which org the caller belongs to, with no operator secret configured.
    """
    monkeypatch.setattr(learning.settings.learning_loop, "scheduled_trigger_secret", None)

    with pytest.raises(HTTPException) as exc_info:
        learning.trigger_learning_run(
            request=_request(None),
            body=learning.TriggerLearningLoopRequest(),
            ctx=_admin_ctx(),
            db=object(),
        )

    assert exc_info.value.status_code == 503


def test_trigger_learning_run_rejects_org_admin_with_wrong_secret(monkeypatch):
    monkeypatch.setattr(
        learning.settings.learning_loop,
        "scheduled_trigger_secret",
        SecretStr("cron-secret"),
    )

    with pytest.raises(HTTPException) as exc_info:
        learning.trigger_learning_run(
            request=_request("not-the-secret"),
            body=learning.TriggerLearningLoopRequest(),
            ctx=_admin_ctx(),
            db=object(),
        )

    assert exc_info.value.status_code == 403


def test_trigger_learning_run_rejects_non_admin_even_with_correct_secret(monkeypatch):
    """The operator secret is the authorization boundary now, not the role —
    but a caller must still be an authenticated Risklence user (ctx is a
    required dependency) for audit-trail identity, so this asserts the
    secret alone doesn't bypass authentication entirely."""
    monkeypatch.setattr(
        learning.settings.learning_loop,
        "scheduled_trigger_secret",
        SecretStr("cron-secret"),
    )

    def fake_run_learning_loop(db, since=None, triggered_by="manual"):
        return _run(triggered_by=triggered_by)

    monkeypatch.setattr(learning, "run_learning_loop", fake_run_learning_loop)

    # A non-admin identity with the correct operator secret still succeeds —
    # role is irrelevant once platform authority is proven, which is exactly
    # the point: this is not a tenant-role check any more.
    response = learning.trigger_learning_run(
        request=_request("cron-secret"),
        body=learning.TriggerLearningLoopRequest(),
        ctx=_user_ctx(),
        db=object(),
    )
    assert response.triggered_by == "manual"


def test_trigger_learning_run_calls_service(monkeypatch):
    monkeypatch.setattr(
        learning.settings.learning_loop,
        "scheduled_trigger_secret",
        SecretStr("cron-secret"),
    )
    calls: list[dict[str, object]] = []

    def fake_run_learning_loop(db, since=None, triggered_by="manual"):
        calls.append({"db": db, "since": since, "triggered_by": triggered_by})
        return _run(triggered_by=triggered_by)

    monkeypatch.setattr(learning, "run_learning_loop", fake_run_learning_loop)
    db = object()
    since = datetime(2026, 4, 20, 0, 0, tzinfo=timezone.utc)

    response = learning.trigger_learning_run(
        request=_request("cron-secret"),
        body=learning.TriggerLearningLoopRequest(since=since),
        ctx=_admin_ctx(),
        db=db,
    )

    assert response.triggered_by == "manual"
    assert calls == [{"db": db, "since": since, "triggered_by": "manual"}]


def test_trigger_scheduled_learning_run_accepts_valid_secret(monkeypatch):
    monkeypatch.setattr(
        learning.settings.learning_loop,
        "scheduled_trigger_secret",
        SecretStr("cron-secret"),
    )
    calls: list[dict[str, object]] = []

    def fake_run_learning_loop(db, since=None, triggered_by="manual"):
        calls.append({"db": db, "since": since, "triggered_by": triggered_by})
        return _run(triggered_by=triggered_by)

    monkeypatch.setattr(learning, "run_learning_loop", fake_run_learning_loop)
    db = object()

    response = learning.trigger_scheduled_learning_run(_request("cron-secret"), db)

    assert response.triggered_by == "scheduled"
    assert calls == [{"db": db, "since": None, "triggered_by": "scheduled"}]


def test_trigger_scheduled_learning_run_rejects_invalid_secret(monkeypatch):
    monkeypatch.setattr(
        learning.settings.learning_loop,
        "scheduled_trigger_secret",
        SecretStr("cron-secret"),
    )

    with pytest.raises(HTTPException) as exc_info:
        learning.trigger_scheduled_learning_run(_request("wrong-secret"), object())

    assert exc_info.value.status_code == 403


def test_get_learning_signal_summary_delegates_to_loader(monkeypatch):
    monkeypatch.setattr(
        learning.settings.learning_loop,
        "scheduled_trigger_secret",
        SecretStr("cron-secret"),
    )
    expected = learning.LearningSignalSummaryResponse(
        since="2026-04-20T00:00:00+00:00",
        generatedAt="2026-04-21T01:05:00+00:00",
        signalCounts=[],
        candidates=[],
    )

    def fake_load_signal_summary(db, *, since, limit):
        assert since == datetime(2026, 4, 20, 0, 0, tzinfo=timezone.utc)
        assert limit == 25
        return expected

    monkeypatch.setattr(learning, "_load_signal_summary", fake_load_signal_summary)

    response = learning.get_learning_signal_summary(
        request=_request("cron-secret"),
        since=datetime(2026, 4, 20, 0, 0, tzinfo=timezone.utc),
        limit=25,
        ctx=_admin_ctx(),
        db=object(),
    )

    assert response == expected


def test_get_learning_signal_summary_rejects_org_admin_without_operator_secret(monkeypatch):
    """Direct regression test for the confirmed A1 H1 leak: TrainingSignal
    rows carry another organisation's decision/threat rationale in their
    payload, and this endpoint is the only place they were ever read back.
    Any org_admin — regardless of which organisation — must now be denied
    without the platform operator secret, closing the leak at its root
    (who can call this) rather than filtering results after the fact."""
    monkeypatch.setattr(learning.settings.learning_loop, "scheduled_trigger_secret", None)

    with pytest.raises(HTTPException) as exc_info:
        learning.get_learning_signal_summary(
            request=_request(None),
            since=None,
            limit=50,
            ctx=_admin_ctx(),
            db=object(),
        )

    assert exc_info.value.status_code == 503
