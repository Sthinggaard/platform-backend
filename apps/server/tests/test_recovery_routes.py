from datetime import datetime, timezone

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import recovery
from src.core.models import RecoveryAction


class DummyQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def all(self):
        return list(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None


class DummyDB:
    def __init__(self, rows):
        self._rows = rows

    def query(self, model):
        return DummyQuery(self._rows.get(model, []))


def _ctx() -> TenantContext:
    return TenantContext(
        user_id=7,
        organization_id=42,
        email="ciso@risklence.test",
        roles=["ciso"],
        permissions=[],
    )


def test_list_recovery_actions_marks_completed_items_without_resolution_for_capture(monkeypatch):
    action = RecoveryAction(
        id=77,
        organization_id=42,
        threat_id="threat-1",
        title="Fix payment edge",
        issue="Payment traffic is degrading.",
        action="Replace the failing edge device.",
        affected_services=[],
        priority="high",
        status="completed",
        progress=100,
        steps=[],
        created_at=datetime(2026, 4, 20, 9, 5, tzinfo=timezone.utc),
        updated_at=datetime(2026, 4, 20, 9, 5, tzinfo=timezone.utc),
    )
    db = DummyDB({RecoveryAction: [action]})

    monkeypatch.setattr(
        recovery,
        "get_latest_decision_for_recovery_action",
        lambda recovery_action_id, org_id, db_session: None,
    )
    monkeypatch.setattr(
        recovery,
        "get_latest_resolution_for_recovery_action",
        lambda recovery_action_id, org_id, db_session: None,
    )

    response = recovery.list_recovery_actions(ctx=_ctx(), db=db)

    assert len(response) == 1
    assert response[0].requiresResolutionCapture is True
