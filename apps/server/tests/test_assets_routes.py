from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import assets
from src.core.models import Asset, AssetEvidenceSignal


class DummyScalars:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class DummyResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return DummyScalars(self._rows)


class DummyDB:
    def __init__(self, rows):
        self._rows = rows

    def execute(self, _query):
        return DummyResult(self._rows)


def _ctx() -> TenantContext:
    return TenantContext(
        user_id=7,
        organization_id=42,
        email="ciso@risklence.test",
        roles=["ciso"],
        permissions=[],
    )


def test_list_org_signals_returns_asset_metadata():
    asset = Asset(
        id=7,
        organization_id=42,
        display_name="Payment Processing App",
        type="Application",
        layer="Application",
    )
    signal = AssetEvidenceSignal(
        id=11,
        organization_id=42,
        asset_id=7,
        kind="backup_failure",
        payload_json={"message": "Backup validation below threshold"},
        observed_at=datetime(2026, 3, 29, 9, 30, tzinfo=timezone.utc),
        confidence=0.91,
        risk_score=73.0,
    )
    signal.asset = asset

    response = assets.list_org_signals(db=DummyDB([signal]), tenant=_ctx())

    assert len(response) == 1
    assert response[0].asset_id == 7
    assert response[0].asset_name == "Payment Processing App"
    assert response[0].asset_type == "Application"
    assert response[0].kind == "backup_failure"


def test_list_org_signals_rejects_cross_tenant_scope():
    with pytest.raises(HTTPException) as exc:
        assets.list_org_signals(org_id=99, db=DummyDB([]), tenant=_ctx())

    assert exc.value.status_code == 403


def test_list_assets_returns_existing_rows_without_seeding(monkeypatch):
    org = type("Org", (), {"id": 42})()
    asset = Asset(
        id=7,
        organization_id=42,
        display_name="Payment Processing App",
        type="Application",
        layer="Application",
    )

    monkeypatch.setattr(assets, "ensure_seed_org", lambda _db: org)
    monkeypatch.setattr(assets, "_resolve_scoped_org_id", lambda requested_org_id, tenant, fallback_org_id=None: 42)
    monkeypatch.setattr(assets, "seed_assets", lambda *args, **kwargs: pytest.fail("seed_assets should not run for GET /assets"))

    response = assets.list_assets(db=DummyDB([asset]), tenant=_ctx())

    assert len(response) == 1
    assert response[0].id == 7
    assert response[0].display_name == "Payment Processing App"
