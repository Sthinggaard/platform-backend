from datetime import datetime, timezone

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import appetite
from src.core.models import Asset, AssetAppetiteConfig


class DummyQuery:
    def __init__(self, result):
        self._result = result

    def filter(self, *_args, **_kwargs):
        return self

    def first(self):
        return self._result


class DummyDB:
    def __init__(self, config):
        self._config = config

    def get(self, model, asset_id):
        if model is Asset and asset_id == 7:
            return Asset(id=7, organization_id=42, display_name="Payment Processing App", layer="Application")
        return None

    def query(self, model):
        if model is AssetAppetiteConfig:
            return DummyQuery(self._config)
        raise AssertionError(f"Unexpected model query: {model}")


def _ctx() -> TenantContext:
    return TenantContext(
        user_id=7,
        organization_id=42,
        email="ciso@risklence.test",
        roles=["ciso"],
        permissions=[],
    )


def test_get_asset_appetite_history_returns_history_items():
    config = AssetAppetiteConfig(
        organization_id=42,
        asset_id=7,
        answers={"dataLoss": 1},
        approved_by="Board Risk Committee",
        approved_at=datetime.now(timezone.utc),
        version=3,
        note="Current version",
        history=[
            {
                "version": 1,
                "approvedBy": "Board Risk Committee",
                "timestamp": "15 Jan 2026",
                "note": "Initial baseline",
                "answers": {"dataLoss": 0, "downtime": 1},
            },
            {
                "version": 2,
                "approvedBy": "Senior Management",
                "timestamp": "12 Feb 2026",
                "note": "Tightened downtime tolerance",
                "answers": {"dataLoss": 0, "downtime": 0},
            },
        ],
    )

    response = appetite.get_asset_appetite_history(
        asset_id=7,
        ctx=_ctx(),
        db=DummyDB(config),
    )

    assert len(response) == 2
    assert response[0].version == 1
    assert response[0].approvedBy == "Board Risk Committee"
    assert response[1].note == "Tightened downtime tolerance"


def test_get_asset_appetite_history_returns_empty_list_when_unconfigured():
    response = appetite.get_asset_appetite_history(
        asset_id=7,
        ctx=_ctx(),
        db=DummyDB(None),
    )

    assert response == []


def test_build_response_keeps_approved_at_as_api_timestamp():
    approved_at = datetime(2026, 5, 17, 13, 45, tzinfo=timezone.utc)
    config = AssetAppetiteConfig(
        organization_id=42,
        asset_id=7,
        answers={"dataLoss": 1},
        approved_by="Board Risk Committee",
        approved_at=approved_at,
        version=1,
        note="Current version",
        history=[],
    )
    asset = Asset(id=7, organization_id=42, display_name="Payment Processing App", layer="Application")

    response = appetite._build_response(config, asset)

    assert response.approvedAt == approved_at
    assert response.model_dump(mode="json")["approvedAt"] == "2026-05-17T13:45:00+00:00"
