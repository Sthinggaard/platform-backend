"""Scenario output must wait for an active Business Process context."""

from types import SimpleNamespace

from src.api.routes import scenarios


def test_active_process_asset_names_exclude_unactivated_processes(monkeypatch):
    records = {
        "ValueStream": [SimpleNamespace(id="process-1")],
        "BusinessService": [
            SimpleNamespace(
                id="service-1",
                value_stream_ids=["process-1"],
                archived_at=None,
                l1=["asset-1"],
                l2=[],
                l3=[],
            )
        ],
        "Asset": [SimpleNamespace(id="asset-1", display_name="Payment Gateway")],
    }

    class Repository:
        def __init__(_self, _db, model, _organization_id):
            _self.model = model

        def get_all(_self):
            return records[_self.model.__name__]

    monkeypatch.setattr(scenarios, "TenantRepository", Repository)
    monkeypatch.setattr(
        scenarios,
        "resolve_process_activation_readiness",
        lambda *_args, **_kwargs: {
            "process-1": SimpleNamespace(impact_model_active=False),
        },
    )

    assert scenarios._active_process_asset_names(object(), 7) == set()

    monkeypatch.setattr(
        scenarios,
        "resolve_process_activation_readiness",
        lambda *_args, **_kwargs: {
            "process-1": SimpleNamespace(impact_model_active=True),
        },
    )
    assert scenarios._active_process_asset_names(object(), 7) == {"payment gateway"}
