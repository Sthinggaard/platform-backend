"""#227 — the BFF publishes the API's real constraints, not a weaker copy.

`BusinessContextRequest` typed six fields as `str`/`list[str]` while the API typed
the same six as `StrEnum`s. Three things followed, all observed against staging:

- The BFF's `/openapi.json` — the contract a client actually reads — advertised
  free-form strings, so a client generated from it sent invalid values.
- The BFF accepted them and forwarded them.
- The **API** answered 422, naming Pydantic enum constraints that the client's own
  contract never mentioned. The error surfaced from a layer the client never called.

The fix is that the BFF imports the API's enums rather than restating their type.
These tests assert the two things that were actually wrong: the contract is
published, and an invalid value stops here instead of becoming someone else's 422.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from bff import app as bff_module
from bff.app import BusinessContextRequest

_CONTEXT_FIELDS = (
    "primaryBusinessActivity",
    "criticalBusinessActivity",
    "customerVisibleImpact",
    "timeSensitivity",
    "hardToReplaceQuickly",
    "operationalReach",
)


def test_every_context_field_publishes_its_allowed_values() -> None:
    """A field typed `str` publishes nothing a client can validate against."""
    schema = BusinessContextRequest.model_json_schema()
    published = set(schema.get("$defs", {}))

    assert published == {
        "PrimaryBusinessActivity",
        "CriticalBusinessActivity",
        "CustomerVisibleImpact",
        "TimeSensitivity",
        "HardToReplaceQuickly",
        "OperationalReach",
    }
    for field in _CONTEXT_FIELDS:
        assert field in schema["properties"], f"{field} missing from the published contract"


def test_the_published_values_are_the_api_s_own() -> None:
    """Imported, not copied — a second hand-written list is what drifted before."""
    from src.pretenant.company_context_enums import PrimaryBusinessActivity

    published = BusinessContextRequest.model_json_schema()["$defs"]["PrimaryBusinessActivity"]["enum"]
    assert set(published) == {member.value for member in PrimaryBusinessActivity}


def test_an_invalid_value_is_refused_here_rather_than_forwarded(monkeypatch: pytest.MonkeyPatch) -> None:
    """The defect this ticket exists for: the BFF accepted a value it should have
    known was invalid, and the client learned about it from the API."""
    forwarded: list[dict[str, Any]] = []

    async def fake_upstream_request(**kwargs: Any):
        forwarded.append(kwargs)
        raise AssertionError("an invalid value reached the upstream call")

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    with TestClient(bff_module.app) as client:
        response = client.post(
            "/public/onboarding/sessions/s_1/business-context",
            json={"primaryBusinessActivity": "not_a_real_activity"},
        )

    assert response.status_code == 422
    assert forwarded == [], "the BFF forwarded a value its own contract forbids"


def test_a_valid_value_still_passes_through(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guards the obvious over-correction: rejecting everything would also make
    the test above pass."""
    forwarded: list[dict[str, Any]] = []

    async def fake_upstream_request(**kwargs: Any):
        forwarded.append(kwargs)

        class _Response:
            status_code = 200
            headers: dict[str, str] = {}

            def json(self) -> dict[str, Any]:
                # The route returns the full CvrLookupResponse; a partial stub
                # fails on response validation and says nothing about the request
                # contract this test is actually about.
                return {
                    "sessionId": "s_1",
                    "expiresAt": "2026-02-21T12:00:00Z",
                    "nextStep": "CONFIRM_CONTEXT",
                    "draftOrganisation": {
                        "cvr": "12345678",
                        "legalName": "Risklence A/S",
                        "industry": "62010",
                        "sizeBracket": None,
                        "geography": "DK",
                    },
                    "assumptionPreview": {
                        "archetypeKey": "professional_services",
                        "archetypeLabel": "Professional services",
                        "summary": "A Danish professional-services company.",
                        "headline": "Professional services, Denmark",
                        "source": {"provider": "cvr"},
                        "businessContext": {},
                        "confidence": {"overall": "high"},
                        "completeness": {"score": 0.8},
                    },
                }

        return _Response()

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    with TestClient(bff_module.app) as client:
        response = client.post(
            "/public/onboarding/sessions/s_1/business-context",
            json={"primaryBusinessActivity": "digital_products"},
        )

    assert response.status_code == 200
    assert len(forwarded) == 1
    # This route forwards `by_alias=True` (the signup routes use `by_alias=False`);
    # asserting the wire shape rather than the field name keeps the test honest
    # about what actually leaves the BFF.
    assert forwarded[0]["json_payload"]["primaryBusinessActivity"] == "digital_products"
