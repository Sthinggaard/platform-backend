"""#363 — the scanner's suggestions name an artefact in the one stored spelling.

``slot_mapping_suggestion_service`` wrote ``asset_id=str(asset.id)`` — ``"92"`` —
into every suggestion. Accepting one carried the digit string into slot rows and
bundle links beside ``"asset-92"``: that is where the second spelling came from
(traced 2026-09-13 from ``slot_instances`` provenance on the development database).

The module's own suite, ``test_slot_mapping_suggestions.py``, is skipped under #353,
so the matcher had no running test at all. These call it directly. The refutation
tests run against real Postgres, because a refusal is read back out of the
append-only decision log, and a refusal recorded before this fix is still spelled
``"92"``.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from src.core.model_defs.assets_runtime import Asset
from src.core.models import MappingDecision, Organization
from src.core.services.slot_mapping_refutation_service import Refutation, load_refutations
from src.core.services.slot_mapping_suggestion_service import _best_match
from src.core.template_models import SlotTemplate

SLOT_ID = "external_provider"


def _slot() -> SlotTemplate:
    return SlotTemplate(
        slot_id=SLOT_ID,
        label="External Service Provider",
        capability_group_key="external_providers",
        matching_hints=["stripe"],
        expected_asset_types=["Third-Party API"],
    )


def _asset(asset_id: int = 92, **overrides: object) -> Asset:
    values: dict[str, object] = {
        "id": asset_id,
        "organization_id": 1,
        "type": "Third-Party API",
        "provider": "stripe",
        "display_name": "Stripe",
        "layer": "L2",
    }
    values.update(overrides)
    return Asset(**values)


def _refused(asset_id: str) -> dict[tuple[str, str], Refutation]:
    return {
        (SLOT_ID, asset_id): Refutation(
            slot_id=SLOT_ID, asset_id=asset_id, reason_code="wrong_asset"
        )
    }


def _record_refusal(
    db_session: Session,
    organization_id: int,
    *,
    asset_id: object,
    reason_code: str = "wrong_asset",
) -> None:
    db_session.add(
        MappingDecision(
            organization_id=organization_id,
            service_id=str(uuid4()),
            bundle_id=str(uuid4()),
            action="reject_slot_mapping",
            group_key="external_providers",
            before_state={"slot_id": SLOT_ID, "asset_id": asset_id},
            after_state={"mapping_status": "rejected", "reason_code": reason_code},
        )
    )
    db_session.flush()


# ─── The matcher ──────────────────────────────────────────────────────────────


def test_a_suggestion_names_its_artefact_in_the_one_stored_spelling():
    """⚠️ The source of #363's digit strings, pinned."""
    suggestion = _best_match(_slot(), [_asset()])

    assert suggestion is not None
    assert suggestion.asset_id == "asset-92"


def test_a_refusal_rules_out_the_artefact_the_engine_now_names():
    assert _best_match(_slot(), [_asset()], _refused("asset-92")) is None


def test_refusing_one_artefact_still_offers_the_next():
    refused = _asset(92)
    better = _asset(93, display_name="Stripe Payments")

    suggestion = _best_match(_slot(), [refused, better], _refused("asset-92"))

    assert suggestion is not None
    assert suggestion.asset_id == "asset-93"


# ─── Refusals read back from the decision log ─────────────────────────────────


@pytest.mark.parametrize("recorded", ["92", "asset-92", 92])
def test_a_refusal_in_any_recorded_spelling_rules_out_the_same_artefact(
    db_session: Session, sample_organization: Organization, recorded: object
):
    """A refusal recorded before the fix says ``"92"``; the engine now names
    ``"asset-92"``. Unless the log is read in the one spelling, every refusal made
    before the fix would silently stop working."""
    _record_refusal(db_session, sample_organization.id, asset_id=recorded)

    refuted = load_refutations(db_session, organization_id=sample_organization.id)

    assert set(refuted) == {(SLOT_ID, "asset-92")}
    assert _best_match(_slot(), [_asset()], refuted) is None


@pytest.mark.parametrize("unusable", ["", None, "asset-"])
def test_a_refusal_that_cannot_name_an_artefact_refutes_nothing(
    db_session: Session, sample_organization: Organization, unusable: object
):
    _record_refusal(db_session, sample_organization.id, asset_id=unusable)

    assert load_refutations(db_session, organization_id=sample_organization.id) == {}


def test_only_a_wrong_asset_refusal_refutes(db_session: Session, sample_organization: Organization):
    _record_refusal(db_session, sample_organization.id, asset_id="92", reason_code="low_confidence")

    assert load_refutations(db_session, organization_id=sample_organization.id) == {}


def test_another_organisations_refusal_refutes_nothing_here(
    db_session: Session, sample_organization: Organization
):
    other = Organization(name="Other Org", slug=f"other-org-{uuid4().hex[:8]}")
    db_session.add(other)
    db_session.flush()
    _record_refusal(db_session, other.id, asset_id="92")

    assert load_refutations(db_session, organization_id=sample_organization.id) == {}
