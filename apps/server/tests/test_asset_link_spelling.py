"""#363 — an asset link is written in one spelling, whichever flow writes it.

The read side was fixed on 2026-08-30 and verified on 2026-09-13. Re-checking it
found the write side still live: the scanner's slot-mapping suggestions wrote an
asset's own id (``"92"``) while the tenant and supersede carry ``"asset-92"``, and
accepting a suggestion stored what it was sent. These tests pin the writers: the
helpers the assign and unassign actions go through, and the request contracts
decide, publish and supersede read. The suggestion service's own fix is pinned in
``test_slot_mapping_suggestions.py``.

Pure: no database. The migration that converges what is already stored has its own
test against Postgres, because its whole job is JSONB SQL.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.api.routes.bundle_contracts import (
    DecideSlotMappingRequest,
    SlotMappingDecision,
    SupersedeSlotMappingRequest,
)
from src.core.services.asset_context_service import (
    link_asset_reference,
    normalise_asset_reference,
    unlink_asset_reference,
)

#: Every spelling an asset link has reached storage in, for the same asset.
SPELLINGS_OF_ASSET_92: list[object] = ["asset-92", "92", 92, " 92 "]


@pytest.mark.parametrize("sent", SPELLINGS_OF_ASSET_92)
def test_assigning_an_asset_stores_it_once_in_the_one_spelling(sent: object):
    reference = normalise_asset_reference(sent)
    assert reference is not None

    assert link_asset_reference(["92"], reference) == ["asset-92"]
    assert link_asset_reference(["asset-92"], reference) == ["asset-92"]


def test_assigning_normalises_the_links_already_on_the_node():
    """Any node a write touches leaves in one spelling — not only the new link."""
    assert link_asset_reference(["asset-7", 5, "92"], "asset-11") == [
        "asset-7",
        "asset-5",
        "asset-92",
        "asset-11",
    ]


def test_one_asset_held_in_two_spellings_is_kept_once_where_it_first_appeared():
    assert link_asset_reference(["92", "asset-7", "asset-92"], "asset-7") == ["asset-92", "asset-7"]


@pytest.mark.parametrize("sent", SPELLINGS_OF_ASSET_92)
@pytest.mark.parametrize("stored", ["asset-92", "92", 92])
def test_unassigning_removes_a_link_however_either_side_spelled_it(sent: object, stored: object):
    """⚠️ The defect: a raw comparison left the other spelling stored."""
    reference = normalise_asset_reference(sent)
    assert reference is not None

    assert unlink_asset_reference([stored, "asset-7"], reference) == ["asset-7"]


def test_unassigning_an_asset_that_is_not_linked_changes_nothing_but_the_spelling():
    assert unlink_asset_reference(["92", "asset-7"], "asset-404") == ["asset-92", "asset-7"]


@pytest.mark.parametrize("unusable", [None, "", "   ", True, "asset-", {"id": 92}])
def test_a_value_that_is_not_an_asset_link_is_never_stored(unusable: object):
    assert link_asset_reference([unusable, "asset-1"], "asset-2") == ["asset-1", "asset-2"]


# ─── Request contracts ───────────────────────────────────────────────────────


@pytest.mark.parametrize("sent", SPELLINGS_OF_ASSET_92)
@pytest.mark.parametrize("contract", [DecideSlotMappingRequest, SlotMappingDecision])
def test_a_slot_decision_carries_the_asset_in_the_one_spelling(contract: type, sent: object):
    fields = {"decision": "mapped", "asset_id": sent}
    if contract is SlotMappingDecision:
        fields["group_key"] = "systems"

    assert contract(**fields).asset_id == "asset-92"


@pytest.mark.parametrize("contract", [DecideSlotMappingRequest, SlotMappingDecision])
@pytest.mark.parametrize("absent", [None, ""])
def test_a_slot_decision_without_an_asset_still_has_none(contract: type, absent: object):
    """No behaviour change for callers that send nothing: an empty value was
    treated as no asset before, and still is."""
    fields = {"decision": "not_applicable", "asset_id": absent}
    if contract is SlotMappingDecision:
        fields["group_key"] = "systems"

    assert contract(**fields).asset_id is None


@pytest.mark.parametrize("sent", SPELLINGS_OF_ASSET_92)
def test_superseding_accepts_either_spelling_and_stores_one(sent: object):
    assert (
        SupersedeSlotMappingRequest(asset_id=sent, reason_code="wrong_asset").asset_id == "asset-92"
    )


@pytest.mark.parametrize("unusable", ["", "   ", None])
def test_superseding_without_a_usable_asset_is_refused(unusable: object):
    with pytest.raises(ValidationError):
        SupersedeSlotMappingRequest(asset_id=unusable, reason_code="wrong_asset")
