"""One stored shape for an asset link, and a reader that survives the other one.

#363: the Risklence internal tenant seed wrote the bare integer `92` while every
other writer and reader used `"asset-92"`. Readers accepting only the reference
form dropped the integers silently — a slot reported as Unmapped while a human
was looking at the asset linked to it. The failure never raised; it looked like
ordinary incomplete setup.
"""

from __future__ import annotations

import inspect

from src.core.services.asset_context_service import (
    ASSET_REFERENCE_PREFIX,
    asset_reference,
    normalise_asset_reference,
)


def test_both_stored_shapes_normalise_to_the_same_reference():
    assert normalise_asset_reference(92) == "asset-92"
    assert normalise_asset_reference("asset-92") == "asset-92"
    assert normalise_asset_reference("92") == "asset-92"
    assert normalise_asset_reference(" asset-92 ") == "asset-92"


def test_a_value_that_is_not_an_asset_link_is_skipped_not_invented():
    for value in (None, "", "   ", True, False, ASSET_REFERENCE_PREFIX, [], {}):
        assert normalise_asset_reference(value) is None, value


def test_a_boolean_is_never_read_as_an_asset_id():
    """`bool` is an `int` in Python, so `True` would otherwise become asset-1."""
    assert normalise_asset_reference(True) is None
    assert normalise_asset_reference(False) is None


def test_the_reference_format_has_one_definition():
    assert asset_reference(92) == f"{ASSET_REFERENCE_PREFIX}92"
    assert normalise_asset_reference(asset_reference(92)) == asset_reference(92)


def test_the_internal_tenant_seed_stores_canonical_references():
    """The seed is where the second shape came from; it must not come back.

    Asserted against the source rather than by running the seed, so the test
    stays cheap and still fails on the exact regression: writing a raw asset id
    into `linked_asset_ids`.
    """
    from src.core.seeds import risklence_internal_tenant_seed as seed

    source = inspect.getsource(seed)
    assert '"linked_asset_ids": [asset.id]' not in source, (
        "The seed is writing a raw asset id again. Every reader expects the "
        "canonical asset-{id} reference; a raw id is dropped silently and the "
        "slot then reports as unmapped."
    )
    assert '"linked_asset_ids": [_asset_ref(asset.id)]' in source
