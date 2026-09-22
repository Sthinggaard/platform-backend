"""#363 — the bundle response understands both stored shapes of an asset link.

``DependencyBundle`` nodes held asset links in two shapes: the canonical
``"asset-92"`` and the bare integer ``92`` written by the Risklence internal
tenant seed. Migration ``20260830_asset_refs`` normalised what was stored and
the seed was fixed at source, but ``groups_to_out`` was the one reader the
ticket's audit missed — and it is the reader behind every dependency-bundle
route response.

It is worth its own test because its failure mode is the opposite of the one
#363 described. ``DependencyNodeOut.linked_asset_ids`` is typed ``list[str]``,
so an integer does not read as "not mapped yet" here — it raises a
``ValidationError`` and the route returns 500. Any database where that
migration has not run still holds the old shape.
"""

from src.api.routes.bundle_common import groups_to_out


def _group_with_links(*links: object) -> list[dict]:
    return [
        {
            "key": "external_providers",
            "label": "External providers",
            "nodes": [{"id": "n1", "label": "Auth Service", "linked_asset_ids": list(links)}],
        }
    ]


def test_a_bare_integer_asset_link_is_understood_not_rejected():
    groups = groups_to_out(_group_with_links(92))

    assert groups[0].nodes[0].linked_asset_ids == ["asset-92"]


def test_both_stored_shapes_reach_the_response_as_one_shape():
    groups = groups_to_out(_group_with_links("asset-92", 7))

    assert groups[0].nodes[0].linked_asset_ids == ["asset-92", "asset-7"]


def test_a_reference_that_is_not_an_asset_id_is_dropped_not_invented():
    groups = groups_to_out(_group_with_links(None, "", True))

    assert groups[0].nodes[0].linked_asset_ids == []
