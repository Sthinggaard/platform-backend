"""#460 — a service's live dependency state is composed from its slot records.

Pure: no database. Each test states one rule the map, the slide-out and the service setup page now
share, because they all read what this composes.
"""

from __future__ import annotations

from types import SimpleNamespace

from src.core.services.dependency_live_state_service import (
    SLOT_RECORD_NODE_SOURCE,
    compose_live_groups,
    humanise_key,
    is_live_dependency,
    is_template_orphaned,
    matching_template_node,
)

GROUPS = [
    {
        "key": "application",
        "label": "Application",
        "question": "What runs the service?",
        "description": "",
        "required": True,
        "template_nodes": [
            {
                "template_key": "api_service",
                "label": "API Service",
                "pattern_key": "application_platform",
            }
        ],
        "nodes": [{"id": "stale-snapshot-node", "label": "Must never be read as live"}],
    },
    {"key": "teams", "label": "Teams", "template_nodes": [], "nodes": []},
]


def _record(slot_id: str, group_key: str = "application", **overrides) -> SimpleNamespace:
    fields = {
        "id": f"row-{slot_id}",
        "slot_id": slot_id,
        "group_key": group_key,
        "status": "unknown",
        "asset_id": None,
        "asset_label": None,
        "mapping_status": "needs_review",
        "mapping_confidence": None,
        "evidence_source": None,
        "decided_by": None,
        "spof": None,
        "fallback_status": None,
        "recovery_dependent": None,
        "impact_type": None,
        "business_impact_level": None,
        "business_consequence": None,
        "critical_for_business": None,
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


def _mapped(slot_id: str, group_key: str = "application", **overrides) -> SimpleNamespace:
    fields = {
        "status": "mapped",
        "asset_id": "92",
        "asset_label": "API Service",
        "mapping_status": "approved",
        "mapping_confidence": 1.0,
        "evidence_source": "manual",
        "decided_by": "2",
    }
    fields.update(overrides)
    return _record(slot_id, group_key, **fields)


def _compose(records, *, canonical=("billing.application.api_service",), labels=None):
    return compose_live_groups(
        GROUPS, records, canonical_slot_ids=canonical, slot_labels=labels or {}
    )


def _group(groups, key):
    return next(group for group in groups if group["key"] == key)


def test_a_person_s_mapping_is_a_live_dependency_with_its_artefact():
    groups = _compose([_mapped("billing.application.api_service")])

    [node] = _group(groups, "application")["nodes"]
    assert node["id"] == "row-billing.application.api_service"
    assert node["slot_id"] == "billing.application.api_service"
    assert node["linked_asset_ids"] == ["asset-92"]
    assert node["validation_status"] == "accepted"
    assert node["source"] == SLOT_RECORD_NODE_SOURCE
    assert node["deferred_asset_mapping"] is False


def test_the_bundle_s_stored_nodes_are_never_read_as_live_state():
    groups = _compose([])

    assert _group(groups, "application")["nodes"] == []


def test_an_untouched_slot_is_not_a_dependency_yet():
    assert (
        _group(_compose([_record("billing.application.api_service")]), "application")["nodes"] == []
    )


def test_an_engine_suggestion_never_reads_as_a_decision():
    suggestion = _mapped(
        "billing.application.api_service", mapping_status="suggested", decided_by=None
    )

    assert is_live_dependency(suggestion) is False
    assert _group(_compose([suggestion]), "application")["nodes"] == []


def test_a_person_s_i_dont_know_is_a_deferred_dependency():
    answer = _record("billing.application.api_service", decided_by="2", evidence_source="manual")

    [node] = _group(_compose([answer]), "application")["nodes"]
    assert node["deferred_asset_mapping"] is True
    assert node["linked_asset_ids"] == []


def test_a_resilience_answer_alone_makes_the_slot_live():
    answered = _record("billing.application.api_service", spof=False)

    [node] = _group(_compose([answered]), "application")["nodes"]
    assert node["spof"] is False


def test_the_slide_out_answer_counts_where_the_map_reads_it():
    """#452: an answer given through `decide` is a node, so the map's `NO DEPS` clears on the next load."""
    decided = _mapped("billing.application.api_service")

    assert _group(_compose([decided]), "application")["nodes"], "the answer must count as mapping"


def test_needs_review_reads_as_draft():
    uncertain = _mapped("billing.application.api_service", mapping_status="needs_review")

    [node] = _group(_compose([uncertain]), "application")["nodes"]
    assert node["validation_status"] == "draft"


def test_not_applicable_is_removed_and_a_wholly_not_applicable_group_is_rejected():
    removed = _record(
        "billing.application.api_service",
        status="not_applicable",
        mapping_status="approved",
        decided_by="2",
    )

    group = _group(_compose([removed]), "application")
    assert group["nodes"] == []
    assert group["rejected"] is True


def test_a_group_with_one_answer_and_one_removal_is_not_rejected():
    group = _group(
        _compose(
            [
                _mapped("billing.application.api_service"),
                _record("billing.application.cache", status="not_applicable", decided_by="2"),
            ],
            canonical=("billing.application.api_service", "billing.application.cache"),
        ),
        "application",
    )
    assert group["rejected"] is None
    assert len(group["nodes"]) == 1


def test_teams_are_not_dependencies_anywhere():
    """#434, and Søren 2026-09-15: kept, never shown or counted."""
    groups = _compose([_mapped("teams", "teams"), _mapped("teams", "application")])

    assert all(group["key"] != "teams" for group in groups)
    assert _group(groups, "application")["nodes"] == []


def test_an_orphaned_decision_stays_live_and_is_flagged():
    """Søren 2026-09-15: a decision whose question left the template is kept, flagged for review."""
    orphan = _mapped("api_platform.application.api_service")

    [node] = _group(_compose([orphan]), "application")["nodes"]
    assert node["template_orphaned"] is True


def test_a_current_template_slot_is_not_flagged():
    [node] = _group(_compose([_mapped("billing.application.api_service")]), "application")["nodes"]

    assert node["template_orphaned"] is False


def test_a_service_with_no_active_template_has_nothing_orphaned():
    """No template means no slots to leave. Reading it as "every slot has gone" flagged all of a
    service's decisions for review."""
    [node] = _group(_compose([_mapped("api_service")], canonical=()), "application")["nodes"]

    assert node["template_orphaned"] is False
    assert is_template_orphaned("api_service", ()) is False
    assert is_template_orphaned("api_service", ("billing.application.api_service",)) is True


def test_the_matching_pattern_is_carried_so_the_page_hides_it_as_already_added():
    [node] = _group(_compose([_mapped("billing.application.api_service")]), "application")["nodes"]

    assert (node["template_key"], node["pattern_key"]) == ("api_service", "application_platform")


def test_a_group_the_bundle_does_not_know_still_counts():
    groups = _compose([_mapped("systems", "systems")])

    group = _group(groups, "systems")
    assert group["label"] == "Systems"
    assert len(group["nodes"]) == 1


def test_label_prefers_the_template_slot_name_then_pattern_then_artefact():
    record = _mapped("billing.application.api_service")

    named = _group(
        _compose([record], labels={"billing.application.api_service": "Application platform"}),
        "application",
    )
    assert named["nodes"][0]["label"] == "Application platform"
    assert _group(_compose([record]), "application")["nodes"][0]["label"] == "API Service"


def test_matching_a_pattern_needs_a_whole_segment():
    options = [{"template_key": "api_service"}]

    assert matching_template_node("billing.application.api_service", options) is not None
    assert matching_template_node("api_service", options) is not None
    assert matching_template_node("internal_api_service", options) is None


def test_group_metadata_comes_from_the_bundle_and_malformed_rows_are_skipped():
    groups = compose_live_groups(
        ["not-a-group", *GROUPS, {"key": "application", "label": "Duplicate"}],
        [],
        canonical_slot_ids=(),
    )

    application = _group(groups, "application")
    assert (application["label"], application["question"], application["required"]) == (
        "Application",
        "What runs the service?",
        True,
    )
    assert [group["key"] for group in groups] == ["application"]


def test_humanise_key_reads_the_last_segment():
    assert humanise_key("billing.infrastructure.managed_postgresql") == "Managed postgresql"
    assert humanise_key("external_providers") == "External providers"
