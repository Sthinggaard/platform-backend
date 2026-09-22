"""A bundle edit is kept, not only answered — and since #460 it is kept on the slot record.

Found verifying #363 live, 2026-09-14. ``PATCH /api/v1/services/{id}/bundle``
answered 200, logged the decision and moved the bundle's lifecycle — and stored
none of the edit. The handler copied ``groups`` shallowly, so every action changed
the node dicts and ``nodes`` lists SQLAlchemy held as the stored value too; ``groups``
is plain JSONB with no mutation tracking, and assigning an equal value back wrote
nothing. On ``dev`` since 2026-04-01.

#460 (Søren, 2026-09-15): the slot record is the one live record of a dependency
decision, and this route is an adapter onto it. So an edit is now read back from
``slot_instances``, and the bundle's stored nodes (the published snapshot) must stay
exactly as they were.

These call the real handler against real Postgres (AGENTS.md §11.2) and read back
from the database after every action. The only stand-in is
``require_service_process_editor``: ownership is what #353 skipped the route suite
on, and it is not what is under test here. Persistence is never mocked.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import bundle_mapping_decide, bundle_template_routes
from src.api.routes.bundle_contracts import (
    BundleActionRequest,
    DecideSlotMappingRequest,
    DependencyBundleResponse,
)
from src.core.models import BusinessService, DependencyBundle, Organization, SlotInstance

GROUP_KEY = "data"
PATTERN_KEY = "general_data_store"
SLOT_ID = f"contract_management.{GROUP_KEY}.{PATTERN_KEY}"
OTHER_SLOT_ID = f"contract_management.{GROUP_KEY}.document_store"


@pytest.fixture(autouse=True)
def _ownership_is_not_under_test(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        bundle_template_routes, "require_service_process_editor", lambda *args, **kwargs: None
    )


def _bundle(
    db_session: Session,
    organization: Organization,
    *,
    lifecycle_state: str = "template_loaded",
    stored_nodes: list[dict] | None = None,
) -> DependencyBundle:
    service = BusinessService(
        id=str(uuid4()), organization_id=organization.id, name="Contract Management"
    )
    db_session.add(service)
    bundle = DependencyBundle(
        id=str(uuid4()),
        organization_id=organization.id,
        service_id=service.id,
        lifecycle_state=lifecycle_state,
        groups=[
            {
                "key": GROUP_KEY,
                "label": "Data",
                "question": "Where is the data kept?",
                "description": "",
                "required": True,
                "template_nodes": [
                    {
                        "template_key": PATTERN_KEY,
                        "pattern_key": PATTERN_KEY,
                        "label": "Data Storage",
                    }
                ],
                "nodes": stored_nodes or [],
            }
        ],
    )
    db_session.add(bundle)
    # An untouched slot record for each dependency the template defines: nobody decided it,
    # nothing observed it. (This service has no template row, so the fixture writes them.)
    for slot_id in (SLOT_ID, OTHER_SLOT_ID):
        db_session.add(
            SlotInstance(
                id=str(uuid4()),
                organization_id=organization.id,
                service_id=service.id,
                slot_id=slot_id,
                group_key=GROUP_KEY,
                status="unknown",
                mapping_status="needs_review",
                evidence_source=None,
                decided_by=None,
            )
        )
    db_session.flush()
    return bundle


def _act(
    db_session: Session, bundle: DependencyBundle, action: str, **fields: object
) -> DependencyBundleResponse:
    return bundle_template_routes.update_bundle(
        service_id=bundle.service_id,
        body=BundleActionRequest(action=action, group_key=GROUP_KEY, **fields),
        ctx=_owner(bundle),
        db=db_session,
    )


def _owner(bundle: DependencyBundle) -> TenantContext:
    return TenantContext(
        user_id=1,
        organization_id=bundle.organization_id,
        email="owner@example.com",
        roles=["admin"],
        permissions=[],
    )


def _stored_record(db_session: Session, bundle: DependencyBundle, slot_id: str = SLOT_ID) -> dict:
    """Straight from the table — not the session's copy of the object."""
    row = (
        db_session.execute(
            text(
                "SELECT status, asset_id, mapping_status, decided_by, spof "
                "FROM slot_instances WHERE service_id = :service AND slot_id = :slot"
            ),
            {"service": bundle.service_id, "slot": slot_id},
        )
        .mappings()
        .one()
    )
    return dict(row)


def _stored_nodes(db_session: Session, bundle: DependencyBundle) -> list[dict]:
    """The bundle's stored nodes — the published snapshot, which no edit may write."""
    groups = db_session.execute(
        text("SELECT groups FROM dependency_bundles WHERE id = :id"), {"id": bundle.id}
    ).scalar_one()
    return next(group for group in groups if group["key"] == GROUP_KEY)["nodes"]


def _live_nodes(response: DependencyBundleResponse) -> list:
    return next(group for group in response.groups if group.key == GROUP_KEY).nodes


def _add_node(db_session: Session, bundle: DependencyBundle) -> str:
    response = _act(db_session, bundle, "add_pattern_node", payload={"template_key": PATTERN_KEY})
    return _live_nodes(response)[0].id


def test_adding_a_node_is_stored_on_its_slot_record(
    db_session: Session, sample_organization: Organization
):
    """⚠️ The #363 defect, pinned: this answered 200 and stored nothing."""
    bundle = _bundle(db_session, sample_organization)

    response = _act(db_session, bundle, "add_pattern_node", payload={"template_key": PATTERN_KEY})

    record = _stored_record(db_session, bundle)
    assert (record["status"], record["decided_by"]) == ("unknown", "1")
    assert [node.template_key for node in _live_nodes(response)] == [PATTERN_KEY]
    assert [node.slot_id for node in _live_nodes(response)] == [SLOT_ID]


def test_no_edit_writes_the_bundle_s_stored_nodes(
    db_session: Session, sample_organization: Organization
):
    """#460: nodes are the published snapshot; only publish writes them."""
    bundle = _bundle(db_session, sample_organization)
    node_id = _add_node(db_session, bundle)

    _act(db_session, bundle, "assign_asset", node_id=node_id, payload={"asset_id": "92"})
    _act(db_session, bundle, "mark_spof", node_id=node_id, payload={"spof": True})

    assert _stored_nodes(db_session, bundle) == []


def test_assigning_and_unassigning_across_spellings_is_stored(
    db_session: Session, sample_organization: Organization
):
    """#363 and #460 together: the link lands in one spelling, one artefact per slot, and is
    removed however the request spells it."""
    bundle = _bundle(db_session, sample_organization)
    node_id = _add_node(db_session, bundle)

    _act(db_session, bundle, "assign_asset", node_id=node_id, payload={"asset_id": "92"})
    assert _stored_record(db_session, bundle)["asset_id"] == "asset-92"
    assert _stored_record(db_session, bundle)["status"] == "mapped"

    _act(db_session, bundle, "assign_asset", node_id=node_id, payload={"asset_id": "asset-92"})
    assert _stored_record(db_session, bundle)["asset_id"] == "asset-92"

    _act(db_session, bundle, "unassign_asset", node_id=node_id, payload={"asset_id": "92"})
    record = _stored_record(db_session, bundle)
    assert (record["asset_id"], record["status"]) == (None, "unknown")


def test_linking_a_second_artefact_replaces_the_first(
    db_session: Session, sample_organization: Organization
):
    """Søren, 2026-09-15: one artefact per dependency slot."""
    bundle = _bundle(db_session, sample_organization)
    node_id = _add_node(db_session, bundle)

    _act(db_session, bundle, "assign_asset", node_id=node_id, payload={"asset_id": "92"})
    response = _act(db_session, bundle, "assign_asset", node_id=node_id, payload={"asset_id": "7"})

    assert _stored_record(db_session, bundle)["asset_id"] == "asset-7"
    assert _live_nodes(response)[0].linked_asset_ids == ["asset-7"]


def test_removing_a_node_marks_its_slot_not_applicable(
    db_session: Session, sample_organization: Organization
):
    bundle = _bundle(db_session, sample_organization)
    node_id = _add_node(db_session, bundle)

    response = _act(db_session, bundle, "remove_node", node_id=node_id)

    assert _stored_record(db_session, bundle)["status"] == "not_applicable"
    assert _live_nodes(response) == []


def test_a_resilience_answer_is_stored_and_validated(
    db_session: Session, sample_organization: Organization
):
    bundle = _bundle(db_session, sample_organization)
    node_id = _add_node(db_session, bundle)

    _act(db_session, bundle, "mark_spof", node_id=node_id, payload={"spof": False})
    assert _stored_record(db_session, bundle)["spof"] is False

    with pytest.raises(HTTPException) as refused:
        _act(db_session, bundle, "mark_spof", node_id=node_id, payload={"spof": "yes"})
    assert refused.value.status_code == 422
    assert _stored_record(db_session, bundle)["spof"] is False


def test_rejecting_a_group_sets_every_dependency_in_it_aside(
    db_session: Session, sample_organization: Organization
):
    bundle = _bundle(db_session, sample_organization)

    response = _act(db_session, bundle, "reject_group")

    assert _stored_record(db_session, bundle)["status"] == "not_applicable"
    assert _stored_record(db_session, bundle, OTHER_SLOT_ID)["status"] == "not_applicable"
    assert next(group for group in response.groups if group.key == GROUP_KEY).rejected is True


def test_a_node_id_from_before_460_still_reaches_its_slot_record(
    db_session: Session, sample_organization: Organization
):
    """A page opened on a stored node keeps working: its id resolves through its pattern."""
    legacy_node_id = str(uuid4())
    bundle = _bundle(
        db_session,
        sample_organization,
        stored_nodes=[{"id": legacy_node_id, "label": "Data Storage", "template_key": PATTERN_KEY}],
    )

    _act(db_session, bundle, "assign_asset", node_id=legacy_node_id, payload={"asset_id": "92"})

    assert _stored_record(db_session, bundle)["asset_id"] == "asset-92"


def test_an_unknown_node_is_refused(db_session: Session, sample_organization: Organization):
    bundle = _bundle(db_session, sample_organization)

    with pytest.raises(HTTPException) as refused:
        _act(db_session, bundle, "remove_node", node_id=str(uuid4()))

    assert refused.value.status_code == 404


@pytest.mark.parametrize("unusable", ["", "   ", None])
def test_an_unusable_asset_is_refused_and_nothing_is_stored(
    db_session: Session, sample_organization: Organization, unusable: object
):
    bundle = _bundle(db_session, sample_organization)
    node_id = _add_node(db_session, bundle)

    with pytest.raises(HTTPException) as refused:
        _act(db_session, bundle, "assign_asset", node_id=node_id, payload={"asset_id": unusable})

    assert refused.value.status_code == 422
    assert _stored_record(db_session, bundle)["asset_id"] is None


def test_a_published_bundle_takes_an_edit_and_keeps_its_snapshot(
    db_session: Session, sample_organization: Organization
):
    """Søren, 2026-09-16: found in his manual test, where the page refused and the slide-out did not.

    Publish is the versioned snapshot (450.2 criterion 2, 450.8), so an edit after it changes
    the live state only: the bundle stays published, and its nodes and validation stay as
    they were published.
    """
    published_validation = {"findings": [], "acknowledged_warning_ids": []}
    bundle = _bundle(db_session, sample_organization, lifecycle_state="bundle_published")
    bundle.validation_snapshot = published_validation
    db_session.flush()

    response = _act(db_session, bundle, "add_pattern_node", payload={"template_key": PATTERN_KEY})
    _act(
        db_session,
        bundle,
        "assign_asset",
        node_id=_live_nodes(response)[0].id,
        payload={"asset_id": "92"},
    )

    record = _stored_record(db_session, bundle)
    assert (record["status"], record["asset_id"], record["decided_by"]) == (
        "mapped",
        "asset-92",
        "1",
    )
    assert response.lifecycle_state == "bundle_published"
    assert _stored_nodes(db_session, bundle) == []
    assert db_session.execute(
        text("SELECT lifecycle_state, validation_snapshot FROM dependency_bundles WHERE id = :id"),
        {"id": bundle.id},
    ).one() == ("bundle_published", published_validation)


def test_the_page_and_the_slide_out_both_take_a_decision_on_a_published_service(
    db_session: Session, sample_organization: Organization, monkeypatch: pytest.MonkeyPatch
):
    """#460: one write path, so one rule — neither surface refuses what the other accepts."""
    monkeypatch.setattr(
        bundle_mapping_decide, "require_service_process_editor", lambda *args, **kwargs: None
    )
    bundle = _bundle(db_session, sample_organization, lifecycle_state="bundle_published")

    node_id = _add_node(db_session, bundle)
    _act(db_session, bundle, "assign_asset", node_id=node_id, payload={"asset_id": "92"})
    bundle_mapping_decide.decide_slot_mapping(
        service_id=bundle.service_id,
        slot_id=OTHER_SLOT_ID,
        body=DecideSlotMappingRequest(decision="mapped", asset_id="93"),
        ctx=_owner(bundle),
        db=db_session,
    )

    assert _stored_record(db_session, bundle)["asset_id"] == "asset-92"
    assert _stored_record(db_session, bundle, OTHER_SLOT_ID)["asset_id"] == "asset-93"
    assert _stored_nodes(db_session, bundle) == []


def test_an_edit_after_validation_asks_for_validation_again(
    db_session: Session, sample_organization: Organization
):
    """A validation describes the live state it was run on; a changed decision ends that."""
    bundle = _bundle(db_session, sample_organization, lifecycle_state="bundle_validated")
    bundle.validation_snapshot = {"findings": [], "acknowledged_warning_ids": ["w-1"]}
    bundle.acknowledged_warning_ids = ["w-1"]
    db_session.flush()

    _add_node(db_session, bundle)

    assert db_session.execute(
        text(
            "SELECT lifecycle_state, validation_snapshot, acknowledged_warning_ids "
            "FROM dependency_bundles WHERE id = :id"
        ),
        {"id": bundle.id},
    ).one() == ("bundle_manual_training", None, [])
