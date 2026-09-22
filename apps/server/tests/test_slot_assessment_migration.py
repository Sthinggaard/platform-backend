"""#460: migration `20260915_slot_assessment` against a real Postgres.

The backfill is JSONB SQL, so a mocked or SQLite database would prove nothing (AGENTS.md §11.2).
Runs inside the conftest transaction and rolls back.

What it must do, from the development database on 2026-09-15: org 7's 15 hand-added bundle nodes
held SPOF, impact and recovery answers that their slot records did not. All 15 match their slot by
`template_key`, some through a namespaced slot id (`api_platform.application.api_service` for
`api_service`).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from src.core.models import BusinessService, DependencyBundle, Organization, SlotInstance

MIGRATION_PATH = (
    Path(__file__).resolve().parents[1] / "alembic" / "versions" / "20260915_slot_assessment.py"
)


def _load_migration():
    spec = importlib.util.spec_from_file_location("slot_assessment_migration", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MIGRATION = _load_migration()

ANSWERS = {
    "spof": True,
    "fallback_status": "partial",
    "recovery_dependent": False,
    "impact_type": "availability",
    "business_impact_level": "high",
    "business_consequence": "API Service is required to keep the service running.",
    "critical_for_business": True,
}


def _node(template_key: str | None, **answers: object) -> dict:
    node = {
        "id": str(uuid4()),
        "label": template_key or "slot wizard node",
        "linked_asset_ids": ["asset-92"],
        "source": "manual" if template_key else "slot_mapping_wizard",
        "template_key": template_key,
        "spof": None,
        "fallback_status": None,
        "recovery_dependent": None,
        "impact_type": None,
        "business_impact_level": None,
        "business_consequence": None,
        "critical_for_business": None,
    }
    node.update(answers)
    return node


@pytest.fixture
def service(db_session: Session, sample_organization: Organization) -> BusinessService:
    row = BusinessService(
        id=str(uuid4()), organization_id=sample_organization.id, name="API Platform"
    )
    db_session.add(row)
    db_session.flush()
    return row


def _bundle(db_session: Session, service: BusinessService, groups: list) -> DependencyBundle:
    row = DependencyBundle(
        id=str(uuid4()),
        organization_id=service.organization_id,
        service_id=service.id,
        groups=groups,
    )
    db_session.add(row)
    db_session.flush()
    return row


def _slot(
    db_session: Session, service: BusinessService, slot_id: str, group_key: str, **fields
) -> SlotInstance:
    row = SlotInstance(
        organization_id=service.organization_id,
        service_id=service.id,
        slot_id=slot_id,
        group_key=group_key,
        status="mapped",
        asset_id="asset-92",
        **fields,
    )
    db_session.add(row)
    db_session.flush()
    return row


def _run(db_session: Session) -> tuple[int, int]:
    copied = db_session.execute(MIGRATION.BACKFILL_SLOT_ASSESSMENT).rowcount
    unmatched = db_session.execute(MIGRATION.COUNT_UNMATCHED_ANSWERED_NODES).scalar()
    db_session.flush()
    db_session.expire_all()
    return copied, unmatched


def _answers(slot: SlotInstance) -> dict:
    return {name: getattr(slot, name) for name in ANSWERS}


def test_a_hand_added_nodes_answers_move_onto_its_namespaced_slot(
    db_session: Session, service: BusinessService
):
    slot = _slot(db_session, service, "api_platform.application.api_service", "application")
    _bundle(
        db_session, service, [{"key": "application", "nodes": [_node("api_service", **ANSWERS)]}]
    )

    copied, unmatched = _run(db_session)

    assert (copied, unmatched) == (1, 0)
    assert _answers(db_session.get(SlotInstance, slot.id)) == ANSWERS


def test_a_slot_id_equal_to_the_template_key_matches_too(
    db_session: Session, service: BusinessService
):
    slot = _slot(db_session, service, "identity_provider", "identity_access")
    _bundle(
        db_session,
        service,
        [{"key": "identity_access", "nodes": [_node("identity_provider", spof=False)]}],
    )

    _run(db_session)

    assert db_session.get(SlotInstance, slot.id).spof is False


def test_the_same_key_in_another_group_is_not_the_same_dependency(
    db_session: Session, service: BusinessService
):
    slot = _slot(db_session, service, "api_platform.operations.api_service", "operations")
    _bundle(
        db_session, service, [{"key": "application", "nodes": [_node("api_service", **ANSWERS)]}]
    )

    copied, unmatched = _run(db_session)

    assert (copied, unmatched) == (0, 1)
    assert db_session.get(SlotInstance, slot.id).spof is None


def test_a_suffix_must_follow_a_dot_not_just_end_the_id(
    db_session: Session, service: BusinessService
):
    """`internal_api_service` does not end with `.api_service` and is a different dependency."""
    slot = _slot(db_session, service, "internal_api_service", "application")
    _bundle(
        db_session, service, [{"key": "application", "nodes": [_node("api_service", **ANSWERS)]}]
    )

    assert _run(db_session) == (0, 1)
    assert db_session.get(SlotInstance, slot.id).spof is None


def test_another_services_slot_never_receives_the_answers(
    db_session: Session, service: BusinessService, sample_organization: Organization
):
    other = BusinessService(
        id=str(uuid4()), organization_id=sample_organization.id, name="Data Platform"
    )
    db_session.add(other)
    db_session.flush()
    other_slot = _slot(db_session, other, "api_service", "application")
    _bundle(
        db_session, service, [{"key": "application", "nodes": [_node("api_service", **ANSWERS)]}]
    )

    _run(db_session)

    assert db_session.get(SlotInstance, other_slot.id).spof is None


def test_a_slot_that_already_holds_an_answer_is_not_overwritten(
    db_session: Session, service: BusinessService
):
    slot = _slot(db_session, service, "api_service", "application", fallback_status="full")
    _bundle(
        db_session, service, [{"key": "application", "nodes": [_node("api_service", **ANSWERS)]}]
    )

    copied, _ = _run(db_session)

    reloaded = db_session.get(SlotInstance, slot.id)
    assert copied == 0
    assert reloaded.fallback_status == "full"
    assert reloaded.spof is None


def test_a_node_with_no_answers_changes_nothing(db_session: Session, service: BusinessService):
    slot = _slot(db_session, service, "api_service", "application")
    _bundle(
        db_session, service, [{"key": "application", "nodes": [_node("api_service"), _node(None)]}]
    )

    assert _run(db_session) == (0, 0)
    assert all(value is None for value in _answers(db_session.get(SlotInstance, slot.id)).values())


def test_a_value_outside_the_allowed_list_is_copied_as_not_answered(
    db_session: Session, service: BusinessService
):
    slot = _slot(db_session, service, "api_service", "application")
    _bundle(
        db_session,
        service,
        [
            {
                "key": "application",
                "nodes": [
                    _node(
                        "api_service",
                        spof="yes",
                        impact_type="catastrophic",
                        business_impact_level="high",
                    )
                ],
            }
        ],
    )

    _run(db_session)

    reloaded = db_session.get(SlotInstance, slot.id)
    assert (reloaded.spof, reloaded.impact_type, reloaded.business_impact_level) == (
        None,
        None,
        "high",
    )


def test_the_artefact_on_the_slot_is_never_changed(db_session: Session, service: BusinessService):
    slot = _slot(db_session, service, "api_service", "application")
    node = _node("api_service", **ANSWERS)
    node["linked_asset_ids"] = ["asset-7"]
    _bundle(db_session, service, [{"key": "application", "nodes": [node]}])

    _run(db_session)

    assert db_session.get(SlotInstance, slot.id).asset_id == "asset-92"


def test_malformed_groups_and_nodes_are_skipped_not_raised(
    db_session: Session, service: BusinessService
):
    _slot(db_session, service, "api_service", "application")
    _bundle(
        db_session,
        service,
        [{"key": "teams"}, "not-a-group", {"key": "application", "nodes": ["not-a-node"]}],
    )

    assert _run(db_session) == (0, 0)


def test_a_second_run_finds_nothing_to_change(db_session: Session, service: BusinessService):
    """Idempotent — a migration that changes data on re-run is a production incident."""
    slot = _slot(db_session, service, "api_service", "application")
    _bundle(
        db_session, service, [{"key": "application", "nodes": [_node("api_service", **ANSWERS)]}]
    )
    _run(db_session)
    first = _answers(db_session.get(SlotInstance, slot.id))

    copied, _ = _run(db_session)

    assert copied == 0
    assert _answers(db_session.get(SlotInstance, slot.id)) == first


def test_the_upgrade_and_downgrade_share_one_column_list():
    assert [name for name, _ in MIGRATION.ASSESSMENT_COLUMNS] == list(ANSWERS)


def test_the_revision_id_fits_alembic_version():
    """`alembic_version.version_num` is varchar(32); a longer id fails only after
    every statement has run (docs/architecture/staging-deploy-2026-09-09.md)."""
    assert len(MIGRATION.revision) <= 32
    assert MIGRATION.down_revision == "20260914_merge_heads"


def test_the_model_carries_every_migrated_column():
    assert {name for name, _ in MIGRATION.ASSESSMENT_COLUMNS} <= set(
        SlotInstance.__table__.columns.keys()
    )
