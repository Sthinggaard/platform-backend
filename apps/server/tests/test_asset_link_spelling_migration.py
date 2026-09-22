"""#363 — migration ``20260913_asset_link_spelling`` against a real Postgres.

Its whole job is JSONB SQL, so a mocked or SQLite database would prove nothing
(AGENTS.md §11.2). Runs inside the conftest transaction and rolls back.

What it must do, from the development database on 2026-09-13: 9 of 71 bundle
links and 38 slot rows stored an asset's own id as a digit string (``"92"``)
beside the canonical ``"asset-92"`` — a spelling ``20260830_asset_refs`` left
alone because it rewrote numbers only.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from src.core.models import BusinessService, DependencyBundle, Organization, SlotInstance

MIGRATION_PATH = (
    Path(__file__).resolve().parents[1] / "alembic" / "versions" / "20260913_asset_link_spelling.py"
)


def _load_migration():
    spec = importlib.util.spec_from_file_location("asset_link_spelling_migration", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MIGRATION = _load_migration()


def _node(label: str, links: list[object]) -> dict:
    return {"id": str(uuid4()), "label": label, "linked_asset_ids": links}


@pytest.fixture
def service(db_session: Session, sample_organization: Organization) -> BusinessService:
    row = BusinessService(
        id=str(uuid4()), organization_id=sample_organization.id, name="Billing & Subscription"
    )
    db_session.add(row)
    db_session.flush()
    return row


@pytest.fixture
def bundle(db_session: Session, service: BusinessService) -> DependencyBundle:
    row = DependencyBundle(
        id=str(uuid4()),
        organization_id=service.organization_id,
        service_id=service.id,
        groups=[
            {
                "key": "systems",
                "nodes": [
                    # Every spelling, a duplicate of one asset, and a value that is not an asset id.
                    _node("API Service", ["92", "asset-7", "asset-92", 5, "vendor-managed"]),
                    _node("Already canonical", ["asset-101"]),
                    _node("Nothing linked", []),
                ],
            },
            {"key": "teams"},  # a group with no nodes is left exactly as it is
            "not-a-group",  # and so is anything that is not a group object
        ],
    )
    db_session.add(row)
    db_session.flush()
    return row


def _slot(
    db_session: Session, service: BusinessService, slot_id: str, asset_id: str | None
) -> SlotInstance:
    row = SlotInstance(
        organization_id=service.organization_id,
        service_id=service.id,
        slot_id=slot_id,
        group_key="systems",
        status="mapped" if asset_id else "unknown",
        asset_id=asset_id,
    )
    db_session.add(row)
    db_session.flush()
    return row


def _run(db_session: Session) -> None:
    db_session.execute(MIGRATION.NORMALISE_BUNDLE_LINKS)
    db_session.execute(MIGRATION.NORMALISE_SLOT_ASSETS)
    db_session.flush()
    db_session.expire_all()


def test_bundle_links_converge_on_one_spelling_each_asset_once(
    db_session: Session, bundle: DependencyBundle
):
    _run(db_session)

    groups = db_session.get(DependencyBundle, bundle.id).groups
    nodes = groups[0]["nodes"]

    assert nodes[0]["linked_asset_ids"] == ["asset-92", "asset-7", "asset-5", "vendor-managed"]
    assert nodes[1]["linked_asset_ids"] == ["asset-101"]
    assert nodes[2]["linked_asset_ids"] == []
    assert groups[1] == {"key": "teams"}
    assert groups[2] == "not-a-group"


def test_everything_but_the_links_is_left_as_it_was(db_session: Session, bundle: DependencyBundle):
    before = db_session.get(DependencyBundle, bundle.id).groups[0]["nodes"][0]

    _run(db_session)

    after = db_session.get(DependencyBundle, bundle.id).groups[0]["nodes"][0]
    assert {k: v for k, v in after.items() if k != "linked_asset_ids"} == {
        k: v for k, v in before.items() if k != "linked_asset_ids"
    }


def test_slot_assets_stored_as_a_digit_string_gain_the_prefix(
    db_session: Session, service: BusinessService
):
    digit = _slot(db_session, service, "api", "92")
    canonical = _slot(db_session, service, "db", "asset-101")
    unanswered = _slot(db_session, service, "ci", None)

    _run(db_session)

    assert db_session.get(SlotInstance, digit.id).asset_id == "asset-92"
    assert db_session.get(SlotInstance, canonical.id).asset_id == "asset-101"
    assert db_session.get(SlotInstance, unanswered.id).asset_id is None


def test_a_second_run_finds_nothing_to_change(
    db_session: Session, bundle: DependencyBundle, service: BusinessService
):
    """Idempotent — a migration that changes data on re-run is a production incident."""
    slot = _slot(db_session, service, "api", "92")
    _run(db_session)
    first_groups = db_session.get(DependencyBundle, bundle.id).groups
    first_updated_at = db_session.get(DependencyBundle, bundle.id).updated_at

    bundle_rows = db_session.execute(MIGRATION.NORMALISE_BUNDLE_LINKS).rowcount
    slot_rows = db_session.execute(MIGRATION.NORMALISE_SLOT_ASSETS).rowcount
    db_session.expire_all()

    assert (bundle_rows, slot_rows) == (0, 0)
    assert db_session.get(DependencyBundle, bundle.id).groups == first_groups
    assert db_session.get(DependencyBundle, bundle.id).updated_at == first_updated_at
    assert db_session.get(SlotInstance, slot.id).asset_id == "asset-92"


def test_the_revision_id_fits_alembic_version():
    """`alembic_version.version_num` is varchar(32); a longer id fails only after
    every statement has run (docs/architecture/staging-deploy-2026-09-09.md)."""
    assert len(MIGRATION.revision) <= 32
    assert MIGRATION.down_revision == "20260910_schema_baseline"
