"""#464 — persist the approved dependency category on logical slots and decisions.

The prior capability-group keys still own question wording and legacy route
addresses. This migration adds the five-category taxonomy separately, so a
slot's business category is stable even if its question changes later.

Known historical groups are mapped without changing a decision or mapped
Artefact. Any unknown custom group is left null and reported: assigning it to a
category would be an unapproved product decision and would corrupt engine
training data.

Revision ID: 20260918_dependency_categories
Revises: 20260915_slot_assessment
Create Date: 2026-09-18 00:00:00.000000
"""

import logging

import sqlalchemy as sa

from alembic import op

revision = "20260918_dependency_categories"
down_revision = "20260915_slot_assessment"
branch_labels = None
depends_on = None

logger = logging.getLogger("alembic.runtime.migration")

_CATEGORY_BY_GROUP: dict[str, str] = {
    "systems": "application",
    "application": "application",
    "infrastructure": "infrastructure",
    "identity_access": "infrastructure",
    "data": "data",
    "external_providers": "third_parties",
    "operations": "operational_team",
    "teams": "operational_team",
}


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:table"),
        {"table": table},
    ).fetchone() is not None


def _column_exists(conn, table: str, column: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name=:table AND column_name=:column"
        ),
        {"table": table, "column": column},
    ).fetchone() is not None


def _backfill(conn, table: str, group_column: str) -> None:
    cases = " ".join(
        f"WHEN '{group_key}' THEN '{category}'"
        for group_key, category in _CATEGORY_BY_GROUP.items()
    )
    updated = conn.execute(
        sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
            f"UPDATE {table} SET dependency_category = CASE {group_column} {cases} END "
            "WHERE dependency_category IS NULL"
        )
    ).rowcount
    category_counts = conn.execute(
        sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
            f"SELECT dependency_category, count(*) FROM {table} "
            "GROUP BY dependency_category ORDER BY dependency_category"
        )
    ).all()
    unknown_count = conn.execute(
        sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
            f"SELECT count(*) FROM {table} WHERE dependency_category IS NULL"
        )
    ).scalar() or 0
    logger.info(
        "20260918_dependency_categories: %s rows updated in %s; category counts=%s; "
        "%s rows need a category decision",
        updated,
        table,
        category_counts,
        unknown_count,
    )


def upgrade() -> None:
    conn = op.get_bind()
    for table, group_column in (
        ("slot_templates", "capability_group_key"),
        ("slot_instances", "group_key"),
    ):
        if not _table_exists(conn, table):
            continue
        if not _column_exists(conn, table, "dependency_category"):
            op.add_column(table, sa.Column("dependency_category", sa.String(length=30), nullable=True))
        _backfill(conn, table, group_column)


def downgrade() -> None:
    conn = op.get_bind()
    for table in ("slot_instances", "slot_templates"):
        if _table_exists(conn, table) and _column_exists(conn, table, "dependency_category"):
            op.drop_column(table, "dependency_category")
