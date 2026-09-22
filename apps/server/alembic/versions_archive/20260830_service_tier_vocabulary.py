"""Constrain BusinessService tiers to the BIA-derived vocabulary.

Revision ID: 20260830_service_tier_vocabulary
Revises: abf721d5a599
Create Date: 2026-08-30 02:10:00.000000
"""

import sqlalchemy as sa

from alembic import op
from src.core.constants.service_model import (
    LEGACY_SERVICE_TIER_VALUES,
    SERVICE_TIER_SQL_CHECK,
    SERVICE_TIER_SQL_CHECK_CONSTRAINT,
    SERVICE_TIERS,
)

revision = "20260830_service_tier_vocabulary"
down_revision = "abf721d5a599"
branch_labels = None
depends_on = None


def _constraint_exists(connection: sa.Connection) -> bool:
    return (
        connection.execute(
            sa.text(
                "SELECT 1 FROM pg_constraint "
                "WHERE conname = :constraint_name "
                "AND conrelid = 'business_services'::regclass"
            ),
            {"constraint_name": SERVICE_TIER_SQL_CHECK_CONSTRAINT},
        ).fetchone()
        is not None
    )


def _invalid_tier_values(connection: sa.Connection) -> list[str]:
    statement = sa.text(
        "SELECT DISTINCT tier FROM business_services "
        "WHERE tier NOT IN :service_tiers ORDER BY tier"
    ).bindparams(sa.bindparam("service_tiers", expanding=True))
    return list(
        connection.execute(
            statement,
            {"service_tiers": tuple(tier.value for tier in SERVICE_TIERS)},
        ).scalars()
    )


def upgrade() -> None:
    connection = op.get_bind()

    # Do not replace a value through loose casing/punctuation heuristics. Each
    # repair is a named historical spelling from the canonical tier contract.
    for legacy_tier, canonical_tier in LEGACY_SERVICE_TIER_VALUES.items():
        connection.execute(
            sa.text("UPDATE business_services SET tier = :canonical WHERE tier = :legacy"),
            {"canonical": canonical_tier.value, "legacy": legacy_tier},
        )

    invalid_values = _invalid_tier_values(connection)
    if invalid_values:
        raise RuntimeError(
            "Cannot constrain business_services.tier; unknown values require a governed "
            f"migration decision: {invalid_values}"
        )

    if not _constraint_exists(connection):
        op.create_check_constraint(
            SERVICE_TIER_SQL_CHECK_CONSTRAINT,
            "business_services",
            SERVICE_TIER_SQL_CHECK,
        )


def downgrade() -> None:
    connection = op.get_bind()
    if _constraint_exists(connection):
        op.drop_constraint(
            SERVICE_TIER_SQL_CHECK_CONSTRAINT,
            "business_services",
            type_="check",
        )
