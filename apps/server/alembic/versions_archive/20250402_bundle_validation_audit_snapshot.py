"""Add validation audit snapshot fields to dependency bundles."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "20250402_bundle_validation_audit_snapshot"
down_revision: Union[str, None] = "20250402_service_journey_signals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    bundle_columns = {column["name"] for column in inspector.get_columns("dependency_bundles")}

    if "validation_snapshot" not in bundle_columns:
        op.add_column(
            "dependency_bundles",
            sa.Column("validation_snapshot", JSONB, nullable=True),
        )

    if "acknowledged_warning_ids" not in bundle_columns:
        op.add_column(
            "dependency_bundles",
            sa.Column(
                "acknowledged_warning_ids",
                JSONB,
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    bundle_columns = {column["name"] for column in inspector.get_columns("dependency_bundles")}

    if "acknowledged_warning_ids" in bundle_columns:
        op.drop_column("dependency_bundles", "acknowledged_warning_ids")

    if "validation_snapshot" in bundle_columns:
        op.drop_column("dependency_bundles", "validation_snapshot")
