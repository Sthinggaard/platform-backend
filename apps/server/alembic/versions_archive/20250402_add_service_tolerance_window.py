"""Add tolerance_window to business_services."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20250402_add_service_tolerance_window"
down_revision: Union[str, None] = "20250331_dependency_bundle"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("business_services")}
    if "tolerance_window" not in columns:
        op.add_column("business_services", sa.Column("tolerance_window", sa.String(length=20), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("business_services")}
    if "tolerance_window" in columns:
        op.drop_column("business_services", "tolerance_window")
