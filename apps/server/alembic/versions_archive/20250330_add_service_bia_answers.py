"""Add bia_answers to business_services for persisted service impact setup."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "20250330_add_service_bia_answers"
down_revision: Union[str, None] = "20250324_recovery_actions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("business_services")}
    if "bia_answers" not in columns:
        op.add_column("business_services", sa.Column("bia_answers", JSONB(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("business_services")}
    if "bia_answers" in columns:
        op.drop_column("business_services", "bia_answers")
