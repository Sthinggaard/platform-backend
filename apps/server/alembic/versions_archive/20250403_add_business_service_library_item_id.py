"""add business service library item provenance

Revision ID: 20250403_add_business_service_library_item_id
Revises: 20250402_bundle_validation_audit_snapshot
Create Date: 2026-04-03 23:30:00.000000
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20250403_add_business_service_library_item_id"
down_revision = "20250402_bundle_validation_audit_snapshot"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("business_services")}
    if "library_item_id" not in columns:
        op.add_column(
            "business_services",
            sa.Column("library_item_id", sa.String(length=100), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("business_services")}
    if "library_item_id" in columns:
        op.drop_column("business_services", "library_item_id")
