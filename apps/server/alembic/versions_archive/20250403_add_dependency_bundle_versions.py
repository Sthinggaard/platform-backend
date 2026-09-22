"""add dependency bundle versions

Revision ID: 20250403_add_dependency_bundle_versions
Revises: 20250403_add_business_service_library_item_id
Create Date: 2026-04-03 23:59:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision = "20250403_add_dependency_bundle_versions"
down_revision = "20250403_add_business_service_library_item_id"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "dependency_bundle_versions" not in tables:
        op.create_table(
            "dependency_bundle_versions",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("organization_id", sa.Integer(), nullable=False),
            sa.Column("bundle_id", sa.String(length=36), nullable=False),
            sa.Column("service_id", sa.String(length=36), nullable=False),
            sa.Column("version_number", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False, server_default="published"),
            sa.Column("lifecycle_state", sa.String(length=40), nullable=False, server_default="bundle_published"),
            sa.Column("groups_snapshot", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
            sa.Column("validation_snapshot", JSONB, nullable=True),
            sa.Column(
                "acknowledged_warning_ids",
                JSONB,
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
            sa.Column("published_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["bundle_id"], ["dependency_bundles.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["service_id"], ["business_services.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_dependency_bundle_versions_bundle",
            "dependency_bundle_versions",
            ["bundle_id"],
            unique=False,
        )
        op.create_index(
            "ix_dependency_bundle_versions_service",
            "dependency_bundle_versions",
            ["service_id"],
            unique=False,
        )
        op.create_index(
            "ix_dependency_bundle_versions_org",
            "dependency_bundle_versions",
            ["organization_id"],
            unique=False,
        )
        op.create_index(
            "ix_dependency_bundle_versions_bundle_version",
            "dependency_bundle_versions",
            ["bundle_id", "version_number"],
            unique=True,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "dependency_bundle_versions" in tables:
        op.drop_index("ix_dependency_bundle_versions_bundle_version", table_name="dependency_bundle_versions")
        op.drop_index("ix_dependency_bundle_versions_org", table_name="dependency_bundle_versions")
        op.drop_index("ix_dependency_bundle_versions_service", table_name="dependency_bundle_versions")
        op.drop_index("ix_dependency_bundle_versions_bundle", table_name="dependency_bundle_versions")
        op.drop_table("dependency_bundle_versions")
