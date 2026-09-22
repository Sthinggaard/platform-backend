"""Baseline revision for Alembic.

This captures the current schema state as a starting point.
Future migrations should be additive and backward compatible.
"""
from alembic import op

# revision identifiers, used by Alembic.
revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # No-op baseline; schema already managed via SQLAlchemy models.
    pass


def downgrade():
    # No-op
    pass

