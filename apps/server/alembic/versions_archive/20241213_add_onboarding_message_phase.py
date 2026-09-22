"""Add phase and structured_json to onboarding_messages."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "20241213_add_onboarding_message_phase"
down_revision: Union[str, None] = "20241212_uc6_onboarding"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("onboarding_messages", sa.Column("phase", sa.String(length=50), nullable=True))
    op.add_column("onboarding_messages", sa.Column("structured_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.create_index("ix_onboarding_messages_phase", "onboarding_messages", ["phase"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_onboarding_messages_phase", table_name="onboarding_messages")
    op.drop_column("onboarding_messages", "structured_json")
    op.drop_column("onboarding_messages", "phase")
