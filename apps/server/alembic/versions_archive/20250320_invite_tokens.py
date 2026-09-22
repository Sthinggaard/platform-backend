"""Add invite-only signup tokens."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "20250320_invite_tokens"
down_revision: Union[str, None] = "20250310_add_mfa"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "invite_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("invited_by_user_id", sa.Integer(), nullable=True),
        sa.Column("token_hash", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["invited_by_user_id"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_invite_tokens_token_hash", "invite_tokens", ["token_hash"], unique=True)
    op.create_index("ix_invite_tokens_user_expires", "invite_tokens", ["user_id", "expires_at"])
    op.create_index("ix_invite_tokens_user_used", "invite_tokens", ["user_id", "used_at"])


def downgrade() -> None:
    op.drop_index("ix_invite_tokens_user_used", table_name="invite_tokens")
    op.drop_index("ix_invite_tokens_user_expires", table_name="invite_tokens")
    op.drop_index("ix_invite_tokens_token_hash", table_name="invite_tokens")
    op.drop_table("invite_tokens")
