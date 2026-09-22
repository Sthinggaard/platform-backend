"""CA-08.3 (#291) — reading deployed configuration gets its own approval.

Søren, 2026-08-24: ``read_service_config`` stays in CA-08's scope, under the
treatment the Docker socket already has. Deployed configuration is where
credentials live, so granting it must not happen by the same click that granted
"read the OS version".

Two columns, mirroring ``docker_socket_approved_*`` exactly — the shape is
already proven here, and a second shape would invite the question of which one
a reviewer should trust.

Additive and guarded per column, so a re-run is a no-op.

**On the inline ``nosemgrep``**: Semgrep's ``avoid-sqlalchemy-text`` rule fires
on the existence check. It is a literal string with no interpolation — the table
and column names are module constants — so there is nothing a request can reach.
Suppressed at the site with the rule id, per the security gate's narrow-exception
rule, exactly as ``20260824_verification_runs`` does.
"""

from alembic import op
import sqlalchemy as sa

revision = "20260824_service_config_approval"
down_revision = "20260824_verification_runs"
branch_labels = None
depends_on = None

_TABLE = "permission_profiles"
_COLUMNS = ("service_config_approved_by_user_id", "service_config_approved_at")


def _col_exists(conn, column: str) -> bool:
    return conn.execute(
        sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :table AND column_name = :column"
        ),
        {"table": _TABLE, "column": column},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _col_exists(conn, _COLUMNS[0]):
        op.add_column(
            _TABLE,
            sa.Column(
                _COLUMNS[0],
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )
    if not _col_exists(conn, _COLUMNS[1]):
        op.add_column(_TABLE, sa.Column(_COLUMNS[1], sa.DateTime(), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    for column in reversed(_COLUMNS):
        if _col_exists(conn, column):
            op.drop_column(_TABLE, column)
