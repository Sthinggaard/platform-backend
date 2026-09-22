"""#262 — preserve schedule history when a cadence is replaced."""

from alembic import op
import sqlalchemy as sa

revision = "20260820_recurrence_schedule_supersession"
down_revision = "20260820_audit_actor_time_and_place"
branch_labels = None
depends_on = None

_TABLE = "recurrence_schedules"


def _column_exists(conn, column: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :table AND column_name = :column"
        ),
        {"table": _TABLE, "column": column},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    for column, column_type in (
        ("supersedes_schedule_id", sa.String(36)),
        ("superseded_by_id", sa.String(36)),
        ("superseded_at", sa.DateTime()),
        ("superseded_by_user_id", sa.Integer()),
    ):
        if not _column_exists(conn, column):
            op.add_column(_TABLE, sa.Column(column, column_type, nullable=True))
    inspector = sa.inspect(conn)
    foreign_keys = {fk["name"] for fk in inspector.get_foreign_keys(_TABLE)}
    if "recurrence_schedules_supersedes_schedule_id_fkey" not in foreign_keys:
        op.create_foreign_key(
            "recurrence_schedules_supersedes_schedule_id_fkey",
            _TABLE,
            _TABLE,
            ["supersedes_schedule_id"],
            ["id"],
            ondelete="SET NULL",
        )
    if "recurrence_schedules_superseded_by_id_fkey" not in foreign_keys:
        op.create_foreign_key(
            "recurrence_schedules_superseded_by_id_fkey",
            _TABLE,
            _TABLE,
            ["superseded_by_id"],
            ["id"],
            ondelete="SET NULL",
        )
    if "recurrence_schedules_superseded_by_user_id_fkey" not in foreign_keys:
        op.create_foreign_key(
            "recurrence_schedules_superseded_by_user_id_fkey",
            _TABLE,
            "users",
            ["superseded_by_user_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    foreign_keys = {fk["name"] for fk in inspector.get_foreign_keys(_TABLE)}
    for name in (
        "recurrence_schedules_superseded_by_user_id_fkey",
        "recurrence_schedules_superseded_by_id_fkey",
        "recurrence_schedules_supersedes_schedule_id_fkey",
    ):
        if name in foreign_keys:
            op.drop_constraint(name, _TABLE, type_="foreignkey")
    for column in ("superseded_by_user_id", "superseded_at", "superseded_by_id", "supersedes_schedule_id"):
        if _column_exists(conn, column):
            op.drop_column(_TABLE, column)
