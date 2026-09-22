"""Separate the Collector's host from the container it runs in (CA-02.3 slice 3).

``os_name`` was written from the agent's ``/etc/os-release``, which inside a
container describes the **image**, not the machine. On a Raspberry Pi it read
"Debian GNU/Linux" — correct there only by coincidence, since the image is also
Debian — and would have been plainly wrong on an Ubuntu or RHEL host, with
nothing downstream able to tell (BUG-CA-02 / #171).

The agent now reports each fact under the scope it can actually vouch for:
``kernel_release`` and ``architecture`` are host facts even from inside a
container (containers share the kernel — verified on real hardware that
``platform.release()`` in the container is byte-identical to the host's
``uname -r``), while the distribution is claimed as the host's only when nothing
stands in between. ``container_runtime`` is what makes a NULL ``os_name``
readable as "cannot be determined from in here" rather than "not reported yet".

Additive and nullable. Existing rows keep whatever they were last sent; nothing
is rewritten, because the platform cannot know retroactively whether a stored
``os_name`` described a host or an image — which is the whole defect.

Revision ID: d4a8b2f60c19
Revises: c3f7a91e5b28
Create Date: 2026-08-14 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "d4a8b2f60c19"
down_revision = "c3f7a91e5b28"
branch_labels = None
depends_on = None

_TABLE = "scanner_instances"
_COLUMNS = (
    ("kernel_release", sa.String(100)),
    ("container_runtime", sa.String(30)),
    ("runtime_os_name", sa.String(100)),
    ("runtime_os_version", sa.String(100)),
)


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
    ).fetchone() is not None


def _col_exists(conn, table: str, column: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ),
        {"t": table, "c": column},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, _TABLE):
        return
    for name, type_ in _COLUMNS:
        if not _col_exists(conn, _TABLE, name):
            op.add_column(_TABLE, sa.Column(name, type_, nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, _TABLE):
        return
    for name, _type in _COLUMNS:
        if _col_exists(conn, _TABLE, name):
            op.drop_column(_TABLE, name)
