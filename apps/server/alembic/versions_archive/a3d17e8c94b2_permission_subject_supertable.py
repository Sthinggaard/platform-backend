"""Permission profiles bound a subject, not a connector (CA-07.3 / Epic C4).

Søren's decision, 2026-08-18, after asking whether the earlier shape would force
a migration if C4's scope widened. It would have — and worse, the usual escape
from that (`subject_type` + `subject_id`) buys open-endedness by giving up the
foreign key entirely: nothing would stop a profile pointing at a deleted row, or
one belonging to another organisation.

A supertable buys the same open-endedness and keeps the checking. Every
permissionable thing owns a row in `permission_subjects`; `permission_profiles`
holds a **real foreign key** to it. Adding a new kind of subject means giving
that table a `permission_subject_id` and registering a row — with no change to
`permission_profiles` and none to the enforcement path.

Done now, while `access_connectors` is the only subject and there is no
production data, which is the cheapest this change will ever be.

`f2a95d7be013` is not edited: it has already been applied. This transforms
forward instead, and backfills rather than dropping — every existing profile
gets a subject row and keeps pointing at the same Connector.

Idempotent per the repo's rules: guarded on the table, each column and each index.

Revision ID: a3d17e8c94b2
Revises: f2a95d7be013
Create Date: 2026-08-18 00:00:00.000000

**On the inline ``nosemgrep`` suppressions.** Semgrep's ``avoid-sqlalchemy-text``
rule fires on every ``sa.text()`` here. Each one is a literal SQL string written
in this file, with the only interpolation being a table or column name held in a
module constant — never a value a request could reach. Where a value does vary it
is bound as a parameter, not formatted in. Suppressed at each site with the rule
id rather than excluded wholesale, per the security gate's own narrow-exception
rule.
"""

from alembic import op
import sqlalchemy as sa

revision = "a3d17e8c94b2"
down_revision = "f2a95d7be013"
branch_labels = None
depends_on = None

_SUBJECTS = "permission_subjects"
_PROFILES = "permission_profiles"
_CONNECTORS = "access_connectors"

_SUBJECT_KIND_INDEX = "ix_permission_subjects_org_kind"
_SUBJECT_ORG_INDEX = "ix_permission_subjects_organization_id"
_PROFILE_SUBJECT_INDEX = "ix_permission_profiles_subject"
_PROFILE_CONNECTOR_INDEX = "ix_permission_profiles_connector"


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

    if not _table_exists(conn, _SUBJECTS):
        op.create_table(
            _SUBJECTS,
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            # Descriptive, for reading and for querying one kind. Never the
            # integrity mechanism — the foreign keys on either side are.
            sa.Column("subject_kind", sa.String(40), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
    op.create_index(
        _SUBJECT_KIND_INDEX, _SUBJECTS, ["organization_id", "subject_kind"], if_not_exists=True
    )
    op.create_index(_SUBJECT_ORG_INDEX, _SUBJECTS, ["organization_id"], if_not_exists=True)

    # --- give every Connector a subject -----------------------------------
    if not _col_exists(conn, _CONNECTORS, "permission_subject_id"):
        op.add_column(_CONNECTORS, sa.Column("permission_subject_id", sa.String(36), nullable=True))
        # Backfill: one subject per existing Connector, same organisation.
        conn.execute(
            sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                f"""
                INSERT INTO {_SUBJECTS} (id, organization_id, subject_kind, created_at)
                SELECT gen_random_uuid()::text, c.organization_id, 'access_connector', NOW()
                FROM {_CONNECTORS} c
                WHERE c.permission_subject_id IS NULL
                """
            )
        )
        conn.execute(
            sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                f"""
                UPDATE {_CONNECTORS} c
                SET permission_subject_id = s.id
                FROM (
                    SELECT s.id, s.organization_id,
                           ROW_NUMBER() OVER (PARTITION BY s.organization_id ORDER BY s.id) rn
                    FROM {_SUBJECTS} s
                    WHERE s.subject_kind = 'access_connector'
                ) s,
                (
                    SELECT c2.id, c2.organization_id,
                           ROW_NUMBER() OVER (PARTITION BY c2.organization_id ORDER BY c2.id) rn
                    FROM {_CONNECTORS} c2
                    WHERE c2.permission_subject_id IS NULL
                ) c2
                WHERE c.id = c2.id
                  AND s.organization_id = c2.organization_id
                  AND s.rn = c2.rn
                """
            )
        )
        op.alter_column(_CONNECTORS, "permission_subject_id", nullable=False)
        op.create_unique_constraint(
            "uq_access_connectors_permission_subject", _CONNECTORS, ["permission_subject_id"]
        )
        op.create_foreign_key(
            "fk_access_connectors_permission_subject",
            _CONNECTORS,
            _SUBJECTS,
            ["permission_subject_id"],
            ["id"],
            ondelete="CASCADE",
        )

    # --- point profiles at the subject ------------------------------------
    if not _col_exists(conn, _PROFILES, "subject_id"):
        op.add_column(_PROFILES, sa.Column("subject_id", sa.String(36), nullable=True))
        conn.execute(
            sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                f"""
                UPDATE {_PROFILES} p
                SET subject_id = c.permission_subject_id
                FROM {_CONNECTORS} c
                WHERE p.connector_id = c.id
                """
            )
        )
        op.alter_column(_PROFILES, "subject_id", nullable=False)
        op.create_foreign_key(
            "fk_permission_profiles_subject",
            _PROFILES,
            _SUBJECTS,
            ["subject_id"],
            ["id"],
            ondelete="CASCADE",
        )
        op.create_index(
            _PROFILE_SUBJECT_INDEX, _PROFILES, ["subject_id", "status"], if_not_exists=True
        )
        op.drop_index(_PROFILE_CONNECTOR_INDEX, table_name=_PROFILES, if_exists=True)
        op.drop_column(_PROFILES, "connector_id")


def downgrade() -> None:
    conn = op.get_bind()
    if _col_exists(conn, _PROFILES, "subject_id"):
        op.add_column(_PROFILES, sa.Column("connector_id", sa.String(36), nullable=True))
        conn.execute(
            sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                f"""
                UPDATE {_PROFILES} p
                SET connector_id = c.id
                FROM {_CONNECTORS} c
                WHERE p.subject_id = c.permission_subject_id
                """
            )
        )
        op.drop_index(_PROFILE_SUBJECT_INDEX, table_name=_PROFILES, if_exists=True)
        op.drop_column(_PROFILES, "subject_id")
        op.create_index(
            _PROFILE_CONNECTOR_INDEX, _PROFILES, ["connector_id", "status"], if_not_exists=True
        )
    if _col_exists(conn, _CONNECTORS, "permission_subject_id"):
        op.drop_column(_CONNECTORS, "permission_subject_id")
    if _table_exists(conn, _SUBJECTS):
        for index in (_SUBJECT_ORG_INDEX, _SUBJECT_KIND_INDEX):
            op.drop_index(index, table_name=_SUBJECTS, if_exists=True)
        op.drop_table(_SUBJECTS)
