"""#248 — move discovery capability storage into PermissionProfile.

The old JSONB bag is converted into a real permission subject/profile pair for
each proposal. Existing decisions keep their status and approver; the note
marks the record as backfilled so it cannot be mistaken for a fresh human
approval.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "20260821_discovery_capabilities_permission_profiles"
down_revision = "20260820_recurrence_schedule_supersession"
branch_labels = None
depends_on = None


def _column_exists(conn, table: str, column: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :table AND column_name = :column"
        ),
        {"table": table, "column": column},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _column_exists(conn, "permission_profiles", "discovery_capabilities"):
        op.add_column(
            "permission_profiles",
            sa.Column("discovery_capabilities", JSONB(), nullable=True),
        )

    for column, foreign_table in (
        ("permission_subject_id", "permission_subjects"),
        ("permission_profile_id", "permission_profiles"),
    ):
        if not _column_exists(conn, "discovery_scope_proposals", column):
            op.add_column(
                "discovery_scope_proposals",
                sa.Column(column, sa.String(36), nullable=True),
            )

    conn.execute(
        sa.text(
            """
            UPDATE permission_profiles
            SET discovery_capabilities = '[]'::jsonb
            WHERE discovery_capabilities IS NULL
            """
        )
    )

    conn.execute(
        sa.text(
            """
            INSERT INTO permission_subjects (id, organization_id, subject_kind, created_at)
            SELECT gen_random_uuid()::text, p.organization_id,
                   'discovery_scope_proposal', NOW()
            FROM discovery_scope_proposals p
            WHERE p.permission_subject_id IS NULL
            """
        )
    )
    conn.execute(
        sa.text(
            """
            WITH proposals AS (
                SELECT id, organization_id,
                       ROW_NUMBER() OVER (PARTITION BY organization_id ORDER BY id) AS rn
                FROM discovery_scope_proposals
                WHERE permission_subject_id IS NULL
            ), subjects AS (
                SELECT id, organization_id,
                       ROW_NUMBER() OVER (PARTITION BY organization_id ORDER BY id) AS rn
                FROM permission_subjects
                WHERE subject_kind = 'discovery_scope_proposal'
                  AND id NOT IN (
                      SELECT permission_subject_id
                      FROM discovery_scope_proposals
                      WHERE permission_subject_id IS NOT NULL
                  )
            )
            UPDATE discovery_scope_proposals p
            SET permission_subject_id = s.id
            FROM proposals pending
            JOIN subjects s ON s.organization_id = pending.organization_id
                            AND s.rn = pending.rn
            WHERE p.id = pending.id
            """
        )
    )
    conn.execute(
        sa.text(
            """
            INSERT INTO permission_profiles (
                id, organization_id, subject_id, name, capabilities,
                discovery_capabilities, status, version, approved_by_user_id,
                approved_at, note, created_at, updated_at
            )
            SELECT gen_random_uuid()::text,
                   p.organization_id,
                   p.permission_subject_id,
                   'Discovery scope proposal',
                   '[]'::jsonb,
                   COALESCE(p.permission_profile->'capabilities', '[]'::jsonb),
                   CASE p.status
                       WHEN 'approved' THEN 'active'
                       WHEN 'awaiting_approval' THEN 'awaiting_approval'
                       WHEN 'draft' THEN 'draft'
                       WHEN 'rejected' THEN 'withdrawn'
                       WHEN 'superseded' THEN 'superseded'
                       ELSE 'withdrawn'
                   END,
                   1,
                   p.decided_by_user_id,
                   p.decided_at,
                   'Backfilled from discovery_scope_proposals.permission_profile; no new approval recorded.',
                   COALESCE(p.created_at, NOW()),
                   COALESCE(p.updated_at, NOW())
            FROM discovery_scope_proposals p
            WHERE p.permission_profile_id IS NULL
            """
        )
    )
    conn.execute(
        sa.text(
            """
            UPDATE discovery_scope_proposals p
            SET permission_profile_id = profile.id
            FROM permission_profiles profile
            WHERE p.permission_profile_id IS NULL
              AND profile.subject_id = p.permission_subject_id
              AND profile.note LIKE 'Backfilled from discovery_scope_proposals.permission_profile%'
            """
        )
    )

    op.alter_column("permission_profiles", "discovery_capabilities", nullable=False)
    op.alter_column("discovery_scope_proposals", "permission_subject_id", nullable=False)
    op.alter_column("discovery_scope_proposals", "permission_profile_id", nullable=False)
    op.create_unique_constraint(
        "uq_discovery_scope_proposals_permission_subject",
        "discovery_scope_proposals",
        ["permission_subject_id"],
    )
    op.create_unique_constraint(
        "uq_discovery_scope_proposals_permission_profile",
        "discovery_scope_proposals",
        ["permission_profile_id"],
    )
    op.create_foreign_key(
        "fk_discovery_scope_proposals_permission_subject",
        "discovery_scope_proposals",
        "permission_subjects",
        ["permission_subject_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_discovery_scope_proposals_permission_profile",
        "discovery_scope_proposals",
        "permission_profiles",
        ["permission_profile_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.drop_column("discovery_scope_proposals", "permission_profile")


def downgrade() -> None:
    op.add_column(
        "discovery_scope_proposals",
        sa.Column("permission_profile", JSONB(), nullable=True),
    )
    op.execute(
        sa.text(
            """
            UPDATE discovery_scope_proposals p
            SET permission_profile = jsonb_build_object(
                'capabilities', COALESCE(profile.discovery_capabilities, '[]'::jsonb)
            )
            FROM permission_profiles profile
            WHERE profile.id = p.permission_profile_id
            """
        )
    )
    op.alter_column("discovery_scope_proposals", "permission_profile", nullable=False)
    op.drop_constraint("fk_discovery_scope_proposals_permission_profile", "discovery_scope_proposals", type_="foreignkey")
    op.drop_constraint("fk_discovery_scope_proposals_permission_subject", "discovery_scope_proposals", type_="foreignkey")
    op.drop_constraint("uq_discovery_scope_proposals_permission_profile", "discovery_scope_proposals", type_="unique")
    op.drop_constraint("uq_discovery_scope_proposals_permission_subject", "discovery_scope_proposals", type_="unique")
    op.drop_column("discovery_scope_proposals", "permission_profile_id")
    op.drop_column("discovery_scope_proposals", "permission_subject_id")
    op.execute(
        sa.text(
            """
            DELETE FROM permission_profiles
            WHERE note LIKE 'Backfilled from discovery_scope_proposals.permission_profile%'
            """
        )
    )
    op.execute(
        sa.text(
            """
            DELETE FROM permission_subjects
            WHERE subject_kind = 'discovery_scope_proposal'
              AND id NOT IN (SELECT subject_id FROM permission_profiles)
            """
        )
    )
    op.drop_column("permission_profiles", "discovery_capabilities")
