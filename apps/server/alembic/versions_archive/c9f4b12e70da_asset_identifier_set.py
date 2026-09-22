"""An artefact's identity becomes a set of observed identifiers (CA-06.1).

Identity used to be one field: the strongest signal available at the time,
hashed into ``assets.canonical_identity_key``. That made an artefact's identity
only as durable as that one field — a host keyed on its IP became a *new*
artefact the next time DHCP moved it, and the same host seen by nmap and by a
cloud provider produced two keys that could never converge. Both are named
directly in the CA-06 checklist.

``asset_identifiers`` records every identifier an artefact has ever been
observed under, with the source that observed it and its own first/last-seen
dates. Resolution matches on that set, so one identifier changing no longer
changes who the artefact is. An identifier is never deleted when it stops being
observed: the address a host used to answer on, and the date it last did, is the
only evidence that the move happened.

**No backfill, deliberately.** Existing artefacts keep their
``canonical_identity_key`` and identity resolution still falls back to it, so
nothing stops matching — their identifier set simply fills in the next time each
one is observed. The alternative would be inferring identifiers from
``display_name``, which for a manually created asset is a person's label, not an
address. Recording that as an observed identifier would be inventing evidence,
and every row of this table is a claim that something *saw* that value.

Idempotent per the repo's rules: guarded on the table and each index, so a
partial apply can be re-run.

Revision ID: c9f4b12e70da
Revises: d4a8b2f60c19
Create Date: 2026-08-15 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "c9f4b12e70da"
down_revision = "d4a8b2f60c19"
branch_labels = None
depends_on = None

_TABLE = "asset_identifiers"
_UNIQUE_INDEX = "uq_asset_identifiers_asset_type_value"
_LOOKUP_INDEX = "ix_asset_identifiers_org_type_value"
_ORG_INDEX = "ix_asset_identifiers_organization_id"
_ASSET_INDEX = "ix_asset_identifiers_asset_id"


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, _TABLE):
        op.create_table(
            _TABLE,
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id"),
                nullable=False,
            ),
            sa.Column(
                "asset_id",
                sa.Integer(),
                sa.ForeignKey("assets.id", ondelete="CASCADE"),
                nullable=False,
            ),
            # Controlled vocabulary (ArtefactIdentifierType) validated at the
            # service layer, matching this domain's existing String-not-Enum
            # precedent (asset_evidence_signals.kind).
            sa.Column("identifier_type", sa.String(40), nullable=False),
            sa.Column("identifier_value", sa.String(500), nullable=False),
            sa.Column("observed_by_source", sa.String(255), nullable=True),
            sa.Column("first_seen_at", sa.DateTime(), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        )

    # One row per distinct identifier per artefact — re-observing an identifier
    # updates last_seen_at rather than adding a duplicate.
    op.create_index(
        _UNIQUE_INDEX,
        _TABLE,
        ["asset_id", "identifier_type", "identifier_value"],
        unique=True,
        if_not_exists=True,
    )
    # The lookup resolution actually performs. Tenant scoping leads, as
    # everywhere in this codebase.
    op.create_index(
        _LOOKUP_INDEX,
        _TABLE,
        ["organization_id", "identifier_type", "identifier_value"],
        if_not_exists=True,
    )
    op.create_index(_ORG_INDEX, _TABLE, ["organization_id"], if_not_exists=True)
    op.create_index(_ASSET_INDEX, _TABLE, ["asset_id"], if_not_exists=True)


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, _TABLE):
        return
    for index in (_ASSET_INDEX, _ORG_INDEX, _LOOKUP_INDEX, _UNIQUE_INDEX):
        op.drop_index(index, table_name=_TABLE, if_exists=True)
    op.drop_table(_TABLE)
