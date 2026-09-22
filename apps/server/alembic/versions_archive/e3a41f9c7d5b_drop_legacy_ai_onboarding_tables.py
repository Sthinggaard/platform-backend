"""Drop the legacy AI-conversation onboarding tables.

The conversational onboarding system (OnboardingSession, ConnectorRequest,
ArchitectureAsset, IntegrationCredential, GeneratedDocument, RiskScanJob, and
their supporting tables) was superseded by the CVR/NACE-driven public
onboarding flow (public_onboarding_sessions) and the governed Business
Process activation ladder. Its tenant UI was already archived
(apps/tenant/archived/app/onboarding-canvas); the last two commits touching
its server code were both mechanical refactors, not feature work. Removed
per explicit product decision (2026-07-14) rather than left as dead schema.

This is a permanent removal, not a temporary rollback candidate: downgrade()
does not recreate the tables. Restoring this feature would mean restoring
the deleted application code first, at which point a fresh migration
belongs with it.

Revision ID: e3a41f9c7d5b
Revises: 6e1f0c8a3b2d
Create Date: 2026-07-14
"""

import sqlalchemy as sa

from alembic import op

revision = "e3a41f9c7d5b"
down_revision = "6e1f0c8a3b2d"
branch_labels = None
depends_on = None

# Children first, then the parent onboarding_sessions table. CASCADE also
# catches any FK dependency the manual ordering misses.
_TABLES_IN_DROP_ORDER = [
    "onboarding_events",
    "onboarding_messages",
    "onboarding_roadmap_items",
    "connector_requests",
    "compliance_profiles",
    "org_profiles",
    "artefact_versions",
    "evidence_signals",
    "architecture_assets",
    "integration_credentials",
    "generated_documents",
    "risk_scan_jobs",
    "onboarding_sessions",
]


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())
    for table_name in _TABLES_IN_DROP_ORDER:
        if table_name in existing:
            op.execute(f'DROP TABLE IF EXISTS "{table_name}" CASCADE')


def downgrade() -> None:
    # Intentional no-op — see module docstring. The application code this
    # schema served no longer exists on any branch past this revision.
    pass
