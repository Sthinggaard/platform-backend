"""The schema, as one statement.

Revision ID: 20260910_schema_baseline
Revises:
Create Date: 2026-09-10

This replaces 131 migrations that could never build a database from nothing.
`0001_baseline` was an explicit no-op — "schema already managed via SQLAlchemy
models" — and nothing in the chain after it ever created `organizations`,
`users`, or any other core table. Every migration was a delta on a schema
`create_all` had already built, so `alembic upgrade head` against an empty
database died on the second revision and always had.

The consequence was two ways for a schema to come into being: `create_all` plus
`alembic stamp head` for a new database, and `alembic upgrade head` for one that
already existed. They could not be reconciled — reconciling them was tried on
staging on 2026-09-09 and produced a `permission_profiles` shaped as the models
describe it today, which a 2026-08-18 migration then tried to index on a column
the models no longer have. A from-scratch environment never exercised what
production would run, which is the whole point of having migrations.

This is that schema frozen: 122 tables and 356 indexes, generated from the
models at `9107ec9dc` and not edited by hand. The 131 migrations it replaces are
kept, unloaded, in `alembic/versions_archive/` — read them to find out why a
column exists, never to run them.

Databases that predate this revision are stamped here by
`scripts/ensure_schema.py`, which refuses to stamp one whose schema does not
match the models.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260910_schema_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('business_process_recommendations',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('process_template_id', sa.String(length=100), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('category', sa.String(length=100), nullable=False),
    sa.Column('confidence', sa.Float(), nullable=False),
    sa.Column('recommendation_reason', sa.Text(), nullable=False),
    sa.Column('source_rule', sa.String(length=120), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('model_version', sa.String(length=80), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_business_process_recommendations_org_status', 'business_process_recommendations', ['organization_id', 'status'], unique=False)
    op.create_index('ix_business_process_recommendations_org_template', 'business_process_recommendations', ['organization_id', 'process_template_id'], unique=False)
    op.create_index(op.f('ix_business_process_recommendations_organization_id'), 'business_process_recommendations', ['organization_id'], unique=False)
    op.create_index(op.f('ix_business_process_recommendations_user_id'), 'business_process_recommendations', ['user_id'], unique=False)
    op.create_table('controls',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('framework', sa.String(length=100), nullable=False),
    sa.Column('control_code', sa.String(length=50), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_controls_framework'), 'controls', ['framework'], unique=False)
    op.create_index('ix_controls_framework_code', 'controls', ['framework', 'control_code'], unique=True)
    op.create_index(op.f('ix_controls_id'), 'controls', ['id'], unique=False)
    op.create_table('learning_loop_runs',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('triggered_by', sa.String(length=30), nullable=False),
    sa.Column('since', sa.DateTime(), nullable=True),
    sa.Column('signals_ingested', sa.Integer(), nullable=False),
    sa.Column('candidates_generated', sa.Integer(), nullable=False),
    sa.Column('candidates_auto_staged', sa.Integer(), nullable=False),
    sa.Column('summary', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('started_at', sa.DateTime(), nullable=False),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_learning_loop_runs_started_at', 'learning_loop_runs', ['started_at'], unique=False)
    op.create_index('ix_learning_loop_runs_status', 'learning_loop_runs', ['status'], unique=False)
    op.create_table('organizations',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('slug', sa.String(length=100), nullable=False),
    sa.Column('industry', sa.String(length=100), nullable=True),
    sa.Column('company_size', sa.String(length=50), nullable=True),
    sa.Column('country', sa.String(length=2), nullable=True),
    sa.Column('required_frameworks', sa.ARRAY(sa.String()), nullable=True),
    sa.Column('compliance_level', sa.String(length=50), nullable=True),
    sa.Column('regulatory_requirements', sa.JSON(), nullable=True),
    sa.Column('plan_tier', sa.String(length=50), nullable=False),
    sa.Column('trial_ends_at', sa.DateTime(), nullable=True),
    sa.Column('subscription_status', sa.String(length=50), nullable=False),
    sa.Column('cvr_number', sa.String(length=20), nullable=True),
    sa.Column('nace_code', sa.String(length=10), nullable=True),
    sa.Column('org_value_stream_profile', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('organization_type', sa.String(length=30), nullable=True),
    sa.Column('headquarters_country', sa.String(length=2), nullable=True),
    sa.Column('operating_countries', sa.ARRAY(sa.String()), nullable=True),
    sa.Column('employee_range', sa.String(length=30), nullable=True),
    sa.Column('website_domain', sa.String(length=255), nullable=True),
    sa.Column('technical_setup_owner_user_id', sa.Integer(), nullable=True),
    sa.Column('settings', sa.JSON(), nullable=True),
    sa.Column('onboarding_completed', sa.Boolean(), nullable=False),
    sa.Column('onboarding_data', sa.JSON(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['technical_setup_owner_user_id'], ['users.id'], name='fk_organizations_technical_setup_owner', ondelete='SET NULL', use_alter=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_organizations_id'), 'organizations', ['id'], unique=False)
    op.create_index(op.f('ix_organizations_slug'), 'organizations', ['slug'], unique=True)
    op.create_table('process_templates',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('template_key', sa.String(length=100), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('process_family', sa.String(length=50), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('service_slots', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('template_key', 'version', name='uq_process_templates_key_version')
    )
    op.create_index('ix_process_templates_family_active', 'process_templates', ['process_family', 'is_active'], unique=False)
    op.create_index('ix_process_templates_key_active', 'process_templates', ['template_key', 'is_active'], unique=False)
    op.create_table('service_templates',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('service_key', sa.String(length=100), nullable=False),
    sa.Column('service_name', sa.String(length=200), nullable=False),
    sa.Column('archetype', sa.String(length=100), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('capability_groups', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('seeded_from', sa.String(length=100), nullable=True),
    sa.Column('capability_statement', sa.Text(), nullable=True),
    sa.Column('default_impact_model', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('operational_expectations', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('common_risk_patterns', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('override_policy', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('service_key', 'version', name='uq_service_templates_key_version')
    )
    op.create_index('ix_service_templates_archetype_active', 'service_templates', ['archetype', 'is_active'], unique=False)
    op.create_index('ix_service_templates_key_active', 'service_templates', ['service_key', 'is_active'], unique=False)
    op.create_table('template_learning_runs',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('triggered_by', sa.String(length=30), nullable=False),
    sa.Column('service_keys_analysed', sa.ARRAY(sa.String()), nullable=False),
    sa.Column('candidates_generated', sa.Integer(), nullable=False),
    sa.Column('candidates_auto_staged', sa.Integer(), nullable=False),
    sa.Column('summary', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('started_at', sa.DateTime(), nullable=False),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_template_learning_runs_started_at', 'template_learning_runs', ['started_at'], unique=False)
    op.create_index('ix_template_learning_runs_status', 'template_learning_runs', ['status'], unique=False)
    op.create_table('auth_tenant_settings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('domain_allowlist', sa.ARRAY(sa.String()), nullable=False),
    sa.Column('local_login_enabled', sa.Boolean(), nullable=False),
    sa.Column('sso_google_enabled', sa.Boolean(), nullable=False),
    sa.Column('sso_ms_enabled', sa.Boolean(), nullable=False),
    sa.Column('sso_required', sa.Boolean(), nullable=False),
    sa.Column('mfa_sms_enabled', sa.Boolean(), nullable=False),
    sa.Column('mfa_required_for_all', sa.Boolean(), nullable=False),
    sa.Column('mfa_required_for_admins', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_auth_tenant_settings_id'), 'auth_tenant_settings', ['id'], unique=False)
    op.create_index(op.f('ix_auth_tenant_settings_organization_id'), 'auth_tenant_settings', ['organization_id'], unique=True)
    op.create_table('baseline_risk_hypotheses',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('company_context', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('assumptions', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('generated_at', sa.DateTime(), nullable=False),
    sa.Column('validated_by', sa.String(length=100), nullable=True),
    sa.Column('validated_at', sa.DateTime(), nullable=True),
    sa.Column('superseded_by_id', sa.String(length=36), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['superseded_by_id'], ['baseline_risk_hypotheses.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_baseline_risk_hypotheses_org_status', 'baseline_risk_hypotheses', ['organization_id', 'status'], unique=False)
    op.create_table('business_process_decision_logs',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('recommendation_id', sa.String(length=36), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('action', sa.String(length=20), nullable=False),
    sa.Column('reason', sa.JSON(), nullable=True),
    sa.Column('model_version', sa.String(length=80), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['recommendation_id'], ['business_process_recommendations.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_business_process_decision_logs_org_created', 'business_process_decision_logs', ['organization_id', 'created_at'], unique=False)
    op.create_index(op.f('ix_business_process_decision_logs_organization_id'), 'business_process_decision_logs', ['organization_id'], unique=False)
    op.create_index('ix_business_process_decision_logs_recommendation', 'business_process_decision_logs', ['recommendation_id'], unique=False)
    op.create_index(op.f('ix_business_process_decision_logs_recommendation_id'), 'business_process_decision_logs', ['recommendation_id'], unique=False)
    op.create_index(op.f('ix_business_process_decision_logs_user_id'), 'business_process_decision_logs', ['user_id'], unique=False)
    op.create_table('cloud_assets',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.String(length=500), nullable=False),
    sa.Column('asset_type', sa.String(length=100), nullable=False),
    sa.Column('cloud_provider', sa.String(length=50), nullable=False),
    sa.Column('region', sa.String(length=100), nullable=True),
    sa.Column('name', sa.String(length=500), nullable=False),
    sa.Column('asset_metadata', sa.JSON(), nullable=True),
    sa.Column('discovered_at', sa.DateTime(), nullable=False),
    sa.Column('last_scanned', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_cloud_assets_asset_id'), 'cloud_assets', ['asset_id'], unique=True)
    op.create_index(op.f('ix_cloud_assets_asset_type'), 'cloud_assets', ['asset_type'], unique=False)
    op.create_index(op.f('ix_cloud_assets_cloud_provider'), 'cloud_assets', ['cloud_provider'], unique=False)
    op.create_index(op.f('ix_cloud_assets_id'), 'cloud_assets', ['id'], unique=False)
    op.create_index(op.f('ix_cloud_assets_organization_id'), 'cloud_assets', ['organization_id'], unique=False)
    op.create_index(op.f('ix_cloud_assets_region'), 'cloud_assets', ['region'], unique=False)
    op.create_table('cloud_credentials',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('cloud_provider', sa.String(length=50), nullable=False),
    sa.Column('credential_name', sa.String(length=200), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('encrypted_credentials', sa.Text(), nullable=False),
    sa.Column('encryption_key_id', sa.String(length=100), nullable=False),
    sa.Column('scope', sa.JSON(), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('last_validated_at', sa.DateTime(), nullable=True),
    sa.Column('validation_status', sa.String(length=50), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_cloud_credentials_id'), 'cloud_credentials', ['id'], unique=False)
    op.create_index(op.f('ix_cloud_credentials_organization_id'), 'cloud_credentials', ['organization_id'], unique=False)
    op.create_table('compliance_frameworks',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=True),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('version', sa.String(length=20), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('is_template', sa.Boolean(), nullable=False),
    sa.Column('source_framework_id', sa.Integer(), nullable=True),
    sa.Column('customization_level', sa.String(length=50), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['source_framework_id'], ['compliance_frameworks.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_compliance_frameworks_id'), 'compliance_frameworks', ['id'], unique=False)
    op.create_index(op.f('ix_compliance_frameworks_name'), 'compliance_frameworks', ['name'], unique=True)
    op.create_index(op.f('ix_compliance_frameworks_organization_id'), 'compliance_frameworks', ['organization_id'], unique=False)
    op.create_table('contextual_access_policies',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('decision', sa.String(length=40), nullable=False),
    sa.Column('choice', sa.String(length=40), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('consequence_statement', sa.Text(), nullable=False),
    sa.Column('consequence_acknowledged', sa.Boolean(), nullable=False),
    sa.Column('prepared_by', sa.String(length=255), nullable=True),
    sa.Column('submitted_by', sa.String(length=255), nullable=True),
    sa.Column('submitted_at', sa.DateTime(), nullable=True),
    sa.Column('approved_by', sa.String(length=255), nullable=True),
    sa.Column('approved_at', sa.DateTime(), nullable=True),
    sa.Column('approval_reference', sa.String(length=500), nullable=True),
    sa.Column('rejected_by', sa.String(length=255), nullable=True),
    sa.Column('rejected_at', sa.DateTime(), nullable=True),
    sa.Column('rejection_reason', sa.Text(), nullable=True),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('effective_from', sa.DateTime(), nullable=True),
    sa.Column('effective_to', sa.DateTime(), nullable=True),
    sa.Column('review_at', sa.DateTime(), nullable=True),
    sa.Column('superseded_by_id', sa.String(length=36), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['superseded_by_id'], ['contextual_access_policies.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_contextual_access_policies_org_decision', 'contextual_access_policies', ['organization_id', 'decision', 'status'], unique=False)
    op.create_table('control_mappings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('control_id', sa.Integer(), nullable=False),
    sa.Column('asset_type', sa.String(length=50), nullable=False),
    sa.Column('signal_kind', sa.String(length=100), nullable=False),
    sa.Column('min_confidence', sa.Float(), nullable=False),
    sa.Column('evidence_rule', sa.String(length=255), nullable=True),
    sa.ForeignKeyConstraint(['control_id'], ['controls.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_control_mappings_asset_type'), 'control_mappings', ['asset_type'], unique=False)
    op.create_index(op.f('ix_control_mappings_control_id'), 'control_mappings', ['control_id'], unique=False)
    op.create_index(op.f('ix_control_mappings_id'), 'control_mappings', ['id'], unique=False)
    op.create_table('control_share_links',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('token', sa.String(length=200), nullable=False),
    sa.Column('scope', sa.JSON(), nullable=True),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token')
    )
    op.create_index(op.f('ix_control_share_links_id'), 'control_share_links', ['id'], unique=False)
    op.create_index(op.f('ix_control_share_links_organization_id'), 'control_share_links', ['organization_id'], unique=False)
    op.create_index('ix_control_share_token', 'control_share_links', ['token'], unique=True)
    op.create_table('key_risk_indicators',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('calculation_method', sa.JSON(), nullable=True),
    sa.Column('threshold_value', sa.Float(), nullable=False),
    sa.Column('current_value', sa.Float(), nullable=True),
    sa.Column('status', sa.String(length=50), nullable=False),
    sa.Column('measured_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_key_risk_indicators_id'), 'key_risk_indicators', ['id'], unique=False)
    op.create_index(op.f('ix_key_risk_indicators_measured_at'), 'key_risk_indicators', ['measured_at'], unique=False)
    op.create_index(op.f('ix_key_risk_indicators_name'), 'key_risk_indicators', ['name'], unique=False)
    op.create_index(op.f('ix_key_risk_indicators_organization_id'), 'key_risk_indicators', ['organization_id'], unique=False)
    op.create_index(op.f('ix_key_risk_indicators_status'), 'key_risk_indicators', ['status'], unique=False)
    op.create_table('learning_improvement_candidates',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('run_id', sa.String(length=36), nullable=False),
    sa.Column('candidate_type', sa.String(length=50), nullable=False),
    sa.Column('target_type', sa.String(length=40), nullable=False),
    sa.Column('target_key', sa.String(length=200), nullable=False),
    sa.Column('governance_class', sa.String(length=1), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('sample_size', sa.Integer(), nullable=False),
    sa.Column('confidence_score', sa.Integer(), nullable=False),
    sa.Column('summary', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('proposed_changes', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('reviewed_by', sa.String(length=255), nullable=True),
    sa.Column('review_note', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['run_id'], ['learning_loop_runs.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_learning_improvement_candidates_governance', 'learning_improvement_candidates', ['governance_class'], unique=False)
    op.create_index('ix_learning_improvement_candidates_run', 'learning_improvement_candidates', ['run_id'], unique=False)
    op.create_index('ix_learning_improvement_candidates_status', 'learning_improvement_candidates', ['status'], unique=False)
    op.create_index('ix_learning_improvement_candidates_target', 'learning_improvement_candidates', ['target_type', 'target_key'], unique=False)
    op.create_index('ix_learning_improvement_candidates_type', 'learning_improvement_candidates', ['candidate_type'], unique=False)
    op.create_table('mapping_decisions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('service_id', sa.String(length=36), nullable=False),
    sa.Column('bundle_id', sa.String(length=36), nullable=False),
    sa.Column('node_id', sa.String(length=36), nullable=True),
    sa.Column('action', sa.String(length=50), nullable=False),
    sa.Column('group_key', sa.String(length=50), nullable=True),
    sa.Column('before_state', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('after_state', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('reason', sa.Text(), nullable=True),
    sa.Column('actor_type', sa.String(length=20), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_mapping_decisions_bundle', 'mapping_decisions', ['bundle_id'], unique=False)
    op.create_index('ix_mapping_decisions_org', 'mapping_decisions', ['organization_id'], unique=False)
    op.create_index('ix_mapping_decisions_service', 'mapping_decisions', ['service_id'], unique=False)
    op.create_table('org_process_configs',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('template_key', sa.String(length=100), nullable=False),
    sa.Column('excluded_service_keys', sa.ARRAY(sa.String()), nullable=False),
    sa.Column('custom_service_slots', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('created_by', sa.String(length=255), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'template_key', name='uq_org_process_configs_org_key')
    )
    op.create_index('ix_org_process_configs_org', 'org_process_configs', ['organization_id'], unique=False)
    op.create_table('org_service_configs',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('service_key', sa.String(length=100), nullable=False),
    sa.Column('excluded_group_keys', sa.ARRAY(sa.String()), nullable=False),
    sa.Column('custom_groups', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('created_by', sa.String(length=255), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'service_key', name='uq_org_service_configs_org_key')
    )
    op.create_index('ix_org_service_configs_org', 'org_service_configs', ['organization_id'], unique=False)
    op.create_table('organization_identity_evidence',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('source_type', sa.String(length=30), nullable=False),
    sa.Column('source_reference', sa.String(length=100), nullable=True),
    sa.Column('observed_at', sa.DateTime(), nullable=False),
    sa.Column('raw_legal_name', sa.String(length=255), nullable=True),
    sa.Column('raw_industry_code', sa.String(length=20), nullable=True),
    sa.Column('raw_legal_form', sa.String(length=100), nullable=True),
    sa.Column('raw_address', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_organization_identity_evidence_org', 'organization_identity_evidence', ['organization_id'], unique=False)
    op.create_table('permission_subjects',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('subject_kind', sa.String(length=40), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_permission_subjects_org_kind', 'permission_subjects', ['organization_id', 'subject_kind'], unique=False)
    op.create_table('risk_appetite',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('domain', sa.String(length=100), nullable=False),
    sa.Column('max_acceptable_score', sa.Float(), nullable=False),
    sa.Column('threshold_critical', sa.Integer(), nullable=True),
    sa.Column('threshold_high', sa.Integer(), nullable=True),
    sa.Column('threshold_medium', sa.Integer(), nullable=True),
    sa.Column('threshold_low', sa.Integer(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('updated_by', sa.String(length=100), nullable=True),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_risk_appetite_domain'), 'risk_appetite', ['domain'], unique=False)
    op.create_index(op.f('ix_risk_appetite_id'), 'risk_appetite', ['id'], unique=False)
    op.create_index('ix_risk_appetite_org_domain', 'risk_appetite', ['organization_id', 'domain'], unique=True)
    op.create_index(op.f('ix_risk_appetite_organization_id'), 'risk_appetite', ['organization_id'], unique=False)
    op.create_table('scan_runs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('scan_type', sa.String(length=50), nullable=False),
    sa.Column('status', sa.Enum('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', name='scanstatus'), nullable=False),
    sa.Column('cloud_provider', sa.String(length=50), nullable=True),
    sa.Column('scope', sa.JSON(), nullable=True),
    sa.Column('started_at', sa.DateTime(), nullable=False),
    sa.Column('completed_at', sa.DateTime(), nullable=True),
    sa.Column('duration_seconds', sa.Integer(), nullable=True),
    sa.Column('total_assets', sa.Integer(), nullable=True),
    sa.Column('total_findings', sa.Integer(), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_runs_cloud_provider'), 'scan_runs', ['cloud_provider'], unique=False)
    op.create_index(op.f('ix_scan_runs_id'), 'scan_runs', ['id'], unique=False)
    op.create_index(op.f('ix_scan_runs_organization_id'), 'scan_runs', ['organization_id'], unique=False)
    op.create_index(op.f('ix_scan_runs_scan_type'), 'scan_runs', ['scan_type'], unique=False)
    op.create_index(op.f('ix_scan_runs_started_at'), 'scan_runs', ['started_at'], unique=False)
    op.create_index(op.f('ix_scan_runs_status'), 'scan_runs', ['status'], unique=False)
    op.create_table('service_journey_signals',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('event', sa.String(length=50), nullable=False),
    sa.Column('service_id', sa.String(length=36), nullable=True),
    sa.Column('library_item_id', sa.String(length=100), nullable=True),
    sa.Column('service_key', sa.String(length=100), nullable=True),
    sa.Column('service_name', sa.String(length=200), nullable=True),
    sa.Column('search_query', sa.String(length=200), nullable=True),
    sa.Column('recommended_service_keys', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('matched_service_keys', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('warning_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('organization_type', sa.String(length=100), nullable=True),
    sa.Column('industry', sa.String(length=100), nullable=True),
    sa.Column('company_size', sa.String(length=50), nullable=True),
    sa.Column('country', sa.String(length=10), nullable=True),
    sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_service_journey_signals_id'), 'service_journey_signals', ['id'], unique=False)
    op.create_index('ix_service_journey_signals_org_event', 'service_journey_signals', ['organization_id', 'event'], unique=False)
    op.create_index('ix_service_journey_signals_segment', 'service_journey_signals', ['organization_type', 'industry', 'company_size', 'country'], unique=False)
    op.create_index('ix_service_journey_signals_service_key', 'service_journey_signals', ['service_key'], unique=False)
    op.create_table('slot_templates',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('service_template_id', sa.String(length=36), nullable=False),
    sa.Column('slot_id', sa.String(length=100), nullable=False),
    sa.Column('label', sa.String(length=200), nullable=False),
    sa.Column('purpose', sa.Text(), nullable=False),
    sa.Column('expected_asset_types', sa.ARRAY(sa.String()), nullable=False),
    sa.Column('required', sa.Boolean(), nullable=False),
    sa.Column('capability_group_key', sa.String(length=100), nullable=False),
    sa.Column('display_order', sa.Integer(), nullable=False),
    sa.Column('matching_hints', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('expected_evidence_types', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('risk_patterns', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['service_template_id'], ['service_templates.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('service_template_id', 'slot_id', name='uq_slot_templates_service_slot')
    )
    op.create_index('ix_slot_templates_service_template', 'slot_templates', ['service_template_id'], unique=False)
    op.create_index('ix_slot_templates_slot_id', 'slot_templates', ['slot_id'], unique=False)
    op.create_table('template_candidates',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('run_id', sa.String(length=36), nullable=False),
    sa.Column('service_key', sa.String(length=100), nullable=False),
    sa.Column('current_version', sa.Integer(), nullable=False),
    sa.Column('candidate_version', sa.Integer(), nullable=False),
    sa.Column('governance_class', sa.String(length=1), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('analysis', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('proposed_changes', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('reviewed_by', sa.String(length=255), nullable=True),
    sa.Column('review_note', sa.Text(), nullable=True),
    sa.Column('published_template_id', sa.String(length=36), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['run_id'], ['template_learning_runs.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_template_candidates_governance_class', 'template_candidates', ['governance_class'], unique=False)
    op.create_index('ix_template_candidates_run', 'template_candidates', ['run_id'], unique=False)
    op.create_index('ix_template_candidates_service_key', 'template_candidates', ['service_key'], unique=False)
    op.create_index('ix_template_candidates_status', 'template_candidates', ['status'], unique=False)
    op.create_table('threats',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('severity', sa.String(length=20), nullable=False),
    sa.Column('source', sa.String(length=20), nullable=False),
    sa.Column('asset', sa.String(length=200), nullable=False),
    sa.Column('tier', sa.String(length=50), nullable=False),
    sa.Column('signal', sa.Text(), nullable=False),
    sa.Column('what_it_means', sa.Text(), nullable=False),
    sa.Column('recommendation', sa.Text(), nullable=False),
    sa.Column('intelligence', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('daily_cost', sa.Integer(), nullable=False),
    sa.Column('frameworks', sa.ARRAY(sa.String()), nullable=False),
    sa.Column('requires_escalation', sa.Boolean(), nullable=False),
    sa.Column('decision', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('saved_per_hour', sa.Integer(), nullable=True),
    sa.Column('resolved_on', sa.String(length=30), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_threats_org_severity', 'threats', ['organization_id', 'severity'], unique=False)
    op.create_index('ix_threats_org_status', 'threats', ['organization_id', 'status'], unique=False)
    op.create_table('training_signals',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('run_id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('source_type', sa.String(length=40), nullable=False),
    sa.Column('source_id', sa.String(length=64), nullable=False),
    sa.Column('signal_type', sa.String(length=50), nullable=False),
    sa.Column('target_type', sa.String(length=40), nullable=False),
    sa.Column('target_key', sa.String(length=200), nullable=False),
    sa.Column('outcome', sa.String(length=50), nullable=False),
    sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('source_created_at', sa.DateTime(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['run_id'], ['learning_loop_runs.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('source_type', 'source_id', name='uq_training_signals_source')
    )
    op.create_index('ix_training_signals_org', 'training_signals', ['organization_id'], unique=False)
    op.create_index('ix_training_signals_run', 'training_signals', ['run_id'], unique=False)
    op.create_index('ix_training_signals_signal_type', 'training_signals', ['signal_type'], unique=False)
    op.create_index('ix_training_signals_source_created', 'training_signals', ['source_created_at'], unique=False)
    op.create_index('ix_training_signals_target', 'training_signals', ['target_type', 'target_key'], unique=False)
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('auth0_user_id', sa.String(length=255), nullable=True),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('email_verified', sa.Boolean(), nullable=False),
    sa.Column('password_hash', sa.Text(), nullable=True),
    sa.Column('first_name', sa.String(length=100), nullable=True),
    sa.Column('last_name', sa.String(length=100), nullable=True),
    sa.Column('title', sa.String(length=200), nullable=True),
    sa.Column('avatar_url', sa.Text(), nullable=True),
    sa.Column('role', sa.String(length=50), nullable=False),
    sa.Column('permissions', sa.JSON(), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('status', sa.Enum('active', 'suspended', 'invited', 'deleted', name='userstatus'), nullable=False),
    sa.Column('last_login_at', sa.DateTime(), nullable=True),
    sa.Column('mfa_enabled', sa.Boolean(), nullable=False),
    sa.Column('mfa_phone_e164', sa.String(length=20), nullable=True),
    sa.Column('mfa_phone_verified_at', sa.DateTime(), nullable=True),
    sa.Column('mfa_method', sa.String(length=20), nullable=True),
    sa.Column('mfa_enforced_by_policy', sa.Boolean(), nullable=False),
    sa.Column('access_expires_at', sa.DateTime(), nullable=True),
    sa.Column('timezone', sa.String(length=64), nullable=True),
    sa.Column('location_country', sa.String(length=2), nullable=True),
    sa.Column('location_city', sa.String(length=120), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_auth0_user_id'), 'users', ['auth0_user_id'], unique=True)
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
    op.create_index(op.f('ix_users_organization_id'), 'users', ['organization_id'], unique=False)
    op.create_table('value_stream_signals',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('event', sa.String(length=50), nullable=False),
    sa.Column('stream_id', sa.String(length=36), nullable=True),
    sa.Column('library_item_id', sa.String(length=100), nullable=True),
    sa.Column('stream_key', sa.String(length=100), nullable=True),
    sa.Column('name', sa.String(length=200), nullable=True),
    sa.Column('priority', sa.String(length=20), nullable=True),
    sa.Column('source', sa.String(length=30), nullable=True),
    sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_value_stream_signals_id'), 'value_stream_signals', ['id'], unique=False)
    op.create_index('ix_value_stream_signals_library_item', 'value_stream_signals', ['library_item_id'], unique=False)
    op.create_index('ix_value_stream_signals_org_event', 'value_stream_signals', ['organization_id', 'event'], unique=False)
    op.create_index('ix_value_stream_signals_stream', 'value_stream_signals', ['stream_id'], unique=False)
    op.create_table('value_streams',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('library_item_id', sa.String(length=100), nullable=True),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('priority', sa.String(length=20), nullable=False),
    sa.Column('source', sa.String(length=30), nullable=False),
    sa.Column('bia_answers', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('bpmn_definition', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_value_streams_org', 'value_streams', ['organization_id'], unique=False)
    op.create_table('activation_audit_outbox',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=True),
    sa.Column('actor_user_id', sa.Integer(), nullable=True),
    sa.Column('event_type', sa.String(length=100), nullable=False),
    sa.Column('metadata', sa.JSON(), nullable=True),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('processed_at', sa.DateTime(), nullable=True),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['actor_user_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_activation_audit_outbox_actor_user_id'), 'activation_audit_outbox', ['actor_user_id'], unique=False)
    op.create_index(op.f('ix_activation_audit_outbox_event_type'), 'activation_audit_outbox', ['event_type'], unique=False)
    op.create_index(op.f('ix_activation_audit_outbox_id'), 'activation_audit_outbox', ['id'], unique=False)
    op.create_index(op.f('ix_activation_audit_outbox_organization_id'), 'activation_audit_outbox', ['organization_id'], unique=False)
    op.create_index(op.f('ix_activation_audit_outbox_status'), 'activation_audit_outbox', ['status'], unique=False)
    op.create_index('ix_activation_audit_outbox_status_created', 'activation_audit_outbox', ['status', 'created_at'], unique=False)
    op.create_table('assets',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('type', sa.String(length=50), nullable=False),
    sa.Column('provider', sa.String(length=50), nullable=True),
    sa.Column('provider_display_name', sa.Text(), nullable=True),
    sa.Column('display_name', sa.String(length=200), nullable=False),
    sa.Column('layer', sa.String(length=50), nullable=False),
    sa.Column('environment', sa.Enum('PROD', 'STAGING', 'DEV', 'SANDBOX', name='environment', native_enum=False), nullable=False),
    sa.Column('criticality', sa.Enum('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='criticality', native_enum=False), nullable=False),
    sa.Column('status', sa.Enum('NOT_CONNECTED', 'PARTIALLY_OBSERVED', 'AT_RISK', 'OPERATIONALLY_COMPLIANT', name='assetstatus', native_enum=False), nullable=False),
    sa.Column('connectivity_status', sa.Enum('PENDING_VERIFICATION', 'NOT_CONNECTED', 'CONNECTED', 'DEGRADED', name='connectivitystatus', native_enum=False), nullable=False),
    sa.Column('setup_confidence', sa.Enum('HIGH', 'MEDIUM', 'LOW', name='setupconfidence', native_enum=False), nullable=False),
    sa.Column('scan_start_mode', sa.Enum('IMMEDIATE', 'AFTER_SME_CONFIRM', 'AUDIT_ONLY', name='scanstartmode', native_enum=False), nullable=False),
    sa.Column('secondary_layers', sa.ARRAY(sa.Integer()), nullable=True),
    sa.Column('intent', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('business_owner_ref', sa.Text(), nullable=True),
    sa.Column('technical_owner_ref', sa.Text(), nullable=True),
    sa.Column('setup_assignee_ref', sa.Text(), nullable=True),
    sa.Column('created_by_ref', sa.Text(), nullable=True),
    sa.Column('level', sa.Integer(), nullable=True),
    sa.Column('is_spof', sa.Boolean(), nullable=False),
    sa.Column('posture_stale', sa.Boolean(), nullable=False),
    sa.Column('observation_level', sa.String(length=50), nullable=True),
    sa.Column('last_observed_at', sa.DateTime(), nullable=True),
    sa.Column('risk_score', sa.Float(), nullable=False),
    sa.Column('findings_count', sa.Integer(), nullable=False),
    sa.Column('confidence', sa.Float(), nullable=False),
    sa.Column('canonical_identity_key', sa.String(length=500), nullable=True),
    sa.Column('lifecycle_state', sa.Enum('ACTIVE', 'INACTIVE', 'UNCONFIRMED', 'MERGED', 'REMOVED', 'NOT_USED', 'WITHDRAWN', name='assetlifecyclestate', native_enum=False), nullable=False),
    sa.Column('merged_into_asset_id', sa.Integer(), nullable=True),
    sa.Column('reviewed_at', sa.DateTime(), nullable=True),
    sa.Column('reviewed_by_user_id', sa.Integer(), nullable=True),
    sa.Column('withdrawn_by_exclusion', sa.String(length=255), nullable=True),
    sa.Column('withdrawn_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['merged_into_asset_id'], ['assets.id'], ),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['reviewed_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_assets_canonical_identity_key'), 'assets', ['canonical_identity_key'], unique=False)
    op.create_index(op.f('ix_assets_connectivity_status'), 'assets', ['connectivity_status'], unique=False)
    op.create_index(op.f('ix_assets_id'), 'assets', ['id'], unique=False)
    op.create_index('ix_assets_intent_gin', 'assets', ['intent'], unique=False, postgresql_using='gin')
    op.create_index(op.f('ix_assets_layer'), 'assets', ['layer'], unique=False)
    op.create_index('ix_assets_org_connectivity', 'assets', ['organization_id', 'connectivity_status'], unique=False)
    op.create_index('ix_assets_org_layer', 'assets', ['organization_id', 'layer'], unique=False)
    op.create_index('ix_assets_org_layer_status', 'assets', ['organization_id', 'layer', 'status'], unique=False)
    op.create_index(op.f('ix_assets_organization_id'), 'assets', ['organization_id'], unique=False)
    op.create_index(op.f('ix_assets_status'), 'assets', ['status'], unique=False)
    op.create_index(op.f('ix_assets_type'), 'assets', ['type'], unique=False)
    op.create_table('audit_events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('actor_user_id', sa.Integer(), nullable=True),
    sa.Column('event_type', sa.String(length=100), nullable=False),
    sa.Column('metadata', sa.JSON(), nullable=True),
    sa.Column('actor_timezone', sa.String(length=64), nullable=True),
    sa.Column('actor_location_country', sa.String(length=2), nullable=True),
    sa.Column('actor_location_city', sa.String(length=120), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['actor_user_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_events_actor_user_id'), 'audit_events', ['actor_user_id'], unique=False)
    op.create_index(op.f('ix_audit_events_event_type'), 'audit_events', ['event_type'], unique=False)
    op.create_index(op.f('ix_audit_events_id'), 'audit_events', ['id'], unique=False)
    op.create_index('ix_audit_events_org_type_created', 'audit_events', ['organization_id', 'event_type', 'created_at'], unique=False)
    op.create_index(op.f('ix_audit_events_organization_id'), 'audit_events', ['organization_id'], unique=False)
    op.create_table('auth_ms_group_roles',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('auth_settings_id', sa.Integer(), nullable=False),
    sa.Column('group_id', sa.String(length=255), nullable=False),
    sa.Column('role', sa.String(length=50), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['auth_settings_id'], ['auth_tenant_settings.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_auth_ms_group_roles_auth_settings_id'), 'auth_ms_group_roles', ['auth_settings_id'], unique=False)
    op.create_index(op.f('ix_auth_ms_group_roles_id'), 'auth_ms_group_roles', ['id'], unique=False)
    op.create_index('ix_auth_ms_group_roles_settings_group', 'auth_ms_group_roles', ['auth_settings_id', 'group_id'], unique=True)
    op.create_table('auth_ms_tenant_allowlist',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('auth_settings_id', sa.Integer(), nullable=False),
    sa.Column('tenant_id', sa.String(length=255), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['auth_settings_id'], ['auth_tenant_settings.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_auth_ms_tenant_allowlist_auth_settings_id'), 'auth_ms_tenant_allowlist', ['auth_settings_id'], unique=False)
    op.create_index(op.f('ix_auth_ms_tenant_allowlist_id'), 'auth_ms_tenant_allowlist', ['id'], unique=False)
    op.create_index('ix_auth_ms_tenant_allowlist_settings_tenant', 'auth_ms_tenant_allowlist', ['auth_settings_id', 'tenant_id'], unique=True)
    op.create_table('business_process_activations',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('process_id', sa.String(length=36), nullable=False),
    sa.Column('confirmed_by_user_id', sa.Integer(), nullable=True),
    sa.Column('confirmed_at', sa.DateTime(), nullable=True),
    sa.Column('confirmation_outcome', sa.String(length=30), nullable=False),
    sa.Column('confirmation_reason_code', sa.String(length=80), nullable=True),
    sa.Column('confirmation_reason_detail', sa.String(length=500), nullable=True),
    sa.Column('successor_process_id', sa.String(length=36), nullable=True),
    sa.Column('activated_by_user_id', sa.Integer(), nullable=True),
    sa.Column('activated_at', sa.DateTime(), nullable=True),
    sa.Column('activated_bia_assessment_id', sa.String(length=36), nullable=True),
    sa.Column('activated_organization_bia_baseline_id', sa.String(length=36), nullable=True),
    sa.Column('activated_owner_acceptance_id', sa.String(length=36), nullable=True),
    sa.Column('activated_appetite_policy_id', sa.String(length=36), nullable=True),
    sa.Column('activated_confirmation_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['activated_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['confirmed_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['process_id'], ['value_streams.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['successor_process_id'], ['value_streams.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'process_id', name='uq_business_process_activations_org_process')
    )
    op.create_index('ix_business_process_activations_org_process', 'business_process_activations', ['organization_id', 'process_id'], unique=False)
    op.create_table('business_services',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('tier', sa.String(length=50), nullable=False),
    sa.Column('tolerance_window', sa.String(length=20), nullable=True),
    sa.Column('trading_impact', sa.Text(), nullable=False),
    sa.Column('bia_answers', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('archetype', sa.String(length=50), nullable=True),
    sa.Column('library_item_id', sa.String(length=100), nullable=True),
    sa.Column('template_key', sa.String(length=100), nullable=True),
    sa.Column('owner_user_id', sa.Integer(), nullable=True),
    sa.Column('owner_source', sa.String(length=20), nullable=True),
    sa.Column('template_version', sa.Integer(), nullable=True),
    sa.Column('value_stream_ids', sa.ARRAY(sa.String()), nullable=False),
    sa.Column('l1', sa.ARRAY(sa.String()), nullable=False),
    sa.Column('l2', sa.ARRAY(sa.String()), nullable=False),
    sa.Column('l3', sa.ARRAY(sa.String()), nullable=False),
    sa.Column('archived_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.CheckConstraint("tier IN ('Mission Critical', 'Business Critical', 'Standard Critical')", name='ck_business_services_tier'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['owner_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_business_services_org', 'business_services', ['organization_id'], unique=False)
    op.create_table('compliance_controls',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=True),
    sa.Column('framework_id', sa.Integer(), nullable=False),
    sa.Column('control_id', sa.String(length=50), nullable=False),
    sa.Column('title', sa.String(length=500), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('severity', sa.Enum('critical', 'high', 'medium', 'low', 'info', name='severitylevel'), nullable=False),
    sa.Column('remediation', sa.Text(), nullable=True),
    sa.Column('references', sa.JSON(), nullable=True),
    sa.ForeignKeyConstraint(['framework_id'], ['compliance_frameworks.id'], ),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_compliance_controls_control_id'), 'compliance_controls', ['control_id'], unique=False)
    op.create_index(op.f('ix_compliance_controls_framework_id'), 'compliance_controls', ['framework_id'], unique=False)
    op.create_index(op.f('ix_compliance_controls_id'), 'compliance_controls', ['id'], unique=False)
    op.create_index(op.f('ix_compliance_controls_organization_id'), 'compliance_controls', ['organization_id'], unique=False)
    op.create_index(op.f('ix_compliance_controls_severity'), 'compliance_controls', ['severity'], unique=False)
    op.create_table('forecast_impacts',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('process_id', sa.String(length=36), nullable=False),
    sa.Column('estimate', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('inputs', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('assumptions', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('confidence', sa.String(length=10), nullable=False),
    sa.Column('source', sa.String(length=60), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['process_id'], ['value_streams.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_forecast_impacts_org_process', 'forecast_impacts', ['organization_id', 'process_id'], unique=False)
    op.create_table('invite_tokens',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('invited_by_user_id', sa.Integer(), nullable=True),
    sa.Column('token_hash', sa.String(length=255), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('used_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['invited_by_user_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_invite_tokens_expires_at'), 'invite_tokens', ['expires_at'], unique=False)
    op.create_index(op.f('ix_invite_tokens_id'), 'invite_tokens', ['id'], unique=False)
    op.create_index(op.f('ix_invite_tokens_organization_id'), 'invite_tokens', ['organization_id'], unique=False)
    op.create_index(op.f('ix_invite_tokens_token_hash'), 'invite_tokens', ['token_hash'], unique=True)
    op.create_index(op.f('ix_invite_tokens_used_at'), 'invite_tokens', ['used_at'], unique=False)
    op.create_index('ix_invite_tokens_user_expires', 'invite_tokens', ['user_id', 'expires_at'], unique=False)
    op.create_index(op.f('ix_invite_tokens_user_id'), 'invite_tokens', ['user_id'], unique=False)
    op.create_index('ix_invite_tokens_user_used', 'invite_tokens', ['user_id', 'used_at'], unique=False)
    op.create_table('leadership_authorizations',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('sponsor_user_id', sa.Integer(), nullable=True),
    sa.Column('approving_body', sa.String(length=30), nullable=False),
    sa.Column('authorized_scope', sa.Text(), nullable=False),
    sa.Column('prepared_by', sa.String(length=255), nullable=True),
    sa.Column('submitted_by', sa.String(length=255), nullable=True),
    sa.Column('submitted_at', sa.DateTime(), nullable=True),
    sa.Column('approved_by', sa.String(length=255), nullable=True),
    sa.Column('approved_at', sa.DateTime(), nullable=True),
    sa.Column('approval_reference', sa.String(length=500), nullable=True),
    sa.Column('rejected_by', sa.String(length=255), nullable=True),
    sa.Column('rejected_at', sa.DateTime(), nullable=True),
    sa.Column('rejection_reason', sa.Text(), nullable=True),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('effective_from', sa.DateTime(), nullable=True),
    sa.Column('superseded_by_id', sa.String(length=36), nullable=True),
    sa.Column('backfilled', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['sponsor_user_id'], ['users.id'], ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['superseded_by_id'], ['leadership_authorizations.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_leadership_authorizations_org_status', 'leadership_authorizations', ['organization_id', 'status'], unique=False)
    op.create_table('mfa_challenges',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('purpose', sa.String(length=20), nullable=False),
    sa.Column('channel', sa.String(length=20), nullable=False),
    sa.Column('destination_hash', sa.String(length=64), nullable=False),
    sa.Column('code_hash', sa.String(length=255), nullable=False),
    sa.Column('salt', sa.String(length=64), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('used_at', sa.DateTime(), nullable=True),
    sa.Column('attempt_count', sa.Integer(), nullable=False),
    sa.Column('max_attempts', sa.Integer(), nullable=False),
    sa.Column('resend_count', sa.Integer(), nullable=False),
    sa.Column('last_sent_at', sa.DateTime(), nullable=True),
    sa.Column('created_ip', sa.String(length=64), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_mfa_challenges_expires_at'), 'mfa_challenges', ['expires_at'], unique=False)
    op.create_index(op.f('ix_mfa_challenges_id'), 'mfa_challenges', ['id'], unique=False)
    op.create_index(op.f('ix_mfa_challenges_organization_id'), 'mfa_challenges', ['organization_id'], unique=False)
    op.create_index(op.f('ix_mfa_challenges_used_at'), 'mfa_challenges', ['used_at'], unique=False)
    op.create_index('ix_mfa_challenges_user_expires', 'mfa_challenges', ['user_id', 'expires_at'], unique=False)
    op.create_index(op.f('ix_mfa_challenges_user_id'), 'mfa_challenges', ['user_id'], unique=False)
    op.create_index('ix_mfa_challenges_user_used', 'mfa_challenges', ['user_id', 'used_at'], unique=False)
    op.create_table('org_mandate_role_assignments',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('canonical_role', sa.String(length=80), nullable=False),
    sa.Column('subject_type', sa.String(length=40), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('identity_group_id', sa.String(length=255), nullable=True),
    sa.Column('identity_provider', sa.String(length=50), nullable=True),
    sa.Column('created_by_user_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.CheckConstraint("(subject_type = 'user' AND user_id IS NOT NULL AND identity_group_id IS NULL AND identity_provider IS NULL) OR (subject_type = 'identity_group' AND user_id IS NULL AND identity_group_id IS NOT NULL AND identity_provider IS NOT NULL)", name='ck_org_mandate_role_assignment_subject'),
    sa.ForeignKeyConstraint(['created_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_org_mandate_role_assignments_org_group', 'org_mandate_role_assignments', ['organization_id', 'identity_group_id'], unique=False)
    op.create_index('ix_org_mandate_role_assignments_org_role', 'org_mandate_role_assignments', ['organization_id', 'canonical_role'], unique=False)
    op.create_index('ix_org_mandate_role_assignments_org_user', 'org_mandate_role_assignments', ['organization_id', 'user_id'], unique=False)
    op.create_index('uq_org_mandate_role_assignments_group', 'org_mandate_role_assignments', ['organization_id', 'canonical_role', 'identity_provider', 'identity_group_id'], unique=True, postgresql_where=sa.text("subject_type = 'identity_group'"))
    op.create_index('uq_org_mandate_role_assignments_user', 'org_mandate_role_assignments', ['organization_id', 'canonical_role', 'user_id'], unique=True, postgresql_where=sa.text("subject_type = 'user'"))
    op.create_table('org_reporting_line_exceptions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('employee_user_id', sa.Integer(), nullable=False),
    sa.Column('manager_user_id', sa.Integer(), nullable=False),
    sa.Column('exception_reason', sa.String(length=500), nullable=False),
    sa.Column('created_by_user_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.CheckConstraint('employee_user_id <> manager_user_id', name='ck_org_reporting_line_exception_distinct_users'),
    sa.ForeignKeyConstraint(['created_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['employee_user_id'], ['users.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['manager_user_id'], ['users.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'employee_user_id', name='uq_org_reporting_line_exceptions_employee')
    )
    op.create_index('ix_org_reporting_line_exceptions_org_manager', 'org_reporting_line_exceptions', ['organization_id', 'manager_user_id'], unique=False)
    op.create_table('org_visibility_policies',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('overview_role_keys', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('full_detail_role_keys', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_by_user_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['created_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', name='uq_org_visibility_policies_organization')
    )
    op.create_table('organization_bia_baselines',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('answers', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('source', sa.String(length=80), nullable=False),
    sa.Column('confidence', sa.String(length=20), nullable=False),
    sa.Column('assumption_state', sa.String(length=30), nullable=False),
    sa.Column('set_by_user_id', sa.Integer(), nullable=True),
    sa.Column('set_at', sa.DateTime(), nullable=False),
    sa.Column('superseded_by_id', sa.String(length=36), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['set_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['superseded_by_id'], ['organization_bia_baselines.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_organization_bia_baselines_org_status', 'organization_bia_baselines', ['organization_id', 'status'], unique=False)
    op.create_table('organization_domains',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('domain', sa.String(length=255), nullable=False),
    sa.Column('domain_type', sa.String(length=20), nullable=False),
    sa.Column('verification_status', sa.String(length=30), nullable=False),
    sa.Column('verification_method', sa.String(length=50), nullable=True),
    sa.Column('verified_by_user_id', sa.Integer(), nullable=True),
    sa.Column('verified_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['verified_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_organization_domains_org', 'organization_domains', ['organization_id'], unique=False)
    op.create_table('organization_identity_confirmations',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('confirmed_legal_name', sa.String(length=255), nullable=True),
    sa.Column('confirmed_registration_country', sa.String(length=2), nullable=True),
    sa.Column('confirmed_organization_type', sa.String(length=30), nullable=True),
    sa.Column('evidence_id', sa.String(length=36), nullable=True),
    sa.Column('confirmed_by_user_id', sa.Integer(), nullable=True),
    sa.Column('confirmed_at', sa.DateTime(), nullable=True),
    sa.Column('superseded_by_id', sa.String(length=36), nullable=True),
    sa.Column('correction_reason', sa.Text(), nullable=True),
    sa.Column('backfilled', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['confirmed_by_user_id'], ['users.id'], ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['evidence_id'], ['organization_identity_evidence.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['superseded_by_id'], ['organization_identity_confirmations.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_organization_identity_confirmations_org_status', 'organization_identity_confirmations', ['organization_id', 'status'], unique=False)
    op.create_table('organization_legal_entities',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('legal_name', sa.String(length=255), nullable=False),
    sa.Column('registration_number', sa.String(length=50), nullable=True),
    sa.Column('registration_country', sa.String(length=2), nullable=False),
    sa.Column('entity_type', sa.String(length=30), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('is_primary', sa.Boolean(), nullable=False),
    sa.Column('parent_entity_id', sa.String(length=36), nullable=True),
    sa.Column('source_evidence_id', sa.String(length=36), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['parent_entity_id'], ['organization_legal_entities.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['source_evidence_id'], ['organization_identity_evidence.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_organization_legal_entities_org', 'organization_legal_entities', ['organization_id'], unique=False)
    op.create_table('organization_operating_context_suggestions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('suggestion_type', sa.String(length=40), nullable=False),
    sa.Column('suggestion_key', sa.String(length=100), nullable=False),
    sa.Column('source_type', sa.String(length=40), nullable=False),
    sa.Column('source_reference', sa.String(length=100), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('decided_by_user_id', sa.Integer(), nullable=True),
    sa.Column('decided_at', sa.DateTime(), nullable=True),
    sa.Column('superseded_by_id', sa.String(length=36), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['decided_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['superseded_by_id'], ['organization_operating_context_suggestions.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_organization_operating_context_org_current', 'organization_operating_context_suggestions', ['organization_id', 'superseded_by_id'], unique=False)
    op.create_table('organization_scopes',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('scope_type', sa.String(length=30), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('included_entity_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('excluded_entity_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('included_countries', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('confirmed_by_user_id', sa.Integer(), nullable=True),
    sa.Column('confirmed_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['confirmed_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_organization_scopes_org_status', 'organization_scopes', ['organization_id', 'status'], unique=False)
    op.create_table('password_reset_tokens',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('token_hash', sa.String(length=255), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('used_at', sa.DateTime(), nullable=True),
    sa.Column('requested_ip', sa.String(length=64), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_password_reset_tokens_expires_at'), 'password_reset_tokens', ['expires_at'], unique=False)
    op.create_index(op.f('ix_password_reset_tokens_id'), 'password_reset_tokens', ['id'], unique=False)
    op.create_index(op.f('ix_password_reset_tokens_organization_id'), 'password_reset_tokens', ['organization_id'], unique=False)
    op.create_index(op.f('ix_password_reset_tokens_token_hash'), 'password_reset_tokens', ['token_hash'], unique=True)
    op.create_index(op.f('ix_password_reset_tokens_user_id'), 'password_reset_tokens', ['user_id'], unique=False)
    op.create_table('permission_profiles',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('subject_id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('capabilities', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('discovery_capabilities', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('prepared_by_user_id', sa.Integer(), nullable=True),
    sa.Column('submitted_at', sa.DateTime(), nullable=True),
    sa.Column('approved_by_user_id', sa.Integer(), nullable=True),
    sa.Column('approved_at', sa.DateTime(), nullable=True),
    sa.Column('rejected_by_user_id', sa.Integer(), nullable=True),
    sa.Column('rejected_at', sa.DateTime(), nullable=True),
    sa.Column('rejection_reason', sa.Text(), nullable=True),
    sa.Column('docker_socket_approved_by_user_id', sa.Integer(), nullable=True),
    sa.Column('docker_socket_approved_at', sa.DateTime(), nullable=True),
    sa.Column('service_config_approved_by_user_id', sa.Integer(), nullable=True),
    sa.Column('service_config_approved_at', sa.DateTime(), nullable=True),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('superseded_by_id', sa.String(length=36), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['approved_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['docker_socket_approved_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['prepared_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['rejected_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['service_config_approved_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['subject_id'], ['permission_subjects.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['superseded_by_id'], ['permission_profiles.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_permission_profiles_org_status', 'permission_profiles', ['organization_id', 'status'], unique=False)
    op.create_index('ix_permission_profiles_subject', 'permission_profiles', ['subject_id', 'status'], unique=False)
    op.create_table('process_bia_assessments',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('process_id', sa.String(length=36), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('answers', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('source', sa.String(length=80), nullable=False),
    sa.Column('confidence', sa.String(length=20), nullable=False),
    sa.Column('assumption_state', sa.String(length=30), nullable=False),
    sa.Column('prepared_by_user_id', sa.Integer(), nullable=True),
    sa.Column('prepared_at', sa.DateTime(), nullable=False),
    sa.Column('attested_by_user_id', sa.Integer(), nullable=True),
    sa.Column('attested_at', sa.DateTime(), nullable=True),
    sa.Column('review_at', sa.DateTime(), nullable=True),
    sa.Column('superseded_by_id', sa.String(length=36), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['attested_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['prepared_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['process_id'], ['value_streams.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['superseded_by_id'], ['process_bia_assessments.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_process_bia_assessments_org_process', 'process_bia_assessments', ['organization_id', 'process_id'], unique=False)
    op.create_index('ix_process_bia_assessments_process_status', 'process_bia_assessments', ['process_id', 'status'], unique=False)
    op.create_table('recommendations',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('threat_id', sa.String(length=36), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('linked_context_type', sa.String(length=20), nullable=False),
    sa.Column('linked_context_id', sa.String(length=200), nullable=False),
    sa.Column('linked_context_label', sa.String(length=255), nullable=True),
    sa.Column('problem', sa.Text(), nullable=False),
    sa.Column('why_it_matters', sa.Text(), nullable=False),
    sa.Column('suggested_action', sa.String(length=20), nullable=False),
    sa.Column('confidence_score', sa.Integer(), nullable=False),
    sa.Column('is_stale', sa.Boolean(), nullable=False),
    sa.Column('intelligence_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('generated_at', sa.DateTime(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['threat_id'], ['threats.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_recommendations_org', 'recommendations', ['organization_id'], unique=False)
    op.create_index('ix_recommendations_org_status', 'recommendations', ['organization_id', 'status'], unique=False)
    op.create_index('ix_recommendations_threat', 'recommendations', ['threat_id'], unique=False)
    op.create_table('recovery_actions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('threat_id', sa.String(length=100), nullable=True),
    sa.Column('title', sa.String(length=500), nullable=False),
    sa.Column('issue', sa.Text(), nullable=False),
    sa.Column('action', sa.Text(), nullable=False),
    sa.Column('affected_services', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('exposure_reduction', sa.String(length=100), nullable=True),
    sa.Column('priority', sa.String(length=20), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('assigned_to', sa.String(length=255), nullable=True),
    sa.Column('due_date', sa.DateTime(), nullable=True),
    sa.Column('ref', sa.String(length=200), nullable=True),
    sa.Column('progress', sa.Integer(), nullable=False),
    sa.Column('steps', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['threat_id'], ['threats.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_recovery_actions_id'), 'recovery_actions', ['id'], unique=False)
    op.create_index('ix_recovery_actions_org', 'recovery_actions', ['organization_id'], unique=False)
    op.create_index('ix_recovery_actions_threat', 'recovery_actions', ['threat_id'], unique=False)
    op.create_table('risk_appetite_policies',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('scope', sa.String(length=30), nullable=False),
    sa.Column('process_id', sa.String(length=36), nullable=True),
    sa.Column('decision_reference', sa.String(length=100), nullable=True),
    sa.Column('answers', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('prepared_by', sa.String(length=255), nullable=True),
    sa.Column('submitted_by', sa.String(length=255), nullable=True),
    sa.Column('submitted_at', sa.DateTime(), nullable=True),
    sa.Column('approved_by', sa.String(length=255), nullable=True),
    sa.Column('approved_at', sa.DateTime(), nullable=True),
    sa.Column('rejected_by', sa.String(length=255), nullable=True),
    sa.Column('rejected_at', sa.DateTime(), nullable=True),
    sa.Column('rejection_reason', sa.Text(), nullable=True),
    sa.Column('approval_reference', sa.String(length=500), nullable=True),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('effective_from', sa.DateTime(), nullable=False),
    sa.Column('effective_to', sa.DateTime(), nullable=True),
    sa.Column('review_at', sa.DateTime(), nullable=True),
    sa.Column('superseded_by_id', sa.String(length=36), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['process_id'], ['value_streams.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['superseded_by_id'], ['risk_appetite_policies.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_risk_appetite_policies_org_scope', 'risk_appetite_policies', ['organization_id', 'scope', 'status'], unique=False)
    op.create_index('ix_risk_appetite_policies_process', 'risk_appetite_policies', ['process_id'], unique=False)
    op.create_table('user_identities',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('provider', sa.String(length=50), nullable=False),
    sa.Column('provider_subject', sa.String(length=255), nullable=False),
    sa.Column('provider_tenant', sa.String(length=255), nullable=True),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_identities_id'), 'user_identities', ['id'], unique=False)
    op.create_index('ix_user_identities_org_provider_email', 'user_identities', ['organization_id', 'provider', 'email'], unique=True)
    op.create_index(op.f('ix_user_identities_organization_id'), 'user_identities', ['organization_id'], unique=False)
    op.create_index('ix_user_identities_provider_subject', 'user_identities', ['provider', 'provider_subject'], unique=True)
    op.create_index(op.f('ix_user_identities_user_id'), 'user_identities', ['user_id'], unique=False)
    op.create_table('user_sessions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('refresh_token_hash', sa.String(length=255), nullable=False),
    sa.Column('rotated_from_session_id', sa.Integer(), nullable=True),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('revoked_at', sa.DateTime(), nullable=True),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('user_agent', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['rotated_from_session_id'], ['user_sessions.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('refresh_token_hash')
    )
    op.create_index(op.f('ix_user_sessions_expires_at'), 'user_sessions', ['expires_at'], unique=False)
    op.create_index(op.f('ix_user_sessions_id'), 'user_sessions', ['id'], unique=False)
    op.create_index(op.f('ix_user_sessions_organization_id'), 'user_sessions', ['organization_id'], unique=False)
    op.create_index(op.f('ix_user_sessions_revoked_at'), 'user_sessions', ['revoked_at'], unique=False)
    op.create_index(op.f('ix_user_sessions_user_id'), 'user_sessions', ['user_id'], unique=False)
    op.create_table('artefact_access_decisions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('choice', sa.String(length=30), nullable=False),
    sa.Column('standing_default', sa.String(length=30), nullable=True),
    sa.Column('deviation_reason', sa.Text(), nullable=True),
    sa.Column('identity_undetermined_reason', sa.String(length=40), nullable=True),
    sa.Column('decided_at', sa.DateTime(), nullable=False),
    sa.Column('decided_by_user_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['decided_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_artefact_access_decisions_org_asset', 'artefact_access_decisions', ['organization_id', 'asset_id'], unique=False)
    op.create_index(op.f('ix_artefact_access_decisions_organization_id'), 'artefact_access_decisions', ['organization_id'], unique=False)
    op.create_table('artefact_identity_conflicts',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('lower_asset_id', sa.Integer(), nullable=False),
    sa.Column('higher_asset_id', sa.Integer(), nullable=False),
    sa.Column('state', sa.String(length=30), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('raised_at', sa.DateTime(), nullable=False),
    sa.Column('last_raised_at', sa.DateTime(), nullable=False),
    sa.Column('resolved_at', sa.DateTime(), nullable=True),
    sa.Column('resolved_by_user_id', sa.Integer(), nullable=True),
    sa.Column('resolution_reason', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['higher_asset_id'], ['assets.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['lower_asset_id'], ['assets.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['resolved_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_artefact_identity_conflicts_higher_asset_id'), 'artefact_identity_conflicts', ['higher_asset_id'], unique=False)
    op.create_index(op.f('ix_artefact_identity_conflicts_id'), 'artefact_identity_conflicts', ['id'], unique=False)
    op.create_index(op.f('ix_artefact_identity_conflicts_lower_asset_id'), 'artefact_identity_conflicts', ['lower_asset_id'], unique=False)
    op.create_index('ix_artefact_identity_conflicts_org_state', 'artefact_identity_conflicts', ['organization_id', 'state'], unique=False)
    op.create_index(op.f('ix_artefact_identity_conflicts_organization_id'), 'artefact_identity_conflicts', ['organization_id'], unique=False)
    op.create_index('uq_artefact_identity_conflicts_pair', 'artefact_identity_conflicts', ['organization_id', 'lower_asset_id', 'higher_asset_id'], unique=True)
    op.create_table('asset_appetite_configs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('answers', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('approved_by', sa.String(length=255), nullable=False),
    sa.Column('approved_at', sa.DateTime(), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('history', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'asset_id', name='uq_asset_appetite_org_asset')
    )
    op.create_index(op.f('ix_asset_appetite_configs_id'), 'asset_appetite_configs', ['id'], unique=False)
    op.create_index('ix_asset_appetite_configs_org', 'asset_appetite_configs', ['organization_id'], unique=False)
    op.create_table('asset_connections',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('auth_type', sa.String(length=50), nullable=True),
    sa.Column('scopes', sa.JSON(), nullable=True),
    sa.Column('external_account_id', sa.String(length=200), nullable=True),
    sa.Column('mock_token', sa.String(length=200), nullable=True),
    sa.Column('connected_at', sa.DateTime(), nullable=True),
    sa.Column('last_sync_at', sa.DateTime(), nullable=True),
    sa.Column('state', sa.String(length=50), nullable=False),
    sa.Column('provider', sa.String(length=50), nullable=True),
    sa.Column('provider_account_id', sa.Text(), nullable=True),
    sa.Column('external_id', sa.Text(), nullable=True),
    sa.Column('role_arn', sa.Text(), nullable=True),
    sa.Column('provider_resource_id', sa.Text(), nullable=True),
    sa.Column('permission_preset', sa.String(length=100), nullable=True),
    sa.Column('connection_state', sa.Enum('DRAFT', 'INSTRUCTIONS_ISSUED', 'PENDING', 'VERIFIED', 'FAILED', 'REVOKED', name='connectionstate', native_enum=False), nullable=False),
    sa.Column('last_error_code', sa.Text(), nullable=True),
    sa.Column('last_error_detail', sa.Text(), nullable=True),
    sa.Column('validated_at', sa.DateTime(), nullable=True),
    sa.Column('auth_method', sa.String(length=100), nullable=True),
    sa.Column('auth_payload_json', sa.JSON(), nullable=True),
    sa.Column('error_code', sa.String(length=50), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_asset_connections_asset_id'), 'asset_connections', ['asset_id'], unique=False)
    op.create_index('ix_asset_connections_asset_state', 'asset_connections', ['asset_id', 'state'], unique=False)
    op.create_index('ix_asset_connections_connection_state', 'asset_connections', ['connection_state'], unique=False)
    op.create_index(op.f('ix_asset_connections_id'), 'asset_connections', ['id'], unique=False)
    op.create_index('ix_asset_connections_provider_account', 'asset_connections', ['provider', 'provider_account_id'], unique=False)
    op.create_table('asset_findings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('domain', sa.String(length=100), nullable=False),
    sa.Column('severity', sa.Enum('critical', 'high', 'medium', 'low', 'info', name='severitylevel'), nullable=False),
    sa.Column('title', sa.String(length=500), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('evidence_refs', sa.JSON(), nullable=True),
    sa.Column('risk_score', sa.Float(), nullable=True),
    sa.Column('first_seen_at', sa.DateTime(), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(), nullable=False),
    sa.Column('status', sa.Enum('OPEN', 'NEEDS_REVIEW', 'RESOLVED', name='assetfindingstatus', native_enum=False), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_asset_findings_asset_id'), 'asset_findings', ['asset_id'], unique=False)
    op.create_index('ix_asset_findings_asset_status', 'asset_findings', ['asset_id', 'status'], unique=False)
    op.create_index(op.f('ix_asset_findings_id'), 'asset_findings', ['id'], unique=False)
    op.create_index('ix_asset_findings_org_status', 'asset_findings', ['organization_id', 'status'], unique=False)
    op.create_index(op.f('ix_asset_findings_organization_id'), 'asset_findings', ['organization_id'], unique=False)
    op.create_index(op.f('ix_asset_findings_severity'), 'asset_findings', ['severity'], unique=False)
    op.create_index(op.f('ix_asset_findings_status'), 'asset_findings', ['status'], unique=False)
    op.create_table('asset_identifiers',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('identifier_type', sa.String(length=40), nullable=False),
    sa.Column('identifier_value', sa.String(length=500), nullable=False),
    sa.Column('observed_by_source', sa.String(length=255), nullable=True),
    sa.Column('first_seen_at', sa.DateTime(), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_asset_identifiers_asset_id'), 'asset_identifiers', ['asset_id'], unique=False)
    op.create_index(op.f('ix_asset_identifiers_id'), 'asset_identifiers', ['id'], unique=False)
    op.create_index('ix_asset_identifiers_org_type_value', 'asset_identifiers', ['organization_id', 'identifier_type', 'identifier_value'], unique=False)
    op.create_index(op.f('ix_asset_identifiers_organization_id'), 'asset_identifiers', ['organization_id'], unique=False)
    op.create_index('uq_asset_identifiers_asset_type_value', 'asset_identifiers', ['asset_id', 'identifier_type', 'identifier_value'], unique=True)
    op.create_table('asset_observed_ports',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('port', sa.Integer(), nullable=False),
    sa.Column('protocol', sa.String(length=10), nullable=False),
    sa.Column('service_name', sa.String(length=100), nullable=True),
    sa.Column('product', sa.String(length=255), nullable=True),
    sa.Column('product_version', sa.String(length=100), nullable=True),
    sa.Column('first_seen_at', sa.DateTime(), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_asset_observed_ports_asset_id'), 'asset_observed_ports', ['asset_id'], unique=False)
    op.create_index(op.f('ix_asset_observed_ports_id'), 'asset_observed_ports', ['id'], unique=False)
    op.create_index('ix_asset_observed_ports_org_asset', 'asset_observed_ports', ['organization_id', 'asset_id'], unique=False)
    op.create_index(op.f('ix_asset_observed_ports_organization_id'), 'asset_observed_ports', ['organization_id'], unique=False)
    op.create_index('uq_asset_observed_ports_asset_port_protocol', 'asset_observed_ports', ['asset_id', 'port', 'protocol'], unique=True)
    op.create_table('asset_status_history',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.Enum('NOT_CONNECTED', 'PARTIALLY_OBSERVED', 'AT_RISK', 'OPERATIONALLY_COMPLIANT', name='assetstatus', native_enum=False), nullable=False),
    sa.Column('risk_score', sa.Float(), nullable=True),
    sa.Column('observation_level', sa.String(length=50), nullable=True),
    sa.Column('findings_count', sa.Integer(), nullable=True),
    sa.Column('confidence', sa.Float(), nullable=True),
    sa.Column('observed_at', sa.DateTime(), nullable=False),
    sa.Column('connectivity_status', sa.Enum('PENDING_VERIFICATION', 'NOT_CONNECTED', 'CONNECTED', 'DEGRADED', name='connectivitystatus', native_enum=False), nullable=True),
    sa.Column('connection_state', sa.Enum('DRAFT', 'INSTRUCTIONS_ISSUED', 'PENDING', 'VERIFIED', 'FAILED', 'REVOKED', name='connectionstate', native_enum=False), nullable=True),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_asset_status_history_asset_id'), 'asset_status_history', ['asset_id'], unique=False)
    op.create_index(op.f('ix_asset_status_history_id'), 'asset_status_history', ['id'], unique=False)
    op.create_index(op.f('ix_asset_status_history_status'), 'asset_status_history', ['status'], unique=False)
    op.create_index('ix_status_history_asset_time', 'asset_status_history', ['asset_id', 'observed_at'], unique=False)
    op.create_table('business_service_appetite_configs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('business_service_id', sa.String(length=36), nullable=False),
    sa.Column('answers', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('approved_by', sa.String(length=255), nullable=False),
    sa.Column('approved_at', sa.DateTime(), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('history', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['business_service_id'], ['business_services.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'business_service_id', name='uq_business_service_appetite_org_service')
    )
    op.create_index(op.f('ix_business_service_appetite_configs_id'), 'business_service_appetite_configs', ['id'], unique=False)
    op.create_index('ix_business_service_appetite_configs_org', 'business_service_appetite_configs', ['organization_id'], unique=False)
    op.create_index('ix_business_service_appetite_configs_service', 'business_service_appetite_configs', ['business_service_id'], unique=False)
    op.create_table('control_evidence',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('control_id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.Enum('COVERED', 'PARTIALLY_COVERED', 'NOT_COVERED', name='controlcoveragestatus', native_enum=False), nullable=False),
    sa.Column('confidence', sa.Float(), nullable=True),
    sa.Column('last_evaluated_at', sa.DateTime(), nullable=False),
    sa.Column('evidence_refs', sa.JSON(), nullable=True),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
    sa.ForeignKeyConstraint(['control_id'], ['controls.id'], ),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_control_evidence_asset_id'), 'control_evidence', ['asset_id'], unique=False)
    op.create_index(op.f('ix_control_evidence_control_id'), 'control_evidence', ['control_id'], unique=False)
    op.create_index(op.f('ix_control_evidence_id'), 'control_evidence', ['id'], unique=False)
    op.create_index('ix_control_evidence_org_control', 'control_evidence', ['organization_id', 'control_id'], unique=False)
    op.create_index(op.f('ix_control_evidence_organization_id'), 'control_evidence', ['organization_id'], unique=False)
    op.create_table('decision_records',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('recommendation_id', sa.String(length=36), nullable=False),
    sa.Column('threat_id', sa.String(length=36), nullable=True),
    sa.Column('selected_action', sa.String(length=20), nullable=False),
    sa.Column('decision_type', sa.String(length=20), nullable=False),
    sa.Column('rationale', sa.Text(), nullable=False),
    sa.Column('decided_by', sa.String(length=255), nullable=False),
    sa.Column('decided_role', sa.String(length=100), nullable=False),
    sa.Column('review_date', sa.String(length=30), nullable=True),
    sa.Column('stale', sa.Boolean(), nullable=False),
    sa.Column('recommendation_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('reasoning_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('forecast_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('integration_ref', sa.String(length=200), nullable=True),
    sa.Column('integration_provider', sa.String(length=50), nullable=True),
    sa.Column('external_url', sa.String(length=500), nullable=True),
    sa.Column('recovery_action_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['recommendation_id'], ['recommendations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['recovery_action_id'], ['recovery_actions.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['threat_id'], ['threats.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_decision_records_org', 'decision_records', ['organization_id'], unique=False)
    op.create_index('ix_decision_records_org_created', 'decision_records', ['organization_id', 'created_at'], unique=False)
    op.create_index('ix_decision_records_recommendation', 'decision_records', ['recommendation_id'], unique=False)
    op.create_index('ix_decision_records_threat', 'decision_records', ['threat_id'], unique=False)
    op.create_table('dependency_bundles',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('service_id', sa.String(length=36), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('mode', sa.String(length=30), nullable=False),
    sa.Column('lifecycle_state', sa.String(length=40), nullable=False),
    sa.Column('groups', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('validation_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('acknowledged_warning_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['service_id'], ['business_services.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_dependency_bundles_org', 'dependency_bundles', ['organization_id'], unique=False)
    op.create_index('ix_dependency_bundles_service', 'dependency_bundles', ['service_id'], unique=False)
    op.create_table('evidence_sources',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('type', sa.String(length=20), nullable=False),
    sa.Column('mode', sa.String(length=20), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('owner_user_id', sa.Integer(), nullable=True),
    sa.Column('business_service_id', sa.String(length=36), nullable=True),
    sa.Column('connected_at', sa.DateTime(), nullable=True),
    sa.Column('first_evidence_received_at', sa.DateTime(), nullable=True),
    sa.Column('last_successful_sync_at', sa.DateTime(), nullable=True),
    sa.Column('last_attempted_sync_at', sa.DateTime(), nullable=True),
    sa.Column('warning_after_hours', sa.Integer(), nullable=True),
    sa.Column('stale_after_hours', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['business_service_id'], ['business_services.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['owner_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_evidence_sources_business_service', 'evidence_sources', ['business_service_id'], unique=False)
    op.create_index('ix_evidence_sources_org_status', 'evidence_sources', ['organization_id', 'status'], unique=False)
    op.create_table('org_mandate_scope_bindings',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('scope_type', sa.String(length=40), nullable=False),
    sa.Column('value_stream_id', sa.String(length=36), nullable=True),
    sa.Column('business_service_id', sa.String(length=36), nullable=True),
    sa.Column('canonical_role', sa.String(length=80), nullable=False),
    sa.Column('role_assignment_id', sa.String(length=36), nullable=False),
    sa.Column('created_by_user_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.CheckConstraint("(scope_type = 'business_process' AND value_stream_id IS NOT NULL AND business_service_id IS NULL) OR (scope_type = 'business_service' AND value_stream_id IS NULL AND business_service_id IS NOT NULL)", name='ck_org_mandate_scope_binding_scope'),
    sa.ForeignKeyConstraint(['business_service_id'], ['business_services.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['created_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['role_assignment_id'], ['org_mandate_role_assignments.id'], ),
    sa.ForeignKeyConstraint(['value_stream_id'], ['value_streams.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_org_mandate_scope_bindings_org_role', 'org_mandate_scope_bindings', ['organization_id', 'canonical_role'], unique=False)
    op.create_index('ix_org_mandate_scope_bindings_role_assignment', 'org_mandate_scope_bindings', ['role_assignment_id'], unique=False)
    op.create_index('uq_org_mandate_scope_bindings_process_role', 'org_mandate_scope_bindings', ['organization_id', 'value_stream_id', 'canonical_role'], unique=True, postgresql_where=sa.text("scope_type = 'business_process'"))
    op.create_index('uq_org_mandate_scope_bindings_service_role', 'org_mandate_scope_bindings', ['organization_id', 'business_service_id', 'canonical_role'], unique=True, postgresql_where=sa.text("scope_type = 'business_service'"))
    op.create_table('organization_units',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('code', sa.String(length=50), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('unit_type', sa.String(length=30), nullable=False),
    sa.Column('parent_unit_id', sa.String(length=36), nullable=True),
    sa.Column('legal_entity_id', sa.String(length=36), nullable=True),
    sa.Column('country_code', sa.String(length=2), nullable=True),
    sa.Column('location_reference', sa.String(length=255), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('scope_status', sa.String(length=30), nullable=False),
    sa.Column('source', sa.String(length=30), nullable=False),
    sa.Column('source_reference', sa.String(length=255), nullable=True),
    sa.Column('confidence', sa.Float(), nullable=True),
    sa.Column('merged_into_unit_id', sa.String(length=36), nullable=True),
    sa.Column('aliases', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('confirmed_by_user_id', sa.Integer(), nullable=True),
    sa.Column('confirmed_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['confirmed_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['legal_entity_id'], ['organization_legal_entities.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['merged_into_unit_id'], ['organization_units.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['parent_unit_id'], ['organization_units.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_organization_units_org_parent', 'organization_units', ['organization_id', 'parent_unit_id'], unique=False)
    op.create_index('ix_organization_units_org_status', 'organization_units', ['organization_id', 'status'], unique=False)
    op.create_table('policy_rules',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=True),
    sa.Column('control_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('rule_definition', sa.JSON(), nullable=False),
    sa.Column('cloud_provider', sa.String(length=50), nullable=False),
    sa.Column('resource_type', sa.String(length=100), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['control_id'], ['compliance_controls.id'], ),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_policy_rules_cloud_provider'), 'policy_rules', ['cloud_provider'], unique=False)
    op.create_index(op.f('ix_policy_rules_control_id'), 'policy_rules', ['control_id'], unique=False)
    op.create_index(op.f('ix_policy_rules_id'), 'policy_rules', ['id'], unique=False)
    op.create_index(op.f('ix_policy_rules_organization_id'), 'policy_rules', ['organization_id'], unique=False)
    op.create_index(op.f('ix_policy_rules_resource_type'), 'policy_rules', ['resource_type'], unique=False)
    op.create_table('risk_evaluations',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('process_id', sa.String(length=36), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('preparedness', sa.String(length=30), nullable=False),
    sa.Column('confidence', sa.String(length=10), nullable=False),
    sa.Column('bia_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('appetite_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('evidence_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('dependency_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('recovery_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('residual', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('explanation', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('forecast_id', sa.String(length=36), nullable=True),
    sa.Column('evaluated_at', sa.DateTime(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['forecast_id'], ['forecast_impacts.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['process_id'], ['value_streams.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_risk_evaluations_org_process', 'risk_evaluations', ['organization_id', 'process_id', 'evaluated_at'], unique=False)
    op.create_table('service_appetite_reassessments',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('business_service_id', sa.String(length=36), nullable=False),
    sa.Column('process_id', sa.String(length=36), nullable=False),
    sa.Column('category', sa.String(length=30), nullable=False),
    sa.Column('requested_level', sa.Integer(), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('evidence', sa.Text(), nullable=True),
    sa.Column('requested_by', sa.String(length=255), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('reviewed_by', sa.String(length=255), nullable=True),
    sa.Column('reviewed_at', sa.DateTime(), nullable=True),
    sa.Column('rejection_reason', sa.Text(), nullable=True),
    sa.Column('effective_from', sa.DateTime(), nullable=True),
    sa.Column('review_at', sa.DateTime(), nullable=True),
    sa.Column('superseded_by_id', sa.String(length=36), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['business_service_id'], ['business_services.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['process_id'], ['value_streams.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['superseded_by_id'], ['service_appetite_reassessments.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_service_appetite_reassessments_process', 'service_appetite_reassessments', ['process_id'], unique=False)
    op.create_index('ix_service_appetite_reassessments_service_category', 'service_appetite_reassessments', ['business_service_id', 'category', 'status'], unique=False)
    op.create_table('service_change_notices',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('service_id', sa.String(length=36), nullable=False),
    sa.Column('process_id', sa.String(length=36), nullable=False),
    sa.Column('recipient_user_id', sa.Integer(), nullable=False),
    sa.Column('kind', sa.String(length=20), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('owner_comment', sa.Text(), nullable=True),
    sa.Column('actor_user_id', sa.Integer(), nullable=True),
    sa.Column('decision_record_id', sa.String(length=36), nullable=True),
    sa.Column('viewed_at', sa.DateTime(), nullable=True),
    sa.Column('acknowledged_at', sa.DateTime(), nullable=True),
    sa.Column('resolved_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['actor_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['process_id'], ['value_streams.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['recipient_user_id'], ['users.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['service_id'], ['business_services.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_service_change_notices_process', 'service_change_notices', ['organization_id', 'process_id'], unique=False)
    op.create_index('ix_service_change_notices_recipient', 'service_change_notices', ['organization_id', 'recipient_user_id'], unique=False)
    op.create_index('ix_service_change_notices_service', 'service_change_notices', ['organization_id', 'service_id'], unique=False)
    op.create_table('slot_instances',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('service_id', sa.String(length=36), nullable=False),
    sa.Column('slot_id', sa.String(length=100), nullable=False),
    sa.Column('template_version', sa.Integer(), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('asset_id', sa.String(length=36), nullable=True),
    sa.Column('asset_label', sa.String(length=255), nullable=True),
    sa.Column('group_key', sa.String(length=100), nullable=True),
    sa.Column('mapping_status', sa.String(length=20), nullable=False),
    sa.Column('mapping_confidence', sa.Float(), nullable=True),
    sa.Column('evidence_source', sa.String(length=30), nullable=True),
    sa.Column('mapping_reason', sa.Text(), nullable=True),
    sa.Column('mapping_reason_code', sa.String(length=60), nullable=True),
    sa.Column('provenance', sa.String(length=30), nullable=True),
    sa.Column('decided_by', sa.String(length=120), nullable=True),
    sa.Column('decided_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['service_id'], ['business_services.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'service_id', 'slot_id', name='uq_slot_instances_org_service_slot')
    )
    op.create_index('ix_slot_instances_org', 'slot_instances', ['organization_id'], unique=False)
    op.create_index('ix_slot_instances_service', 'slot_instances', ['service_id'], unique=False)
    op.create_index('ix_slot_instances_slot', 'slot_instances', ['slot_id'], unique=False)
    op.create_table('artefact_merge_records',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('survivor_asset_id', sa.Integer(), nullable=False),
    sa.Column('merged_asset_id', sa.Integer(), nullable=False),
    sa.Column('conflict_id', sa.Integer(), nullable=True),
    sa.Column('decided_by_user_id', sa.Integer(), nullable=True),
    sa.Column('decided_at', sa.DateTime(), nullable=False),
    sa.Column('reason', sa.Text(), nullable=True),
    sa.Column('previous_lifecycle_state', sa.String(length=20), nullable=False),
    sa.Column('moved', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('reversed_at', sa.DateTime(), nullable=True),
    sa.Column('reversed_by_user_id', sa.Integer(), nullable=True),
    sa.Column('reversal_reason', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['conflict_id'], ['artefact_identity_conflicts.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['decided_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['merged_asset_id'], ['assets.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['reversed_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['survivor_asset_id'], ['assets.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_artefact_merge_records_id'), 'artefact_merge_records', ['id'], unique=False)
    op.create_index(op.f('ix_artefact_merge_records_merged_asset_id'), 'artefact_merge_records', ['merged_asset_id'], unique=False)
    op.create_index('ix_artefact_merge_records_org_merged', 'artefact_merge_records', ['organization_id', 'merged_asset_id'], unique=False)
    op.create_index('ix_artefact_merge_records_org_survivor', 'artefact_merge_records', ['organization_id', 'survivor_asset_id'], unique=False)
    op.create_index(op.f('ix_artefact_merge_records_organization_id'), 'artefact_merge_records', ['organization_id'], unique=False)
    op.create_index(op.f('ix_artefact_merge_records_survivor_asset_id'), 'artefact_merge_records', ['survivor_asset_id'], unique=False)
    op.create_table('dependency_bundle_versions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('bundle_id', sa.String(length=36), nullable=False),
    sa.Column('service_id', sa.String(length=36), nullable=False),
    sa.Column('version_number', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('lifecycle_state', sa.String(length=40), nullable=False),
    sa.Column('groups_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('validation_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('acknowledged_warning_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('published_at', sa.DateTime(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['bundle_id'], ['dependency_bundles.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['service_id'], ['business_services.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_dependency_bundle_versions_bundle', 'dependency_bundle_versions', ['bundle_id'], unique=False)
    op.create_index('ix_dependency_bundle_versions_bundle_version', 'dependency_bundle_versions', ['bundle_id', 'version_number'], unique=True)
    op.create_index('ix_dependency_bundle_versions_org', 'dependency_bundle_versions', ['organization_id'], unique=False)
    op.create_index('ix_dependency_bundle_versions_service', 'dependency_bundle_versions', ['service_id'], unique=False)
    op.create_table('discovery_scope_proposals',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('evidence_source_id', sa.String(length=36), nullable=False),
    sa.Column('permission_subject_id', sa.String(length=36), nullable=False),
    sa.Column('permission_profile_id', sa.String(length=36), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('inclusions', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('exclusions', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('checks', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('rationale', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('proposed_at', sa.DateTime(), nullable=False),
    sa.Column('decided_by_user_id', sa.Integer(), nullable=True),
    sa.Column('decided_at', sa.DateTime(), nullable=True),
    sa.Column('decision_note', sa.Text(), nullable=True),
    sa.Column('superseded_by_proposal_id', sa.String(length=36), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['decided_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['evidence_source_id'], ['evidence_sources.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['permission_profile_id'], ['permission_profiles.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['permission_subject_id'], ['permission_subjects.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('permission_profile_id'),
    sa.UniqueConstraint('permission_subject_id')
    )
    op.create_index('ix_discovery_scope_proposals_org_source_status', 'discovery_scope_proposals', ['organization_id', 'evidence_source_id', 'status'], unique=False)
    op.create_table('evidence_import_batches',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('evidence_source_id', sa.String(length=36), nullable=False),
    sa.Column('filename', sa.String(length=255), nullable=False),
    sa.Column('file_type', sa.String(length=10), nullable=False),
    sa.Column('checksum', sa.String(length=64), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('uploaded_by_user_id', sa.Integer(), nullable=True),
    sa.Column('uploaded_at', sa.DateTime(), nullable=False),
    sa.Column('detected_columns', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('column_mapping', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('parsed_rows_json', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('total_rows', sa.Integer(), nullable=True),
    sa.Column('accepted_rows', sa.Integer(), nullable=True),
    sa.Column('rejected_rows', sa.Integer(), nullable=True),
    sa.Column('warning_rows', sa.Integer(), nullable=True),
    sa.Column('validation_summary', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('completed_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['evidence_source_id'], ['evidence_sources.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['uploaded_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_evidence_import_batches_source', 'evidence_import_batches', ['evidence_source_id', 'status'], unique=False)
    op.create_table('evidence_manual_entries',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('evidence_source_id', sa.String(length=36), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('entered_by_user_id', sa.Integer(), nullable=True),
    sa.Column('entered_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['entered_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['evidence_source_id'], ['evidence_sources.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_evidence_manual_entries_source', 'evidence_manual_entries', ['evidence_source_id'], unique=False)
    op.create_table('evidence_source_exceptions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('evidence_source_id', sa.String(length=36), nullable=False),
    sa.Column('reason_code', sa.String(length=30), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('approved_by_user_id', sa.Integer(), nullable=True),
    sa.Column('approved_at', sa.DateTime(), nullable=False),
    sa.Column('review_at', sa.DateTime(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.ForeignKeyConstraint(['approved_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['evidence_source_id'], ['evidence_sources.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_evidence_source_exceptions_source', 'evidence_source_exceptions', ['evidence_source_id', 'status'], unique=False)
    op.create_table('evidence_source_scopes',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('evidence_source_id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('scope_type', sa.String(length=30), nullable=False),
    sa.Column('organisation_unit_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('legal_entity_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('country_codes', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('confirmed_by_user_id', sa.Integer(), nullable=True),
    sa.Column('confirmed_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['confirmed_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['evidence_source_id'], ['evidence_sources.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('evidence_source_id')
    )
    op.create_table('findings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('scan_run_id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('rule_id', sa.Integer(), nullable=True),
    sa.Column('severity', sa.Enum('critical', 'high', 'medium', 'low', 'info', name='severitylevel'), nullable=False),
    sa.Column('title', sa.String(length=500), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('evidence', sa.JSON(), nullable=True),
    sa.Column('risk_score', sa.Float(), nullable=True),
    sa.Column('business_impact_score', sa.Float(), nullable=True),
    sa.Column('status', sa.Enum('OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'REMEDIATED', 'FALSE_POSITIVE', 'ACCEPTED_RISK', name='findingstatus'), nullable=False),
    sa.Column('detected_at', sa.DateTime(), nullable=False),
    sa.Column('resolved_at', sa.DateTime(), nullable=True),
    sa.Column('resolved_by', sa.String(length=100), nullable=True),
    sa.Column('resolution_notes', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['asset_id'], ['cloud_assets.id'], ),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['rule_id'], ['policy_rules.id'], ),
    sa.ForeignKeyConstraint(['scan_run_id'], ['scan_runs.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_finding_asset_severity', 'findings', ['asset_id', 'severity'], unique=False)
    op.create_index('ix_finding_org', 'findings', ['organization_id'], unique=False)
    op.create_index('ix_finding_scan_status', 'findings', ['scan_run_id', 'status'], unique=False)
    op.create_index(op.f('ix_findings_asset_id'), 'findings', ['asset_id'], unique=False)
    op.create_index(op.f('ix_findings_detected_at'), 'findings', ['detected_at'], unique=False)
    op.create_index(op.f('ix_findings_id'), 'findings', ['id'], unique=False)
    op.create_index(op.f('ix_findings_organization_id'), 'findings', ['organization_id'], unique=False)
    op.create_index(op.f('ix_findings_rule_id'), 'findings', ['rule_id'], unique=False)
    op.create_index(op.f('ix_findings_scan_run_id'), 'findings', ['scan_run_id'], unique=False)
    op.create_index(op.f('ix_findings_severity'), 'findings', ['severity'], unique=False)
    op.create_index(op.f('ix_findings_status'), 'findings', ['status'], unique=False)
    op.create_table('organization_locations',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('organization_unit_id', sa.String(length=36), nullable=True),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('location_type', sa.String(length=20), nullable=False),
    sa.Column('country_code', sa.String(length=2), nullable=True),
    sa.Column('region', sa.String(length=100), nullable=True),
    sa.Column('city', sa.String(length=100), nullable=True),
    sa.Column('address_reference', sa.String(length=255), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_unit_id'], ['organization_units.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_organization_locations_org_unit', 'organization_locations', ['organization_id', 'organization_unit_id'], unique=False)
    op.create_table('organization_unit_match_suggestions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('unit_a_id', sa.String(length=36), nullable=False),
    sa.Column('unit_b_id', sa.String(length=36), nullable=False),
    sa.Column('match_confidence', sa.Float(), nullable=False),
    sa.Column('matching_reasons', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('decided_by_user_id', sa.Integer(), nullable=True),
    sa.Column('decided_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['decided_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['unit_a_id'], ['organization_units.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['unit_b_id'], ['organization_units.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'unit_a_id', 'unit_b_id', name='uq_org_unit_match_pair')
    )
    op.create_table('organization_unit_memberships',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('organization_unit_id', sa.String(length=36), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('membership_role', sa.String(length=30), nullable=False),
    sa.Column('source', sa.String(length=30), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('effective_from', sa.DateTime(), nullable=True),
    sa.Column('effective_to', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_unit_id'], ['organization_units.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_org_unit_memberships_org_unit', 'organization_unit_memberships', ['organization_id', 'organization_unit_id'], unique=False)
    op.create_index('ix_org_unit_memberships_org_user', 'organization_unit_memberships', ['organization_id', 'user_id'], unique=False)
    op.create_table('organization_unit_relationships',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('source_unit_id', sa.String(length=36), nullable=False),
    sa.Column('target_unit_id', sa.String(length=36), nullable=False),
    sa.Column('relationship_type', sa.String(length=30), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('source', sa.String(length=30), nullable=False),
    sa.Column('confidence', sa.Float(), nullable=True),
    sa.Column('confirmed_by_user_id', sa.Integer(), nullable=True),
    sa.Column('confirmed_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['confirmed_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['source_unit_id'], ['organization_units.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['target_unit_id'], ['organization_units.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('source_unit_id', 'target_unit_id', 'relationship_type', name='uq_org_unit_relationship')
    )
    op.create_index('ix_org_unit_relationships_org_source', 'organization_unit_relationships', ['organization_id', 'source_unit_id'], unique=False)
    op.create_table('process_owner_acceptances',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('process_id', sa.String(length=36), nullable=False),
    sa.Column('scope_binding_id', sa.String(length=36), nullable=False),
    sa.Column('role_assignment_id', sa.String(length=36), nullable=False),
    sa.Column('owner_user_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('invited_by_user_id', sa.Integer(), nullable=True),
    sa.Column('invited_at', sa.DateTime(), nullable=False),
    sa.Column('accepted_at', sa.DateTime(), nullable=True),
    sa.Column('rejected_at', sa.DateTime(), nullable=True),
    sa.Column('rejection_reason', sa.String(length=80), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.CheckConstraint("status IN ('invitation_sent', 'accepted', 'rejected')", name='ck_process_owner_acceptance_status'),
    sa.ForeignKeyConstraint(['invited_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['owner_user_id'], ['users.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['process_id'], ['value_streams.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['scope_binding_id'], ['org_mandate_scope_bindings.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'scope_binding_id', name='uq_process_owner_acceptances_org_scope_binding')
    )
    op.create_index('ix_process_owner_acceptances_org_process', 'process_owner_acceptances', ['organization_id', 'process_id'], unique=False)
    op.create_index('ix_process_owner_acceptances_process_status', 'process_owner_acceptances', ['process_id', 'status'], unique=False)
    op.create_table('resolution_records',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('recommendation_id', sa.String(length=36), nullable=False),
    sa.Column('decision_record_id', sa.String(length=36), nullable=True),
    sa.Column('threat_id', sa.String(length=36), nullable=True),
    sa.Column('recovery_action_id', sa.Integer(), nullable=True),
    sa.Column('resolution_type', sa.String(length=40), nullable=False),
    sa.Column('selected_action_option', sa.String(length=20), nullable=False),
    sa.Column('alternative_category', sa.String(length=40), nullable=True),
    sa.Column('resolution_summary', sa.Text(), nullable=True),
    sa.Column('resolved_by', sa.String(length=255), nullable=False),
    sa.Column('resolved_role', sa.String(length=100), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('verification_status', sa.String(length=30), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['decision_record_id'], ['decision_records.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['recommendation_id'], ['recommendations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['recovery_action_id'], ['recovery_actions.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['threat_id'], ['threats.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_resolution_records_decision', 'resolution_records', ['decision_record_id'], unique=False)
    op.create_index('ix_resolution_records_org', 'resolution_records', ['organization_id'], unique=False)
    op.create_index('ix_resolution_records_org_created', 'resolution_records', ['organization_id', 'created_at'], unique=False)
    op.create_index('ix_resolution_records_recommendation', 'resolution_records', ['recommendation_id'], unique=False)
    op.create_index('ix_resolution_records_recovery_action', 'resolution_records', ['recovery_action_id'], unique=False)
    op.create_table('review_reopenings',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('process_id', sa.String(length=36), nullable=False),
    sa.Column('source', sa.String(length=30), nullable=False),
    sa.Column('decision_reference', sa.String(length=100), nullable=False),
    sa.Column('review_due_at', sa.String(length=30), nullable=False),
    sa.Column('review_owner', sa.String(length=255), nullable=True),
    sa.Column('evaluation_id', sa.String(length=36), nullable=True),
    sa.Column('scenario_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('reopened_at', sa.DateTime(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['evaluation_id'], ['risk_evaluations.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['process_id'], ['value_streams.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'process_id', 'source', 'decision_reference', 'review_due_at', name='uq_review_reopenings_reference_due')
    )
    op.create_index('ix_review_reopenings_org_process', 'review_reopenings', ['organization_id', 'process_id'], unique=False)
    op.create_table('scanner_domain_targets',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('evidence_source_id', sa.String(length=36), nullable=False),
    sa.Column('domain', sa.String(length=255), nullable=False),
    sa.Column('source', sa.String(length=30), nullable=False),
    sa.Column('ownership_status', sa.String(length=30), nullable=False),
    sa.Column('scan_enabled', sa.Boolean(), nullable=False),
    sa.Column('include_subdomains', sa.Boolean(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('approved_by_user_id', sa.Integer(), nullable=True),
    sa.Column('approved_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['approved_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['evidence_source_id'], ['evidence_sources.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scanner_domain_targets_source', 'scanner_domain_targets', ['evidence_source_id', 'status'], unique=False)
    op.create_table('scanner_instances',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('evidence_source_id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('public_instance_id', sa.String(length=36), nullable=False),
    sa.Column('installation_method', sa.String(length=30), nullable=False),
    sa.Column('scanner_version', sa.String(length=50), nullable=True),
    sa.Column('configuration_version', sa.String(length=50), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('os_name', sa.String(length=100), nullable=True),
    sa.Column('os_version', sa.String(length=100), nullable=True),
    sa.Column('architecture', sa.String(length=30), nullable=True),
    sa.Column('kernel_release', sa.String(length=100), nullable=True),
    sa.Column('container_runtime', sa.String(length=30), nullable=True),
    sa.Column('network_segments', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('runtime_os_name', sa.String(length=100), nullable=True),
    sa.Column('runtime_os_version', sa.String(length=100), nullable=True),
    sa.Column('activation_token_hash', sa.String(length=64), nullable=False),
    sa.Column('activated_at', sa.DateTime(), nullable=False),
    sa.Column('activation_revoked_at', sa.DateTime(), nullable=True),
    sa.Column('command_signing_key_encrypted', sa.LargeBinary(), nullable=True),
    sa.Column('scan_profile', sa.String(length=30), nullable=True),
    sa.Column('tool_status', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('tool_validation_at', sa.DateTime(), nullable=True),
    sa.Column('connection_verified_at', sa.DateTime(), nullable=True),
    sa.Column('test_scan_status', sa.String(length=30), nullable=True),
    sa.Column('test_scan_completed_at', sa.DateTime(), nullable=True),
    sa.Column('scope_confirmed_by_user_id', sa.Integer(), nullable=True),
    sa.Column('scope_confirmed_at', sa.DateTime(), nullable=True),
    sa.Column('registered_at', sa.DateTime(), nullable=False),
    sa.Column('last_heartbeat_at', sa.DateTime(), nullable=True),
    sa.Column('last_successful_connection_at', sa.DateTime(), nullable=True),
    sa.Column('last_scan_at', sa.DateTime(), nullable=True),
    sa.Column('pending_instruction', sa.String(length=30), nullable=True),
    sa.Column('pending_instruction_requested_at', sa.DateTime(), nullable=True),
    sa.Column('pending_instruction_requested_by_user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['evidence_source_id'], ['evidence_sources.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['pending_instruction_requested_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['scope_confirmed_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('evidence_source_id')
    )
    op.create_index('ix_scanner_instances_source', 'scanner_instances', ['evidence_source_id'], unique=True)
    op.create_table('access_connectors',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('scanner_instance_id', sa.String(length=36), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=True),
    sa.Column('permission_subject_id', sa.String(length=36), nullable=False),
    sa.Column('connector_type', sa.String(length=30), nullable=False),
    sa.Column('credential_model', sa.String(length=30), nullable=False),
    sa.Column('target_host', sa.String(length=255), nullable=False),
    sa.Column('target_port', sa.Integer(), nullable=True),
    sa.Column('target_username', sa.String(length=255), nullable=True),
    sa.Column('credential_fingerprint', sa.String(length=128), nullable=True),
    sa.Column('credential_registered_at', sa.DateTime(), nullable=True),
    sa.Column('credential_rotated_at', sa.DateTime(), nullable=True),
    sa.Column('requires_docker_socket', sa.Boolean(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('paused_at', sa.DateTime(), nullable=True),
    sa.Column('revoked_at', sa.DateTime(), nullable=True),
    sa.Column('revoked_by_user_id', sa.Integer(), nullable=True),
    sa.Column('revocation_reason', sa.Text(), nullable=True),
    sa.Column('disconnected_at', sa.DateTime(), nullable=True),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('created_by_user_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['created_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['permission_subject_id'], ['permission_subjects.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['revoked_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['scanner_instance_id'], ['scanner_instances.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('permission_subject_id')
    )
    op.create_index('ix_access_connectors_asset', 'access_connectors', ['organization_id', 'asset_id'], unique=False)
    op.create_index('ix_access_connectors_instance', 'access_connectors', ['scanner_instance_id', 'status'], unique=False)
    op.create_index('ix_access_connectors_org_status', 'access_connectors', ['organization_id', 'status'], unique=False)
    op.create_table('collector_readiness_reports',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('scanner_instance_id', sa.String(length=36), nullable=False),
    sa.Column('reported_at', sa.DateTime(), nullable=False),
    sa.Column('self_check_started_at', sa.DateTime(), nullable=True),
    sa.Column('self_check_completed_at', sa.DateTime(), nullable=True),
    sa.Column('overall_status', sa.String(length=20), nullable=False),
    sa.Column('platform_connectivity_status', sa.String(length=20), nullable=False),
    sa.Column('evidence_storage_status', sa.String(length=20), nullable=False),
    sa.Column('collector_version', sa.String(length=50), nullable=True),
    sa.Column('template_pack_version', sa.String(length=50), nullable=True),
    sa.Column('components', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('failure_reason_codes', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('trigger', sa.String(length=20), nullable=True),
    sa.Column('requested_by_user_id', sa.Integer(), nullable=True),
    sa.Column('schema_version', sa.String(length=20), nullable=False),
    sa.Column('report_sequence', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['requested_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['scanner_instance_id'], ['scanner_instances.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_collector_readiness_instance_reported', 'collector_readiness_reports', ['scanner_instance_id', 'reported_at'], unique=False)
    op.create_table('discovery_runs',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('evidence_source_id', sa.String(length=36), nullable=False),
    sa.Column('scanner_instance_id', sa.String(length=36), nullable=False),
    sa.Column('requested_by_user_id', sa.Integer(), nullable=False),
    sa.Column('approved_by_user_id', sa.Integer(), nullable=True),
    sa.Column('request_source', sa.String(length=20), nullable=False),
    sa.Column('discovery_purpose', sa.String(length=40), nullable=False),
    sa.Column('profile_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('target_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('target_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('business_process_id', sa.String(length=36), nullable=True),
    sa.Column('business_service_id', sa.String(length=36), nullable=True),
    sa.Column('process_scan_scope_id', sa.String(length=36), nullable=True),
    sa.Column('process_scan_scope_revision', sa.Integer(), nullable=True),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('current_stage', sa.String(length=30), nullable=False),
    sa.Column('approval_status', sa.String(length=20), nullable=False),
    sa.Column('requested_at', sa.DateTime(), nullable=False),
    sa.Column('approved_at', sa.DateTime(), nullable=True),
    sa.Column('queued_at', sa.DateTime(), nullable=True),
    sa.Column('command_available_at', sa.DateTime(), nullable=True),
    sa.Column('acknowledged_at', sa.DateTime(), nullable=True),
    sa.Column('started_at', sa.DateTime(), nullable=True),
    sa.Column('completed_at', sa.DateTime(), nullable=True),
    sa.Column('cancelled_at', sa.DateTime(), nullable=True),
    sa.Column('failed_at', sa.DateTime(), nullable=True),
    sa.Column('cancellation_requested_at', sa.DateTime(), nullable=True),
    sa.Column('cancellation_requested_by_user_id', sa.Integer(), nullable=True),
    sa.Column('cancellation_reason_code', sa.String(length=40), nullable=True),
    sa.Column('cancellation_reason_note', sa.Text(), nullable=True),
    sa.Column('retry_of_discovery_run_id', sa.String(length=36), nullable=True),
    sa.Column('retry_count', sa.Integer(), nullable=False),
    sa.Column('failure_code', sa.String(length=60), nullable=True),
    sa.Column('failure_message', sa.Text(), nullable=True),
    sa.Column('next_action', sa.Text(), nullable=True),
    sa.Column('idempotency_key', sa.String(length=100), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['approved_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['business_process_id'], ['value_streams.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['business_service_id'], ['business_services.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['cancellation_requested_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['evidence_source_id'], ['evidence_sources.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['requested_by_user_id'], ['users.id'], ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['retry_of_discovery_run_id'], ['discovery_runs.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['scanner_instance_id'], ['scanner_instances.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'requested_by_user_id', 'idempotency_key', name='uq_discovery_run_idempotency')
    )
    op.create_index('ix_discovery_runs_org_status', 'discovery_runs', ['organization_id', 'status'], unique=False)
    op.create_index('ix_discovery_runs_scanner_instance_status', 'discovery_runs', ['scanner_instance_id', 'status'], unique=False)
    op.create_table('evidence_receipts',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('evidence_source_id', sa.String(length=36), nullable=False),
    sa.Column('evidence_import_batch_id', sa.String(length=36), nullable=True),
    sa.Column('received_at', sa.DateTime(), nullable=False),
    sa.Column('record_count', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('validation_summary', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.ForeignKeyConstraint(['evidence_import_batch_id'], ['evidence_import_batches.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['evidence_source_id'], ['evidence_sources.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_evidence_receipts_source', 'evidence_receipts', ['evidence_source_id'], unique=False)
    op.create_table('jira_tickets',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('finding_id', sa.Integer(), nullable=False),
    sa.Column('ticket_key', sa.String(length=50), nullable=False),
    sa.Column('ticket_url', sa.String(length=500), nullable=False),
    sa.Column('status', sa.Enum('CREATED', 'IN_PROGRESS', 'RESOLVED', 'CLOSED', name='jiraticketstatus'), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_jira_tickets_finding_id'), 'jira_tickets', ['finding_id'], unique=True)
    op.create_index(op.f('ix_jira_tickets_id'), 'jira_tickets', ['id'], unique=False)
    op.create_index(op.f('ix_jira_tickets_organization_id'), 'jira_tickets', ['organization_id'], unique=False)
    op.create_index(op.f('ix_jira_tickets_ticket_key'), 'jira_tickets', ['ticket_key'], unique=True)
    op.create_table('recurrence_schedules',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('authorizing_policy_id', sa.String(length=36), nullable=False),
    sa.Column('scanner_instance_id', sa.String(length=36), nullable=False),
    sa.Column('supersedes_schedule_id', sa.String(length=36), nullable=True),
    sa.Column('superseded_by_id', sa.String(length=36), nullable=True),
    sa.Column('superseded_at', sa.DateTime(), nullable=True),
    sa.Column('superseded_by_user_id', sa.Integer(), nullable=True),
    sa.Column('cadence_interval', sa.Integer(), server_default='1', nullable=False),
    sa.Column('cadence_type', sa.String(length=20), server_default='interval_days', nullable=False),
    sa.Column('cadence_weekdays', sa.JSON(), server_default='[]', nullable=False),
    sa.Column('cadence_day_of_month', sa.Integer(), nullable=True),
    sa.Column('cadence_month', sa.Integer(), nullable=True),
    sa.Column('anchor_timezone', sa.String(length=64), server_default='UTC', nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('next_occurrence_at', sa.DateTime(), nullable=False),
    sa.Column('last_occurrence_at', sa.DateTime(), nullable=True),
    sa.Column('purpose', sa.Text(), nullable=True),
    sa.Column('created_by_user_id', sa.Integer(), nullable=True),
    sa.Column('paused_at', sa.DateTime(), nullable=True),
    sa.Column('paused_by_user_id', sa.Integer(), nullable=True),
    sa.Column('cancelled_at', sa.DateTime(), nullable=True),
    sa.Column('cancelled_by_user_id', sa.Integer(), nullable=True),
    sa.Column('lapsed_at', sa.DateTime(), nullable=True),
    sa.Column('lapsed_reason', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['authorizing_policy_id'], ['contextual_access_policies.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['cancelled_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['created_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['paused_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['scanner_instance_id'], ['scanner_instances.id'], ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['superseded_by_id'], ['recurrence_schedules.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['superseded_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['supersedes_schedule_id'], ['recurrence_schedules.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_recurrence_schedules_due', 'recurrence_schedules', ['status', 'next_occurrence_at'], unique=False)
    op.create_index('ix_recurrence_schedules_org_status', 'recurrence_schedules', ['organization_id', 'status'], unique=False)
    op.create_table('scanner_credentials',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('scanner_instance_id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('validity_policy', sa.String(length=20), nullable=False),
    sa.Column('validity_custom_days', sa.Integer(), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('created_by_user_id', sa.Integer(), nullable=True),
    sa.Column('expires_at', sa.DateTime(), nullable=True),
    sa.Column('consumed_at', sa.DateTime(), nullable=True),
    sa.Column('last_rotated_at', sa.DateTime(), nullable=True),
    sa.Column('paused_at', sa.DateTime(), nullable=True),
    sa.Column('revoked_at', sa.DateTime(), nullable=True),
    sa.Column('revoked_by_user_id', sa.Integer(), nullable=True),
    sa.Column('deleted_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['created_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['revoked_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['scanner_instance_id'], ['scanner_instances.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token_hash')
    )
    op.create_index('ix_scanner_credentials_instance', 'scanner_credentials', ['scanner_instance_id', 'status'], unique=False)
    op.create_table('scanner_network_targets',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('evidence_source_id', sa.String(length=36), nullable=False),
    sa.Column('cidr', sa.String(length=50), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('organisation_unit_id', sa.String(length=36), nullable=True),
    sa.Column('location_id', sa.String(length=36), nullable=True),
    sa.Column('environment', sa.String(length=50), nullable=True),
    sa.Column('network_type', sa.String(length=20), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('approved_by_user_id', sa.Integer(), nullable=True),
    sa.Column('approved_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['approved_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['evidence_source_id'], ['evidence_sources.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['location_id'], ['organization_locations.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organisation_unit_id'], ['organization_units.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scanner_network_targets_source', 'scanner_network_targets', ['evidence_source_id', 'status'], unique=False)
    op.create_table('verification_records',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('resolution_record_id', sa.String(length=36), nullable=False),
    sa.Column('recommendation_id', sa.String(length=36), nullable=False),
    sa.Column('threat_id', sa.String(length=36), nullable=True),
    sa.Column('verification_status', sa.String(length=30), nullable=False),
    sa.Column('confidence_score', sa.Integer(), nullable=False),
    sa.Column('observed_changes', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('linked_context_type', sa.String(length=20), nullable=True),
    sa.Column('linked_context_id', sa.String(length=200), nullable=True),
    sa.Column('compared_observed_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['recommendation_id'], ['recommendations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['resolution_record_id'], ['resolution_records.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['threat_id'], ['threats.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_verification_records_org', 'verification_records', ['organization_id'], unique=False)
    op.create_index('ix_verification_records_org_created', 'verification_records', ['organization_id', 'created_at'], unique=False)
    op.create_index('ix_verification_records_recommendation', 'verification_records', ['recommendation_id'], unique=False)
    op.create_index('ix_verification_records_resolution', 'verification_records', ['resolution_record_id'], unique=False)
    op.create_table('connector_access_tests',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('connector_id', sa.String(length=36), nullable=False),
    sa.Column('permission_profile_id', sa.String(length=36), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('requested_at', sa.DateTime(), nullable=False),
    sa.Column('requested_by_user_id', sa.Integer(), nullable=True),
    sa.Column('completed_at', sa.DateTime(), nullable=True),
    sa.Column('reachable', sa.Boolean(), nullable=True),
    sa.Column('permissions_adequate', sa.Boolean(), nullable=True),
    sa.Column('capabilities_confirmed', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('failure_code', sa.String(length=50), nullable=True),
    sa.Column('failure_detail', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['connector_id'], ['access_connectors.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['permission_profile_id'], ['permission_profiles.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['requested_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_connector_access_tests_connector', 'connector_access_tests', ['connector_id', 'status'], unique=False)
    op.create_index('ix_connector_access_tests_org_status', 'connector_access_tests', ['organization_id', 'status'], unique=False)
    op.create_table('discovery_execution_plans',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('discovery_run_id', sa.String(length=36), nullable=False),
    sa.Column('plan_definition', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('generated_at', sa.DateTime(), nullable=False),
    sa.Column('started_at', sa.DateTime(), nullable=True),
    sa.Column('completed_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['discovery_run_id'], ['discovery_runs.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('discovery_run_id', name='uq_discovery_execution_plan_run')
    )
    op.create_index('ix_discovery_execution_plans_org_status', 'discovery_execution_plans', ['organization_id', 'status'], unique=False)
    op.create_table('recurrence_occurrences',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('schedule_id', sa.String(length=36), nullable=False),
    sa.Column('scheduled_for', sa.DateTime(), nullable=False),
    sa.Column('materialized_at', sa.DateTime(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('claimed_at', sa.DateTime(), nullable=True),
    sa.Column('created_work_ref', sa.String(length=255), nullable=True),
    sa.Column('resolved_at', sa.DateTime(), nullable=True),
    sa.Column('failure_reason', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['schedule_id'], ['recurrence_schedules.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_recurrence_occurrences_org_status', 'recurrence_occurrences', ['organization_id', 'status'], unique=False)
    op.create_index('ix_recurrence_occurrences_schedule', 'recurrence_occurrences', ['schedule_id', 'status'], unique=False)
    op.create_table('artefact_access_lifecycles',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('state', sa.String(length=30), nullable=False),
    sa.Column('requested_choice', sa.String(length=30), nullable=False),
    sa.Column('deviation_reason', sa.Text(), nullable=True),
    sa.Column('requested_at', sa.DateTime(), nullable=False),
    sa.Column('requested_by_user_id', sa.Integer(), nullable=True),
    sa.Column('connector_id', sa.String(length=36), nullable=True),
    sa.Column('configured_at', sa.DateTime(), nullable=True),
    sa.Column('access_test_id', sa.String(length=36), nullable=True),
    sa.Column('tested_at', sa.DateTime(), nullable=True),
    sa.Column('verification_ready_at', sa.DateTime(), nullable=True),
    sa.Column('verification_approved_at', sa.DateTime(), nullable=True),
    sa.Column('verification_approved_by_user_id', sa.Integer(), nullable=True),
    sa.Column('verification_approved_source', sa.String(length=30), nullable=True),
    sa.Column('verification_approval_policy_id', sa.String(length=36), nullable=True),
    sa.Column('running_at', sa.DateTime(), nullable=True),
    sa.Column('completed_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.CheckConstraint("state NOT IN ('running', 'complete') OR verification_approved_at IS NOT NULL", name='ck_artefact_access_run_requires_approval'),
    sa.CheckConstraint('verification_approved_at IS NULL OR verification_approved_source IS NOT NULL', name='ck_artefact_access_approval_names_its_source'),
    sa.ForeignKeyConstraint(['access_test_id'], ['connector_access_tests.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['connector_id'], ['access_connectors.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['requested_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['verification_approval_policy_id'], ['contextual_access_policies.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['verification_approved_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'asset_id', name='uq_artefact_access_lifecycle_artefact')
    )
    op.create_index('ix_artefact_access_lifecycles_org_state', 'artefact_access_lifecycles', ['organization_id', 'state'], unique=False)
    op.create_table('execution_stages',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('execution_plan_id', sa.String(length=36), nullable=False),
    sa.Column('stage_key', sa.String(length=30), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('required', sa.Boolean(), nullable=False),
    sa.Column('started_at', sa.DateTime(), nullable=True),
    sa.Column('completed_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['execution_plan_id'], ['discovery_execution_plans.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('execution_plan_id', 'stage_key', name='uq_execution_stage_plan_key')
    )
    op.create_index('ix_execution_stages_plan_status', 'execution_stages', ['execution_plan_id', 'status'], unique=False)
    op.create_table('execution_stage_dependencies',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('execution_stage_id', sa.String(length=36), nullable=False),
    sa.Column('depends_on_stage_id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['depends_on_stage_id'], ['execution_stages.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['execution_stage_id'], ['execution_stages.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('execution_stage_id', 'depends_on_stage_id', name='uq_execution_stage_dependency')
    )
    op.create_index('ix_execution_stage_dependencies_stage', 'execution_stage_dependencies', ['execution_stage_id'], unique=False)
    op.create_table('provider_executions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('execution_stage_id', sa.String(length=36), nullable=False),
    sa.Column('provider_id', sa.String(length=60), nullable=False),
    sa.Column('provider_version', sa.String(length=50), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('attempt_number', sa.Integer(), nullable=False),
    sa.Column('retry_of_provider_execution_id', sa.String(length=36), nullable=True),
    sa.Column('checkpoint', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('failure_code', sa.String(length=60), nullable=True),
    sa.Column('failure_message', sa.Text(), nullable=True),
    sa.Column('next_retry_at', sa.DateTime(), nullable=True),
    sa.Column('started_at', sa.DateTime(), nullable=True),
    sa.Column('completed_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['execution_stage_id'], ['execution_stages.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['retry_of_provider_execution_id'], ['provider_executions.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_provider_executions_stage_status', 'provider_executions', ['execution_stage_id', 'status'], unique=False)
    op.create_index('ix_provider_executions_status_next_retry_at', 'provider_executions', ['status', 'next_retry_at'], unique=False)
    op.create_table('verification_runs',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('lifecycle_id', sa.String(length=36), nullable=False),
    sa.Column('approval_source', sa.String(length=30), nullable=False),
    sa.Column('approved_by_user_id', sa.Integer(), nullable=True),
    sa.Column('approved_at', sa.DateTime(), nullable=True),
    sa.Column('permission_profile_id', sa.String(length=36), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('began_at', sa.DateTime(), nullable=False),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.Column('failure_reason', sa.Text(), nullable=True),
    sa.Column('began_by_user_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['approved_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['began_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['lifecycle_id'], ['artefact_access_lifecycles.id'], ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['permission_profile_id'], ['permission_profiles.id'], ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_verification_runs_asset', 'verification_runs', ['organization_id', 'asset_id', 'began_at'], unique=False)
    op.create_index('ix_verification_runs_org_status', 'verification_runs', ['organization_id', 'status'], unique=False)
    op.create_table('evidence_packages',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('discovery_run_id', sa.String(length=36), nullable=False),
    sa.Column('execution_plan_id', sa.String(length=36), nullable=False),
    sa.Column('execution_stage_id', sa.String(length=36), nullable=False),
    sa.Column('provider_execution_id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('provider_id', sa.String(length=60), nullable=False),
    sa.Column('provider_version', sa.String(length=50), nullable=True),
    sa.Column('collector_version', sa.String(length=50), nullable=True),
    sa.Column('captured_at', sa.DateTime(), nullable=False),
    sa.Column('schema_version', sa.String(length=20), nullable=False),
    sa.Column('raw_evidence_reference', sa.Text(), nullable=False),
    sa.Column('evidence_format', sa.String(length=30), nullable=False),
    sa.Column('integrity_hash', sa.String(length=128), nullable=True),
    sa.Column('execution_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('provenance_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('processing_status', sa.String(length=20), nullable=False),
    sa.Column('normalization_status', sa.String(length=20), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['discovery_run_id'], ['discovery_runs.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['execution_plan_id'], ['discovery_execution_plans.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['execution_stage_id'], ['execution_stages.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['provider_execution_id'], ['provider_executions.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('provider_execution_id', name='uq_evidence_package_provider_execution')
    )
    op.create_index('ix_evidence_packages_org_normalization_status', 'evidence_packages', ['organization_id', 'normalization_status'], unique=False)
    op.create_index('ix_evidence_packages_run', 'evidence_packages', ['discovery_run_id'], unique=False)
    op.create_table('scanner_commands',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('scanner_instance_id', sa.String(length=36), nullable=False),
    sa.Column('discovery_run_id', sa.String(length=36), nullable=False),
    sa.Column('provider_execution_id', sa.String(length=36), nullable=True),
    sa.Column('check_key', sa.String(length=30), nullable=True),
    sa.Column('business_process_id', sa.String(length=36), nullable=True),
    sa.Column('business_service_id', sa.String(length=36), nullable=True),
    sa.Column('command_type', sa.String(length=30), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('issued_at', sa.DateTime(), nullable=False),
    sa.Column('not_before', sa.DateTime(), nullable=True),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('delivered_at', sa.DateTime(), nullable=True),
    sa.Column('acknowledged_at', sa.DateTime(), nullable=True),
    sa.Column('accepted', sa.Boolean(), nullable=True),
    sa.Column('rejection_code', sa.String(length=60), nullable=True),
    sa.Column('rejection_message', sa.Text(), nullable=True),
    sa.Column('scanner_runtime_version', sa.String(length=50), nullable=True),
    sa.Column('execution_policy', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('signature_version', sa.String(length=10), nullable=False),
    sa.Column('signature', sa.String(length=128), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['business_process_id'], ['value_streams.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['business_service_id'], ['business_services.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['discovery_run_id'], ['discovery_runs.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['provider_execution_id'], ['provider_executions.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['scanner_instance_id'], ['scanner_instances.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scanner_commands_instance_status', 'scanner_commands', ['scanner_instance_id', 'status'], unique=False)
    op.create_index('ix_scanner_commands_provider_execution', 'scanner_commands', ['provider_execution_id'], unique=False)
    op.create_index('ix_scanner_commands_run', 'scanner_commands', ['discovery_run_id'], unique=False)
    op.create_table('worker_leases',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('provider_execution_id', sa.String(length=36), nullable=False),
    sa.Column('worker_id', sa.String(length=120), nullable=False),
    sa.Column('leased_at', sa.DateTime(), nullable=False),
    sa.Column('lease_expires_at', sa.DateTime(), nullable=False),
    sa.Column('heartbeat_at', sa.DateTime(), nullable=True),
    sa.Column('released_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['provider_execution_id'], ['provider_executions.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('provider_execution_id', name='uq_worker_lease_provider_execution')
    )
    op.create_table('artefact_relationships',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('source_asset_id', sa.Integer(), nullable=False),
    sa.Column('target_asset_id', sa.Integer(), nullable=False),
    sa.Column('relationship_type', sa.String(length=40), nullable=False),
    sa.Column('origin', sa.String(length=30), nullable=False),
    sa.Column('confidence', sa.String(length=10), nullable=False),
    sa.Column('state', sa.String(length=20), nullable=False),
    sa.Column('reason', sa.Text(), nullable=True),
    sa.Column('evidence_package_id', sa.String(length=36), nullable=True),
    sa.Column('scanner_instance_id', sa.String(length=36), nullable=True),
    sa.Column('observed_by_source', sa.String(length=255), nullable=True),
    sa.Column('asserted_by_user_id', sa.Integer(), nullable=True),
    sa.Column('first_seen_at', sa.DateTime(), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(), nullable=False),
    sa.Column('withdrawn_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.CheckConstraint('source_asset_id <> target_asset_id', name='ck_artefact_relationship_not_self'),
    sa.ForeignKeyConstraint(['asserted_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['evidence_package_id'], ['evidence_packages.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['scanner_instance_id'], ['scanner_instances.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['source_asset_id'], ['assets.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['target_asset_id'], ['assets.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_artefact_relationships_id'), 'artefact_relationships', ['id'], unique=False)
    op.create_index('ix_artefact_relationships_org_source', 'artefact_relationships', ['organization_id', 'source_asset_id'], unique=False)
    op.create_index('ix_artefact_relationships_org_state', 'artefact_relationships', ['organization_id', 'state'], unique=False)
    op.create_index('ix_artefact_relationships_org_target', 'artefact_relationships', ['organization_id', 'target_asset_id'], unique=False)
    op.create_index(op.f('ix_artefact_relationships_organization_id'), 'artefact_relationships', ['organization_id'], unique=False)
    op.create_index(op.f('ix_artefact_relationships_source_asset_id'), 'artefact_relationships', ['source_asset_id'], unique=False)
    op.create_index(op.f('ix_artefact_relationships_target_asset_id'), 'artefact_relationships', ['target_asset_id'], unique=False)
    op.create_index('uq_artefact_relationships_source_target_type', 'artefact_relationships', ['source_asset_id', 'target_asset_id', 'relationship_type'], unique=True)
    op.create_table('asset_evidence_signals',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('kind', sa.String(length=100), nullable=False),
    sa.Column('payload_json', sa.JSON(), nullable=False),
    sa.Column('observed_at', sa.DateTime(), nullable=False),
    sa.Column('confidence', sa.Float(), nullable=True),
    sa.Column('risk_score', sa.Float(), nullable=True),
    sa.Column('observation_type', sa.String(length=60), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=True),
    sa.Column('severity', sa.String(length=20), nullable=True),
    sa.Column('evidence_package_id', sa.String(length=36), nullable=True),
    sa.Column('provider_execution_id', sa.String(length=36), nullable=True),
    sa.Column('scanner_instance_id', sa.String(length=36), nullable=True),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
    sa.ForeignKeyConstraint(['evidence_package_id'], ['evidence_packages.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['provider_execution_id'], ['provider_executions.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['scanner_instance_id'], ['scanner_instances.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_asset_evidence_signals_asset_id'), 'asset_evidence_signals', ['asset_id'], unique=False)
    op.create_index(op.f('ix_asset_evidence_signals_id'), 'asset_evidence_signals', ['id'], unique=False)
    op.create_index(op.f('ix_asset_evidence_signals_observed_at'), 'asset_evidence_signals', ['observed_at'], unique=False)
    op.create_index(op.f('ix_asset_evidence_signals_organization_id'), 'asset_evidence_signals', ['organization_id'], unique=False)
    op.create_index('ix_asset_signals_asset_time', 'asset_evidence_signals', ['asset_id', 'observed_at'], unique=False)
    op.create_table('risk_intelligence_ingestion_batches',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('source_name', sa.String(length=150), nullable=False),
    sa.Column('collector_profile', sa.String(length=150), nullable=False),
    sa.Column('file_name', sa.String(length=255), nullable=True),
    sa.Column('content_type', sa.String(length=100), nullable=True),
    sa.Column('payload_checksum', sa.String(length=64), nullable=False),
    sa.Column('raw_payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('raw_payload_size_bytes', sa.Integer(), nullable=False),
    sa.Column('status', sa.Enum('RECEIVED', 'NORMALIZED', 'ANALYZED', 'NEEDS_REVIEW', 'REVIEWED', 'FAILED', name='riskingestionbatchstatus', native_enum=False), nullable=False),
    sa.Column('received_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('decision_evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('evidence_package_id', sa.String(length=36), nullable=True),
    sa.ForeignKeyConstraint(['evidence_package_id'], ['evidence_packages.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_risk_intel_ingestion_batches_org_created', 'risk_intelligence_ingestion_batches', ['organization_id', 'received_at'], unique=False)
    op.create_index('ix_risk_intel_ingestion_batches_org_status', 'risk_intelligence_ingestion_batches', ['organization_id', 'status'], unique=False)
    op.create_index(op.f('ix_risk_intelligence_ingestion_batches_collector_profile'), 'risk_intelligence_ingestion_batches', ['collector_profile'], unique=False)
    op.create_index(op.f('ix_risk_intelligence_ingestion_batches_evidence_package_id'), 'risk_intelligence_ingestion_batches', ['evidence_package_id'], unique=False)
    op.create_index(op.f('ix_risk_intelligence_ingestion_batches_id'), 'risk_intelligence_ingestion_batches', ['id'], unique=False)
    op.create_index(op.f('ix_risk_intelligence_ingestion_batches_organization_id'), 'risk_intelligence_ingestion_batches', ['organization_id'], unique=False)
    op.create_index(op.f('ix_risk_intelligence_ingestion_batches_payload_checksum'), 'risk_intelligence_ingestion_batches', ['payload_checksum'], unique=False)
    op.create_index(op.f('ix_risk_intelligence_ingestion_batches_received_at'), 'risk_intelligence_ingestion_batches', ['received_at'], unique=False)
    op.create_index(op.f('ix_risk_intelligence_ingestion_batches_source_name'), 'risk_intelligence_ingestion_batches', ['source_name'], unique=False)
    op.create_index(op.f('ix_risk_intelligence_ingestion_batches_status'), 'risk_intelligence_ingestion_batches', ['status'], unique=False)


    # `organizations.technical_setup_owner_user_id -> users.id` closes a cycle:
    # users reference organizations too. The model marks it `use_alter=True` so
    # `create_all` emits it as a separate ALTER after both tables exist — but
    # `op.create_table` has no deferred pass, so the constraint was dropped on
    # the floor without a word. `organizations` came out with no foreign keys at
    # all, 524 lines before `users` existed. Emitted here, where both do.
    op.create_foreign_key(
        "fk_organizations_technical_setup_owner",
        "organizations",
        "users",
        ["technical_setup_owner_user_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade():
    op.drop_constraint("fk_organizations_technical_setup_owner", "organizations", type_="foreignkey")
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_risk_intelligence_ingestion_batches_status'), table_name='risk_intelligence_ingestion_batches')
    op.drop_index(op.f('ix_risk_intelligence_ingestion_batches_source_name'), table_name='risk_intelligence_ingestion_batches')
    op.drop_index(op.f('ix_risk_intelligence_ingestion_batches_received_at'), table_name='risk_intelligence_ingestion_batches')
    op.drop_index(op.f('ix_risk_intelligence_ingestion_batches_payload_checksum'), table_name='risk_intelligence_ingestion_batches')
    op.drop_index(op.f('ix_risk_intelligence_ingestion_batches_organization_id'), table_name='risk_intelligence_ingestion_batches')
    op.drop_index(op.f('ix_risk_intelligence_ingestion_batches_id'), table_name='risk_intelligence_ingestion_batches')
    op.drop_index(op.f('ix_risk_intelligence_ingestion_batches_evidence_package_id'), table_name='risk_intelligence_ingestion_batches')
    op.drop_index(op.f('ix_risk_intelligence_ingestion_batches_collector_profile'), table_name='risk_intelligence_ingestion_batches')
    op.drop_index('ix_risk_intel_ingestion_batches_org_status', table_name='risk_intelligence_ingestion_batches')
    op.drop_index('ix_risk_intel_ingestion_batches_org_created', table_name='risk_intelligence_ingestion_batches')
    op.drop_table('risk_intelligence_ingestion_batches')
    op.drop_index('ix_asset_signals_asset_time', table_name='asset_evidence_signals')
    op.drop_index(op.f('ix_asset_evidence_signals_organization_id'), table_name='asset_evidence_signals')
    op.drop_index(op.f('ix_asset_evidence_signals_observed_at'), table_name='asset_evidence_signals')
    op.drop_index(op.f('ix_asset_evidence_signals_id'), table_name='asset_evidence_signals')
    op.drop_index(op.f('ix_asset_evidence_signals_asset_id'), table_name='asset_evidence_signals')
    op.drop_table('asset_evidence_signals')
    op.drop_index('uq_artefact_relationships_source_target_type', table_name='artefact_relationships')
    op.drop_index(op.f('ix_artefact_relationships_target_asset_id'), table_name='artefact_relationships')
    op.drop_index(op.f('ix_artefact_relationships_source_asset_id'), table_name='artefact_relationships')
    op.drop_index(op.f('ix_artefact_relationships_organization_id'), table_name='artefact_relationships')
    op.drop_index('ix_artefact_relationships_org_target', table_name='artefact_relationships')
    op.drop_index('ix_artefact_relationships_org_state', table_name='artefact_relationships')
    op.drop_index('ix_artefact_relationships_org_source', table_name='artefact_relationships')
    op.drop_index(op.f('ix_artefact_relationships_id'), table_name='artefact_relationships')
    op.drop_table('artefact_relationships')
    op.drop_table('worker_leases')
    op.drop_index('ix_scanner_commands_run', table_name='scanner_commands')
    op.drop_index('ix_scanner_commands_provider_execution', table_name='scanner_commands')
    op.drop_index('ix_scanner_commands_instance_status', table_name='scanner_commands')
    op.drop_table('scanner_commands')
    op.drop_index('ix_evidence_packages_run', table_name='evidence_packages')
    op.drop_index('ix_evidence_packages_org_normalization_status', table_name='evidence_packages')
    op.drop_table('evidence_packages')
    op.drop_index('ix_verification_runs_org_status', table_name='verification_runs')
    op.drop_index('ix_verification_runs_asset', table_name='verification_runs')
    op.drop_table('verification_runs')
    op.drop_index('ix_provider_executions_status_next_retry_at', table_name='provider_executions')
    op.drop_index('ix_provider_executions_stage_status', table_name='provider_executions')
    op.drop_table('provider_executions')
    op.drop_index('ix_execution_stage_dependencies_stage', table_name='execution_stage_dependencies')
    op.drop_table('execution_stage_dependencies')
    op.drop_index('ix_execution_stages_plan_status', table_name='execution_stages')
    op.drop_table('execution_stages')
    op.drop_index('ix_artefact_access_lifecycles_org_state', table_name='artefact_access_lifecycles')
    op.drop_table('artefact_access_lifecycles')
    op.drop_index('ix_recurrence_occurrences_schedule', table_name='recurrence_occurrences')
    op.drop_index('ix_recurrence_occurrences_org_status', table_name='recurrence_occurrences')
    op.drop_table('recurrence_occurrences')
    op.drop_index('ix_discovery_execution_plans_org_status', table_name='discovery_execution_plans')
    op.drop_table('discovery_execution_plans')
    op.drop_index('ix_connector_access_tests_org_status', table_name='connector_access_tests')
    op.drop_index('ix_connector_access_tests_connector', table_name='connector_access_tests')
    op.drop_table('connector_access_tests')
    op.drop_index('ix_verification_records_resolution', table_name='verification_records')
    op.drop_index('ix_verification_records_recommendation', table_name='verification_records')
    op.drop_index('ix_verification_records_org_created', table_name='verification_records')
    op.drop_index('ix_verification_records_org', table_name='verification_records')
    op.drop_table('verification_records')
    op.drop_index('ix_scanner_network_targets_source', table_name='scanner_network_targets')
    op.drop_table('scanner_network_targets')
    op.drop_index('ix_scanner_credentials_instance', table_name='scanner_credentials')
    op.drop_table('scanner_credentials')
    op.drop_index('ix_recurrence_schedules_org_status', table_name='recurrence_schedules')
    op.drop_index('ix_recurrence_schedules_due', table_name='recurrence_schedules')
    op.drop_table('recurrence_schedules')
    op.drop_index(op.f('ix_jira_tickets_ticket_key'), table_name='jira_tickets')
    op.drop_index(op.f('ix_jira_tickets_organization_id'), table_name='jira_tickets')
    op.drop_index(op.f('ix_jira_tickets_id'), table_name='jira_tickets')
    op.drop_index(op.f('ix_jira_tickets_finding_id'), table_name='jira_tickets')
    op.drop_table('jira_tickets')
    op.drop_index('ix_evidence_receipts_source', table_name='evidence_receipts')
    op.drop_table('evidence_receipts')
    op.drop_index('ix_discovery_runs_scanner_instance_status', table_name='discovery_runs')
    op.drop_index('ix_discovery_runs_org_status', table_name='discovery_runs')
    op.drop_table('discovery_runs')
    op.drop_index('ix_collector_readiness_instance_reported', table_name='collector_readiness_reports')
    op.drop_table('collector_readiness_reports')
    op.drop_index('ix_access_connectors_org_status', table_name='access_connectors')
    op.drop_index('ix_access_connectors_instance', table_name='access_connectors')
    op.drop_index('ix_access_connectors_asset', table_name='access_connectors')
    op.drop_table('access_connectors')
    op.drop_index('ix_scanner_instances_source', table_name='scanner_instances')
    op.drop_table('scanner_instances')
    op.drop_index('ix_scanner_domain_targets_source', table_name='scanner_domain_targets')
    op.drop_table('scanner_domain_targets')
    op.drop_index('ix_review_reopenings_org_process', table_name='review_reopenings')
    op.drop_table('review_reopenings')
    op.drop_index('ix_resolution_records_recovery_action', table_name='resolution_records')
    op.drop_index('ix_resolution_records_recommendation', table_name='resolution_records')
    op.drop_index('ix_resolution_records_org_created', table_name='resolution_records')
    op.drop_index('ix_resolution_records_org', table_name='resolution_records')
    op.drop_index('ix_resolution_records_decision', table_name='resolution_records')
    op.drop_table('resolution_records')
    op.drop_index('ix_process_owner_acceptances_process_status', table_name='process_owner_acceptances')
    op.drop_index('ix_process_owner_acceptances_org_process', table_name='process_owner_acceptances')
    op.drop_table('process_owner_acceptances')
    op.drop_index('ix_org_unit_relationships_org_source', table_name='organization_unit_relationships')
    op.drop_table('organization_unit_relationships')
    op.drop_index('ix_org_unit_memberships_org_user', table_name='organization_unit_memberships')
    op.drop_index('ix_org_unit_memberships_org_unit', table_name='organization_unit_memberships')
    op.drop_table('organization_unit_memberships')
    op.drop_table('organization_unit_match_suggestions')
    op.drop_index('ix_organization_locations_org_unit', table_name='organization_locations')
    op.drop_table('organization_locations')
    op.drop_index(op.f('ix_findings_status'), table_name='findings')
    op.drop_index(op.f('ix_findings_severity'), table_name='findings')
    op.drop_index(op.f('ix_findings_scan_run_id'), table_name='findings')
    op.drop_index(op.f('ix_findings_rule_id'), table_name='findings')
    op.drop_index(op.f('ix_findings_organization_id'), table_name='findings')
    op.drop_index(op.f('ix_findings_id'), table_name='findings')
    op.drop_index(op.f('ix_findings_detected_at'), table_name='findings')
    op.drop_index(op.f('ix_findings_asset_id'), table_name='findings')
    op.drop_index('ix_finding_scan_status', table_name='findings')
    op.drop_index('ix_finding_org', table_name='findings')
    op.drop_index('ix_finding_asset_severity', table_name='findings')
    op.drop_table('findings')
    op.drop_table('evidence_source_scopes')
    op.drop_index('ix_evidence_source_exceptions_source', table_name='evidence_source_exceptions')
    op.drop_table('evidence_source_exceptions')
    op.drop_index('ix_evidence_manual_entries_source', table_name='evidence_manual_entries')
    op.drop_table('evidence_manual_entries')
    op.drop_index('ix_evidence_import_batches_source', table_name='evidence_import_batches')
    op.drop_table('evidence_import_batches')
    op.drop_index('ix_discovery_scope_proposals_org_source_status', table_name='discovery_scope_proposals')
    op.drop_table('discovery_scope_proposals')
    op.drop_index('ix_dependency_bundle_versions_service', table_name='dependency_bundle_versions')
    op.drop_index('ix_dependency_bundle_versions_org', table_name='dependency_bundle_versions')
    op.drop_index('ix_dependency_bundle_versions_bundle_version', table_name='dependency_bundle_versions')
    op.drop_index('ix_dependency_bundle_versions_bundle', table_name='dependency_bundle_versions')
    op.drop_table('dependency_bundle_versions')
    op.drop_index(op.f('ix_artefact_merge_records_survivor_asset_id'), table_name='artefact_merge_records')
    op.drop_index(op.f('ix_artefact_merge_records_organization_id'), table_name='artefact_merge_records')
    op.drop_index('ix_artefact_merge_records_org_survivor', table_name='artefact_merge_records')
    op.drop_index('ix_artefact_merge_records_org_merged', table_name='artefact_merge_records')
    op.drop_index(op.f('ix_artefact_merge_records_merged_asset_id'), table_name='artefact_merge_records')
    op.drop_index(op.f('ix_artefact_merge_records_id'), table_name='artefact_merge_records')
    op.drop_table('artefact_merge_records')
    op.drop_index('ix_slot_instances_slot', table_name='slot_instances')
    op.drop_index('ix_slot_instances_service', table_name='slot_instances')
    op.drop_index('ix_slot_instances_org', table_name='slot_instances')
    op.drop_table('slot_instances')
    op.drop_index('ix_service_change_notices_service', table_name='service_change_notices')
    op.drop_index('ix_service_change_notices_recipient', table_name='service_change_notices')
    op.drop_index('ix_service_change_notices_process', table_name='service_change_notices')
    op.drop_table('service_change_notices')
    op.drop_index('ix_service_appetite_reassessments_service_category', table_name='service_appetite_reassessments')
    op.drop_index('ix_service_appetite_reassessments_process', table_name='service_appetite_reassessments')
    op.drop_table('service_appetite_reassessments')
    op.drop_index('ix_risk_evaluations_org_process', table_name='risk_evaluations')
    op.drop_table('risk_evaluations')
    op.drop_index(op.f('ix_policy_rules_resource_type'), table_name='policy_rules')
    op.drop_index(op.f('ix_policy_rules_organization_id'), table_name='policy_rules')
    op.drop_index(op.f('ix_policy_rules_id'), table_name='policy_rules')
    op.drop_index(op.f('ix_policy_rules_control_id'), table_name='policy_rules')
    op.drop_index(op.f('ix_policy_rules_cloud_provider'), table_name='policy_rules')
    op.drop_table('policy_rules')
    op.drop_index('ix_organization_units_org_status', table_name='organization_units')
    op.drop_index('ix_organization_units_org_parent', table_name='organization_units')
    op.drop_table('organization_units')
    op.drop_index('uq_org_mandate_scope_bindings_service_role', table_name='org_mandate_scope_bindings', postgresql_where=sa.text("scope_type = 'business_service'"))
    op.drop_index('uq_org_mandate_scope_bindings_process_role', table_name='org_mandate_scope_bindings', postgresql_where=sa.text("scope_type = 'business_process'"))
    op.drop_index('ix_org_mandate_scope_bindings_role_assignment', table_name='org_mandate_scope_bindings')
    op.drop_index('ix_org_mandate_scope_bindings_org_role', table_name='org_mandate_scope_bindings')
    op.drop_table('org_mandate_scope_bindings')
    op.drop_index('ix_evidence_sources_org_status', table_name='evidence_sources')
    op.drop_index('ix_evidence_sources_business_service', table_name='evidence_sources')
    op.drop_table('evidence_sources')
    op.drop_index('ix_dependency_bundles_service', table_name='dependency_bundles')
    op.drop_index('ix_dependency_bundles_org', table_name='dependency_bundles')
    op.drop_table('dependency_bundles')
    op.drop_index('ix_decision_records_threat', table_name='decision_records')
    op.drop_index('ix_decision_records_recommendation', table_name='decision_records')
    op.drop_index('ix_decision_records_org_created', table_name='decision_records')
    op.drop_index('ix_decision_records_org', table_name='decision_records')
    op.drop_table('decision_records')
    op.drop_index(op.f('ix_control_evidence_organization_id'), table_name='control_evidence')
    op.drop_index('ix_control_evidence_org_control', table_name='control_evidence')
    op.drop_index(op.f('ix_control_evidence_id'), table_name='control_evidence')
    op.drop_index(op.f('ix_control_evidence_control_id'), table_name='control_evidence')
    op.drop_index(op.f('ix_control_evidence_asset_id'), table_name='control_evidence')
    op.drop_table('control_evidence')
    op.drop_index('ix_business_service_appetite_configs_service', table_name='business_service_appetite_configs')
    op.drop_index('ix_business_service_appetite_configs_org', table_name='business_service_appetite_configs')
    op.drop_index(op.f('ix_business_service_appetite_configs_id'), table_name='business_service_appetite_configs')
    op.drop_table('business_service_appetite_configs')
    op.drop_index('ix_status_history_asset_time', table_name='asset_status_history')
    op.drop_index(op.f('ix_asset_status_history_status'), table_name='asset_status_history')
    op.drop_index(op.f('ix_asset_status_history_id'), table_name='asset_status_history')
    op.drop_index(op.f('ix_asset_status_history_asset_id'), table_name='asset_status_history')
    op.drop_table('asset_status_history')
    op.drop_index('uq_asset_observed_ports_asset_port_protocol', table_name='asset_observed_ports')
    op.drop_index(op.f('ix_asset_observed_ports_organization_id'), table_name='asset_observed_ports')
    op.drop_index('ix_asset_observed_ports_org_asset', table_name='asset_observed_ports')
    op.drop_index(op.f('ix_asset_observed_ports_id'), table_name='asset_observed_ports')
    op.drop_index(op.f('ix_asset_observed_ports_asset_id'), table_name='asset_observed_ports')
    op.drop_table('asset_observed_ports')
    op.drop_index('uq_asset_identifiers_asset_type_value', table_name='asset_identifiers')
    op.drop_index(op.f('ix_asset_identifiers_organization_id'), table_name='asset_identifiers')
    op.drop_index('ix_asset_identifiers_org_type_value', table_name='asset_identifiers')
    op.drop_index(op.f('ix_asset_identifiers_id'), table_name='asset_identifiers')
    op.drop_index(op.f('ix_asset_identifiers_asset_id'), table_name='asset_identifiers')
    op.drop_table('asset_identifiers')
    op.drop_index(op.f('ix_asset_findings_status'), table_name='asset_findings')
    op.drop_index(op.f('ix_asset_findings_severity'), table_name='asset_findings')
    op.drop_index(op.f('ix_asset_findings_organization_id'), table_name='asset_findings')
    op.drop_index('ix_asset_findings_org_status', table_name='asset_findings')
    op.drop_index(op.f('ix_asset_findings_id'), table_name='asset_findings')
    op.drop_index('ix_asset_findings_asset_status', table_name='asset_findings')
    op.drop_index(op.f('ix_asset_findings_asset_id'), table_name='asset_findings')
    op.drop_table('asset_findings')
    op.drop_index('ix_asset_connections_provider_account', table_name='asset_connections')
    op.drop_index(op.f('ix_asset_connections_id'), table_name='asset_connections')
    op.drop_index('ix_asset_connections_connection_state', table_name='asset_connections')
    op.drop_index('ix_asset_connections_asset_state', table_name='asset_connections')
    op.drop_index(op.f('ix_asset_connections_asset_id'), table_name='asset_connections')
    op.drop_table('asset_connections')
    op.drop_index('ix_asset_appetite_configs_org', table_name='asset_appetite_configs')
    op.drop_index(op.f('ix_asset_appetite_configs_id'), table_name='asset_appetite_configs')
    op.drop_table('asset_appetite_configs')
    op.drop_index('uq_artefact_identity_conflicts_pair', table_name='artefact_identity_conflicts')
    op.drop_index(op.f('ix_artefact_identity_conflicts_organization_id'), table_name='artefact_identity_conflicts')
    op.drop_index('ix_artefact_identity_conflicts_org_state', table_name='artefact_identity_conflicts')
    op.drop_index(op.f('ix_artefact_identity_conflicts_lower_asset_id'), table_name='artefact_identity_conflicts')
    op.drop_index(op.f('ix_artefact_identity_conflicts_id'), table_name='artefact_identity_conflicts')
    op.drop_index(op.f('ix_artefact_identity_conflicts_higher_asset_id'), table_name='artefact_identity_conflicts')
    op.drop_table('artefact_identity_conflicts')
    op.drop_index(op.f('ix_artefact_access_decisions_organization_id'), table_name='artefact_access_decisions')
    op.drop_index('ix_artefact_access_decisions_org_asset', table_name='artefact_access_decisions')
    op.drop_table('artefact_access_decisions')
    op.drop_index(op.f('ix_user_sessions_user_id'), table_name='user_sessions')
    op.drop_index(op.f('ix_user_sessions_revoked_at'), table_name='user_sessions')
    op.drop_index(op.f('ix_user_sessions_organization_id'), table_name='user_sessions')
    op.drop_index(op.f('ix_user_sessions_id'), table_name='user_sessions')
    op.drop_index(op.f('ix_user_sessions_expires_at'), table_name='user_sessions')
    op.drop_table('user_sessions')
    op.drop_index(op.f('ix_user_identities_user_id'), table_name='user_identities')
    op.drop_index('ix_user_identities_provider_subject', table_name='user_identities')
    op.drop_index(op.f('ix_user_identities_organization_id'), table_name='user_identities')
    op.drop_index('ix_user_identities_org_provider_email', table_name='user_identities')
    op.drop_index(op.f('ix_user_identities_id'), table_name='user_identities')
    op.drop_table('user_identities')
    op.drop_index('ix_risk_appetite_policies_process', table_name='risk_appetite_policies')
    op.drop_index('ix_risk_appetite_policies_org_scope', table_name='risk_appetite_policies')
    op.drop_table('risk_appetite_policies')
    op.drop_index('ix_recovery_actions_threat', table_name='recovery_actions')
    op.drop_index('ix_recovery_actions_org', table_name='recovery_actions')
    op.drop_index(op.f('ix_recovery_actions_id'), table_name='recovery_actions')
    op.drop_table('recovery_actions')
    op.drop_index('ix_recommendations_threat', table_name='recommendations')
    op.drop_index('ix_recommendations_org_status', table_name='recommendations')
    op.drop_index('ix_recommendations_org', table_name='recommendations')
    op.drop_table('recommendations')
    op.drop_index('ix_process_bia_assessments_process_status', table_name='process_bia_assessments')
    op.drop_index('ix_process_bia_assessments_org_process', table_name='process_bia_assessments')
    op.drop_table('process_bia_assessments')
    op.drop_index('ix_permission_profiles_subject', table_name='permission_profiles')
    op.drop_index('ix_permission_profiles_org_status', table_name='permission_profiles')
    op.drop_table('permission_profiles')
    op.drop_index(op.f('ix_password_reset_tokens_user_id'), table_name='password_reset_tokens')
    op.drop_index(op.f('ix_password_reset_tokens_token_hash'), table_name='password_reset_tokens')
    op.drop_index(op.f('ix_password_reset_tokens_organization_id'), table_name='password_reset_tokens')
    op.drop_index(op.f('ix_password_reset_tokens_id'), table_name='password_reset_tokens')
    op.drop_index(op.f('ix_password_reset_tokens_expires_at'), table_name='password_reset_tokens')
    op.drop_table('password_reset_tokens')
    op.drop_index('ix_organization_scopes_org_status', table_name='organization_scopes')
    op.drop_table('organization_scopes')
    op.drop_index('ix_organization_operating_context_org_current', table_name='organization_operating_context_suggestions')
    op.drop_table('organization_operating_context_suggestions')
    op.drop_index('ix_organization_legal_entities_org', table_name='organization_legal_entities')
    op.drop_table('organization_legal_entities')
    op.drop_index('ix_organization_identity_confirmations_org_status', table_name='organization_identity_confirmations')
    op.drop_table('organization_identity_confirmations')
    op.drop_index('ix_organization_domains_org', table_name='organization_domains')
    op.drop_table('organization_domains')
    op.drop_index('ix_organization_bia_baselines_org_status', table_name='organization_bia_baselines')
    op.drop_table('organization_bia_baselines')
    op.drop_table('org_visibility_policies')
    op.drop_index('ix_org_reporting_line_exceptions_org_manager', table_name='org_reporting_line_exceptions')
    op.drop_table('org_reporting_line_exceptions')
    op.drop_index('uq_org_mandate_role_assignments_user', table_name='org_mandate_role_assignments', postgresql_where=sa.text("subject_type = 'user'"))
    op.drop_index('uq_org_mandate_role_assignments_group', table_name='org_mandate_role_assignments', postgresql_where=sa.text("subject_type = 'identity_group'"))
    op.drop_index('ix_org_mandate_role_assignments_org_user', table_name='org_mandate_role_assignments')
    op.drop_index('ix_org_mandate_role_assignments_org_role', table_name='org_mandate_role_assignments')
    op.drop_index('ix_org_mandate_role_assignments_org_group', table_name='org_mandate_role_assignments')
    op.drop_table('org_mandate_role_assignments')
    op.drop_index('ix_mfa_challenges_user_used', table_name='mfa_challenges')
    op.drop_index(op.f('ix_mfa_challenges_user_id'), table_name='mfa_challenges')
    op.drop_index('ix_mfa_challenges_user_expires', table_name='mfa_challenges')
    op.drop_index(op.f('ix_mfa_challenges_used_at'), table_name='mfa_challenges')
    op.drop_index(op.f('ix_mfa_challenges_organization_id'), table_name='mfa_challenges')
    op.drop_index(op.f('ix_mfa_challenges_id'), table_name='mfa_challenges')
    op.drop_index(op.f('ix_mfa_challenges_expires_at'), table_name='mfa_challenges')
    op.drop_table('mfa_challenges')
    op.drop_index('ix_leadership_authorizations_org_status', table_name='leadership_authorizations')
    op.drop_table('leadership_authorizations')
    op.drop_index('ix_invite_tokens_user_used', table_name='invite_tokens')
    op.drop_index(op.f('ix_invite_tokens_user_id'), table_name='invite_tokens')
    op.drop_index('ix_invite_tokens_user_expires', table_name='invite_tokens')
    op.drop_index(op.f('ix_invite_tokens_used_at'), table_name='invite_tokens')
    op.drop_index(op.f('ix_invite_tokens_token_hash'), table_name='invite_tokens')
    op.drop_index(op.f('ix_invite_tokens_organization_id'), table_name='invite_tokens')
    op.drop_index(op.f('ix_invite_tokens_id'), table_name='invite_tokens')
    op.drop_index(op.f('ix_invite_tokens_expires_at'), table_name='invite_tokens')
    op.drop_table('invite_tokens')
    op.drop_index('ix_forecast_impacts_org_process', table_name='forecast_impacts')
    op.drop_table('forecast_impacts')
    op.drop_index(op.f('ix_compliance_controls_severity'), table_name='compliance_controls')
    op.drop_index(op.f('ix_compliance_controls_organization_id'), table_name='compliance_controls')
    op.drop_index(op.f('ix_compliance_controls_id'), table_name='compliance_controls')
    op.drop_index(op.f('ix_compliance_controls_framework_id'), table_name='compliance_controls')
    op.drop_index(op.f('ix_compliance_controls_control_id'), table_name='compliance_controls')
    op.drop_table('compliance_controls')
    op.drop_index('ix_business_services_org', table_name='business_services')
    op.drop_table('business_services')
    op.drop_index('ix_business_process_activations_org_process', table_name='business_process_activations')
    op.drop_table('business_process_activations')
    op.drop_index('ix_auth_ms_tenant_allowlist_settings_tenant', table_name='auth_ms_tenant_allowlist')
    op.drop_index(op.f('ix_auth_ms_tenant_allowlist_id'), table_name='auth_ms_tenant_allowlist')
    op.drop_index(op.f('ix_auth_ms_tenant_allowlist_auth_settings_id'), table_name='auth_ms_tenant_allowlist')
    op.drop_table('auth_ms_tenant_allowlist')
    op.drop_index('ix_auth_ms_group_roles_settings_group', table_name='auth_ms_group_roles')
    op.drop_index(op.f('ix_auth_ms_group_roles_id'), table_name='auth_ms_group_roles')
    op.drop_index(op.f('ix_auth_ms_group_roles_auth_settings_id'), table_name='auth_ms_group_roles')
    op.drop_table('auth_ms_group_roles')
    op.drop_index(op.f('ix_audit_events_organization_id'), table_name='audit_events')
    op.drop_index('ix_audit_events_org_type_created', table_name='audit_events')
    op.drop_index(op.f('ix_audit_events_id'), table_name='audit_events')
    op.drop_index(op.f('ix_audit_events_event_type'), table_name='audit_events')
    op.drop_index(op.f('ix_audit_events_actor_user_id'), table_name='audit_events')
    op.drop_table('audit_events')
    op.drop_index(op.f('ix_assets_type'), table_name='assets')
    op.drop_index(op.f('ix_assets_status'), table_name='assets')
    op.drop_index(op.f('ix_assets_organization_id'), table_name='assets')
    op.drop_index('ix_assets_org_layer_status', table_name='assets')
    op.drop_index('ix_assets_org_layer', table_name='assets')
    op.drop_index('ix_assets_org_connectivity', table_name='assets')
    op.drop_index(op.f('ix_assets_layer'), table_name='assets')
    op.drop_index('ix_assets_intent_gin', table_name='assets', postgresql_using='gin')
    op.drop_index(op.f('ix_assets_id'), table_name='assets')
    op.drop_index(op.f('ix_assets_connectivity_status'), table_name='assets')
    op.drop_index(op.f('ix_assets_canonical_identity_key'), table_name='assets')
    op.drop_table('assets')
    op.drop_index('ix_activation_audit_outbox_status_created', table_name='activation_audit_outbox')
    op.drop_index(op.f('ix_activation_audit_outbox_status'), table_name='activation_audit_outbox')
    op.drop_index(op.f('ix_activation_audit_outbox_organization_id'), table_name='activation_audit_outbox')
    op.drop_index(op.f('ix_activation_audit_outbox_id'), table_name='activation_audit_outbox')
    op.drop_index(op.f('ix_activation_audit_outbox_event_type'), table_name='activation_audit_outbox')
    op.drop_index(op.f('ix_activation_audit_outbox_actor_user_id'), table_name='activation_audit_outbox')
    op.drop_table('activation_audit_outbox')
    op.drop_index('ix_value_streams_org', table_name='value_streams')
    op.drop_table('value_streams')
    op.drop_index('ix_value_stream_signals_stream', table_name='value_stream_signals')
    op.drop_index('ix_value_stream_signals_org_event', table_name='value_stream_signals')
    op.drop_index('ix_value_stream_signals_library_item', table_name='value_stream_signals')
    op.drop_index(op.f('ix_value_stream_signals_id'), table_name='value_stream_signals')
    op.drop_table('value_stream_signals')
    op.drop_index(op.f('ix_users_organization_id'), table_name='users')
    op.drop_index(op.f('ix_users_id'), table_name='users')
    op.drop_index(op.f('ix_users_auth0_user_id'), table_name='users')
    op.drop_table('users')
    op.drop_index('ix_training_signals_target', table_name='training_signals')
    op.drop_index('ix_training_signals_source_created', table_name='training_signals')
    op.drop_index('ix_training_signals_signal_type', table_name='training_signals')
    op.drop_index('ix_training_signals_run', table_name='training_signals')
    op.drop_index('ix_training_signals_org', table_name='training_signals')
    op.drop_table('training_signals')
    op.drop_index('ix_threats_org_status', table_name='threats')
    op.drop_index('ix_threats_org_severity', table_name='threats')
    op.drop_table('threats')
    op.drop_index('ix_template_candidates_status', table_name='template_candidates')
    op.drop_index('ix_template_candidates_service_key', table_name='template_candidates')
    op.drop_index('ix_template_candidates_run', table_name='template_candidates')
    op.drop_index('ix_template_candidates_governance_class', table_name='template_candidates')
    op.drop_table('template_candidates')
    op.drop_index('ix_slot_templates_slot_id', table_name='slot_templates')
    op.drop_index('ix_slot_templates_service_template', table_name='slot_templates')
    op.drop_table('slot_templates')
    op.drop_index('ix_service_journey_signals_service_key', table_name='service_journey_signals')
    op.drop_index('ix_service_journey_signals_segment', table_name='service_journey_signals')
    op.drop_index('ix_service_journey_signals_org_event', table_name='service_journey_signals')
    op.drop_index(op.f('ix_service_journey_signals_id'), table_name='service_journey_signals')
    op.drop_table('service_journey_signals')
    op.drop_index(op.f('ix_scan_runs_status'), table_name='scan_runs')
    op.drop_index(op.f('ix_scan_runs_started_at'), table_name='scan_runs')
    op.drop_index(op.f('ix_scan_runs_scan_type'), table_name='scan_runs')
    op.drop_index(op.f('ix_scan_runs_organization_id'), table_name='scan_runs')
    op.drop_index(op.f('ix_scan_runs_id'), table_name='scan_runs')
    op.drop_index(op.f('ix_scan_runs_cloud_provider'), table_name='scan_runs')
    op.drop_table('scan_runs')
    op.drop_index(op.f('ix_risk_appetite_organization_id'), table_name='risk_appetite')
    op.drop_index('ix_risk_appetite_org_domain', table_name='risk_appetite')
    op.drop_index(op.f('ix_risk_appetite_id'), table_name='risk_appetite')
    op.drop_index(op.f('ix_risk_appetite_domain'), table_name='risk_appetite')
    op.drop_table('risk_appetite')
    op.drop_index('ix_permission_subjects_org_kind', table_name='permission_subjects')
    op.drop_table('permission_subjects')
    op.drop_index('ix_organization_identity_evidence_org', table_name='organization_identity_evidence')
    op.drop_table('organization_identity_evidence')
    op.drop_index('ix_org_service_configs_org', table_name='org_service_configs')
    op.drop_table('org_service_configs')
    op.drop_index('ix_org_process_configs_org', table_name='org_process_configs')
    op.drop_table('org_process_configs')
    op.drop_index('ix_mapping_decisions_service', table_name='mapping_decisions')
    op.drop_index('ix_mapping_decisions_org', table_name='mapping_decisions')
    op.drop_index('ix_mapping_decisions_bundle', table_name='mapping_decisions')
    op.drop_table('mapping_decisions')
    op.drop_index('ix_learning_improvement_candidates_type', table_name='learning_improvement_candidates')
    op.drop_index('ix_learning_improvement_candidates_target', table_name='learning_improvement_candidates')
    op.drop_index('ix_learning_improvement_candidates_status', table_name='learning_improvement_candidates')
    op.drop_index('ix_learning_improvement_candidates_run', table_name='learning_improvement_candidates')
    op.drop_index('ix_learning_improvement_candidates_governance', table_name='learning_improvement_candidates')
    op.drop_table('learning_improvement_candidates')
    op.drop_index(op.f('ix_key_risk_indicators_status'), table_name='key_risk_indicators')
    op.drop_index(op.f('ix_key_risk_indicators_organization_id'), table_name='key_risk_indicators')
    op.drop_index(op.f('ix_key_risk_indicators_name'), table_name='key_risk_indicators')
    op.drop_index(op.f('ix_key_risk_indicators_measured_at'), table_name='key_risk_indicators')
    op.drop_index(op.f('ix_key_risk_indicators_id'), table_name='key_risk_indicators')
    op.drop_table('key_risk_indicators')
    op.drop_index('ix_control_share_token', table_name='control_share_links')
    op.drop_index(op.f('ix_control_share_links_organization_id'), table_name='control_share_links')
    op.drop_index(op.f('ix_control_share_links_id'), table_name='control_share_links')
    op.drop_table('control_share_links')
    op.drop_index(op.f('ix_control_mappings_id'), table_name='control_mappings')
    op.drop_index(op.f('ix_control_mappings_control_id'), table_name='control_mappings')
    op.drop_index(op.f('ix_control_mappings_asset_type'), table_name='control_mappings')
    op.drop_table('control_mappings')
    op.drop_index('ix_contextual_access_policies_org_decision', table_name='contextual_access_policies')
    op.drop_table('contextual_access_policies')
    op.drop_index(op.f('ix_compliance_frameworks_organization_id'), table_name='compliance_frameworks')
    op.drop_index(op.f('ix_compliance_frameworks_name'), table_name='compliance_frameworks')
    op.drop_index(op.f('ix_compliance_frameworks_id'), table_name='compliance_frameworks')
    op.drop_table('compliance_frameworks')
    op.drop_index(op.f('ix_cloud_credentials_organization_id'), table_name='cloud_credentials')
    op.drop_index(op.f('ix_cloud_credentials_id'), table_name='cloud_credentials')
    op.drop_table('cloud_credentials')
    op.drop_index(op.f('ix_cloud_assets_region'), table_name='cloud_assets')
    op.drop_index(op.f('ix_cloud_assets_organization_id'), table_name='cloud_assets')
    op.drop_index(op.f('ix_cloud_assets_id'), table_name='cloud_assets')
    op.drop_index(op.f('ix_cloud_assets_cloud_provider'), table_name='cloud_assets')
    op.drop_index(op.f('ix_cloud_assets_asset_type'), table_name='cloud_assets')
    op.drop_index(op.f('ix_cloud_assets_asset_id'), table_name='cloud_assets')
    op.drop_table('cloud_assets')
    op.drop_index(op.f('ix_business_process_decision_logs_user_id'), table_name='business_process_decision_logs')
    op.drop_index(op.f('ix_business_process_decision_logs_recommendation_id'), table_name='business_process_decision_logs')
    op.drop_index('ix_business_process_decision_logs_recommendation', table_name='business_process_decision_logs')
    op.drop_index(op.f('ix_business_process_decision_logs_organization_id'), table_name='business_process_decision_logs')
    op.drop_index('ix_business_process_decision_logs_org_created', table_name='business_process_decision_logs')
    op.drop_table('business_process_decision_logs')
    op.drop_index('ix_baseline_risk_hypotheses_org_status', table_name='baseline_risk_hypotheses')
    op.drop_table('baseline_risk_hypotheses')
    op.drop_index(op.f('ix_auth_tenant_settings_organization_id'), table_name='auth_tenant_settings')
    op.drop_index(op.f('ix_auth_tenant_settings_id'), table_name='auth_tenant_settings')
    op.drop_table('auth_tenant_settings')
    op.drop_index('ix_template_learning_runs_status', table_name='template_learning_runs')
    op.drop_index('ix_template_learning_runs_started_at', table_name='template_learning_runs')
    op.drop_table('template_learning_runs')
    op.drop_index('ix_service_templates_key_active', table_name='service_templates')
    op.drop_index('ix_service_templates_archetype_active', table_name='service_templates')
    op.drop_table('service_templates')
    op.drop_index('ix_process_templates_key_active', table_name='process_templates')
    op.drop_index('ix_process_templates_family_active', table_name='process_templates')
    op.drop_table('process_templates')
    op.drop_index(op.f('ix_organizations_slug'), table_name='organizations')
    op.drop_index(op.f('ix_organizations_id'), table_name='organizations')
    op.drop_table('organizations')
    op.drop_index('ix_learning_loop_runs_status', table_name='learning_loop_runs')
    op.drop_index('ix_learning_loop_runs_started_at', table_name='learning_loop_runs')
    op.drop_table('learning_loop_runs')
    op.drop_index(op.f('ix_controls_id'), table_name='controls')
    op.drop_index('ix_controls_framework_code', table_name='controls')
    op.drop_index(op.f('ix_controls_framework'), table_name='controls')
    op.drop_table('controls')
    op.drop_index(op.f('ix_business_process_recommendations_user_id'), table_name='business_process_recommendations')
    op.drop_index(op.f('ix_business_process_recommendations_organization_id'), table_name='business_process_recommendations')
    op.drop_index('ix_business_process_recommendations_org_template', table_name='business_process_recommendations')
    op.drop_index('ix_business_process_recommendations_org_status', table_name='business_process_recommendations')
    op.drop_table('business_process_recommendations')

