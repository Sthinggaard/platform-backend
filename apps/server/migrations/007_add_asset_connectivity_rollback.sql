-- Rollback connectivity/onboarding metadata additions

ALTER TABLE asset_status_history
    DROP COLUMN IF EXISTS connectivity_status,
    DROP COLUMN IF EXISTS connection_state;

DROP INDEX IF EXISTS ix_asset_connections_connection_state;
DROP INDEX IF EXISTS ix_asset_connections_provider_account;
ALTER TABLE asset_connections
    DROP COLUMN IF EXISTS provider_account_id,
    DROP COLUMN IF EXISTS external_id,
    DROP COLUMN IF EXISTS role_arn,
    DROP COLUMN IF EXISTS permission_preset,
    DROP COLUMN IF EXISTS connection_state,
    DROP COLUMN IF EXISTS last_error_code,
    DROP COLUMN IF EXISTS last_error_detail,
    DROP COLUMN IF EXISTS validated_at;

DROP INDEX IF EXISTS ix_assets_intent_gin;
DROP INDEX IF EXISTS ix_assets_org_connectivity;
ALTER TABLE assets
    DROP COLUMN IF EXISTS environment,
    DROP COLUMN IF EXISTS criticality,
    DROP COLUMN IF EXISTS connectivity_status,
    DROP COLUMN IF EXISTS setup_confidence,
    DROP COLUMN IF EXISTS scan_start_mode,
    DROP COLUMN IF EXISTS secondary_layers,
    DROP COLUMN IF EXISTS intent,
    DROP COLUMN IF EXISTS business_owner_ref,
    DROP COLUMN IF EXISTS technical_owner_ref,
    DROP COLUMN IF EXISTS setup_assignee_ref,
    DROP COLUMN IF EXISTS created_by_ref,
    DROP COLUMN IF EXISTS posture_stale;
