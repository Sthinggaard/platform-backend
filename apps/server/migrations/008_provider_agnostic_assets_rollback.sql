-- Rollback for provider-agnostic OSI onboarding updates

DROP INDEX IF EXISTS ix_assets_org_layer;
ALTER TABLE assets DROP COLUMN IF EXISTS provider_display_name;

DROP INDEX IF EXISTS ix_asset_connections_provider_account_id;
ALTER TABLE asset_connections
    DROP COLUMN IF EXISTS auth_method,
    DROP COLUMN IF EXISTS auth_payload_json;

-- revert permission_preset to stricter varchar(30) NOT NULL with default
ALTER TABLE asset_connections
    ALTER COLUMN permission_preset TYPE VARCHAR(30),
    ALTER COLUMN permission_preset SET NOT NULL,
    ALTER COLUMN permission_preset SET DEFAULT 'SECURITY_READONLY';

