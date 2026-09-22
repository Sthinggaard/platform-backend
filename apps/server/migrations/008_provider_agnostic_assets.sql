-- Provider-agnostic OSI onboarding updates

-- assets: provider display name for OTHER and indexing by layer
ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS provider_display_name TEXT NULL;

CREATE INDEX IF NOT EXISTS ix_assets_org_layer ON assets (organization_id, layer);

-- asset_connections: provider-agnostic auth metadata
ALTER TABLE asset_connections
    ADD COLUMN IF NOT EXISTS auth_method TEXT NULL,
    ADD COLUMN IF NOT EXISTS auth_payload_json JSONB NULL;

-- relax permission_preset to free-form text while keeping existing default
ALTER TABLE asset_connections
    ALTER COLUMN permission_preset DROP NOT NULL,
    ALTER COLUMN permission_preset TYPE TEXT,
    ALTER COLUMN permission_preset SET DEFAULT 'SECURITY_READONLY';

-- provider account id lookup
CREATE INDEX IF NOT EXISTS ix_asset_connections_provider_account_id ON asset_connections (provider_account_id);

