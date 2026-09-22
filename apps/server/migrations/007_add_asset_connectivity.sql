-- Add connectivity and onboarding metadata for assets and asset_connections

-- assets: new lifecycle fields (connectivity vs posture) and metadata
ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS environment VARCHAR(20) NOT NULL DEFAULT 'PROD',
    ADD COLUMN IF NOT EXISTS criticality VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    ADD COLUMN IF NOT EXISTS connectivity_status VARCHAR(50) NOT NULL DEFAULT 'PENDING_VERIFICATION',
    ADD COLUMN IF NOT EXISTS setup_confidence VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    ADD COLUMN IF NOT EXISTS scan_start_mode VARCHAR(30) NOT NULL DEFAULT 'AFTER_SME_CONFIRM',
    ADD COLUMN IF NOT EXISTS secondary_layers INTEGER[] NULL,
    ADD COLUMN IF NOT EXISTS intent JSONB NULL,
    ADD COLUMN IF NOT EXISTS business_owner_ref TEXT NULL,
    ADD COLUMN IF NOT EXISTS technical_owner_ref TEXT NULL,
    ADD COLUMN IF NOT EXISTS setup_assignee_ref TEXT NULL,
    ADD COLUMN IF NOT EXISTS created_by_ref TEXT NULL,
    ADD COLUMN IF NOT EXISTS posture_stale BOOLEAN NOT NULL DEFAULT FALSE;

-- Map legacy NOT_CONNECTED posture to connectivity_status when applicable
UPDATE assets
SET connectivity_status = 'NOT_CONNECTED'
WHERE status = 'NOT_CONNECTED';

-- indexes for new columns
CREATE INDEX IF NOT EXISTS ix_assets_org_connectivity ON assets (organization_id, connectivity_status);
CREATE INDEX IF NOT EXISTS ix_assets_intent_gin ON assets USING GIN (intent);

-- asset_connections: AWS onboarding metadata (no secrets)
ALTER TABLE asset_connections
    ADD COLUMN IF NOT EXISTS provider TEXT NULL,
    ADD COLUMN IF NOT EXISTS provider_account_id TEXT NULL,
    ADD COLUMN IF NOT EXISTS external_id TEXT NULL,
    ADD COLUMN IF NOT EXISTS role_arn TEXT NULL,
    ADD COLUMN IF NOT EXISTS permission_preset VARCHAR(30) NOT NULL DEFAULT 'SECURITY_READONLY',
    ADD COLUMN IF NOT EXISTS connection_state VARCHAR(30) NOT NULL DEFAULT 'DRAFT',
    ADD COLUMN IF NOT EXISTS last_error_code TEXT NULL,
    ADD COLUMN IF NOT EXISTS last_error_detail TEXT NULL,
    ADD COLUMN IF NOT EXISTS validated_at TIMESTAMP WITH TIME ZONE NULL;

CREATE INDEX IF NOT EXISTS ix_asset_connections_provider_account ON asset_connections (provider, provider_account_id);
CREATE INDEX IF NOT EXISTS ix_asset_connections_connection_state ON asset_connections (connection_state);

-- Optional history columns to capture connectivity snapshots
ALTER TABLE asset_status_history
    ADD COLUMN IF NOT EXISTS connectivity_status VARCHAR(50),
    ADD COLUMN IF NOT EXISTS connection_state VARCHAR(50);
