-- Add provider_resource_id to asset_connections for provider-specific identifiers

ALTER TABLE asset_connections
    ADD COLUMN IF NOT EXISTS provider_resource_id TEXT NULL;

