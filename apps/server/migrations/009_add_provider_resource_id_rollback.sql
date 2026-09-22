-- Rollback provider_resource_id column

ALTER TABLE asset_connections
    DROP COLUMN IF EXISTS provider_resource_id;

