-- Migration Rollback: 001_add_multi_tenancy
-- Description: Rollback multi-tenant changes
-- WARNING: This will DROP multi-tenant tables and columns. Data will be lost.
-- Author: Risklence Tower
-- Date: 2024-01-01

-- =============================================================================
-- SECTION 1: Remove organization_id from Existing Tables
-- =============================================================================

-- Remove from risk_appetite
DO $$ 
BEGIN
    -- Drop composite unique constraint
    ALTER TABLE risk_appetite DROP CONSTRAINT IF EXISTS unique_control_per_org;
    
    -- Drop foreign key
    ALTER TABLE risk_appetite DROP CONSTRAINT IF EXISTS fk_risk_appetite_organization;
    
    -- Drop column
    ALTER TABLE risk_appetite DROP COLUMN IF EXISTS organization_id;
    
    RAISE NOTICE 'Removed organization_id from risk_appetite';
END $$;

-- Remove from key_risk_indicators
DO $$ 
BEGIN
    ALTER TABLE key_risk_indicators DROP CONSTRAINT IF EXISTS fk_key_risk_indicators_organization;
    ALTER TABLE key_risk_indicators DROP COLUMN IF EXISTS organization_id;
    RAISE NOTICE 'Removed organization_id from key_risk_indicators';
END $$;

-- Remove from jira_tickets
DO $$ 
BEGIN
    ALTER TABLE jira_tickets DROP CONSTRAINT IF EXISTS fk_jira_tickets_organization;
    ALTER TABLE jira_tickets DROP COLUMN IF EXISTS organization_id;
    RAISE NOTICE 'Removed organization_id from jira_tickets';
END $$;

-- Remove from findings
DO $$ 
BEGIN
    ALTER TABLE findings DROP CONSTRAINT IF EXISTS fk_findings_organization;
    ALTER TABLE findings DROP COLUMN IF EXISTS organization_id;
    RAISE NOTICE 'Removed organization_id from findings';
END $$;

-- Remove from scan_runs
DO $$ 
BEGIN
    ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS fk_scan_runs_organization;
    ALTER TABLE scan_runs DROP COLUMN IF EXISTS organization_id;
    RAISE NOTICE 'Removed organization_id from scan_runs';
END $$;

-- Remove from cloud_assets
DO $$ 
BEGIN
    ALTER TABLE cloud_assets DROP CONSTRAINT IF EXISTS fk_cloud_assets_organization;
    ALTER TABLE cloud_assets DROP COLUMN IF EXISTS organization_id;
    RAISE NOTICE 'Removed organization_id from cloud_assets';
END $$;

-- Remove from policy_rules
DO $$ 
BEGIN
    ALTER TABLE policy_rules DROP COLUMN IF EXISTS organization_id;
    RAISE NOTICE 'Removed organization_id from policy_rules';
END $$;

-- Remove from compliance_controls
DO $$ 
BEGIN
    ALTER TABLE compliance_controls DROP COLUMN IF EXISTS organization_id;
    RAISE NOTICE 'Removed organization_id from compliance_controls';
END $$;

-- Remove from compliance_frameworks
DO $$ 
BEGIN
    ALTER TABLE compliance_frameworks DROP COLUMN IF EXISTS organization_id;
    RAISE NOTICE 'Removed organization_id from compliance_frameworks';
END $$;

-- =============================================================================
-- SECTION 2: Drop New Multi-Tenant Tables
-- =============================================================================

-- Drop triggers first
DROP TRIGGER IF EXISTS update_cloud_credentials_updated_at ON cloud_credentials;
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_organizations_updated_at ON organizations;

-- Drop tables (CASCADE will drop dependent foreign keys)
DROP TABLE IF EXISTS cloud_credentials CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS organizations CASCADE;

-- =============================================================================
-- SECTION 3: Drop Helper Functions
-- =============================================================================

-- We keep update_updated_at_column() function as it might be used by other tables

-- =============================================================================
-- Rollback Complete
-- =============================================================================

DO $$ 
BEGIN
    RAISE NOTICE 'Migration 001_add_multi_tenancy rollback completed successfully';
    RAISE WARNING 'All multi-tenant data has been removed';
END $$;
