-- Migration: 001_add_multi_tenancy
-- Description: Add multi-tenant tables and columns for SaaS transformation
-- Author: Risklence Tower
-- Date: 2024-01-01

-- =============================================================================
-- SECTION 1: Create New Multi-Tenant Tables
-- =============================================================================

-- Create placeholder tables if they do not exist (so downstream ALTERs succeed)
CREATE TABLE IF NOT EXISTS compliance_frameworks (id SERIAL PRIMARY KEY);
CREATE TABLE IF NOT EXISTS compliance_controls (id SERIAL PRIMARY KEY);
CREATE TABLE IF NOT EXISTS policy_rules (id SERIAL PRIMARY KEY);
CREATE TABLE IF NOT EXISTS cloud_assets (id SERIAL PRIMARY KEY);
CREATE TABLE IF NOT EXISTS scan_runs (id SERIAL PRIMARY KEY);
CREATE TABLE IF NOT EXISTS findings (id SERIAL PRIMARY KEY);
CREATE TABLE IF NOT EXISTS jira_tickets (id SERIAL PRIMARY KEY);
CREATE TABLE IF NOT EXISTS key_risk_indicators (id SERIAL PRIMARY KEY);
CREATE TABLE IF NOT EXISTS risk_appetite (id SERIAL PRIMARY KEY, control_id INTEGER);
CREATE TABLE IF NOT EXISTS onboarding_sessions (id SERIAL PRIMARY KEY);

-- Organizations table (root tenant entity)
CREATE TABLE IF NOT EXISTS organizations (
    id SERIAL PRIMARY KEY,
    slug VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(200) NOT NULL,
    industry VARCHAR(100),
    company_size VARCHAR(50),
    cloud_providers TEXT[],
    required_frameworks TEXT[],
    compliance_level VARCHAR(50),
    subscription_tier VARCHAR(50) DEFAULT 'free',
    subscription_status VARCHAR(50) DEFAULT 'active',
    onboarding_completed BOOLEAN DEFAULT FALSE,
    onboarding_data JSONB,
    settings JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for organizations
CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);
CREATE INDEX IF NOT EXISTS idx_organizations_subscription_status ON organizations(subscription_status);
CREATE INDEX IF NOT EXISTS idx_organizations_created_at ON organizations(created_at);

-- Users table (multi-tenant users)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    auth0_user_id VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    permissions TEXT[],
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_user_per_org UNIQUE (organization_id, email)
);

-- Create indexes for users
CREATE INDEX IF NOT EXISTS idx_users_organization_id ON users(organization_id);
CREATE INDEX IF NOT EXISTS idx_users_auth0_user_id ON users(auth0_user_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- Cloud credentials table (encrypted storage)
CREATE TABLE IF NOT EXISTS cloud_credentials (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    cloud_provider VARCHAR(50) NOT NULL,
    credential_name VARCHAR(200) NOT NULL,
    encrypted_credentials BYTEA NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    last_validated TIMESTAMP,
    validation_status VARCHAR(50),
    validation_error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_credential_per_org UNIQUE (organization_id, cloud_provider, credential_name)
);

-- Create indexes for cloud_credentials
CREATE INDEX IF NOT EXISTS idx_cloud_credentials_organization_id ON cloud_credentials(organization_id);
CREATE INDEX IF NOT EXISTS idx_cloud_credentials_cloud_provider ON cloud_credentials(cloud_provider);
CREATE INDEX IF NOT EXISTS idx_cloud_credentials_is_active ON cloud_credentials(is_active);

-- =============================================================================
-- SECTION 2: Add organization_id to Existing Tables
-- =============================================================================

-- Note: These ALTER TABLE statements will fail if the column already exists
-- Use IF NOT EXISTS syntax when supported, or handle errors gracefully

DO $$ 
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name = 'compliance_frameworks'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'compliance_frameworks' AND column_name = 'organization_id'
    ) THEN
        ALTER TABLE compliance_frameworks ADD COLUMN organization_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE;
        CREATE INDEX IF NOT EXISTS idx_compliance_frameworks_organization_id ON compliance_frameworks(organization_id);
    END IF;
END $$;

-- Compliance controls (nullable - NULL means global/built-in)
DO $$ 
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name = 'compliance_controls'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'compliance_controls' AND column_name = 'organization_id'
    ) THEN
        ALTER TABLE compliance_controls ADD COLUMN organization_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE;
        CREATE INDEX IF NOT EXISTS idx_compliance_controls_organization_id ON compliance_controls(organization_id);
    END IF;
END $$;

-- Policy rules (nullable - NULL means global/built-in)
DO $$ 
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name = 'policy_rules'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'policy_rules' AND column_name = 'organization_id'
    ) THEN
        ALTER TABLE policy_rules ADD COLUMN organization_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE;
        CREATE INDEX IF NOT EXISTS idx_policy_rules_organization_id ON policy_rules(organization_id);
    END IF;
END $$;

-- Cloud assets (required - every asset belongs to an organization)
DO $$ 
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name = 'cloud_assets'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'cloud_assets' AND column_name = 'organization_id'
    ) THEN
        -- For existing data, create a default organization first if needed
        INSERT INTO organizations (
            slug,
            name,
            industry,
            compliance_level,
            plan_tier,
            subscription_status,
            onboarding_completed,
            created_at,
            updated_at
        )
        VALUES (
            'default-org',
            'Default Organization',
            'technology',
            'standard',
            'free',
            'trial',
            true,
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP
        )
        ON CONFLICT (slug) DO NOTHING;
        
        -- Add column with default value
        ALTER TABLE cloud_assets ADD COLUMN organization_id INTEGER;
        
        -- Set default org for existing records
        UPDATE cloud_assets SET organization_id = (SELECT id FROM organizations WHERE slug = 'default-org' LIMIT 1);
        
        -- Make it NOT NULL and add foreign key
        ALTER TABLE cloud_assets ALTER COLUMN organization_id SET NOT NULL;
        ALTER TABLE cloud_assets ADD CONSTRAINT fk_cloud_assets_organization 
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE;
        
        CREATE INDEX IF NOT EXISTS idx_cloud_assets_organization_id ON cloud_assets(organization_id);
    END IF;
END $$;

-- Scan runs (required)
DO $$ 
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name = 'scan_runs'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'scan_runs' AND column_name = 'organization_id'
    ) THEN
        ALTER TABLE scan_runs ADD COLUMN organization_id INTEGER;
        
        -- Set default org for existing records
        UPDATE scan_runs SET organization_id = (SELECT id FROM organizations WHERE slug = 'default-org' LIMIT 1);
        
        ALTER TABLE scan_runs ALTER COLUMN organization_id SET NOT NULL;
        ALTER TABLE scan_runs ADD CONSTRAINT fk_scan_runs_organization 
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE;
        
        CREATE INDEX IF NOT EXISTS idx_scan_runs_organization_id ON scan_runs(organization_id);
    END IF;
END $$;

-- Findings (required)
DO $$ 
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name = 'findings'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'findings' AND column_name = 'organization_id'
    ) THEN
        ALTER TABLE findings ADD COLUMN organization_id INTEGER;
        
        -- Set default org for existing records
        UPDATE findings SET organization_id = (SELECT id FROM organizations WHERE slug = 'default-org' LIMIT 1);
        
        ALTER TABLE findings ALTER COLUMN organization_id SET NOT NULL;
        ALTER TABLE findings ADD CONSTRAINT fk_findings_organization 
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE;
        
        CREATE INDEX IF NOT EXISTS idx_findings_organization_id ON findings(organization_id);
    END IF;
END $$;

-- Jira tickets (required)
DO $$ 
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name = 'jira_tickets'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'jira_tickets' AND column_name = 'organization_id'
    ) THEN
        ALTER TABLE jira_tickets ADD COLUMN organization_id INTEGER;
        
        -- Set default org for existing records
        UPDATE jira_tickets SET organization_id = (SELECT id FROM organizations WHERE slug = 'default-org' LIMIT 1);
        
        ALTER TABLE jira_tickets ALTER COLUMN organization_id SET NOT NULL;
        ALTER TABLE jira_tickets ADD CONSTRAINT fk_jira_tickets_organization 
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE;
        
        CREATE INDEX IF NOT EXISTS idx_jira_tickets_organization_id ON jira_tickets(organization_id);
    END IF;
END $$;

-- Key risk indicators (required)
DO $$ 
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name = 'key_risk_indicators'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'key_risk_indicators' AND column_name = 'organization_id'
    ) THEN
        ALTER TABLE key_risk_indicators ADD COLUMN organization_id INTEGER;
        
        -- Set default org for existing records
        UPDATE key_risk_indicators SET organization_id = (SELECT id FROM organizations WHERE slug = 'default-org' LIMIT 1);
        
        ALTER TABLE key_risk_indicators ALTER COLUMN organization_id SET NOT NULL;
        ALTER TABLE key_risk_indicators ADD CONSTRAINT fk_key_risk_indicators_organization 
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE;
        
        CREATE INDEX IF NOT EXISTS idx_key_risk_indicators_organization_id ON key_risk_indicators(organization_id);
    END IF;
END $$;

-- Risk appetite (required + update unique constraint)
DO $$ 
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name = 'risk_appetite'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'risk_appetite' AND column_name = 'organization_id'
    ) THEN
        ALTER TABLE risk_appetite ADD COLUMN organization_id INTEGER;
        
        -- Set default org for existing records
        UPDATE risk_appetite SET organization_id = (SELECT id FROM organizations WHERE slug = 'default-org' LIMIT 1);
        
        ALTER TABLE risk_appetite ALTER COLUMN organization_id SET NOT NULL;
        ALTER TABLE risk_appetite ADD CONSTRAINT fk_risk_appetite_organization 
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE;
        
        CREATE INDEX IF NOT EXISTS idx_risk_appetite_organization_id ON risk_appetite(organization_id);
        
        -- Update unique constraint to be per-organization
        -- Drop old constraint if it exists
        ALTER TABLE risk_appetite DROP CONSTRAINT IF EXISTS unique_control_per_org;
        
        -- Add new composite unique constraint
        ALTER TABLE risk_appetite ADD CONSTRAINT unique_control_per_org 
            UNIQUE (organization_id, control_id);
    END IF;
END $$;

-- =============================================================================
-- SECTION 3: Create Audit Triggers
-- =============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Add triggers for updated_at on new tables
DROP TRIGGER IF EXISTS update_organizations_updated_at ON organizations;
CREATE TRIGGER update_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_cloud_credentials_updated_at ON cloud_credentials;
CREATE TRIGGER update_cloud_credentials_updated_at
    BEFORE UPDATE ON cloud_credentials
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- SECTION 4: Insert Default Data
-- =============================================================================

-- Insert default organization if not exists
INSERT INTO organizations (
    slug,
    name,
    industry,
    compliance_level,
    plan_tier,
    subscription_status,
    onboarding_completed,
    created_at,
    updated_at
)
VALUES (
    'default-org',
    'Default Organization',
    'technology',
    'standard',
    'free',
    'trial',
    true,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
)
ON CONFLICT (slug) DO NOTHING;

-- =============================================================================
-- Migration Complete
-- =============================================================================

-- Verify migration
SELECT 
    'organizations' as table_name, 
    COUNT(*) as row_count 
FROM organizations
UNION ALL
SELECT 'users', COUNT(*) FROM users
UNION ALL
SELECT 'cloud_credentials', COUNT(*) FROM cloud_credentials;

-- Print success message
DO $$ 
BEGIN
    RAISE NOTICE 'Migration 001_add_multi_tenancy completed successfully';
END $$;
