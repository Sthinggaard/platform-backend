-- UC-01/02/03 asset monitoring + audit tables

CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id),
    type VARCHAR(50) NOT NULL,
    provider VARCHAR(50),
    display_name VARCHAR(200) NOT NULL,
    layer VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'NOT_CONNECTED',
    observation_level VARCHAR(50),
    last_observed_at TIMESTAMP WITH TIME ZONE,
    risk_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    findings_count INTEGER NOT NULL DEFAULT 0,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_assets_org_layer_status ON assets (organization_id, layer, status);

CREATE TABLE IF NOT EXISTS asset_connections (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER NOT NULL REFERENCES assets(id),
    auth_type VARCHAR(50),
    scopes JSONB,
    external_account_id VARCHAR(200),
    mock_token VARCHAR(200),
    connected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_sync_at TIMESTAMP WITH TIME ZONE,
    state VARCHAR(50) NOT NULL DEFAULT 'DISCONNECTED',
    error_code VARCHAR(50),
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_asset_connections_asset_state ON asset_connections (asset_id, state);

CREATE TABLE IF NOT EXISTS asset_status_history (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER NOT NULL REFERENCES assets(id),
    status VARCHAR(50) NOT NULL,
    risk_score DOUBLE PRECISION,
    observation_level VARCHAR(50),
    findings_count INTEGER,
    confidence DOUBLE PRECISION,
    observed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_status_history_asset_time ON asset_status_history (asset_id, observed_at);

CREATE TABLE IF NOT EXISTS asset_evidence_signals (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id),
    asset_id INTEGER NOT NULL REFERENCES assets(id),
    kind VARCHAR(100) NOT NULL,
    payload_json JSONB NOT NULL,
    observed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    confidence DOUBLE PRECISION,
    risk_score DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS ix_asset_signals_asset_time ON asset_evidence_signals (asset_id, observed_at);

CREATE TABLE IF NOT EXISTS asset_findings (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id),
    asset_id INTEGER NOT NULL REFERENCES assets(id),
    domain VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    evidence_refs JSONB,
    risk_score DOUBLE PRECISION,
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    status VARCHAR(50) NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS ix_asset_findings_asset_status ON asset_findings (asset_id, status);
CREATE INDEX IF NOT EXISTS ix_asset_findings_org_status ON asset_findings (organization_id, status);

CREATE TABLE IF NOT EXISTS controls (
    id SERIAL PRIMARY KEY,
    framework VARCHAR(100) NOT NULL,
    control_code VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_controls_framework_code ON controls (framework, control_code);

CREATE TABLE IF NOT EXISTS control_mappings (
    id SERIAL PRIMARY KEY,
    control_id INTEGER NOT NULL REFERENCES controls(id),
    asset_type VARCHAR(50) NOT NULL,
    signal_kind VARCHAR(100) NOT NULL,
    min_confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    evidence_rule VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS control_evidence (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id),
    control_id INTEGER NOT NULL REFERENCES controls(id),
    asset_id INTEGER NOT NULL REFERENCES assets(id),
    status VARCHAR(50) NOT NULL DEFAULT 'NOT_COVERED',
    confidence DOUBLE PRECISION,
    last_evaluated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    evidence_refs JSONB
);
CREATE INDEX IF NOT EXISTS ix_control_evidence_org_control ON control_evidence (organization_id, control_id);

CREATE TABLE IF NOT EXISTS control_share_links (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id),
    token VARCHAR(200) NOT NULL UNIQUE,
    scope JSONB,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_control_share_token ON control_share_links (token);
