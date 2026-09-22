-- UC-18: Evidence signals feeding artefacts (assets are signals, not artefacts)
CREATE TABLE IF NOT EXISTS evidence_signals (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    session_id INTEGER REFERENCES onboarding_sessions(id) ON DELETE SET NULL,
    asset_type VARCHAR(100) NOT NULL,
    provider VARCHAR(100),
    identifier VARCHAR(200) NOT NULL,
    artefact_ref VARCHAR(200),
    signal JSON NOT NULL,
    confidence DOUBLE PRECISION,
    source VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_org_session_created
    ON evidence_signals (organization_id, session_id, created_at);
