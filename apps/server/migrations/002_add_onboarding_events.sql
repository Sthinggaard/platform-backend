-- UC-18: Append-only onboarding events
CREATE TABLE IF NOT EXISTS onboarding_events (
    id SERIAL PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES onboarding_sessions(id) ON DELETE CASCADE,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor VARCHAR(50) NOT NULL,
    type VARCHAR(100) NOT NULL,
    payload JSON NOT NULL,
    artefact_ref VARCHAR(200),
    confidence DOUBLE PRECISION,
    rationale TEXT,
    source VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_onboarding_events_session_created
    ON onboarding_events (session_id, created_at);
