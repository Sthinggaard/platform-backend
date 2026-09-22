-- UC-18: Artefact versioning engine
CREATE TABLE IF NOT EXISTS artefact_versions (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    session_id INTEGER REFERENCES onboarding_sessions(id) ON DELETE SET NULL,
    artefact_type VARCHAR(100) NOT NULL,
    artefact_id VARCHAR(100),
    version_number INTEGER NOT NULL DEFAULT 1,
    prev_version_id INTEGER REFERENCES artefact_versions(id) ON DELETE SET NULL,
    patch JSON NOT NULL,
    patch_type VARCHAR(20) NOT NULL DEFAULT 'json_patch',
    snapshot JSON NOT NULL,
    confidence DOUBLE PRECISION,
    rationale TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_artefact_versions_org_type_id_version
    ON artefact_versions (organization_id, artefact_type, artefact_id, version_number);
