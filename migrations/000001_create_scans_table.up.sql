CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY,
    url TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    domain VARCHAR(255),
    protocol VARCHAR(20),
    safe BOOLEAN NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL,
    reasons JSONB NOT NULL DEFAULT '[]',
    cached BOOLEAN NOT NULL DEFAULT FALSE,
    scan_duration_ms BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON scans(risk_level);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
