CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'analyst'
        CHECK (role IN ('admin', 'analyst', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS url_scans (
    id BIGSERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    domain TEXT,
    threat_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    is_malicious BOOLEAN NOT NULL DEFAULT FALSE,
    scan_source VARCHAR(50) NOT NULL DEFAULT 'user',
    features JSONB NOT NULL DEFAULT '{}'::jsonb,
    whois_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    ssl_info JSONB NOT NULL DEFAULT '{}'::jsonb,
    scanned_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_url_scans_user_created
ON url_scans(scanned_by, created_at DESC);

CREATE TABLE IF NOT EXISTS email_analyses (
    id BIGSERIAL PRIMARY KEY,
    raw_headers TEXT NOT NULL,
    sender_ip TEXT,
    from_domain TEXT,
    spf_result TEXT,
    dkim_result TEXT,
    dmarc_result TEXT,
    is_spoofed BOOLEAN NOT NULL DEFAULT FALSE,
    analyzed_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS community_reports (
    id BIGSERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    reported_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    reason TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'verified', 'dismissed')),
    upvotes INTEGER NOT NULL DEFAULT 0,
    downvotes INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS threat_entries (
    id BIGSERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'unknown',
    threat_type TEXT,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE(url, source)
);

CREATE INDEX IF NOT EXISTS idx_threat_entries_last_seen
ON threat_entries(last_seen DESC);
