-- ============================================================
-- PROJECT 2: WINDOWS DETECTION PLATFORM
-- UPGRADE 3: BEHAVIORAL BASELINE SCHEMA
-- ============================================================

-- ============================================================
-- 1. PROCESS BASELINE
-- ============================================================

CREATE TABLE IF NOT EXISTS baseline_processes (
    id BIGSERIAL PRIMARY KEY,

    computer_name TEXT NOT NULL,
    user_name TEXT,

    image TEXT NOT NULL,

    event_count INTEGER NOT NULL DEFAULT 0,

    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,

    frequency_per_hour NUMERIC(12,4),

    rarity_score NUMERIC(5,2),

    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (
        computer_name,
        user_name,
        image
    )
);


-- ============================================================
-- 2. PARENT-CHILD PROCESS BASELINE
-- ============================================================

CREATE TABLE IF NOT EXISTS baseline_parent_child (
    id BIGSERIAL PRIMARY KEY,

    computer_name TEXT NOT NULL,

    parent_image TEXT NOT NULL,
    child_image TEXT NOT NULL,

    event_count INTEGER NOT NULL DEFAULT 0,

    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,

    frequency_per_hour NUMERIC(12,4),

    rarity_score NUMERIC(5,2),

    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (
        computer_name,
        parent_image,
        child_image
    )
);


-- ============================================================
-- 3. USER/PROCESS BASELINE
-- ============================================================

CREATE TABLE IF NOT EXISTS baseline_user_processes (
    id BIGSERIAL PRIMARY KEY,

    computer_name TEXT NOT NULL,
    user_name TEXT NOT NULL,
    image TEXT NOT NULL,

    event_count INTEGER NOT NULL DEFAULT 0,

    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,

    frequency_per_hour NUMERIC(12,4),

    rarity_score NUMERIC(5,2),

    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (
        computer_name,
        user_name,
        image
    )
);


-- ============================================================
-- 4. NETWORK DESTINATION BASELINE
-- ============================================================

CREATE TABLE IF NOT EXISTS baseline_network_destinations (
    id BIGSERIAL PRIMARY KEY,

    computer_name TEXT NOT NULL,

    image TEXT,

    destination_ip INET NOT NULL,
    destination_port INTEGER,
    protocol TEXT,

    event_count INTEGER NOT NULL DEFAULT 0,

    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,

    frequency_per_hour NUMERIC(12,4),

    rarity_score NUMERIC(5,2),

    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (
        computer_name,
        image,
        destination_ip,
        destination_port,
        protocol
    )
);


-- ============================================================
-- 5. DNS BASELINE
-- ============================================================

CREATE TABLE IF NOT EXISTS baseline_dns_queries (
    id BIGSERIAL PRIMARY KEY,

    computer_name TEXT NOT NULL,

    image TEXT,

    dns_query TEXT NOT NULL,

    event_count INTEGER NOT NULL DEFAULT 0,

    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,

    frequency_per_hour NUMERIC(12,4),

    rarity_score NUMERIC(5,2),

    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (
        computer_name,
        image,
        dns_query
    )
);


-- ============================================================
-- INDEXES
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_baseline_process_image
ON baseline_processes(image);

CREATE INDEX IF NOT EXISTS idx_baseline_process_user
ON baseline_processes(user_name);

CREATE INDEX IF NOT EXISTS idx_baseline_parent
ON baseline_parent_child(parent_image);

CREATE INDEX IF NOT EXISTS idx_baseline_child
ON baseline_parent_child(child_image);

CREATE INDEX IF NOT EXISTS idx_baseline_network_ip
ON baseline_network_destinations(destination_ip);

CREATE INDEX IF NOT EXISTS idx_baseline_network_image
ON baseline_network_destinations(image);

CREATE INDEX IF NOT EXISTS idx_baseline_dns_query
ON baseline_dns_queries(dns_query);

CREATE INDEX IF NOT EXISTS idx_baseline_dns_image
ON baseline_dns_queries(image);
