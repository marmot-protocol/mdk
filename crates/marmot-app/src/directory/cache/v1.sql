CREATE TABLE IF NOT EXISTS directory_users (
    account_id_hex TEXT PRIMARY KEY NOT NULL,
    npub TEXT NOT NULL,
    local_account_json TEXT,
    profile_json TEXT,
    relay_lists_json TEXT NOT NULL,
    key_package_json TEXT,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS directory_user_follows (
    account_id_hex TEXT NOT NULL,
    follow_account_id_hex TEXT NOT NULL,
    position INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (account_id_hex, follow_account_id_hex)
);
CREATE INDEX IF NOT EXISTS directory_user_follows_follow_idx
    ON directory_user_follows(follow_account_id_hex);
CREATE TABLE IF NOT EXISTS directory_follow_source_relays (
    account_id_hex TEXT NOT NULL,
    relay_url TEXT NOT NULL,
    position INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (account_id_hex, relay_url)
);
CREATE TABLE IF NOT EXISTS directory_known_user_reasons (
    account_id_hex TEXT NOT NULL,
    reason TEXT NOT NULL,
    first_seen_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    PRIMARY KEY (account_id_hex, reason)
);
CREATE TABLE IF NOT EXISTS directory_search_graph_users (
    account_id_hex TEXT PRIMARY KEY NOT NULL,
    npub TEXT NOT NULL,
    profile_json TEXT,
    metadata_updated_at INTEGER,
    metadata_expires_at INTEGER,
    follows_known INTEGER NOT NULL DEFAULT 0,
    follows_updated_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS directory_search_graph_follows (
    account_id_hex TEXT NOT NULL,
    follow_account_id_hex TEXT NOT NULL,
    position INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (account_id_hex, follow_account_id_hex)
);
CREATE INDEX IF NOT EXISTS directory_search_graph_follows_follow_idx
    ON directory_search_graph_follows(follow_account_id_hex);
