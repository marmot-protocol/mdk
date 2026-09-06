-- Extracted from fe133b82f0c2ed29c18861013d56d6dfb3a5e9f1
-- crates/storage-sqlite/src/shared.rs, from_connection.
CREATE TABLE IF NOT EXISTS directory_users (
    account_id_hex TEXT PRIMARY KEY NOT NULL,
    npub TEXT NOT NULL,
    profile_json TEXT,
    relay_lists_json TEXT NOT NULL,
    key_package_json TEXT,
    event_id_hex TEXT,
    event_kind INTEGER,
    event_created_at INTEGER
);
CREATE TABLE IF NOT EXISTS directory_user_follows (
    account_id_hex TEXT NOT NULL REFERENCES directory_users(account_id_hex) ON DELETE CASCADE,
    follow_account_id_hex TEXT NOT NULL,
    position INTEGER NOT NULL,
    event_id_hex TEXT,
    event_created_at INTEGER,
    PRIMARY KEY (account_id_hex, follow_account_id_hex)
);
	CREATE TABLE IF NOT EXISTS relay_telemetry_settings (
	    id INTEGER PRIMARY KEY CHECK (id = 1),
	    export_enabled INTEGER NOT NULL DEFAULT 0,
	    export_interval_seconds INTEGER NOT NULL DEFAULT 60,
	    updated_at_ms INTEGER NOT NULL
	);
		CREATE TABLE IF NOT EXISTS audit_log_settings (
		    id INTEGER PRIMARY KEY CHECK (id = 1),
		    enabled INTEGER NOT NULL DEFAULT 0,
		    updated_at_ms INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS telemetry_install (
		    id INTEGER PRIMARY KEY CHECK (id = 1),
		    install_id TEXT NOT NULL,
		    updated_at_ms INTEGER NOT NULL
		);
