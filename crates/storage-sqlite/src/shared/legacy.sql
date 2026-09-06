-- Recognized compatibility columns, evidenced by shared.rs at 9db9dbc092d52eb7b2d5bc6dcfb1f9beb3125464:
-- clears_legacy_plaintext_relay_telemetry_endpoint and from_connection respectively.
CREATE TABLE relay_telemetry_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    export_enabled INTEGER NOT NULL DEFAULT 0,
    otlp_endpoint TEXT,
    export_interval_seconds INTEGER NOT NULL DEFAULT 60,
    updated_at_ms INTEGER NOT NULL
);
CREATE TABLE audit_log_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    data_mode TEXT NOT NULL DEFAULT 'obfuscated_sensitive_data',
    updated_at_ms INTEGER NOT NULL
);
