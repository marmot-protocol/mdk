-- Extracted independently from 9db9dbc092d52eb7b2d5bc6dcfb1f9beb3125464 shared.rs tests:
-- clears_legacy_plaintext_relay_telemetry_endpoint and
-- audit_log_settings_data_mode_column_is_added_to_legacy_table.
-- This is compatibility-test evidence, not a verified deployed build.
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
                    updated_at_ms INTEGER NOT NULL
                 );
