-- Host-configured local audit-log retention. No row means the defaults.
CREATE TABLE audit_log_retention_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    max_age_days INTEGER NOT NULL CHECK (typeof(max_age_days) = 'integer' AND max_age_days > 0),
    max_bytes_per_account INTEGER NOT NULL CHECK (typeof(max_bytes_per_account) = 'integer' AND max_bytes_per_account > 0),
    updated_at_ms INTEGER NOT NULL
);
