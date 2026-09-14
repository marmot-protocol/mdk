CREATE TABLE usage_diagnostics_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    decision INTEGER NOT NULL CHECK (decision IN (0, 1, 2)),
    policy_revision TEXT NOT NULL,
    registry_revision TEXT NOT NULL,
    scope_revision TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    previously_enabled INTEGER NOT NULL CHECK (previously_enabled IN (0, 1))
);
INSERT INTO usage_diagnostics_settings
    SELECT 1, 0, '', '', '', 0, COALESCE((SELECT export_enabled FROM relay_telemetry_settings WHERE id = 1), 0);
