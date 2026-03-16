-- Add label column to group_exporter_secrets to distinguish MIP-03 and MIP-04 exporters.
--
-- MIP-03 (kind:445 message encryption): label = 'group-event'
--   Derived via MLS-Exporter("marmot", "group-event", 32)
--
-- MIP-04 (encrypted media): label = 'encrypted-media'
--   Derived via MLS-Exporter("marmot", "encrypted-media", 32)
--
-- IMPORTANT: SQLite cannot change an existing PRIMARY KEY with ALTER TABLE ADD COLUMN.
-- We must rebuild the table so both labels can coexist for the same (mls_group_id, epoch).

CREATE TABLE group_exporter_secrets_new (
    mls_group_id BLOB NOT NULL,
    epoch INTEGER NOT NULL,
    label TEXT NOT NULL,
    secret BLOB NOT NULL,
    PRIMARY KEY (mls_group_id, epoch, label),
    FOREIGN KEY (mls_group_id) REFERENCES groups(mls_group_id) ON DELETE CASCADE
);

-- Existing rows from before this migration are MIP-03 group-event exporter secrets.
INSERT INTO group_exporter_secrets_new (mls_group_id, epoch, label, secret)
SELECT mls_group_id, epoch, 'group-event', secret
FROM group_exporter_secrets;

DROP TABLE group_exporter_secrets;
ALTER TABLE group_exporter_secrets_new RENAME TO group_exporter_secrets;

CREATE INDEX IF NOT EXISTS idx_group_exporter_secrets_mls_group_id
ON group_exporter_secrets(mls_group_id);
