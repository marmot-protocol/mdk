-- Add label column to group_exporter_secrets to distinguish MIP-03 and MIP-04 exporters.
--
-- MIP-03 (kind:445 message encryption): label = 'group-event'
--   Derived via MLS-Exporter("marmot", "group-event", 32)
--
-- MIP-04 (encrypted media): label = 'encrypted-media'
--   Derived via MLS-Exporter("marmot", "encrypted-media", 32)
--
-- Existing rows from before this migration are the MIP-03 group-event exporter.
ALTER TABLE group_exporter_secrets ADD COLUMN label TEXT NOT NULL DEFAULT 'group-event';
