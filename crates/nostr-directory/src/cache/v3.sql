-- Selected-account availability for direct follows. The containing cache is
-- the account scope; no local account id or shared-tier copy is needed.
CREATE TABLE follow_availability (
    follow_account_id_hex TEXT PRIMARY KEY NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('ready', 'unknown', 'not_found')),
    checked_at INTEGER,
    fresh_until INTEGER,
    key_package_event_id TEXT,
    key_package_id TEXT,
    superseded_event_id TEXT,
    superseded_at INTEGER,
    superseded_last_resort INTEGER,
    source INTEGER NOT NULL CHECK (source IN (0, 1)),
    updated_at INTEGER NOT NULL,
    CHECK (
        (state = 'ready' AND key_package_event_id IS NOT NULL AND fresh_until IS NOT NULL)
        OR state != 'ready'
    )
);
