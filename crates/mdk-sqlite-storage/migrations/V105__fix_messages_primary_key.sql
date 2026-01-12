-- Fix messages table primary key to be group-scoped
-- This prevents messages from different groups from overwriting each other

-- Step 1: Drop the existing primary key constraint
-- SQLite doesn't support DROP CONSTRAINT directly, so we need to recreate the table
CREATE TABLE IF NOT EXISTS messages_new (
    id BLOB NOT NULL,  -- Event ID as byte array
    pubkey BLOB NOT NULL, -- Pubkey as byte array
    kind INTEGER NOT NULL,
    mls_group_id BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    content TEXT NOT NULL,
    tags JSONB NOT NULL,
    event JSONB NOT NULL,
    wrapper_event_id BLOB NOT NULL, -- Wrapper event ID as byte array
    state TEXT NOT NULL,
    PRIMARY KEY (mls_group_id, id),
    FOREIGN KEY (mls_group_id) REFERENCES groups(mls_group_id) ON DELETE CASCADE
);

-- Step 2: Clean up orphaned messages (those referencing nonexistent groups)
-- This prevents migration failure when PRAGMA foreign_keys=ON
DELETE FROM messages WHERE mls_group_id NOT IN (SELECT mls_group_id FROM groups);

-- Step 3: Copy data from old table to new table
INSERT INTO messages_new
SELECT id, pubkey, kind, mls_group_id, created_at, content, tags, event, wrapper_event_id, state
FROM messages;

-- Step 4: Drop old table
DROP TABLE messages;

-- Step 5: Rename new table to original name
ALTER TABLE messages_new RENAME TO messages;

-- Step 6: Recreate indexes (they were dropped with the old table)
CREATE INDEX IF NOT EXISTS idx_messages_mls_group_id ON messages(mls_group_id);
CREATE INDEX IF NOT EXISTS idx_messages_wrapper_event_id ON messages(wrapper_event_id);
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);
CREATE INDEX IF NOT EXISTS idx_messages_pubkey ON messages(pubkey);
CREATE INDEX IF NOT EXISTS idx_messages_kind ON messages(kind);
CREATE INDEX IF NOT EXISTS idx_messages_state ON messages(state);

