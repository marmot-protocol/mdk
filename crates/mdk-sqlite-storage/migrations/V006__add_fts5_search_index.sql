-- FTS5 full-text search index for message content.
-- Uses external-content mode so the index stays in sync with the messages table
-- via triggers, without duplicating the content column.

CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    content,
    content='messages',
    content_rowid='rowid'
);

-- Keep FTS index in sync on INSERT.
CREATE TRIGGER messages_fts_insert AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, content) VALUES (new.rowid, new.content);
END;

-- Keep FTS index in sync on DELETE.
CREATE TRIGGER messages_fts_delete AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, content) VALUES ('delete', old.rowid, old.content);
END;

-- Keep FTS index in sync on UPDATE.
CREATE TRIGGER messages_fts_update AFTER UPDATE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, content) VALUES ('delete', old.rowid, old.content);
    INSERT INTO messages_fts(rowid, content) VALUES (new.rowid, new.content);
END;

-- Backfill existing messages into the FTS index.
INSERT INTO messages_fts(rowid, content)
    SELECT rowid, content FROM messages;
