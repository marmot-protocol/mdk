-- Add processed_at column to messages table
-- This timestamp records when this client processed/received the message,
-- which is useful for consistent message ordering across devices with clock skew.
-- For existing rows, we default to created_at as the best available approximation.
ALTER TABLE messages ADD COLUMN processed_at INTEGER;
UPDATE messages SET processed_at = created_at WHERE processed_at IS NULL;

-- Create a composite index for the new sort order (created_at DESC, processed_at DESC, id DESC)
-- This ensures stable ordering: by sender's timestamp, then by reception time, then by id for determinism
CREATE INDEX IF NOT EXISTS idx_messages_sorting ON messages(mls_group_id, created_at DESC, processed_at DESC, id DESC);
