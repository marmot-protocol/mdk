-- Add self-update tracking fields to groups table (MIP-02 post-join self-update).
-- needs_self_update: set after accept_welcome(), cleared after merge_pending_commit()
-- last_self_update_at: timestamp of last successful self-update merge

ALTER TABLE groups ADD COLUMN needs_self_update INTEGER NOT NULL DEFAULT 0;
ALTER TABLE groups ADD COLUMN last_self_update_at INTEGER;
