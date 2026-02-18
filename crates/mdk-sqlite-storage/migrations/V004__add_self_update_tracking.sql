-- Add self-update tracking to groups table.
-- NULL = no self-update obligation (e.g., group creator before first rotation)
-- 0    = self-update required (post-join obligation per MIP-02)
-- >0   = unix timestamp of last successful self-update (periodic rotation per MIP-00)

ALTER TABLE groups ADD COLUMN last_self_update_at INTEGER;
