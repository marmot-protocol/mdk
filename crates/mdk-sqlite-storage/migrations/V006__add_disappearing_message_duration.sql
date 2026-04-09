-- Add disappearing message duration to groups table.
-- NULL means disabled (messages persist forever).
-- Non-null positive integer means messages expire after that many seconds.
ALTER TABLE groups ADD COLUMN disappearing_message_duration_secs INTEGER;
