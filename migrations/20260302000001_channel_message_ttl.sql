-- Per-channel default disappearing message timer (in seconds).
-- NULL = disabled (messages persist indefinitely, the default).
-- When set, new messages without an explicit expires_at get:
--   expires_at = NOW() + (message_ttl * INTERVAL '1 second')
ALTER TABLE channels ADD COLUMN message_ttl INTEGER DEFAULT NULL
    CHECK (message_ttl IS NULL OR message_ttl > 0);
