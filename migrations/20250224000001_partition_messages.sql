-- Message table partitioning: convert to PARTITION BY RANGE(timestamp)
-- Monthly partitions for efficient queries and maintenance at scale.

-- Step 1: Drop FK constraints referencing messages(id)
-- PostgreSQL < 17 doesn't support FKs referencing partitioned tables.
-- Application-level referential integrity is enforced via query logic.
ALTER TABLE attachments DROP CONSTRAINT IF EXISTS attachments_message_id_fkey;
ALTER TABLE reactions DROP CONSTRAINT IF EXISTS reactions_message_id_fkey;
ALTER TABLE pinned_messages DROP CONSTRAINT IF EXISTS pinned_messages_message_id_fkey;
ALTER TABLE reports DROP CONSTRAINT IF EXISTS reports_message_id_fkey;
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_reply_to_id_fkey;

-- Step 2: Drop indexes on old table (will be recreated on partitioned table)
DROP INDEX IF EXISTS idx_messages_channel_time;
DROP INDEX IF EXISTS idx_messages_expires;
DROP INDEX IF EXISTS idx_messages_sender;

-- Step 3: Rename old table
ALTER TABLE messages RENAME TO messages_old;

-- Step 4: Create partitioned table with same schema
-- PK must include partition key (timestamp)
CREATE TABLE messages (
    id              UUID NOT NULL,
    channel_id      UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    sender_token    BYTEA NOT NULL,
    encrypted_body  BYTEA NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    has_attachments BOOLEAN NOT NULL DEFAULT FALSE,
    sender_id       UUID REFERENCES users(id),
    edited_at       TIMESTAMPTZ,
    reply_to_id     UUID,
    message_type    VARCHAR(20) NOT NULL DEFAULT 'user',
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Step 5: Create default partition (catches rows outside defined ranges)
CREATE TABLE messages_default PARTITION OF messages DEFAULT;

-- Step 6: Create monthly partitions (2025-01 through 2026-12)
CREATE TABLE messages_y2025m01 PARTITION OF messages FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE messages_y2025m02 PARTITION OF messages FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
CREATE TABLE messages_y2025m03 PARTITION OF messages FOR VALUES FROM ('2025-03-01') TO ('2025-04-01');
CREATE TABLE messages_y2025m04 PARTITION OF messages FOR VALUES FROM ('2025-04-01') TO ('2025-05-01');
CREATE TABLE messages_y2025m05 PARTITION OF messages FOR VALUES FROM ('2025-05-01') TO ('2025-06-01');
CREATE TABLE messages_y2025m06 PARTITION OF messages FOR VALUES FROM ('2025-06-01') TO ('2025-07-01');
CREATE TABLE messages_y2025m07 PARTITION OF messages FOR VALUES FROM ('2025-07-01') TO ('2025-08-01');
CREATE TABLE messages_y2025m08 PARTITION OF messages FOR VALUES FROM ('2025-08-01') TO ('2025-09-01');
CREATE TABLE messages_y2025m09 PARTITION OF messages FOR VALUES FROM ('2025-09-01') TO ('2025-10-01');
CREATE TABLE messages_y2025m10 PARTITION OF messages FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');
CREATE TABLE messages_y2025m11 PARTITION OF messages FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');
CREATE TABLE messages_y2025m12 PARTITION OF messages FOR VALUES FROM ('2025-12-01') TO ('2026-01-01');
CREATE TABLE messages_y2026m01 PARTITION OF messages FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE messages_y2026m02 PARTITION OF messages FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE messages_y2026m03 PARTITION OF messages FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE messages_y2026m04 PARTITION OF messages FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE messages_y2026m05 PARTITION OF messages FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE messages_y2026m06 PARTITION OF messages FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
CREATE TABLE messages_y2026m07 PARTITION OF messages FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE messages_y2026m08 PARTITION OF messages FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE messages_y2026m09 PARTITION OF messages FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE messages_y2026m10 PARTITION OF messages FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE messages_y2026m11 PARTITION OF messages FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE messages_y2026m12 PARTITION OF messages FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');

-- Step 7: Copy data from old table
INSERT INTO messages SELECT * FROM messages_old;

-- Step 8: Recreate indexes on the partitioned table
CREATE INDEX idx_messages_channel_time ON messages(channel_id, timestamp DESC);
CREATE INDEX idx_messages_expires ON messages(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_messages_sender ON messages(sender_id) WHERE sender_id IS NOT NULL;

-- Step 9: Drop old table
DROP TABLE messages_old;
