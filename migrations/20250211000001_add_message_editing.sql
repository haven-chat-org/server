-- Add sender_id to messages for edit authorization
-- Nullable because existing messages don't have it (sealed sender)
ALTER TABLE messages ADD COLUMN sender_id UUID REFERENCES users(id);

-- Track when a message was last edited
ALTER TABLE messages ADD COLUMN edited_at TIMESTAMPTZ;

CREATE INDEX idx_messages_sender ON messages(sender_id) WHERE sender_id IS NOT NULL;
