-- Composite indexes for common query patterns identified in performance audit.

-- Used by get_member_permissions, get_member_roles — permission checks are per-request
CREATE INDEX IF NOT EXISTS idx_member_roles_user ON member_roles(user_id);

-- Used by find_dm_channel — DM lookup needs both user_id and channel_id
CREATE INDEX IF NOT EXISTS idx_channel_members_user_channel ON channel_members(user_id, channel_id);

-- Used by friendship lookups — bidirectional queries (requester OR addressee)
CREATE INDEX IF NOT EXISTS idx_friendships_pair ON friendships(requester_id, addressee_id);
CREATE INDEX IF NOT EXISTS idx_friendships_pair_reverse ON friendships(addressee_id, requester_id);

-- Used by get_pending_friend_requests — filter by status + addressee
CREATE INDEX IF NOT EXISTS idx_friendships_addressee_status ON friendships(addressee_id, status);

-- Used by message edit/delete authorization — verify sender owns the message
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id) WHERE sender_id IS NOT NULL;
