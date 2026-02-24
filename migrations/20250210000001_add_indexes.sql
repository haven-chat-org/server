-- Additional indexes for scalability

-- Used by find_dm_channel and get_user_dm_channels queries
CREATE INDEX IF NOT EXISTS idx_channels_type ON channels(channel_type);

-- Used by refresh token cleanup worker
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at)
    WHERE expires_at IS NOT NULL;

-- Used for owner lookup on servers
CREATE INDEX IF NOT EXISTS idx_servers_owner ON servers(owner_id);
