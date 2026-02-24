-- Server bans
CREATE TABLE IF NOT EXISTS bans (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id   UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason      TEXT,
    banned_by   UUID NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(server_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_bans_server ON bans(server_id);
CREATE INDEX IF NOT EXISTS idx_bans_user ON bans(user_id);
