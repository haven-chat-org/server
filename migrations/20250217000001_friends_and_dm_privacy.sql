-- Friends & DM Privacy
CREATE TABLE IF NOT EXISTS friendships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    requester_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    addressee_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(requester_id, addressee_id),
    CHECK(requester_id != addressee_id)
);

CREATE INDEX idx_friendships_requester ON friendships(requester_id);
CREATE INDEX idx_friendships_addressee ON friendships(addressee_id);
CREATE INDEX idx_friendships_status ON friendships(status);

-- DM privacy: who can message this user directly
ALTER TABLE users ADD COLUMN IF NOT EXISTS dm_privacy TEXT NOT NULL DEFAULT 'friends_only'
    CHECK (dm_privacy IN ('everyone', 'friends_only', 'server_members'));

-- DM channel status: active channels vs pending message requests
ALTER TABLE channels ADD COLUMN IF NOT EXISTS dm_status TEXT DEFAULT 'active'
    CHECK (dm_status IN ('active', 'pending', 'declined'));
