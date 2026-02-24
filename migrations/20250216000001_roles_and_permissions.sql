-- Roles & Permissions
CREATE TABLE IF NOT EXISTS roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id   UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    color       TEXT,           -- hex color e.g. "#ff0000"
    permissions BIGINT NOT NULL DEFAULT 0,
    position    INT NOT NULL DEFAULT 0,
    is_default  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_roles_server ON roles(server_id);

-- Many-to-many: which members have which roles
CREATE TABLE IF NOT EXISTS member_roles (
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id   UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (server_id, user_id, role_id)
);

-- Per-channel permission overwrites (role or member level)
CREATE TABLE IF NOT EXISTS channel_permission_overwrites (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id  UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    target_type TEXT NOT NULL CHECK (target_type IN ('role', 'member')),
    target_id   UUID NOT NULL,
    allow_bits  BIGINT NOT NULL DEFAULT 0,
    deny_bits   BIGINT NOT NULL DEFAULT 0,
    UNIQUE (channel_id, target_type, target_id)
);
CREATE INDEX IF NOT EXISTS idx_channel_overwrites_channel ON channel_permission_overwrites(channel_id);
