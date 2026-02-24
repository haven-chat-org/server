-- Haven Initial Schema
-- Privacy-first: minimal PII, encrypted blobs, ephemeral tokens

-- ─── Users ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY,
    username        TEXT UNIQUE NOT NULL,
    display_name    TEXT,
    email_hash      TEXT,                  -- Optional, bcrypt-hashed email for recovery
    password_hash   TEXT NOT NULL,          -- Argon2id
    identity_key    BYTEA NOT NULL,         -- X25519 public identity key
    signed_prekey   BYTEA NOT NULL,         -- Signed pre-key (public)
    signed_prekey_sig BYTEA NOT NULL,       -- Signature over the signed pre-key
    totp_secret     TEXT,                   -- TOTP secret for 2FA (encrypted at rest ideally)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_username ON users(username);

-- ─── One-Time Pre-Keys (X3DH) ─────────────────────────

CREATE TABLE IF NOT EXISTS prekeys (
    id              UUID PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_id          INT NOT NULL,
    public_key      BYTEA NOT NULL,
    used            BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_prekeys_user_unused ON prekeys(user_id, used) WHERE used = false;

-- ─── Refresh Tokens ────────────────────────────────────

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id              UUID PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      TEXT UNIQUE NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);

-- ─── Servers (Communities) ─────────────────────────────

CREATE TABLE IF NOT EXISTS servers (
    id              UUID PRIMARY KEY,
    encrypted_meta  BYTEA,                 -- Name, description, icon (encrypted with server key)
    owner_id        UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Server Members ────────────────────────────────────

CREATE TABLE IF NOT EXISTS server_members (
    id              UUID PRIMARY KEY,
    server_id       UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_role  BYTEA,                 -- Role encrypted with server key
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(server_id, user_id)
);

CREATE INDEX idx_server_members_server ON server_members(server_id);
CREATE INDEX idx_server_members_user ON server_members(user_id);

-- ─── Channels ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS channels (
    id              UUID PRIMARY KEY,
    server_id       UUID REFERENCES servers(id) ON DELETE CASCADE,  -- NULL for DM channels
    encrypted_meta  BYTEA,
    channel_type    TEXT NOT NULL DEFAULT 'text',  -- 'text', 'dm'
    position        INT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_channels_server ON channels(server_id);

-- ─── Channel Members ───────────────────────────────────

CREATE TABLE IF NOT EXISTS channel_members (
    id              UUID PRIMARY KEY,
    channel_id      UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(channel_id, user_id)
);

CREATE INDEX idx_channel_members_channel ON channel_members(channel_id);
CREATE INDEX idx_channel_members_user ON channel_members(user_id);

-- ─── Messages ──────────────────────────────────────────
-- Server stores ONLY encrypted blobs. Cannot read content.

CREATE TABLE IF NOT EXISTS messages (
    id              UUID PRIMARY KEY,
    channel_id      UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    sender_token    BYTEA NOT NULL,        -- Sealed sender: ephemeral token, not a user ID
    encrypted_body  BYTEA NOT NULL,        -- E2EE payload
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,           -- For disappearing messages
    has_attachments BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_messages_channel_time ON messages(channel_id, timestamp DESC);
CREATE INDEX idx_messages_expires ON messages(expires_at) WHERE expires_at IS NOT NULL;

-- ─── Attachments ───────────────────────────────────────
-- Server stores encrypted blobs in MinIO. Metadata is opaque.

CREATE TABLE IF NOT EXISTS attachments (
    id              UUID PRIMARY KEY,
    message_id      UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    storage_key     TEXT NOT NULL,          -- MinIO object key
    encrypted_meta  BYTEA,                 -- Filename, MIME type (encrypted, sent in message)
    size_bucket     INT NOT NULL DEFAULT 0, -- Padded size category for privacy
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_attachments_message ON attachments(message_id);

-- ─── Invite Links ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS invites (
    id              UUID PRIMARY KEY,
    server_id       UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    created_by      UUID NOT NULL REFERENCES users(id),
    code            TEXT UNIQUE NOT NULL,
    max_uses        INT,                   -- NULL = unlimited
    use_count       INT NOT NULL DEFAULT 0,
    expires_at      TIMESTAMPTZ,           -- NULL = never expires
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_invites_code ON invites(code);
CREATE INDEX idx_invites_server ON invites(server_id);
