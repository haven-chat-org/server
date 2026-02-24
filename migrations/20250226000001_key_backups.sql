-- Encrypted key backup for multi-device E2EE support.
-- The server stores an opaque encrypted blob derived from a user's security phrase.
-- Only one active backup per user (upserted on each update).

CREATE TABLE IF NOT EXISTS key_backups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_data  BYTEA NOT NULL,
    nonce           BYTEA NOT NULL,
    salt            BYTEA NOT NULL,
    version         INT NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id)
);

CREATE INDEX idx_key_backups_user ON key_backups(user_id);
