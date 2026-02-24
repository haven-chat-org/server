-- Sender Key Distribution Messages (SKDMs) for group E2EE.
-- The server stores encrypted SKDM blobs and delivers them to recipients.
-- Each row = one encrypted SKDM for one recipient.

CREATE TABLE IF NOT EXISTS sender_key_distributions (
    id              UUID PRIMARY KEY,
    channel_id      UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    from_user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    to_user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    distribution_id UUID NOT NULL,
    encrypted_skdm  BYTEA NOT NULL,      -- crypto_box_seal encrypted, server cannot read
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(channel_id, from_user_id, to_user_id, distribution_id)
);

CREATE INDEX idx_skdm_to_user_channel ON sender_key_distributions(to_user_id, channel_id);
CREATE INDEX idx_skdm_from_user_channel ON sender_key_distributions(from_user_id, channel_id);
