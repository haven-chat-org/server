-- Custom server emojis (PNG/GIF/JPEG, max 256KB each)
CREATE TABLE custom_emojis (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id   UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    name        VARCHAR(64) NOT NULL,
    uploaded_by UUID REFERENCES users(id) ON DELETE SET NULL,
    animated    BOOLEAN NOT NULL DEFAULT FALSE,
    storage_key VARCHAR(255) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(server_id, name)
);
CREATE INDEX idx_custom_emojis_server_id ON custom_emojis(server_id);

-- Widen reactions.emoji to fit UUID strings (36 chars)
ALTER TABLE reactions ALTER COLUMN emoji TYPE VARCHAR(64);
