-- Channel categories (groupable parents for channels)
CREATE TABLE IF NOT EXISTS channel_categories (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id   UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    position    INT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_channel_categories_server ON channel_categories(server_id);

-- Add optional category FK to channels
ALTER TABLE channels ADD COLUMN IF NOT EXISTS category_id UUID REFERENCES channel_categories(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_channels_category ON channels(category_id);
