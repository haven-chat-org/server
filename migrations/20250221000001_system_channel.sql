-- Add system_channel_id to servers for landing/join messages
ALTER TABLE servers ADD COLUMN system_channel_id UUID REFERENCES channels(id) ON DELETE SET NULL;
