-- Add is_private flag to channels for role-gated visibility.
-- When is_private = true, only members with VIEW_CHANNELS permission
-- via channel_permission_overwrites can see and access the channel.

ALTER TABLE channels ADD COLUMN IF NOT EXISTS is_private BOOLEAN NOT NULL DEFAULT FALSE;
