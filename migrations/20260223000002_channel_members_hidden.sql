-- Allow users to hide DM channels from their sidebar without deleting them.
-- Hidden channels are automatically un-hidden when a new message arrives.
ALTER TABLE channel_members ADD COLUMN IF NOT EXISTS hidden BOOLEAN NOT NULL DEFAULT FALSE;
