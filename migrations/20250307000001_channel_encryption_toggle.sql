-- Per-channel encryption toggle.
-- Existing channels default to TRUE (encrypted). Server owners can opt out
-- for public info/help channels where new members need to read history.
ALTER TABLE channels ADD COLUMN IF NOT EXISTS encrypted BOOLEAN NOT NULL DEFAULT TRUE;
