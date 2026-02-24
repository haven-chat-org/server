-- Per-server nicknames
ALTER TABLE server_members ADD COLUMN IF NOT EXISTS nickname VARCHAR(32);
