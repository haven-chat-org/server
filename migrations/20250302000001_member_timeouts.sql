-- Member timeout support (temporary communication restriction)
ALTER TABLE server_members ADD COLUMN IF NOT EXISTS timed_out_until TIMESTAMPTZ;
