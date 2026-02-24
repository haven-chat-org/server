-- Add session metadata to refresh tokens for session management UI.
-- device_name: parsed User-Agent (e.g. "Chrome on macOS")
-- ip_address: client IP at login time
-- last_activity: updated on each token refresh

ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS device_name TEXT;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS ip_address TEXT;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS last_activity TIMESTAMPTZ;
