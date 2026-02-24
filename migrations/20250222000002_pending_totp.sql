-- TOTP setup race condition fix: store secret in pending column until user verifies.
-- Only promote to totp_secret after successful code verification.
ALTER TABLE users ADD COLUMN pending_totp_secret TEXT;
