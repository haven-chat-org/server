-- Add email_hash column to registration_invites for beta code deduplication.
-- Stores a SHA-256 hash of the requester's email (not the email itself).
-- Only beta codes (created_by IS NULL) use this column; regular invites leave it NULL.
ALTER TABLE registration_invites ADD COLUMN email_hash TEXT;

-- Index for fast duplicate lookups
CREATE INDEX idx_registration_invites_email_hash ON registration_invites (email_hash) WHERE email_hash IS NOT NULL;
