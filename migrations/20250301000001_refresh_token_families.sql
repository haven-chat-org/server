-- Add family-based refresh token rotation for theft detection.
-- family_id groups tokens from the same login session.
-- revoked flag allows detecting replayed (stolen) tokens.

ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS family_id UUID;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS revoked BOOLEAN NOT NULL DEFAULT false;

-- Index for family-based revocation
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id)
    WHERE family_id IS NOT NULL;
