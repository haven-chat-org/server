-- Encrypted user profiles: about_me, custom_status, custom_status_emoji
-- are encrypted client-side and stored as a single blob.
-- display_name remains plaintext (needed for mentions/member lists).

ALTER TABLE users ADD COLUMN encrypted_profile BYTEA;

-- Profile key distributions: each user generates a profile key,
-- encrypts it to each contact's identity public key, and stores it here.
-- Recipients use their identity key to decrypt and then decrypt the profile blob.
CREATE TABLE profile_key_distributions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    to_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_profile_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(from_user_id, to_user_id)
);

CREATE INDEX idx_pkd_to_user ON profile_key_distributions(to_user_id);
