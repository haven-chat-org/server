-- Known-bad hash blocklist for file uploads (CSAM prevention)
CREATE TABLE blocked_hashes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hash TEXT NOT NULL UNIQUE,
    description TEXT,
    added_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_blocked_hashes_hash ON blocked_hashes(hash);

-- Store plaintext file hash on attachments for retroactive matching
ALTER TABLE attachments ADD COLUMN file_hash TEXT;
CREATE INDEX idx_attachments_file_hash ON attachments(file_hash);
