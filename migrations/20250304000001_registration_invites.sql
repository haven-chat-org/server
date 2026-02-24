-- Registration invite codes (instance-level, separate from server invites).
-- Each code is single-use: one registration per code.
-- New users automatically receive N invite codes they can share.

CREATE TABLE IF NOT EXISTS registration_invites (
    id          UUID PRIMARY KEY,
    code        TEXT UNIQUE NOT NULL,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    used_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    used_at     TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_reg_invites_code ON registration_invites(code);
CREATE INDEX idx_reg_invites_created_by ON registration_invites(created_by);
