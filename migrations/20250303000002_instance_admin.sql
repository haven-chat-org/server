-- Add instance admin flag to users
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_instance_admin BOOLEAN NOT NULL DEFAULT FALSE;
