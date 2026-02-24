-- Add export_allowed column to channels table.
-- Only meaningful for DM channels; server channels ignore it.
ALTER TABLE channels ADD COLUMN export_allowed BOOLEAN NOT NULL DEFAULT TRUE;
