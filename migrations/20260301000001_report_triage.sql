-- Report triage: add review/escalation tracking columns
ALTER TABLE reports ADD COLUMN reviewed_by UUID REFERENCES users(id);
ALTER TABLE reports ADD COLUMN reviewed_at TIMESTAMPTZ;
ALTER TABLE reports ADD COLUMN admin_notes TEXT;
ALTER TABLE reports ADD COLUMN escalated_to VARCHAR(50);
ALTER TABLE reports ADD COLUMN escalated_at TIMESTAMPTZ;
ALTER TABLE reports ADD COLUMN escalated_by UUID REFERENCES users(id);
CREATE INDEX idx_reports_status ON reports(status);
CREATE INDEX idx_reports_created_at ON reports(created_at DESC);
