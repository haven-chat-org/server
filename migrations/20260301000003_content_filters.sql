-- Content filters: server-level keyword/regex filters for client-side enforcement
CREATE TABLE content_filters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    pattern TEXT NOT NULL,
    filter_type VARCHAR(10) NOT NULL DEFAULT 'keyword',
    action VARCHAR(10) NOT NULL DEFAULT 'hide',
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_content_filters_server_id ON content_filters(server_id);
