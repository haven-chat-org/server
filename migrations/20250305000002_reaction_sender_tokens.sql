-- Add sender_token to message reactions for sealed sender.
-- Instead of broadcasting user_id in WS events, we broadcast
-- an opaque sender_token. The user_id is resolved via REST when needed.

ALTER TABLE reactions ADD COLUMN IF NOT EXISTS sender_token TEXT;
