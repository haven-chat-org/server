-- System user ("Haven") and default landing server for new users.
-- The Haven user cannot log in (unusable password hash) and is flagged is_system = TRUE.
-- The default server has two unencrypted channels: #welcome and #general.

-- ─── Schema changes ──────────────────────────────────────
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_system BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS is_system BOOLEAN NOT NULL DEFAULT FALSE;

-- ─── Seed data ───────────────────────────────────────────
-- Uses fixed UUIDs so we can reference them across inserts.
DO $$
DECLARE
  haven_user_id     UUID := '00000000-0000-4000-8000-000000000001';
  haven_server_id   UUID := '00000000-0000-4000-8000-000000000002';
  welcome_ch_id     UUID := '00000000-0000-4000-8000-000000000003';
  general_ch_id     UUID := '00000000-0000-4000-8000-000000000004';
  welcome_msg_id    UUID := '00000000-0000-4000-8000-000000000005';
BEGIN
  -- Haven system user (dummy crypto keys, unusable password)
  INSERT INTO users (
    id, username, display_name, password_hash,
    identity_key, signed_prekey, signed_prekey_sig,
    custom_status, is_system, created_at, updated_at
  ) VALUES (
    haven_user_id,
    'haven',
    'Haven',
    '!SYSTEM_USER_NO_LOGIN!',
    decode(lpad('', 64, '0'), 'hex'),   -- 32 zero bytes (X25519 placeholder)
    decode(lpad('', 64, '0'), 'hex'),   -- 32 zero bytes
    decode(lpad('', 128, '0'), 'hex'),  -- 64 zero bytes (signature placeholder)
    'Official Haven Message',
    TRUE,
    NOW(), NOW()
  ) ON CONFLICT (id) DO NOTHING;

  -- Haven system server
  INSERT INTO servers (id, encrypted_meta, owner_id, is_system, created_at)
  VALUES (
    haven_server_id,
    convert_to('{"name":"Haven"}', 'UTF8'),
    haven_user_id,
    TRUE,
    NOW()
  ) ON CONFLICT (id) DO NOTHING;

  -- #welcome channel (unencrypted, position 0)
  INSERT INTO channels (id, server_id, encrypted_meta, channel_type, position, encrypted, created_at)
  VALUES (
    welcome_ch_id,
    haven_server_id,
    convert_to('{"name":"welcome"}', 'UTF8'),
    'text', 0, FALSE, NOW()
  ) ON CONFLICT (id) DO NOTHING;

  -- #general channel (unencrypted, position 1)
  INSERT INTO channels (id, server_id, encrypted_meta, channel_type, position, encrypted, created_at)
  VALUES (
    general_ch_id,
    haven_server_id,
    convert_to('{"name":"general"}', 'UTF8'),
    'text', 1, FALSE, NOW()
  ) ON CONFLICT (id) DO NOTHING;

  -- Set #welcome as the server's system channel
  UPDATE servers SET system_channel_id = welcome_ch_id WHERE id = haven_server_id;

  -- Haven user as server member
  INSERT INTO server_members (id, server_id, user_id, encrypted_role, joined_at)
  VALUES (gen_random_uuid(), haven_server_id, haven_user_id, convert_to('owner', 'UTF8'), NOW())
  ON CONFLICT (server_id, user_id) DO NOTHING;

  -- Haven user as member of both channels
  INSERT INTO channel_members (id, channel_id, user_id, joined_at)
  VALUES (gen_random_uuid(), welcome_ch_id, haven_user_id, NOW())
  ON CONFLICT (channel_id, user_id) DO NOTHING;

  INSERT INTO channel_members (id, channel_id, user_id, joined_at)
  VALUES (gen_random_uuid(), general_ch_id, haven_user_id, NOW())
  ON CONFLICT (channel_id, user_id) DO NOTHING;

  -- Welcome message from Haven in #welcome (plaintext — channel is unencrypted)
  -- No ON CONFLICT here: messages table is partitioned with PK (id, timestamp),
  -- so there's no unique constraint on id alone.
  INSERT INTO messages (id, channel_id, sender_token, encrypted_body, timestamp, has_attachments, sender_id)
  VALUES (
    welcome_msg_id,
    welcome_ch_id,
    '\x00'::bytea,
    convert_to('Welcome to Haven! This is your home for private, encrypted communication. Explore the channels, add friends, and make yourself at home.', 'UTF8'),
    NOW(),
    FALSE,
    haven_user_id
  );
END $$;
