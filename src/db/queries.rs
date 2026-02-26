use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::Pool;
use crate::errors::{AppError, AppResult};
use crate::models::*;

// ─── Users ─────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn create_user(
    pool: &Pool,
    username: &str,
    display_name: Option<&str>,
    email_hash: Option<&str>,
    password_hash: &str,
    identity_key: &[u8],
    signed_prekey: &[u8],
    signed_prekey_sig: &[u8],
) -> AppResult<User> {
    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (id, username, display_name, email_hash, password_hash,
                          identity_key, signed_prekey, signed_prekey_sig,
                          created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(username)
    .bind(display_name)
    .bind(email_hash)
    .bind(password_hash)
    .bind(identity_key)
    .bind(signed_prekey)
    .bind(signed_prekey_sig)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref db_err) if db_err.constraint() == Some("users_username_key") => {
            AppError::UsernameTaken
        }
        other => AppError::Database(other),
    })?;

    Ok(user)
}

pub async fn find_user_by_username(pool: &Pool, username: &str) -> AppResult<Option<User>> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE LOWER(username) = LOWER($1)")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

pub async fn find_user_by_id(pool: &Pool, id: Uuid) -> AppResult<Option<User>> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

/// Cached variant — checks cache first, falls back to DB, caches for 5 min.
pub async fn find_user_by_id_cached(
    pool: &Pool,
    redis: &mut Option<redis::aio::ConnectionManager>,
    memory: &crate::memory_store::MemoryStore,
    id: Uuid,
) -> AppResult<Option<User>> {
    let key = format!("haven:user:{}", id);
    if let Some(user) = crate::cache::get_cached::<User>(redis.as_mut(), memory, &key).await {
        return Ok(Some(user));
    }
    let user = find_user_by_id(pool, id).await?;
    if let Some(ref u) = user {
        crate::cache::set_cached(redis.as_mut(), memory, &key, u, 300).await;
    }
    Ok(user)
}

pub async fn update_user_keys(
    pool: &Pool,
    user_id: Uuid,
    identity_key: &[u8],
    signed_prekey: &[u8],
    signed_prekey_sig: &[u8],
) -> AppResult<()> {
    sqlx::query(
        "UPDATE users SET identity_key = $1, signed_prekey = $2, signed_prekey_sig = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4",
    )
    .bind(identity_key)
    .bind(signed_prekey)
    .bind(signed_prekey_sig)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn set_user_totp_secret(pool: &Pool, user_id: Uuid, secret: &str) -> AppResult<()> {
    sqlx::query("UPDATE users SET totp_secret = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2")
        .bind(secret)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Store TOTP secret in the pending column (not yet verified).
pub async fn set_pending_totp_secret(pool: &Pool, user_id: Uuid, secret: &str) -> AppResult<()> {
    sqlx::query("UPDATE users SET pending_totp_secret = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2")
        .bind(secret)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Promote pending TOTP secret to active after successful verification.
pub async fn promote_pending_totp(pool: &Pool, user_id: Uuid) -> AppResult<()> {
    sqlx::query(
        "UPDATE users SET totp_secret = pending_totp_secret, pending_totp_secret = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = $1"
    )
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn clear_user_totp_secret(pool: &Pool, user_id: Uuid) -> AppResult<()> {
    sqlx::query("UPDATE users SET totp_secret = NULL, pending_totp_secret = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_user_password(pool: &Pool, user_id: Uuid, password_hash: &str) -> AppResult<()> {
    sqlx::query("UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2")
        .bind(password_hash)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── Pre-Keys ──────────────────────────────────────────

pub async fn insert_prekeys(pool: &Pool, user_id: Uuid, keys: &[(i32, Vec<u8>)]) -> AppResult<()> {
    // Batch insert using a transaction
    let mut tx = pool.begin().await?;

    for (key_id, public_key) in keys {
        sqlx::query(
            r#"
            INSERT INTO prekeys (id, user_id, key_id, public_key, used, created_at)
            VALUES ($1, $2, $3, $4, false, CURRENT_TIMESTAMP)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(key_id)
        .bind(public_key)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

/// Fetch and consume one unused one-time prekey (marks it as used atomically).
pub async fn consume_prekey(pool: &Pool, user_id: Uuid) -> AppResult<Option<PreKey>> {
    let prekey = sqlx::query_as::<_, PreKey>(
        r#"
        UPDATE prekeys SET used = true
        WHERE id = (
            SELECT id FROM prekeys
            WHERE user_id = $1 AND used = false
            ORDER BY created_at ASC
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        )
        RETURNING *
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(prekey)
}

pub async fn count_unused_prekeys(pool: &Pool, user_id: Uuid) -> AppResult<i64> {
    let row: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM prekeys WHERE user_id = $1 AND used = false")
            .bind(user_id)
            .fetch_one(pool)
            .await?;
    Ok(row.0)
}

/// Delete all unused one-time prekeys for a user.
/// Called on login before uploading fresh prekeys so the server only has
/// OTPs whose private keys exist in the client's current MemoryStore.
pub async fn delete_unused_prekeys(pool: &Pool, user_id: Uuid) -> AppResult<i64> {
    let result = sqlx::query("DELETE FROM prekeys WHERE user_id = $1 AND used = false")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() as i64)
}

// ─── Refresh Tokens ────────────────────────────────────

pub async fn store_refresh_token(
    pool: &Pool,
    user_id: Uuid,
    token_hash: &str,
    expires_at: DateTime<Utc>,
) -> AppResult<()> {
    store_refresh_token_with_family(pool, user_id, token_hash, expires_at, None).await
}

pub async fn store_refresh_token_with_family(
    pool: &Pool,
    user_id: Uuid,
    token_hash: &str,
    expires_at: DateTime<Utc>,
    family_id: Option<Uuid>,
) -> AppResult<()> {
    store_refresh_token_with_metadata(pool, user_id, token_hash, expires_at, family_id, None, None).await
}

pub async fn store_refresh_token_with_metadata(
    pool: &Pool,
    user_id: Uuid,
    token_hash: &str,
    expires_at: DateTime<Utc>,
    family_id: Option<Uuid>,
    device_name: Option<&str>,
    ip_address: Option<&str>,
) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at, family_id, revoked, device_name, ip_address, last_activity)
        VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, $5, false, $6, $7, CURRENT_TIMESTAMP)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(token_hash)
    .bind(expires_at)
    .bind(family_id)
    .bind(device_name)
    .bind(ip_address)
    .execute(pool)
    .await?;
    Ok(())
}

/// Find a refresh token by hash, including revoked ones (for theft detection).
pub async fn find_refresh_token(pool: &Pool, token_hash: &str) -> AppResult<Option<RefreshToken>> {
    let token = sqlx::query_as::<_, RefreshToken>(
        "SELECT * FROM refresh_tokens WHERE token_hash = $1 AND expires_at > CURRENT_TIMESTAMP",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(token)
}

/// Mark a refresh token as revoked (soft-delete for theft detection).
pub async fn revoke_refresh_token(pool: &Pool, token_hash: &str) -> AppResult<()> {
    sqlx::query("UPDATE refresh_tokens SET revoked = true WHERE token_hash = $1")
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// Revoke all tokens in a family (used when token theft is detected).
pub async fn revoke_token_family(pool: &Pool, family_id: Uuid) -> AppResult<u64> {
    let result = sqlx::query("DELETE FROM refresh_tokens WHERE family_id = $1")
        .bind(family_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub async fn revoke_all_user_refresh_tokens(pool: &Pool, user_id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn purge_expired_refresh_tokens(pool: &Pool) -> AppResult<u64> {
    let result = sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < CURRENT_TIMESTAMP")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// List active sessions for a user (one per token family, most recent token per family).
pub async fn list_user_sessions(pool: &Pool, user_id: Uuid) -> AppResult<Vec<RefreshToken>> {
    let tokens = sqlx::query_as::<_, RefreshToken>(
        r#"
        SELECT DISTINCT ON (family_id) *
        FROM refresh_tokens
        WHERE user_id = $1 AND NOT revoked AND expires_at > CURRENT_TIMESTAMP AND family_id IS NOT NULL
        ORDER BY family_id, created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(tokens)
}

/// Revoke a single session by family_id (only if it belongs to user_id).
pub async fn revoke_session(pool: &Pool, user_id: Uuid, family_id: Uuid) -> AppResult<u64> {
    let result = sqlx::query(
        "DELETE FROM refresh_tokens WHERE user_id = $1 AND family_id = $2",
    )
    .bind(user_id)
    .bind(family_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Update last_activity for a token family.
pub async fn update_session_activity(pool: &Pool, family_id: Uuid) -> AppResult<()> {
    sqlx::query(
        "UPDATE refresh_tokens SET last_activity = CURRENT_TIMESTAMP WHERE family_id = $1 AND NOT revoked",
    )
    .bind(family_id)
    .execute(pool)
    .await?;
    Ok(())
}

// ─── Servers ───────────────────────────────────────────

pub async fn create_server(
    pool: &Pool,
    owner_id: Uuid,
    encrypted_meta: &[u8],
) -> AppResult<Server> {
    let server = sqlx::query_as::<_, Server>(
        r#"
        INSERT INTO servers (id, encrypted_meta, owner_id, created_at)
        VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(encrypted_meta)
    .bind(owner_id)
    .fetch_one(pool)
    .await?;
    Ok(server)
}

pub async fn find_server_by_id(pool: &Pool, id: Uuid) -> AppResult<Option<Server>> {
    let server = sqlx::query_as::<_, Server>("SELECT * FROM servers WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(server)
}

/// Cached variant — checks cache first, falls back to DB, caches for 5 min.
pub async fn find_server_by_id_cached(
    pool: &Pool,
    redis: &mut Option<redis::aio::ConnectionManager>,
    memory: &crate::memory_store::MemoryStore,
    id: Uuid,
) -> AppResult<Option<Server>> {
    let key = format!("haven:server:{}", id);
    if let Some(server) = crate::cache::get_cached::<Server>(redis.as_mut(), memory, &key).await {
        return Ok(Some(server));
    }
    let server = find_server_by_id(pool, id).await?;
    if let Some(ref s) = server {
        crate::cache::set_cached(redis.as_mut(), memory, &key, s, 300).await;
    }
    Ok(server)
}

pub async fn get_user_servers(pool: &Pool, user_id: Uuid) -> AppResult<Vec<Server>> {
    let servers = sqlx::query_as::<_, Server>(
        r#"
        SELECT s.* FROM servers s
        INNER JOIN server_members sm ON s.id = sm.server_id
        WHERE sm.user_id = $1
        ORDER BY s.created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(servers)
}

pub async fn update_system_channel(
    pool: &Pool,
    server_id: Uuid,
    system_channel_id: Option<Uuid>,
) -> AppResult<()> {
    sqlx::query("UPDATE servers SET system_channel_id = $1 WHERE id = $2")
        .bind(system_channel_id)
        .bind(server_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_server_meta(
    pool: &Pool,
    server_id: Uuid,
    encrypted_meta: &[u8],
) -> AppResult<()> {
    sqlx::query("UPDATE servers SET encrypted_meta = $1 WHERE id = $2")
        .bind(encrypted_meta)
        .bind(server_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_server_icon(
    pool: &Pool,
    server_id: Uuid,
    icon_url: Option<&str>,
) -> AppResult<()> {
    sqlx::query("UPDATE servers SET icon_url = $1 WHERE id = $2")
        .bind(icon_url)
        .bind(server_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── Server Members ────────────────────────────────────

pub async fn add_server_member(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
    encrypted_role: &[u8],
) -> AppResult<ServerMember> {
    let member = sqlx::query_as::<_, ServerMember>(
        r#"
        INSERT INTO server_members (id, server_id, user_id, encrypted_role, joined_at)
        VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
        ON CONFLICT (server_id, user_id) DO UPDATE SET encrypted_role = EXCLUDED.encrypted_role
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(server_id)
    .bind(user_id)
    .bind(encrypted_role)
    .fetch_one(pool)
    .await?;
    Ok(member)
}

pub async fn is_server_member(pool: &Pool, server_id: Uuid, user_id: Uuid) -> AppResult<bool> {
    let row: (bool,) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM server_members WHERE server_id = $1 AND user_id = $2)",
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

// ─── Channels ──────────────────────────────────────────

/// Find an existing DM channel between exactly two users.
pub async fn find_dm_channel(pool: &Pool, user_a: Uuid, user_b: Uuid) -> AppResult<Option<Channel>> {
    let channel = sqlx::query_as::<_, Channel>(
        r#"
        SELECT c.* FROM channels c
        WHERE c.channel_type = 'dm'
          AND (SELECT COUNT(*) FROM channel_members cm WHERE cm.channel_id = c.id) = 2
          AND EXISTS (SELECT 1 FROM channel_members cm WHERE cm.channel_id = c.id AND cm.user_id = $1)
          AND EXISTS (SELECT 1 FROM channel_members cm WHERE cm.channel_id = c.id AND cm.user_id = $2)
        LIMIT 1
        "#,
    )
    .bind(user_a)
    .bind(user_b)
    .fetch_optional(pool)
    .await?;
    Ok(channel)
}

#[allow(clippy::too_many_arguments)]
pub async fn create_channel(
    pool: &Pool,
    server_id: Option<Uuid>,
    encrypted_meta: &[u8],
    channel_type: &str,
    position: i32,
    category_id: Option<Uuid>,
    is_private: bool,
    encrypted: bool,
) -> AppResult<Channel> {
    let channel = sqlx::query_as::<_, Channel>(
        r#"
        INSERT INTO channels (id, server_id, encrypted_meta, channel_type, position, category_id, is_private, encrypted, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(server_id)
    .bind(encrypted_meta)
    .bind(channel_type)
    .bind(position)
    .bind(category_id)
    .bind(is_private)
    .bind(encrypted)
    .fetch_one(pool)
    .await?;
    Ok(channel)
}

pub async fn get_server_channels(pool: &Pool, server_id: Uuid) -> AppResult<Vec<Channel>> {
    let channels = sqlx::query_as::<_, Channel>(
        "SELECT * FROM channels WHERE server_id = $1 ORDER BY position ASC",
    )
    .bind(server_id)
    .fetch_all(pool)
    .await?;
    Ok(channels)
}

pub async fn get_user_dm_channels(pool: &Pool, user_id: Uuid) -> AppResult<Vec<Channel>> {
    let channels = sqlx::query_as::<_, Channel>(
        r#"
        SELECT c.* FROM channels c
        INNER JOIN channel_members cm ON c.id = cm.channel_id
        WHERE cm.user_id = $1 AND c.channel_type IN ('dm', 'group') AND cm.hidden = FALSE
        ORDER BY c.created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(channels)
}

pub async fn find_channel_by_id(pool: &Pool, id: Uuid) -> AppResult<Option<Channel>> {
    let ch = sqlx::query_as::<_, Channel>("SELECT * FROM channels WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(ch)
}

pub async fn update_channel_meta(
    pool: &Pool,
    channel_id: Uuid,
    encrypted_meta: &[u8],
    encrypted: Option<bool>,
) -> AppResult<Channel> {
    let ch = sqlx::query_as::<_, Channel>(
        "UPDATE channels SET encrypted_meta = $1, encrypted = COALESCE($3, encrypted) WHERE id = $2 RETURNING *",
    )
    .bind(encrypted_meta)
    .bind(channel_id)
    .bind(encrypted)
    .fetch_one(pool)
    .await?;
    Ok(ch)
}

pub async fn delete_channel(pool: &Pool, channel_id: Uuid) -> AppResult<()> {
    // Delete members first, then message children, then messages, then the channel
    sqlx::query("DELETE FROM channel_members WHERE channel_id = $1")
        .bind(channel_id)
        .execute(pool)
        .await?;
    // Clean up child rows before deleting messages (no FK cascade on partitioned table)
    cleanup_channel_message_children(pool, channel_id).await?;
    sqlx::query("DELETE FROM messages WHERE channel_id = $1")
        .bind(channel_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM sender_key_distributions WHERE channel_id = $1")
        .bind(channel_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM channels WHERE id = $1")
        .bind(channel_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── Channel Members ───────────────────────────────────

pub async fn add_channel_member(
    pool: &Pool,
    channel_id: Uuid,
    user_id: Uuid,
) -> AppResult<ChannelMember> {
    let member = sqlx::query_as::<_, ChannelMember>(
        r#"
        INSERT INTO channel_members (id, channel_id, user_id, joined_at)
        VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
        ON CONFLICT (channel_id, user_id) DO UPDATE SET joined_at = EXCLUDED.joined_at
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(channel_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(member)
}

/// Bulk-insert a user into all channels belonging to a server (single query).
pub async fn add_channel_members_bulk(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
) -> AppResult<u64> {
    let result = sqlx::query(
        r#"
        INSERT INTO channel_members (id, channel_id, user_id, joined_at)
        SELECT gen_random_uuid(), c.id, $1, CURRENT_TIMESTAMP
        FROM channels c
        WHERE c.server_id = $2
        ON CONFLICT (channel_id, user_id) DO UPDATE SET joined_at = EXCLUDED.joined_at
        "#,
    )
    .bind(user_id)
    .bind(server_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn is_channel_member(pool: &Pool, channel_id: Uuid, user_id: Uuid) -> AppResult<bool> {
    let row: (bool,) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM channel_members WHERE channel_id = $1 AND user_id = $2)",
    )
    .bind(channel_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Check if a user can access a channel: either via channel_members (DM/group)
/// or via server membership (server channels).
pub async fn can_access_channel(pool: &Pool, channel_id: Uuid, user_id: Uuid) -> AppResult<bool> {
    let row: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM channel_members WHERE channel_id = $1 AND user_id = $2
            UNION ALL
            SELECT 1 FROM channels c
            JOIN server_members sm ON sm.server_id = c.server_id
            WHERE c.id = $1 AND sm.user_id = $2 AND c.server_id IS NOT NULL
        )
        "#,
    )
    .bind(channel_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn get_channel_member_ids(pool: &Pool, channel_id: Uuid) -> AppResult<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> =
        sqlx::query_as("SELECT user_id FROM channel_members WHERE channel_id = $1")
            .bind(channel_id)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

/// Remove a user from a channel.
pub async fn remove_channel_member(
    pool: &Pool,
    channel_id: Uuid,
    user_id: Uuid,
) -> AppResult<()> {
    sqlx::query("DELETE FROM channel_members WHERE channel_id = $1 AND user_id = $2")
        .bind(channel_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Get channel members with user info (for DM/group member sidebar).
pub async fn get_channel_members_info(
    pool: &Pool,
    channel_id: Uuid,
) -> AppResult<Vec<ChannelMemberInfo>> {
    let members = sqlx::query_as::<_, ChannelMemberInfo>(
        r#"
        SELECT cm.user_id, u.username, u.display_name, u.avatar_url, cm.joined_at
        FROM channel_members cm
        INNER JOIN users u ON u.id = cm.user_id
        WHERE cm.channel_id = $1
        ORDER BY cm.joined_at ASC
        "#,
    )
    .bind(channel_id)
    .fetch_all(pool)
    .await?;
    Ok(members)
}

/// Get all channel IDs a user belongs to (for presence broadcast).
/// Includes DM/group channels (via channel_members) and server channels (via server membership).
pub async fn get_user_channel_ids(pool: &Pool, user_id: Uuid) -> AppResult<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT channel_id FROM channel_members WHERE user_id = $1
        UNION
        SELECT c.id FROM channels c
        JOIN server_members sm ON sm.server_id = c.server_id
        WHERE sm.user_id = $1 AND c.server_id IS NOT NULL
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

// ─── Messages ──────────────────────────────────────────

pub async fn find_message_by_id(pool: &Pool, id: Uuid) -> AppResult<Option<Message>> {
    let msg = sqlx::query_as::<_, Message>("SELECT * FROM messages WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(msg)
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_message(
    pool: &Pool,
    channel_id: Uuid,
    sender_token: &[u8],
    encrypted_body: &[u8],
    expires_at: Option<DateTime<Utc>>,
    has_attachments: bool,
    sender_id: Uuid,
    reply_to_id: Option<Uuid>,
) -> AppResult<Message> {
    let msg = sqlx::query_as::<_, Message>(
        r#"
        INSERT INTO messages (id, channel_id, sender_token, encrypted_body,
                             timestamp, expires_at, has_attachments, sender_id, reply_to_id)
        VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, $5, $6, $7, $8)
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(channel_id)
    .bind(sender_token)
    .bind(encrypted_body)
    .bind(expires_at)
    .bind(has_attachments)
    .bind(sender_id)
    .bind(reply_to_id)
    .fetch_one(pool)
    .await?;
    Ok(msg)
}

/// Update encrypted_body of a message (for editing). Only the original sender can edit.
pub async fn update_message_body(
    pool: &Pool,
    message_id: Uuid,
    sender_id: Uuid,
    new_encrypted_body: &[u8],
) -> AppResult<Message> {
    let msg = sqlx::query_as::<_, Message>(
        r#"
        UPDATE messages
        SET encrypted_body = $1, edited_at = CURRENT_TIMESTAMP
        WHERE id = $2 AND sender_id = $3
        RETURNING *
        "#,
    )
    .bind(new_encrypted_body)
    .bind(message_id)
    .bind(sender_id)
    .fetch_optional(pool)
    .await?;

    msg.ok_or_else(|| AppError::Forbidden("Cannot edit this message".into()))
}

/// Clean up child rows that previously relied on FK CASCADE from messages.
/// Must be called before deleting messages (partitioned tables can't have FK refs).
async fn cleanup_message_children(pool: &Pool, message_id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM attachments WHERE message_id = $1")
        .bind(message_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM reactions WHERE message_id = $1")
        .bind(message_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM pinned_messages WHERE message_id = $1")
        .bind(message_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM reports WHERE message_id = $1")
        .bind(message_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Clean up child rows for all messages in a channel.
/// Used when deleting a channel (bulk message delete).
async fn cleanup_channel_message_children(pool: &Pool, channel_id: Uuid) -> AppResult<()> {
    sqlx::query(
        "DELETE FROM attachments WHERE message_id IN (SELECT id FROM messages WHERE channel_id = $1)"
    )
    .bind(channel_id)
    .execute(pool)
    .await?;
    sqlx::query(
        "DELETE FROM reactions WHERE message_id IN (SELECT id FROM messages WHERE channel_id = $1)"
    )
    .bind(channel_id)
    .execute(pool)
    .await?;
    sqlx::query(
        "DELETE FROM pinned_messages WHERE channel_id = $1"
    )
    .bind(channel_id)
    .execute(pool)
    .await?;
    sqlx::query(
        "DELETE FROM reports WHERE channel_id = $1"
    )
    .bind(channel_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete a message. Only the original sender can delete.
/// Returns the deleted message (for getting channel_id).
pub async fn delete_message(
    pool: &Pool,
    message_id: Uuid,
    sender_id: Uuid,
) -> AppResult<Message> {
    // Clean up child rows (no FK cascade on partitioned table)
    cleanup_message_children(pool, message_id).await?;

    let msg = sqlx::query_as::<_, Message>(
        r#"
        DELETE FROM messages
        WHERE id = $1 AND sender_id = $2
        RETURNING *
        "#,
    )
    .bind(message_id)
    .bind(sender_id)
    .fetch_optional(pool)
    .await?;

    msg.ok_or_else(|| AppError::Forbidden("Cannot delete this message".into()))
}

/// Delete a message by ID (admin/owner — no sender check).
pub async fn delete_message_admin(
    pool: &Pool,
    message_id: Uuid,
) -> AppResult<Message> {
    // Clean up child rows (no FK cascade on partitioned table)
    cleanup_message_children(pool, message_id).await?;

    let msg = sqlx::query_as::<_, Message>(
        r#"
        DELETE FROM messages
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(message_id)
    .fetch_optional(pool)
    .await?;

    msg.ok_or_else(|| AppError::NotFound("Message not found".into()))
}

pub async fn get_channel_messages(
    pool: &Pool,
    channel_id: Uuid,
    before: Option<DateTime<Utc>>,
    after: Option<DateTime<Utc>>,
    limit: i64,
) -> AppResult<Vec<Message>> {
    let messages = sqlx::query_as::<_, Message>(
        r#"
        SELECT * FROM messages
        WHERE channel_id = $1
          AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
          AND ($2::timestamptz IS NULL OR timestamp < $2)
          AND ($3::timestamptz IS NULL OR timestamp > $3)
        ORDER BY timestamp DESC
        LIMIT $4
        "#,
    )
    .bind(channel_id)
    .bind(before)
    .bind(after)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(messages)
}

/// Get all exportable messages for a channel (excludes disappearing messages).
/// Used by the bulk export endpoint. Internally paginates in batches of 500.
pub async fn get_export_messages(
    pool: &Pool,
    channel_id: Uuid,
    after: Option<DateTime<Utc>>,
    before: Option<DateTime<Utc>>,
) -> AppResult<Vec<Message>> {
    let messages = sqlx::query_as::<_, Message>(
        r#"
        SELECT * FROM messages
        WHERE channel_id = $1
          AND expires_at IS NULL
          AND ($2::timestamptz IS NULL OR timestamp > $2)
          AND ($3::timestamptz IS NULL OR timestamp < $3)
        ORDER BY timestamp ASC
        "#,
    )
    .bind(channel_id)
    .bind(after)
    .bind(before)
    .fetch_all(pool)
    .await?;
    Ok(messages)
}

/// Purge expired messages (called by background worker).
/// Cleans up child rows first since FK cascades were removed for partitioning.
pub async fn purge_expired_messages(pool: &Pool) -> AppResult<u64> {
    let expired_condition = "message_id IN (SELECT id FROM messages WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP)";
    sqlx::query(&format!("DELETE FROM attachments WHERE {}", expired_condition))
        .execute(pool)
        .await?;
    sqlx::query(&format!("DELETE FROM reactions WHERE {}", expired_condition))
        .execute(pool)
        .await?;
    sqlx::query(&format!("DELETE FROM pinned_messages WHERE {}", expired_condition))
        .execute(pool)
        .await?;
    sqlx::query(&format!("DELETE FROM reports WHERE {}", expired_condition))
        .execute(pool)
        .await?;
    let result = sqlx::query("DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Ensure monthly message partitions exist for the next 3 months.
/// Called by a daily background worker. PostgreSQL only — SQLite doesn't support partitioning.
#[cfg(feature = "postgres")]
pub async fn ensure_future_partitions(pool: &Pool) -> AppResult<()> {
    use chrono::Datelike;

    let now = Utc::now();
    for month_offset in 0..3 {
        let target = now
            .checked_add_months(chrono::Months::new(month_offset))
            .unwrap_or(now);
        let name = format!("messages_y{}m{:02}", target.year(), target.month());
        let start = format!("{}-{:02}-01", target.year(), target.month());
        let next = target
            .checked_add_months(chrono::Months::new(1))
            .unwrap_or(target);
        let end = format!("{}-{:02}-01", next.year(), next.month());

        let sql = format!(
            "CREATE TABLE IF NOT EXISTS {} PARTITION OF messages FOR VALUES FROM ('{}') TO ('{}')",
            name, start, end
        );
        // Ignore errors — partition may already exist or overlap with default
        if let Err(e) = sqlx::query(&sql).execute(pool).await {
            tracing::debug!("Partition {} already exists or overlaps: {}", name, e);
        }
    }
    Ok(())
}

/// No-op for SQLite — partitioning is not supported or needed.
#[cfg(feature = "sqlite")]
pub async fn ensure_future_partitions(_pool: &Pool) -> AppResult<()> {
    Ok(())
}

// ─── Data Retention Purge ──────────────────────────────

/// Delete audit log entries older than `retention_days` days.
/// Called by a daily background worker when audit_log_retention_days > 0.
pub async fn purge_old_audit_logs(pool: &Pool, retention_days: u32) -> AppResult<u64> {
    let result = sqlx::query(
        "DELETE FROM audit_log WHERE created_at < CURRENT_TIMESTAMP - make_interval(days => $1)"
    )
    .bind(retention_days as i32)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Delete resolved/dismissed reports older than `retention_days` days.
/// Pending reports are never auto-deleted.
pub async fn purge_old_resolved_reports(pool: &Pool, retention_days: u32) -> AppResult<u64> {
    let result = sqlx::query(
        "DELETE FROM reports WHERE status != 'pending' AND created_at < CURRENT_TIMESTAMP - make_interval(days => $1)"
    )
    .bind(retention_days as i32)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Delete invites that have passed their expiration time.
/// Invites with no expiry (expires_at IS NULL) are never deleted.
pub async fn purge_expired_invites(pool: &Pool) -> AppResult<u64> {
    let result = sqlx::query(
        "DELETE FROM invites WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP"
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

// ─── Attachments ───────────────────────────────────────

/// Link an attachment (uploaded via presigned URL) to a message.
pub async fn link_attachment(
    pool: &Pool,
    attachment_id: Uuid,
    message_id: Uuid,
    storage_key: &str,
) -> AppResult<Attachment> {
    let att = sqlx::query_as::<_, Attachment>(
        r#"
        INSERT INTO attachments (id, message_id, storage_key, encrypted_meta, size_bucket, created_at)
        VALUES ($1, $2, $3, $4, 0, CURRENT_TIMESTAMP)
        RETURNING *
        "#,
    )
    .bind(attachment_id)
    .bind(message_id)
    .bind(storage_key)
    .bind(&[] as &[u8])
    .fetch_one(pool)
    .await?;
    Ok(att)
}

pub async fn find_attachment_by_id(pool: &Pool, id: Uuid) -> AppResult<Option<Attachment>> {
    let att = sqlx::query_as::<_, Attachment>("SELECT * FROM attachments WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(att)
}

pub async fn insert_attachment(
    pool: &Pool,
    message_id: Uuid,
    storage_key: &str,
    encrypted_meta: &[u8],
    size_bucket: i32,
) -> AppResult<Attachment> {
    let att = sqlx::query_as::<_, Attachment>(
        r#"
        INSERT INTO attachments (id, message_id, storage_key, encrypted_meta, size_bucket, created_at)
        VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(message_id)
    .bind(storage_key)
    .bind(encrypted_meta)
    .bind(size_bucket)
    .fetch_one(pool)
    .await?;
    Ok(att)
}

// ─── Invites ──────────────────────────────────────────

pub async fn create_invite(
    pool: &Pool,
    server_id: Uuid,
    created_by: Uuid,
    code: &str,
    max_uses: Option<i32>,
    expires_at: Option<DateTime<Utc>>,
) -> AppResult<Invite> {
    let invite = sqlx::query_as::<_, Invite>(
        r#"
        INSERT INTO invites (id, server_id, created_by, code, max_uses, use_count, expires_at, created_at)
        VALUES ($1, $2, $3, $4, $5, 0, $6, CURRENT_TIMESTAMP)
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(server_id)
    .bind(created_by)
    .bind(code)
    .bind(max_uses)
    .bind(expires_at)
    .fetch_one(pool)
    .await?;
    Ok(invite)
}

pub async fn find_invite_by_code(pool: &Pool, code: &str) -> AppResult<Option<Invite>> {
    let invite = sqlx::query_as::<_, Invite>("SELECT * FROM invites WHERE code = $1")
        .bind(code)
        .fetch_optional(pool)
        .await?;
    Ok(invite)
}

pub async fn get_server_invites(pool: &Pool, server_id: Uuid, limit: i64, offset: i64) -> AppResult<Vec<Invite>> {
    let invites = sqlx::query_as::<_, Invite>(
        "SELECT * FROM invites WHERE server_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(server_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok(invites)
}

pub async fn increment_invite_uses(pool: &Pool, invite_id: Uuid) -> AppResult<()> {
    sqlx::query("UPDATE invites SET use_count = use_count + 1 WHERE id = $1")
        .bind(invite_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_invite(pool: &Pool, invite_id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM invites WHERE id = $1")
        .bind(invite_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── Reactions ────────────────────────────────────────

/// Add a reaction. Returns the reaction (upsert — ignores if already exists).
pub async fn add_reaction(
    pool: &Pool,
    message_id: Uuid,
    user_id: Uuid,
    emoji: &str,
    sender_token: Option<&str>,
) -> AppResult<Reaction> {
    let reaction = sqlx::query_as::<_, Reaction>(
        r#"
        INSERT INTO reactions (message_id, user_id, emoji, sender_token)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (message_id, user_id, emoji) DO UPDATE SET created_at = reactions.created_at
        RETURNING *
        "#,
    )
    .bind(message_id)
    .bind(user_id)
    .bind(emoji)
    .bind(sender_token)
    .fetch_one(pool)
    .await?;
    Ok(reaction)
}

/// Remove a reaction. Returns true if a row was deleted.
pub async fn remove_reaction(
    pool: &Pool,
    message_id: Uuid,
    user_id: Uuid,
    emoji: &str,
) -> AppResult<bool> {
    let result = sqlx::query(
        "DELETE FROM reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3",
    )
    .bind(message_id)
    .bind(user_id)
    .bind(emoji)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Get all reactions for a set of message IDs, grouped by emoji.
pub async fn get_reactions_for_messages(
    pool: &Pool,
    message_ids: &[Uuid],
) -> AppResult<Vec<Reaction>> {
    if message_ids.is_empty() {
        return Ok(Vec::new());
    }

    // PostgreSQL supports ANY($1) with array binding; SQLite needs dynamic IN clause.
    #[cfg(feature = "postgres")]
    let reactions = sqlx::query_as::<_, Reaction>(
        "SELECT * FROM reactions WHERE message_id = ANY($1) ORDER BY created_at ASC",
    )
    .bind(message_ids)
    .fetch_all(pool)
    .await?;

    #[cfg(feature = "sqlite")]
    let reactions = {
        let placeholders: Vec<String> = (1..=message_ids.len()).map(|i| format!("${}", i)).collect();
        let sql = format!(
            "SELECT * FROM reactions WHERE message_id IN ({}) ORDER BY created_at ASC",
            placeholders.join(", ")
        );
        let mut query = sqlx::query_as::<_, Reaction>(&sql);
        for id in message_ids {
            query = query.bind(id);
        }
        query.fetch_all(pool).await?
    };

    Ok(reactions)
}

/// Get all reactions for a specific message (for resolving who reacted).
pub async fn get_reactions_for_message(
    pool: &Pool,
    message_id: Uuid,
) -> AppResult<Vec<Reaction>> {
    let reactions = sqlx::query_as::<_, Reaction>(
        "SELECT * FROM reactions WHERE message_id = $1 ORDER BY created_at ASC",
    )
    .bind(message_id)
    .fetch_all(pool)
    .await?;
    Ok(reactions)
}

// ─── Sender Key Distributions ─────────────────────────

/// Store a batch of encrypted SKDMs for a channel.
pub async fn insert_sender_key_distributions(
    pool: &Pool,
    channel_id: Uuid,
    from_user_id: Uuid,
    distributions: &[(Uuid, Uuid, Vec<u8>)], // (to_user_id, distribution_id, encrypted_skdm)
) -> AppResult<()> {
    let mut tx = pool.begin().await?;

    for (to_user_id, distribution_id, encrypted_skdm) in distributions {
        sqlx::query(
            r#"
            INSERT INTO sender_key_distributions
                (id, channel_id, from_user_id, to_user_id, distribution_id, encrypted_skdm, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
            ON CONFLICT (channel_id, from_user_id, to_user_id, distribution_id)
            DO UPDATE SET encrypted_skdm = EXCLUDED.encrypted_skdm, created_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(channel_id)
        .bind(from_user_id)
        .bind(to_user_id)
        .bind(distribution_id)
        .bind(encrypted_skdm)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

/// Fetch all pending SKDMs for a user in a specific channel.
pub async fn get_sender_key_distributions(
    pool: &Pool,
    channel_id: Uuid,
    to_user_id: Uuid,
) -> AppResult<Vec<SenderKeyDistribution>> {
    let rows = sqlx::query_as::<_, SenderKeyDistribution>(
        r#"
        SELECT * FROM sender_key_distributions
        WHERE channel_id = $1 AND to_user_id = $2
        ORDER BY created_at ASC
        "#,
    )
    .bind(channel_id)
    .bind(to_user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Delete all SKDMs targeting a user (used when their identity key changes).
pub async fn clear_sender_key_distributions_for_user(
    pool: &Pool,
    user_id: Uuid,
) -> AppResult<()> {
    sqlx::query("DELETE FROM sender_key_distributions WHERE to_user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete consumed SKDMs (after client has fetched them).
pub async fn delete_sender_key_distributions(
    pool: &Pool,
    ids: &[Uuid],
) -> AppResult<()> {
    if ids.is_empty() {
        return Ok(());
    }

    #[cfg(feature = "postgres")]
    {
        sqlx::query("DELETE FROM sender_key_distributions WHERE id = ANY($1)")
            .bind(ids)
            .execute(pool)
            .await?;
    }

    #[cfg(feature = "sqlite")]
    {
        let placeholders: Vec<String> = (1..=ids.len()).map(|i| format!("${}", i)).collect();
        let sql = format!(
            "DELETE FROM sender_key_distributions WHERE id IN ({})",
            placeholders.join(", ")
        );
        let mut query = sqlx::query(&sql);
        for id in ids {
            query = query.bind(id);
        }
        query.execute(pool).await?;
    }

    Ok(())
}

/// Get all channel member identity keys (for SKDM encryption).
/// Returns (user_id, identity_key) pairs for ALL members including the requester,
/// so users also receive their own SKDM and can decrypt their own messages after re-login.
/// For server channels, includes all server members (not just channel_members).
pub async fn get_channel_member_identity_keys(
    pool: &Pool,
    channel_id: Uuid,
    _requester_id: Uuid,
) -> AppResult<Vec<(Uuid, Vec<u8>)>> {
    let rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT DISTINCT u.id, u.identity_key FROM (
            SELECT cm.user_id FROM channel_members cm WHERE cm.channel_id = $1
            UNION
            SELECT sm.user_id FROM server_members sm
            JOIN channels c ON c.server_id = sm.server_id
            WHERE c.id = $1 AND c.server_id IS NOT NULL
        ) members
        JOIN users u ON u.id = members.user_id
        "#,
    )
    .bind(channel_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// ─── Server Members (extended) ────────────────────────

pub async fn get_server_members(
    pool: &Pool,
    server_id: Uuid,
    limit: i64,
    offset: i64,
) -> AppResult<Vec<ServerMemberResponse>> {
    // Step 1: Get members (paginated)
    #[allow(clippy::type_complexity)]
    let rows: Vec<(Uuid, String, Option<String>, Option<String>, DateTime<Utc>, Option<String>, Option<DateTime<Utc>>, bool)> =
        sqlx::query_as(
            r#"
            SELECT sm.user_id, u.username, u.display_name, u.avatar_url, sm.joined_at, sm.nickname, sm.timed_out_until, u.is_system
            FROM server_members sm
            INNER JOIN users u ON u.id = sm.user_id
            WHERE sm.server_id = $1
            ORDER BY sm.joined_at ASC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(server_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

    // Step 2: Get all role assignments for this server in one query
    let role_assignments: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT user_id, role_id FROM member_roles WHERE server_id = $1",
    )
    .bind(server_id)
    .fetch_all(pool)
    .await?;

    // Build a map: user_id -> Vec<role_id>
    let mut role_map: std::collections::HashMap<Uuid, Vec<Uuid>> =
        std::collections::HashMap::new();
    for (uid, rid) in role_assignments {
        role_map.entry(uid).or_default().push(rid);
    }

    Ok(rows
        .into_iter()
        .map(
            |(user_id, username, display_name, avatar_url, joined_at, nickname, timed_out_until, is_sys)| {
                // Only include timed_out_until if it's still in the future
                let active_timeout = timed_out_until.filter(|t| *t > Utc::now());
                ServerMemberResponse {
                    user_id,
                    username,
                    display_name,
                    avatar_url,
                    joined_at,
                    nickname,
                    role_ids: role_map.remove(&user_id).unwrap_or_default(),
                    timed_out_until: active_timeout,
                    is_system: if is_sys { Some(true) } else { None },
                }
            },
        )
        .collect())
}

pub async fn get_server_member_ids(pool: &Pool, server_id: Uuid) -> AppResult<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> =
        sqlx::query_as("SELECT user_id FROM server_members WHERE server_id = $1")
            .bind(server_id)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

pub async fn remove_server_member(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
) -> AppResult<()> {
    // Remove from all server channels
    sqlx::query(
        r#"
        DELETE FROM channel_members
        WHERE user_id = $1
          AND channel_id IN (SELECT id FROM channels WHERE server_id = $2)
        "#,
    )
    .bind(user_id)
    .bind(server_id)
    .execute(pool)
    .await?;

    // Remove from server
    sqlx::query("DELETE FROM server_members WHERE server_id = $1 AND user_id = $2")
        .bind(server_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn count_server_members(pool: &Pool, server_id: Uuid) -> AppResult<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM server_members WHERE server_id = $1")
        .bind(server_id)
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

pub async fn delete_server(pool: &Pool, server_id: Uuid) -> AppResult<()> {
    // All child tables use ON DELETE CASCADE, so this single delete
    // removes server_members, channels (→ messages, channel_members, etc.),
    // roles, member_roles, invites, bans, categories, etc.
    sqlx::query("DELETE FROM servers WHERE id = $1")
        .bind(server_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── Key Backups ─────────────────────────────────────

pub async fn upsert_key_backup(
    pool: &Pool,
    user_id: Uuid,
    encrypted_data: &[u8],
    nonce: &[u8],
    salt: &[u8],
    version: i32,
) -> AppResult<KeyBackup> {
    let backup = sqlx::query_as::<_, KeyBackup>(
        r#"
        INSERT INTO key_backups (id, user_id, encrypted_data, nonce, salt, version, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT (user_id) DO UPDATE SET
            encrypted_data = EXCLUDED.encrypted_data,
            nonce = EXCLUDED.nonce,
            salt = EXCLUDED.salt,
            version = EXCLUDED.version,
            updated_at = CURRENT_TIMESTAMP
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(encrypted_data)
    .bind(nonce)
    .bind(salt)
    .bind(version)
    .fetch_one(pool)
    .await?;
    Ok(backup)
}

pub async fn get_key_backup(pool: &Pool, user_id: Uuid) -> AppResult<Option<KeyBackup>> {
    let backup = sqlx::query_as::<_, KeyBackup>(
        "SELECT * FROM key_backups WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(backup)
}

pub async fn delete_key_backup(pool: &Pool, user_id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM key_backups WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── User Profiles ───────────────────────────────────

pub async fn update_user_profile(
    pool: &Pool,
    user_id: Uuid,
    display_name: Option<&str>,
    about_me: Option<&str>,
    custom_status: Option<&str>,
    custom_status_emoji: Option<&str>,
    encrypted_profile: Option<&[u8]>,
) -> AppResult<User> {
    let user = sqlx::query_as::<_, User>(
        r#"
        UPDATE users SET
            display_name = COALESCE($2, display_name),
            about_me = $3,
            custom_status = $4,
            custom_status_emoji = $5,
            encrypted_profile = COALESCE($6, encrypted_profile),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(display_name)
    .bind(about_me)
    .bind(custom_status)
    .bind(custom_status_emoji)
    .bind(encrypted_profile)
    .fetch_one(pool)
    .await?;
    Ok(user)
}

pub async fn update_user_avatar(pool: &Pool, user_id: Uuid, avatar_url: &str) -> AppResult<User> {
    let user = sqlx::query_as::<_, User>(
        "UPDATE users SET avatar_url = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *",
    )
    .bind(user_id)
    .bind(avatar_url)
    .fetch_one(pool)
    .await?;
    Ok(user)
}

pub async fn update_user_banner(pool: &Pool, user_id: Uuid, banner_url: &str) -> AppResult<User> {
    let user = sqlx::query_as::<_, User>(
        "UPDATE users SET banner_url = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *",
    )
    .bind(user_id)
    .bind(banner_url)
    .fetch_one(pool)
    .await?;
    Ok(user)
}

// ─── Blocked Users ───────────────────────────────────

pub async fn block_user(pool: &Pool, blocker_id: Uuid, blocked_id: Uuid) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO blocked_users (blocker_id, blocked_id)
        VALUES ($1, $2)
        ON CONFLICT (blocker_id, blocked_id) DO NOTHING
        "#,
    )
    .bind(blocker_id)
    .bind(blocked_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn unblock_user(pool: &Pool, blocker_id: Uuid, blocked_id: Uuid) -> AppResult<bool> {
    let result = sqlx::query("DELETE FROM blocked_users WHERE blocker_id = $1 AND blocked_id = $2")
        .bind(blocker_id)
        .bind(blocked_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn is_blocked(pool: &Pool, blocker_id: Uuid, blocked_id: Uuid) -> AppResult<bool> {
    let row: (bool,) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM blocked_users WHERE blocker_id = $1 AND blocked_id = $2)",
    )
    .bind(blocker_id)
    .bind(blocked_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn get_blocked_users(pool: &Pool, blocker_id: Uuid, limit: i64, offset: i64) -> AppResult<Vec<BlockedUserResponse>> {
    let rows = sqlx::query_as::<_, BlockedUserResponse>(
        r#"
        SELECT bu.blocked_id AS user_id, u.username, u.display_name, u.avatar_url, bu.created_at AS blocked_at
        FROM blocked_users bu
        INNER JOIN users u ON u.id = bu.blocked_id
        WHERE bu.blocker_id = $1
        ORDER BY bu.created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(blocker_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get_blocked_user_ids(pool: &Pool, blocker_id: Uuid) -> AppResult<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> =
        sqlx::query_as("SELECT blocked_id FROM blocked_users WHERE blocker_id = $1")
            .bind(blocker_id)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

// ─── Channel Categories ─────────────────────────────────

pub async fn create_category(
    pool: &Pool,
    server_id: Uuid,
    name: &str,
    position: i32,
) -> AppResult<ChannelCategory> {
    let cat = sqlx::query_as::<_, ChannelCategory>(
        r#"
        INSERT INTO channel_categories (server_id, name, position)
        VALUES ($1, $2, $3)
        RETURNING *
        "#,
    )
    .bind(server_id)
    .bind(name)
    .bind(position)
    .fetch_one(pool)
    .await?;
    Ok(cat)
}

pub async fn get_server_categories(pool: &Pool, server_id: Uuid) -> AppResult<Vec<ChannelCategory>> {
    let cats = sqlx::query_as::<_, ChannelCategory>(
        "SELECT * FROM channel_categories WHERE server_id = $1 ORDER BY position ASC",
    )
    .bind(server_id)
    .fetch_all(pool)
    .await?;
    Ok(cats)
}

pub async fn find_category_by_id(pool: &Pool, category_id: Uuid) -> AppResult<Option<ChannelCategory>> {
    let cat = sqlx::query_as::<_, ChannelCategory>(
        "SELECT * FROM channel_categories WHERE id = $1",
    )
    .bind(category_id)
    .fetch_optional(pool)
    .await?;
    Ok(cat)
}

pub async fn update_category(
    pool: &Pool,
    category_id: Uuid,
    name: Option<&str>,
    position: Option<i32>,
) -> AppResult<ChannelCategory> {
    let cat = sqlx::query_as::<_, ChannelCategory>(
        r#"
        UPDATE channel_categories
        SET name = COALESCE($2, name),
            position = COALESCE($3, position)
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(category_id)
    .bind(name)
    .bind(position)
    .fetch_one(pool)
    .await?;
    Ok(cat)
}

pub async fn delete_category(pool: &Pool, category_id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM channel_categories WHERE id = $1")
        .bind(category_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn reorder_categories(
    pool: &Pool,
    server_id: Uuid,
    order: &[(Uuid, i32)],
) -> AppResult<()> {
    let mut tx = pool.begin().await?;
    for (cat_id, pos) in order {
        sqlx::query(
            "UPDATE channel_categories SET position = $1 WHERE id = $2 AND server_id = $3",
        )
        .bind(pos)
        .bind(cat_id)
        .bind(server_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn reorder_channels(
    pool: &Pool,
    server_id: Uuid,
    order: &[(Uuid, i32, Option<Uuid>)],
) -> AppResult<()> {
    let mut tx = pool.begin().await?;
    for (channel_id, pos, category_id) in order {
        sqlx::query(
            "UPDATE channels SET position = $1, category_id = $2 WHERE id = $3 AND server_id = $4",
        )
        .bind(pos)
        .bind(category_id)
        .bind(channel_id)
        .bind(server_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn set_channel_category(
    pool: &Pool,
    channel_id: Uuid,
    category_id: Option<Uuid>,
) -> AppResult<Channel> {
    let channel = sqlx::query_as::<_, Channel>(
        r#"
        UPDATE channels SET category_id = $2 WHERE id = $1 RETURNING *
        "#,
    )
    .bind(channel_id)
    .bind(category_id)
    .fetch_one(pool)
    .await?;
    Ok(channel)
}

// ─── Roles ──────────────────────────────────────────────

pub async fn create_role(
    pool: &Pool,
    server_id: Uuid,
    name: &str,
    color: Option<&str>,
    permissions: i64,
    position: i32,
    is_default: bool,
) -> AppResult<Role> {
    let role = sqlx::query_as::<_, Role>(
        r#"
        INSERT INTO roles (server_id, name, color, permissions, position, is_default)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#,
    )
    .bind(server_id)
    .bind(name)
    .bind(color)
    .bind(permissions)
    .bind(position)
    .bind(is_default)
    .fetch_one(pool)
    .await?;
    Ok(role)
}

pub async fn get_server_roles(pool: &Pool, server_id: Uuid) -> AppResult<Vec<Role>> {
    let roles = sqlx::query_as::<_, Role>(
        "SELECT * FROM roles WHERE server_id = $1 ORDER BY position ASC",
    )
    .bind(server_id)
    .fetch_all(pool)
    .await?;
    Ok(roles)
}

pub async fn find_role_by_id(pool: &Pool, role_id: Uuid) -> AppResult<Option<Role>> {
    let role = sqlx::query_as::<_, Role>("SELECT * FROM roles WHERE id = $1")
        .bind(role_id)
        .fetch_optional(pool)
        .await?;
    Ok(role)
}

pub async fn find_default_role(pool: &Pool, server_id: Uuid) -> AppResult<Option<Role>> {
    let role = sqlx::query_as::<_, Role>(
        "SELECT * FROM roles WHERE server_id = $1 AND is_default = TRUE LIMIT 1",
    )
    .bind(server_id)
    .fetch_optional(pool)
    .await?;
    Ok(role)
}

pub async fn update_role(
    pool: &Pool,
    role_id: Uuid,
    name: Option<&str>,
    color: Option<Option<&str>>,
    permissions: Option<i64>,
    position: Option<i32>,
) -> AppResult<Role> {
    let role = sqlx::query_as::<_, Role>(
        r#"
        UPDATE roles
        SET name = COALESCE($2, name),
            color = CASE WHEN $3::bool THEN $4 ELSE color END,
            permissions = COALESCE($5, permissions),
            position = COALESCE($6, position)
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(role_id)
    .bind(name)
    .bind(color.is_some())                             // $3: should we update color?
    .bind(color.flatten())                             // $4: new color value (nullable)
    .bind(permissions)
    .bind(position)
    .fetch_one(pool)
    .await?;
    Ok(role)
}

pub async fn delete_role(pool: &Pool, role_id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM roles WHERE id = $1")
        .bind(role_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── Member Roles ────────────────────────────────────────

pub async fn assign_role(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
    role_id: Uuid,
) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO member_roles (server_id, user_id, role_id)
        VALUES ($1, $2, $3)
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(server_id)
    .bind(user_id)
    .bind(role_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn remove_role(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
    role_id: Uuid,
) -> AppResult<()> {
    sqlx::query(
        "DELETE FROM member_roles WHERE server_id = $1 AND user_id = $2 AND role_id = $3",
    )
    .bind(server_id)
    .bind(user_id)
    .bind(role_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_member_role_ids(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT role_id FROM member_roles WHERE server_id = $1 AND user_id = $2",
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

pub async fn get_member_roles(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<Role>> {
    let roles = sqlx::query_as::<_, Role>(
        r#"
        SELECT r.* FROM roles r
        INNER JOIN member_roles mr ON r.id = mr.role_id
        WHERE mr.server_id = $1 AND mr.user_id = $2
        ORDER BY r.position ASC
        "#,
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(roles)
}

// ─── Permission Computation ─────────────────────────────

/// Get a member's effective server-level permissions.
/// Returns (is_owner, effective_permissions).
pub async fn get_member_permissions(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
) -> AppResult<(bool, i64)> {
    use crate::permissions;

    let server = find_server_by_id(pool, server_id)
        .await?
        .ok_or(AppError::NotFound("Server not found".into()))?;

    let is_owner = server.owner_id == user_id;

    // Get @everyone role
    let everyone = find_default_role(pool, server_id).await?;
    let everyone_perms = everyone.as_ref().map(|r| r.permissions).unwrap_or(permissions::DEFAULT_PERMISSIONS);

    // Get member's additional roles
    let member_roles = get_member_roles(pool, server_id, user_id).await?;
    let member_role_perms: Vec<i64> = member_roles.iter().map(|r| r.permissions).collect();

    let effective = permissions::compute_server_permissions(is_owner, everyone_perms, &member_role_perms);
    Ok((is_owner, effective))
}

/// Cached variant — checks cache first, falls back to DB, caches for 2 min.
pub async fn get_member_permissions_cached(
    pool: &Pool,
    redis: &mut Option<redis::aio::ConnectionManager>,
    memory: &crate::memory_store::MemoryStore,
    server_id: Uuid,
    user_id: Uuid,
) -> AppResult<(bool, i64)> {
    let key = format!("haven:perms:{}:{}", server_id, user_id);
    if let Some((is_owner, perms)) = crate::cache::get_cached::<(bool, i64)>(redis.as_mut(), memory, &key).await {
        return Ok((is_owner, perms));
    }
    let result = get_member_permissions(pool, server_id, user_id).await?;
    crate::cache::set_cached(redis.as_mut(), memory, &key, &result, 120).await;
    Ok(result)
}

/// Check if a user has a required permission on a server. Returns error if not.
pub async fn require_server_permission(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
    required: i64,
) -> AppResult<()> {
    use crate::permissions;

    let (_, effective) = get_member_permissions(pool, server_id, user_id).await?;
    if !permissions::has_permission(effective, required) {
        return Err(AppError::Forbidden("Missing required permission".into()));
    }
    Ok(())
}

// ─── Channel Permission Overwrites ──────────────────────

pub async fn get_channel_overwrites(
    pool: &Pool,
    channel_id: Uuid,
) -> AppResult<Vec<ChannelPermissionOverwrite>> {
    let rows = sqlx::query_as::<_, ChannelPermissionOverwrite>(
        "SELECT * FROM channel_permission_overwrites WHERE channel_id = $1",
    )
    .bind(channel_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn set_channel_overwrite(
    pool: &Pool,
    channel_id: Uuid,
    target_type: &str,
    target_id: Uuid,
    allow_bits: i64,
    deny_bits: i64,
) -> AppResult<ChannelPermissionOverwrite> {
    let row = sqlx::query_as::<_, ChannelPermissionOverwrite>(
        r#"
        INSERT INTO channel_permission_overwrites (channel_id, target_type, target_id, allow_bits, deny_bits)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (channel_id, target_type, target_id)
        DO UPDATE SET allow_bits = $4, deny_bits = $5
        RETURNING *
        "#,
    )
    .bind(channel_id)
    .bind(target_type)
    .bind(target_id)
    .bind(allow_bits)
    .bind(deny_bits)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

pub async fn delete_channel_overwrite(
    pool: &Pool,
    channel_id: Uuid,
    target_type: &str,
    target_id: Uuid,
) -> AppResult<()> {
    sqlx::query(
        "DELETE FROM channel_permission_overwrites WHERE channel_id = $1 AND target_type = $2 AND target_id = $3",
    )
    .bind(channel_id)
    .bind(target_type)
    .bind(target_id)
    .execute(pool)
    .await?;
    Ok(())
}

// ─── Friends ──────────────────────────────────────────────

pub async fn send_friend_request(
    pool: &Pool,
    requester_id: Uuid,
    addressee_id: Uuid,
) -> AppResult<Friendship> {
    let friendship = sqlx::query_as::<_, Friendship>(
        r#"
        INSERT INTO friendships (requester_id, addressee_id, status)
        VALUES ($1, $2, 'pending')
        RETURNING *
        "#,
    )
    .bind(requester_id)
    .bind(addressee_id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref db_err) if db_err.constraint().is_some() => {
            AppError::Validation("Friend request already exists".into())
        }
        other => AppError::Database(other),
    })?;
    Ok(friendship)
}

pub async fn find_friendship_by_id(pool: &Pool, id: Uuid) -> AppResult<Option<Friendship>> {
    let f = sqlx::query_as::<_, Friendship>("SELECT * FROM friendships WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(f)
}

/// Find a friendship between two users (in either direction).
pub async fn find_friendship(pool: &Pool, user_a: Uuid, user_b: Uuid) -> AppResult<Option<Friendship>> {
    let f = sqlx::query_as::<_, Friendship>(
        r#"
        SELECT * FROM friendships
        WHERE (requester_id = $1 AND addressee_id = $2)
           OR (requester_id = $2 AND addressee_id = $1)
        LIMIT 1
        "#,
    )
    .bind(user_a)
    .bind(user_b)
    .fetch_optional(pool)
    .await?;
    Ok(f)
}

pub async fn accept_friend_request(pool: &Pool, friendship_id: Uuid) -> AppResult<Friendship> {
    let f = sqlx::query_as::<_, Friendship>(
        r#"
        UPDATE friendships SET status = 'accepted', updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(friendship_id)
    .fetch_one(pool)
    .await?;
    Ok(f)
}

pub async fn delete_friendship(pool: &Pool, friendship_id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM friendships WHERE id = $1")
        .bind(friendship_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn are_friends(pool: &Pool, user_a: Uuid, user_b: Uuid) -> AppResult<bool> {
    let row: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM friendships
            WHERE status = 'accepted'
              AND ((requester_id = $1 AND addressee_id = $2) OR (requester_id = $2 AND addressee_id = $1))
        )
        "#,
    )
    .bind(user_a)
    .bind(user_b)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Check if two users share any server.
pub async fn share_server(pool: &Pool, user_a: Uuid, user_b: Uuid) -> AppResult<bool> {
    let row: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM server_members sm1
            INNER JOIN server_members sm2 ON sm1.server_id = sm2.server_id
            WHERE sm1.user_id = $1 AND sm2.user_id = $2
        )
        "#,
    )
    .bind(user_a)
    .bind(user_b)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn get_friends_list(pool: &Pool, user_id: Uuid, limit: i64, offset: i64) -> AppResult<Vec<FriendResponse>> {
    let friends: Vec<FriendResponse> = sqlx::query_as::<_, FriendResponse>(
        r#"
        SELECT * FROM (
            SELECT f.id, f.addressee_id AS user_id, u.username, u.display_name, u.avatar_url,
                   f.status, FALSE AS is_incoming, f.created_at,
                   CASE WHEN u.is_system THEN TRUE ELSE NULL END AS is_system
            FROM friendships f
            INNER JOIN users u ON u.id = f.addressee_id
            WHERE f.requester_id = $1
            UNION ALL
            SELECT f.id, f.requester_id AS user_id, u.username, u.display_name, u.avatar_url,
                   f.status, TRUE AS is_incoming, f.created_at,
                   CASE WHEN u.is_system THEN TRUE ELSE NULL END AS is_system
            FROM friendships f
            INNER JOIN users u ON u.id = f.requester_id
            WHERE f.addressee_id = $1
        ) AS combined
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(friends)
}

pub async fn set_export_allowed(pool: &Pool, channel_id: Uuid, allowed: bool) -> AppResult<()> {
    sqlx::query("UPDATE channels SET export_allowed = $2 WHERE id = $1")
        .bind(channel_id)
        .bind(allowed)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_dm_status(pool: &Pool, channel_id: Uuid, status: &str) -> AppResult<()> {
    sqlx::query("UPDATE channels SET dm_status = $2 WHERE id = $1")
        .bind(channel_id)
        .bind(status)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_pending_dm_channels(pool: &Pool, user_id: Uuid) -> AppResult<Vec<Channel>> {
    let channels = sqlx::query_as::<_, Channel>(
        r#"
        SELECT c.* FROM channels c
        INNER JOIN channel_members cm ON c.id = cm.channel_id
        WHERE cm.user_id = $1 AND c.channel_type = 'dm' AND c.dm_status = 'pending'
        ORDER BY c.created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(channels)
}

// ─── Mutual Friends / Servers ───────────────────────────

pub async fn get_mutual_friends(
    pool: &Pool,
    viewer_id: Uuid,
    target_id: Uuid,
) -> AppResult<Vec<MutualFriendInfo>> {
    let friends = sqlx::query_as::<_, MutualFriendInfo>(
        r#"
        SELECT u.id AS user_id, u.username, u.display_name, u.avatar_url
        FROM users u
        WHERE u.id != $1 AND u.id != $2
          AND EXISTS (
            SELECT 1 FROM friendships f WHERE f.status = 'accepted'
              AND ((f.requester_id = $1 AND f.addressee_id = u.id)
                OR (f.requester_id = u.id AND f.addressee_id = $1))
          )
          AND EXISTS (
            SELECT 1 FROM friendships f WHERE f.status = 'accepted'
              AND ((f.requester_id = $2 AND f.addressee_id = u.id)
                OR (f.requester_id = u.id AND f.addressee_id = $2))
          )
        LIMIT 10
        "#,
    )
    .bind(viewer_id)
    .bind(target_id)
    .fetch_all(pool)
    .await?;
    Ok(friends)
}

pub async fn get_mutual_server_count(
    pool: &Pool,
    viewer_id: Uuid,
    target_id: Uuid,
) -> AppResult<i64> {
    let row: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM server_members sm1
        INNER JOIN server_members sm2 ON sm1.server_id = sm2.server_id
        WHERE sm1.user_id = $1 AND sm2.user_id = $2
        "#,
    )
    .bind(viewer_id)
    .bind(target_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn update_dm_privacy(pool: &Pool, user_id: Uuid, dm_privacy: &str) -> AppResult<()> {
    sqlx::query("UPDATE users SET dm_privacy = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1")
        .bind(user_id)
        .bind(dm_privacy)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── Bans ──────────────────────────────────────────────

pub async fn create_ban(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
    reason: Option<&str>,
    banned_by: Uuid,
) -> AppResult<crate::models::Ban> {
    let ban = sqlx::query_as::<_, crate::models::Ban>(
        "INSERT INTO bans (server_id, user_id, reason, banned_by) VALUES ($1, $2, $3, $4) RETURNING *"
    )
    .bind(server_id)
    .bind(user_id)
    .bind(reason)
    .bind(banned_by)
    .fetch_one(pool)
    .await?;
    Ok(ban)
}

pub async fn remove_ban(pool: &Pool, server_id: Uuid, user_id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM bans WHERE server_id = $1 AND user_id = $2")
        .bind(server_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_bans(pool: &Pool, server_id: Uuid, limit: i64, offset: i64) -> AppResult<Vec<crate::models::BanResponse>> {
    let rows = sqlx::query_as::<_, (Uuid, Uuid, Option<String>, Uuid, chrono::DateTime<chrono::Utc>, String)>(
        "SELECT b.id, b.user_id, b.reason, b.banned_by, b.created_at, u.username \
         FROM bans b JOIN users u ON u.id = b.user_id \
         WHERE b.server_id = $1 ORDER BY b.created_at DESC LIMIT $2 OFFSET $3"
    )
    .bind(server_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(id, user_id, reason, banned_by, created_at, username)| {
        crate::models::BanResponse {
            id,
            user_id,
            username,
            reason,
            banned_by,
            created_at: created_at.to_rfc3339(),
        }
    }).collect())
}

pub async fn is_banned(pool: &Pool, server_id: Uuid, user_id: Uuid) -> AppResult<bool> {
    let row: (bool,) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM bans WHERE server_id = $1 AND user_id = $2)"
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

// ─── Pinned Messages ────────────────────────────────

pub async fn pin_message(
    pool: &Pool,
    channel_id: Uuid,
    message_id: Uuid,
    pinned_by: Uuid,
) -> AppResult<PinnedMessage> {
    // Cap at 50 pins per channel
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM pinned_messages WHERE channel_id = $1"
    )
    .bind(channel_id)
    .fetch_one(pool)
    .await?;
    if count.0 >= 50 {
        return Err(AppError::Validation("Channel has reached the maximum of 50 pinned messages".into()));
    }

    let pin = sqlx::query_as::<_, PinnedMessage>(
        r#"
        INSERT INTO pinned_messages (channel_id, message_id, pinned_by)
        VALUES ($1, $2, $3)
        ON CONFLICT (channel_id, message_id) DO NOTHING
        RETURNING *
        "#,
    )
    .bind(channel_id)
    .bind(message_id)
    .bind(pinned_by)
    .fetch_optional(pool)
    .await?;

    pin.ok_or_else(|| AppError::Validation("Message is already pinned".into()))
}

pub async fn unpin_message(
    pool: &Pool,
    channel_id: Uuid,
    message_id: Uuid,
) -> AppResult<bool> {
    let result = sqlx::query(
        "DELETE FROM pinned_messages WHERE channel_id = $1 AND message_id = $2"
    )
    .bind(channel_id)
    .bind(message_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn get_pinned_messages(
    pool: &Pool,
    channel_id: Uuid,
) -> AppResult<Vec<Message>> {
    let rows = sqlx::query_as::<_, Message>(
        r#"
        SELECT m.*
        FROM pinned_messages pm
        JOIN messages m ON m.id = pm.message_id
        WHERE pm.channel_id = $1
        ORDER BY pm.pinned_at DESC
        "#,
    )
    .bind(channel_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get_pinned_message_ids(
    pool: &Pool,
    channel_id: Uuid,
) -> AppResult<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT message_id FROM pinned_messages WHERE channel_id = $1 ORDER BY pinned_at DESC"
    )
    .bind(channel_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

// ─── Reports ────────────────────────────────────────

pub async fn create_report(
    pool: &Pool,
    reporter_id: Uuid,
    message_id: Uuid,
    channel_id: Uuid,
    reason: &str,
) -> AppResult<Report> {
    // Rate limit: max 5 reports per user per hour
    #[cfg(feature = "postgres")]
    let count_sql = "SELECT COUNT(*) FROM reports WHERE reporter_id = $1 AND created_at > CURRENT_TIMESTAMP - INTERVAL '1 hour'";
    #[cfg(feature = "sqlite")]
    let count_sql = "SELECT COUNT(*) FROM reports WHERE reporter_id = $1 AND created_at > datetime('now', '-1 hour')";

    let count: (i64,) = sqlx::query_as(count_sql)
        .bind(reporter_id)
        .fetch_one(pool)
        .await?;
    if count.0 >= 5 {
        return Err(AppError::Validation("You can only submit 5 reports per hour".into()));
    }

    let report = sqlx::query_as::<_, Report>(
        r#"
        INSERT INTO reports (reporter_id, message_id, channel_id, reason)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        "#,
    )
    .bind(reporter_id)
    .bind(message_id)
    .bind(channel_id)
    .bind(reason)
    .fetch_one(pool)
    .await?;
    Ok(report)
}

// ─── System Messages ────────────────────────────────

/// Insert a system message (plaintext, not encrypted).
pub async fn insert_system_message(
    pool: &Pool,
    channel_id: Uuid,
    body: &str,
) -> AppResult<Message> {
    let msg = sqlx::query_as::<_, Message>(
        r#"
        INSERT INTO messages (id, channel_id, sender_token, encrypted_body,
                             timestamp, has_attachments, message_type)
        VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, false, 'system')
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(channel_id)
    .bind(Vec::<u8>::new()) // empty sender_token
    .bind(body.as_bytes())
    .fetch_one(pool)
    .await?;
    Ok(msg)
}

// ─── Server Nicknames ────────────────────────────────

pub async fn update_member_nickname(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
    nickname: Option<&str>,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE server_members SET nickname = $1 WHERE server_id = $2 AND user_id = $3",
    )
    .bind(nickname)
    .bind(server_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

// ─── Profile Key Distribution ───────────────────────

pub async fn distribute_profile_keys_bulk(
    pool: &Pool,
    from_user_id: Uuid,
    distributions: &[(Uuid, Vec<u8>)],
) -> AppResult<()> {
    for (to_user_id, encrypted_key) in distributions {
        sqlx::query(
            r#"
            INSERT INTO profile_key_distributions (from_user_id, to_user_id, encrypted_profile_key)
            VALUES ($1, $2, $3)
            ON CONFLICT (from_user_id, to_user_id)
            DO UPDATE SET encrypted_profile_key = EXCLUDED.encrypted_profile_key,
                          created_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(from_user_id)
        .bind(to_user_id)
        .bind(encrypted_key)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn get_profile_key(
    pool: &Pool,
    from_user_id: Uuid,
    to_user_id: Uuid,
) -> AppResult<Option<ProfileKeyDistribution>> {
    let dist = sqlx::query_as::<_, ProfileKeyDistribution>(
        r#"
        SELECT id, from_user_id, to_user_id, encrypted_profile_key, created_at
        FROM profile_key_distributions
        WHERE from_user_id = $1 AND to_user_id = $2
        "#,
    )
    .bind(from_user_id)
    .bind(to_user_id)
    .fetch_optional(pool)
    .await?;
    Ok(dist)
}

// ─── Custom Emojis ───────────────────────────────────

pub async fn list_server_emojis(pool: &Pool, server_id: Uuid) -> AppResult<Vec<CustomEmoji>> {
    let emojis = sqlx::query_as::<_, CustomEmoji>(
        "SELECT * FROM custom_emojis WHERE server_id = $1 ORDER BY created_at",
    )
    .bind(server_id)
    .fetch_all(pool)
    .await?;
    Ok(emojis)
}

pub async fn get_emoji_by_id(pool: &Pool, emoji_id: Uuid) -> AppResult<Option<CustomEmoji>> {
    let emoji = sqlx::query_as::<_, CustomEmoji>("SELECT * FROM custom_emojis WHERE id = $1")
        .bind(emoji_id)
        .fetch_optional(pool)
        .await?;
    Ok(emoji)
}

/// Returns (static_count, animated_count) for a server's custom emojis.
pub async fn count_server_emojis(pool: &Pool, server_id: Uuid) -> AppResult<(i64, i64)> {
    let row: (i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE NOT animated),
            COUNT(*) FILTER (WHERE animated)
        FROM custom_emojis
        WHERE server_id = $1
        "#,
    )
    .bind(server_id)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

pub async fn create_emoji(
    pool: &Pool,
    id: Uuid,
    server_id: Uuid,
    name: &str,
    uploaded_by: Uuid,
    animated: bool,
    storage_key: &str,
) -> AppResult<CustomEmoji> {
    let emoji = sqlx::query_as::<_, CustomEmoji>(
        r#"
        INSERT INTO custom_emojis (id, server_id, name, uploaded_by, animated, storage_key)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(server_id)
    .bind(name)
    .bind(uploaded_by)
    .bind(animated)
    .bind(storage_key)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref db_err) if db_err.constraint() == Some("custom_emojis_server_id_name_key") => {
            AppError::Validation(format!("An emoji named '{}' already exists in this server", name))
        }
        other => AppError::Database(other),
    })?;
    Ok(emoji)
}

/// Delete an emoji and return it (for storage cleanup).
pub async fn delete_emoji(pool: &Pool, emoji_id: Uuid) -> AppResult<Option<CustomEmoji>> {
    let emoji = sqlx::query_as::<_, CustomEmoji>(
        "DELETE FROM custom_emojis WHERE id = $1 RETURNING *",
    )
    .bind(emoji_id)
    .fetch_optional(pool)
    .await?;
    Ok(emoji)
}

pub async fn rename_emoji(pool: &Pool, emoji_id: Uuid, new_name: &str) -> AppResult<CustomEmoji> {
    let emoji = sqlx::query_as::<_, CustomEmoji>(
        r#"
        UPDATE custom_emojis SET name = $2 WHERE id = $1 RETURNING *
        "#,
    )
    .bind(emoji_id)
    .bind(new_name)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Emoji not found".into()))?;
    Ok(emoji)
}

// ─── Servers (ownership) ────────────────────────────

pub async fn get_servers_owned_by(pool: &Pool, user_id: Uuid) -> AppResult<Vec<Server>> {
    let servers = sqlx::query_as::<_, Server>(
        "SELECT * FROM servers WHERE owner_id = $1",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(servers)
}

// ─── Member Timeouts ─────────────────────────────────

pub async fn set_member_timeout(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
    timed_out_until: Option<DateTime<Utc>>,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE server_members SET timed_out_until = $1 WHERE server_id = $2 AND user_id = $3",
    )
    .bind(timed_out_until)
    .bind(server_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn is_member_timed_out(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
) -> AppResult<bool> {
    let row: (bool,) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM server_members WHERE server_id = $1 AND user_id = $2 AND timed_out_until > NOW())",
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

// ─── Channel Hide/Unhide ─────────────────────────────

pub async fn set_channel_member_hidden(
    pool: &Pool,
    channel_id: Uuid,
    user_id: Uuid,
    hidden: bool,
) -> AppResult<()> {
    sqlx::query("UPDATE channel_members SET hidden = $3 WHERE channel_id = $1 AND user_id = $2")
        .bind(channel_id)
        .bind(user_id)
        .bind(hidden)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn unhide_channel_for_members(
    pool: &Pool,
    channel_id: Uuid,
) -> AppResult<()> {
    sqlx::query("UPDATE channel_members SET hidden = FALSE WHERE channel_id = $1 AND hidden = TRUE")
        .bind(channel_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── Audit Log ───────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn insert_audit_log(
    pool: &Pool,
    server_id: Uuid,
    actor_id: Uuid,
    action: &str,
    target_type: Option<&str>,
    target_id: Option<Uuid>,
    changes: Option<&serde_json::Value>,
    reason: Option<&str>,
) -> AppResult<AuditLogEntry> {
    let entry = sqlx::query_as::<_, AuditLogEntry>(
        r#"
        INSERT INTO audit_log (server_id, actor_id, action, target_type, target_id, changes, reason)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        "#,
    )
    .bind(server_id)
    .bind(actor_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(changes)
    .bind(reason)
    .fetch_one(pool)
    .await?;
    Ok(entry)
}

pub async fn get_audit_log(
    pool: &Pool,
    server_id: Uuid,
    limit: i64,
    before: Option<DateTime<Utc>>,
) -> AppResult<Vec<AuditLogResponse>> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(Uuid, Uuid, String, String, Option<String>, Option<Uuid>, Option<serde_json::Value>, Option<String>, DateTime<Utc>)> = if let Some(before_ts) = before {
        sqlx::query_as(
            r#"
            SELECT al.id, al.actor_id, u.username, al.action, al.target_type, al.target_id, al.changes, al.reason, al.created_at
            FROM audit_log al
            INNER JOIN users u ON u.id = al.actor_id
            WHERE al.server_id = $1 AND al.created_at < $2
            ORDER BY al.created_at DESC
            LIMIT $3
            "#,
        )
        .bind(server_id)
        .bind(before_ts)
        .bind(limit)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT al.id, al.actor_id, u.username, al.action, al.target_type, al.target_id, al.changes, al.reason, al.created_at
            FROM audit_log al
            INNER JOIN users u ON u.id = al.actor_id
            WHERE al.server_id = $1
            ORDER BY al.created_at DESC
            LIMIT $2
            "#,
        )
        .bind(server_id)
        .bind(limit)
        .fetch_all(pool)
        .await?
    };

    Ok(rows
        .into_iter()
        .map(|(id, actor_id, actor_username, action, target_type, target_id, changes, reason, created_at)| {
            AuditLogResponse {
                id,
                actor_id,
                actor_username,
                action,
                target_type,
                target_id,
                changes,
                reason,
                created_at,
            }
        })
        .collect())
}

// ─── Bulk Message Delete ─────────────────────────────

pub async fn bulk_delete_messages(
    pool: &Pool,
    channel_id: Uuid,
    message_ids: &[Uuid],
) -> AppResult<Vec<Uuid>> {
    // Delete child rows first (no FK cascades on partitioned messages table)
    sqlx::query("DELETE FROM attachments WHERE message_id = ANY($1)")
        .bind(message_ids)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM reactions WHERE message_id = ANY($1)")
        .bind(message_ids)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM pinned_messages WHERE message_id = ANY($1)")
        .bind(message_ids)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM reports WHERE message_id = ANY($1)")
        .bind(message_ids)
        .execute(pool)
        .await?;

    // Delete messages and return IDs that were actually deleted
    let deleted: Vec<(Uuid,)> = sqlx::query_as(
        "DELETE FROM messages WHERE id = ANY($1) AND channel_id = $2 RETURNING id",
    )
    .bind(message_ids)
    .bind(channel_id)
    .fetch_all(pool)
    .await?;

    Ok(deleted.into_iter().map(|(id,)| id).collect())
}

// ─── Read States ─────────────────────────────────────

/// Upsert the user's read position in a channel (sets last_read_at = NOW()).
pub async fn upsert_read_state(
    pool: &Pool,
    user_id: Uuid,
    channel_id: Uuid,
) -> AppResult<ReadState> {
    let state = sqlx::query_as::<_, ReadState>(
        r#"
        INSERT INTO read_states (user_id, channel_id, last_read_at)
        VALUES ($1, $2, CURRENT_TIMESTAMP)
        ON CONFLICT (user_id, channel_id) DO UPDATE
        SET last_read_at = CURRENT_TIMESTAMP
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(channel_id)
    .fetch_one(pool)
    .await?;
    Ok(state)
}

/// Bulk fetch read states for a user across multiple channels.
pub async fn get_user_read_states(
    pool: &Pool,
    user_id: Uuid,
    channel_ids: &[Uuid],
) -> AppResult<Vec<ReadState>> {
    if channel_ids.is_empty() {
        return Ok(vec![]);
    }
    let states = sqlx::query_as::<_, ReadState>(
        "SELECT * FROM read_states WHERE user_id = $1 AND channel_id = ANY($2)",
    )
    .bind(user_id)
    .bind(channel_ids)
    .fetch_all(pool)
    .await?;
    Ok(states)
}

/// Get the last message ID + timestamp for each of the given channels.
pub async fn get_channel_last_message_ids(
    pool: &Pool,
    channel_ids: &[Uuid],
) -> AppResult<Vec<(Uuid, Uuid, DateTime<Utc>)>> {
    if channel_ids.is_empty() {
        return Ok(vec![]);
    }
    let rows: Vec<(Uuid, Uuid, DateTime<Utc>)> = sqlx::query_as(
        r#"
        SELECT DISTINCT ON (channel_id) channel_id, id, timestamp
        FROM messages
        WHERE channel_id = ANY($1)
          AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
        ORDER BY channel_id, timestamp DESC
        "#,
    )
    .bind(channel_ids)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Get unread message counts for a user across multiple channels.
pub async fn get_user_unread_counts(
    pool: &Pool,
    user_id: Uuid,
    channel_ids: &[Uuid],
) -> AppResult<Vec<(Uuid, i64)>> {
    if channel_ids.is_empty() {
        return Ok(vec![]);
    }
    let rows: Vec<(Uuid, i64)> = sqlx::query_as(
        r#"
        SELECT m.channel_id, COUNT(*)
        FROM messages m
        LEFT JOIN read_states rs ON rs.user_id = $1 AND rs.channel_id = m.channel_id
        WHERE m.channel_id = ANY($2)
          AND (rs.last_read_at IS NULL OR m.timestamp > rs.last_read_at)
          AND (m.expires_at IS NULL OR m.expires_at > CURRENT_TIMESTAMP)
        GROUP BY m.channel_id
        "#,
    )
    .bind(user_id)
    .bind(channel_ids)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// ─── Admin Dashboard ────────────────────────────────────

pub async fn count_all_users(pool: &Pool) -> AppResult<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

pub async fn count_all_servers(pool: &Pool) -> AppResult<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM servers")
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

pub async fn count_all_channels(pool: &Pool) -> AppResult<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM channels")
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

pub async fn count_all_messages(pool: &Pool) -> AppResult<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM messages")
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

pub async fn search_users_admin(
    pool: &Pool,
    search: Option<&str>,
    limit: i64,
    offset: i64,
) -> AppResult<Vec<AdminUserResponse>> {
    let rows = sqlx::query_as::<_, AdminUserResponse>(
        r#"
        SELECT u.id, u.username, u.display_name, u.avatar_url,
               u.created_at, u.is_instance_admin,
               COALESCE(sc.cnt, 0) AS server_count
        FROM users u
        LEFT JOIN (
            SELECT user_id, COUNT(*) AS cnt FROM server_members GROUP BY user_id
        ) sc ON sc.user_id = u.id
        WHERE ($1::TEXT IS NULL OR u.username ILIKE '%' || $1 || '%'
               OR u.display_name ILIKE '%' || $1 || '%')
        ORDER BY u.created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(search)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn set_instance_admin(pool: &Pool, user_id: Uuid, is_admin: bool) -> AppResult<()> {
    sqlx::query("UPDATE users SET is_instance_admin = $1 WHERE id = $2")
        .bind(is_admin)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_user_account(pool: &Pool, user_id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn is_first_user(pool: &Pool) -> AppResult<bool> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    // Count is 1 when the user just created is the only one
    Ok(row.0 <= 1)
}

/// Check if no users exist yet (called BEFORE user creation for invite bypass).
pub async fn is_first_user_precheck(pool: &Pool) -> AppResult<bool> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    Ok(row.0 == 0)
}

// ─── Registration Invites (instance-level) ────────────

pub async fn find_registration_invite_by_code(
    pool: &Pool,
    code: &str,
) -> AppResult<Option<RegistrationInvite>> {
    let invite = sqlx::query_as::<_, RegistrationInvite>(
        "SELECT * FROM registration_invites WHERE code = $1",
    )
    .bind(code)
    .fetch_optional(pool)
    .await?;
    Ok(invite)
}

pub async fn consume_registration_invite(
    pool: &Pool,
    invite_id: Uuid,
    user_id: Uuid,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE registration_invites SET used_by = $1, used_at = NOW() WHERE id = $2 AND used_by IS NULL",
    )
    .bind(user_id)
    .bind(invite_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn create_registration_invites(
    pool: &Pool,
    created_by: Option<Uuid>,
    count: u32,
) -> AppResult<Vec<RegistrationInvite>> {
    let mut invites = Vec::new();
    for _ in 0..count {
        let code = crate::crypto::generate_invite_code();
        let invite = sqlx::query_as::<_, RegistrationInvite>(
            r#"INSERT INTO registration_invites (id, code, created_by, created_at)
               VALUES ($1, $2, $3, NOW())
               RETURNING *"#,
        )
        .bind(Uuid::new_v4())
        .bind(&code)
        .bind(created_by)
        .fetch_one(pool)
        .await?;
        invites.push(invite);
    }
    Ok(invites)
}

pub async fn list_registration_invites_by_user(
    pool: &Pool,
    user_id: Uuid,
) -> AppResult<Vec<RegistrationInvite>> {
    let invites = sqlx::query_as::<_, RegistrationInvite>(
        "SELECT * FROM registration_invites WHERE created_by = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(invites)
}

pub async fn count_registration_invites_by_user(
    pool: &Pool,
    user_id: Uuid,
) -> AppResult<i64> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM registration_invites WHERE created_by = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn list_all_registration_invites(
    pool: &Pool,
    limit: i64,
    offset: i64,
) -> AppResult<Vec<RegistrationInvite>> {
    let invites = sqlx::query_as::<_, RegistrationInvite>(
        "SELECT * FROM registration_invites ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok(invites)
}

/// Count beta codes (registration invites with created_by = NULL).
pub async fn count_beta_codes(pool: &Pool) -> AppResult<i64> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM registration_invites WHERE created_by IS NULL",
    )
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Create a beta invite (created_by = NULL, with expiry).
pub async fn create_beta_invite(pool: &Pool, expiry_days: i64) -> AppResult<RegistrationInvite> {
    let code = crate::crypto::generate_invite_code();
    let invite = sqlx::query_as::<_, RegistrationInvite>(
        r#"INSERT INTO registration_invites (id, code, created_by, expires_at, created_at)
           VALUES ($1, $2, NULL, NOW() + make_interval(days => $3), NOW())
           RETURNING *"#,
    )
    .bind(Uuid::new_v4())
    .bind(&code)
    .bind(expiry_days as i32)
    .fetch_one(pool)
    .await?;
    Ok(invite)
}

pub async fn delete_registration_invite(pool: &Pool, invite_id: Uuid) -> AppResult<bool> {
    let result = sqlx::query(
        "DELETE FROM registration_invites WHERE id = $1 AND used_by IS NULL",
    )
    .bind(invite_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

// ─── System user / server helpers ─────────────────────

/// Find the system server (is_system = TRUE).
pub async fn find_system_server(pool: &Pool) -> AppResult<Option<Server>> {
    let server = sqlx::query_as::<_, Server>(
        "SELECT * FROM servers WHERE is_system = TRUE LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(server)
}

/// Find the system user (is_system = TRUE).
pub async fn find_system_user(pool: &Pool) -> AppResult<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE is_system = TRUE LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(user)
}

/// Set the system_channel_id on a server (used during per-user server creation).
pub async fn set_server_system_channel(pool: &Pool, server_id: Uuid, channel_id: Uuid) -> AppResult<()> {
    sqlx::query("UPDATE servers SET system_channel_id = $1 WHERE id = $2")
        .bind(channel_id)
        .bind(server_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Create an auto-accepted friendship (bypasses the request/accept flow).
pub async fn create_accepted_friendship(pool: &Pool, user_a: Uuid, user_b: Uuid) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO friendships (id, requester_id, addressee_id, status, created_at, updated_at)
        VALUES (gen_random_uuid(), $1, $2, 'accepted', NOW(), NOW())
        ON CONFLICT (requester_id, addressee_id) DO NOTHING
        "#,
    )
    .bind(user_a)
    .bind(user_b)
    .execute(pool)
    .await?;
    Ok(())
}
