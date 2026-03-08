use uuid::Uuid;

use crate::db::Pool;
use crate::errors::AppResult;
use crate::models::*;

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

pub async fn update_channel_ttl(
    pool: &Pool,
    channel_id: Uuid,
    message_ttl: Option<i32>,
) -> AppResult<Channel> {
    let ch = sqlx::query_as::<_, Channel>(
        "UPDATE channels SET message_ttl = $1 WHERE id = $2 RETURNING *",
    )
    .bind(message_ttl)
    .bind(channel_id)
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
