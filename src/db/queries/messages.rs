use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::Pool;
use crate::errors::{AppError, AppResult};
use crate::models::*;

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

/// Collect channel_id + message_id pairs for expired messages (before purging).
/// Used by the purge worker to broadcast MessagesExpired events.
pub async fn get_expired_message_ids(pool: &Pool) -> AppResult<Vec<(Uuid, Uuid)>> {
    let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT channel_id, id FROM messages WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP"
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Clear the expires_at field on a message (e.g., when pinning).
pub async fn clear_message_expiry(pool: &Pool, message_id: Uuid) -> AppResult<()> {
    sqlx::query("UPDATE messages SET expires_at = NULL WHERE id = $1")
        .bind(message_id)
        .execute(pool)
        .await?;
    Ok(())
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
