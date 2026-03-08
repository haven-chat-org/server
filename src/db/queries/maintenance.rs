use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::Pool;
use crate::errors::AppResult;
use crate::models::*;

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
