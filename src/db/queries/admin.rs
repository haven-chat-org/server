use uuid::Uuid;

use crate::db::Pool;
use crate::errors::{AppError, AppResult};
use crate::models::*;

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

// ─── Admin Report Triage ─────────────────────────────

pub async fn list_reports_admin(
    pool: &Pool,
    status_filter: Option<&str>,
    limit: i64,
    offset: i64,
) -> AppResult<Vec<crate::models::AdminReportResponse>> {
    let rows = if let Some(status) = status_filter {
        sqlx::query_as::<_, (Uuid, Uuid, String, Uuid, Uuid, String, String, Option<Uuid>, Option<chrono::DateTime<chrono::Utc>>, Option<String>, Option<String>, Option<chrono::DateTime<chrono::Utc>>, Option<Uuid>, chrono::DateTime<chrono::Utc>)>(
            r#"
            SELECT r.id, r.reporter_id, u.username, r.message_id, r.channel_id, r.reason, r.status,
                   r.reviewed_by, r.reviewed_at, r.admin_notes,
                   r.escalated_to, r.escalated_at, r.escalated_by, r.created_at
            FROM reports r
            JOIN users u ON u.id = r.reporter_id
            WHERE r.status = $1
            ORDER BY r.created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(status)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, (Uuid, Uuid, String, Uuid, Uuid, String, String, Option<Uuid>, Option<chrono::DateTime<chrono::Utc>>, Option<String>, Option<String>, Option<chrono::DateTime<chrono::Utc>>, Option<Uuid>, chrono::DateTime<chrono::Utc>)>(
            r#"
            SELECT r.id, r.reporter_id, u.username, r.message_id, r.channel_id, r.reason, r.status,
                   r.reviewed_by, r.reviewed_at, r.admin_notes,
                   r.escalated_to, r.escalated_at, r.escalated_by, r.created_at
            FROM reports r
            JOIN users u ON u.id = r.reporter_id
            ORDER BY r.created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    };

    Ok(rows.into_iter().map(|(id, reporter_id, reporter_username, message_id, channel_id, reason, status, reviewed_by, reviewed_at, admin_notes, escalated_to, escalated_at, escalated_by, created_at)| {
        crate::models::AdminReportResponse {
            id,
            reporter_id,
            reporter_username,
            message_id,
            channel_id,
            reason,
            status,
            reviewed_by,
            reviewed_at,
            admin_notes,
            escalated_to,
            escalated_at,
            escalated_by,
            created_at,
        }
    }).collect())
}

pub async fn get_report_admin(
    pool: &Pool,
    report_id: Uuid,
) -> AppResult<Option<crate::models::AdminReportResponse>> {
    let row = sqlx::query_as::<_, (Uuid, Uuid, String, Uuid, Uuid, String, String, Option<Uuid>, Option<chrono::DateTime<chrono::Utc>>, Option<String>, Option<String>, Option<chrono::DateTime<chrono::Utc>>, Option<Uuid>, chrono::DateTime<chrono::Utc>)>(
        r#"
        SELECT r.id, r.reporter_id, u.username, r.message_id, r.channel_id, r.reason, r.status,
               r.reviewed_by, r.reviewed_at, r.admin_notes,
               r.escalated_to, r.escalated_at, r.escalated_by, r.created_at
        FROM reports r
        JOIN users u ON u.id = r.reporter_id
        WHERE r.id = $1
        "#,
    )
    .bind(report_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|(id, reporter_id, reporter_username, message_id, channel_id, reason, status, reviewed_by, reviewed_at, admin_notes, escalated_to, escalated_at, escalated_by, created_at)| {
        crate::models::AdminReportResponse {
            id,
            reporter_id,
            reporter_username,
            message_id,
            channel_id,
            reason,
            status,
            reviewed_by,
            reviewed_at,
            admin_notes,
            escalated_to,
            escalated_at,
            escalated_by,
            created_at,
        }
    }))
}

pub async fn update_report_status(
    pool: &Pool,
    report_id: Uuid,
    status: &str,
    reviewed_by: Uuid,
    admin_notes: Option<&str>,
) -> AppResult<()> {
    sqlx::query(
        r#"
        UPDATE reports
        SET status = $1, reviewed_by = $2, reviewed_at = NOW(), admin_notes = $3
        WHERE id = $4
        "#,
    )
    .bind(status)
    .bind(reviewed_by)
    .bind(admin_notes)
    .bind(report_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn escalate_report(
    pool: &Pool,
    report_id: Uuid,
    escalated_by: Uuid,
) -> AppResult<()> {
    sqlx::query(
        r#"
        UPDATE reports
        SET status = 'escalated_ncmec', escalated_to = 'ncmec', escalated_at = NOW(),
            escalated_by = $1, reviewed_by = $1, reviewed_at = NOW()
        WHERE id = $2
        "#,
    )
    .bind(escalated_by)
    .bind(report_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn count_reports_by_status(pool: &Pool) -> AppResult<crate::models::ReportCounts> {
    let row: (i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE status = 'pending') AS pending,
            COUNT(*) FILTER (WHERE status = 'reviewed') AS reviewed,
            COUNT(*) FILTER (WHERE status = 'dismissed') AS dismissed,
            COUNT(*) FILTER (WHERE status = 'escalated_ncmec') AS escalated
        FROM reports
        "#,
    )
    .fetch_one(pool)
    .await?;
    Ok(crate::models::ReportCounts {
        pending: row.0,
        reviewed: row.1,
        dismissed: row.2,
        escalated: row.3,
    })
}

// ─── Content Filters ─────────────────────────────────

pub async fn list_content_filters(
    pool: &Pool,
    server_id: Uuid,
) -> AppResult<Vec<crate::models::ContentFilter>> {
    let filters = sqlx::query_as::<_, crate::models::ContentFilter>(
        "SELECT * FROM content_filters WHERE server_id = $1 ORDER BY created_at ASC",
    )
    .bind(server_id)
    .fetch_all(pool)
    .await?;
    Ok(filters)
}

pub async fn create_content_filter(
    pool: &Pool,
    server_id: Uuid,
    pattern: &str,
    filter_type: &str,
    action: &str,
    created_by: Uuid,
) -> AppResult<crate::models::ContentFilter> {
    let filter = sqlx::query_as::<_, crate::models::ContentFilter>(
        r#"
        INSERT INTO content_filters (server_id, pattern, filter_type, action, created_by)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        "#,
    )
    .bind(server_id)
    .bind(pattern)
    .bind(filter_type)
    .bind(action)
    .bind(created_by)
    .fetch_one(pool)
    .await?;
    Ok(filter)
}

pub async fn delete_content_filter(
    pool: &Pool,
    filter_id: Uuid,
    server_id: Uuid,
) -> AppResult<()> {
    sqlx::query("DELETE FROM content_filters WHERE id = $1 AND server_id = $2")
        .bind(filter_id)
        .bind(server_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn count_content_filters(pool: &Pool, server_id: Uuid) -> AppResult<i64> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM content_filters WHERE server_id = $1",
    )
    .bind(server_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}
