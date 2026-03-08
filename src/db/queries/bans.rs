use uuid::Uuid;

use crate::db::Pool;
use crate::errors::AppResult;

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

// ─── Instance Bans ───────────────────────────────────

pub async fn create_instance_ban(
    pool: &Pool,
    user_id: Uuid,
    reason: Option<&str>,
    banned_by: Uuid,
) -> AppResult<crate::models::InstanceBan> {
    let ban = sqlx::query_as::<_, crate::models::InstanceBan>(
        "INSERT INTO instance_bans (user_id, reason, banned_by) VALUES ($1, $2, $3) RETURNING *",
    )
    .bind(user_id)
    .bind(reason)
    .bind(banned_by)
    .fetch_one(pool)
    .await?;
    Ok(ban)
}

pub async fn remove_instance_ban(pool: &Pool, user_id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM instance_bans WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_instance_bans(
    pool: &Pool,
    limit: i64,
    offset: i64,
) -> AppResult<Vec<crate::models::InstanceBanResponse>> {
    let rows = sqlx::query_as::<_, (Uuid, Uuid, Option<String>, Uuid, chrono::DateTime<chrono::Utc>, String, String)>(
        r#"
        SELECT ib.id, ib.user_id, ib.reason, ib.banned_by, ib.created_at,
               u.username, admin.username
        FROM instance_bans ib
        JOIN users u ON u.id = ib.user_id
        JOIN users admin ON admin.id = ib.banned_by
        ORDER BY ib.created_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(id, user_id, reason, banned_by, created_at, username, banned_by_username)| {
        crate::models::InstanceBanResponse {
            id,
            user_id,
            username,
            reason,
            banned_by,
            banned_by_username,
            created_at: created_at.to_rfc3339(),
        }
    }).collect())
}

pub async fn is_instance_banned(pool: &Pool, user_id: Uuid) -> AppResult<bool> {
    let row: (bool,) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM instance_bans WHERE user_id = $1)",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}
