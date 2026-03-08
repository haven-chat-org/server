use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::Pool;
use crate::errors::AppResult;
use crate::models::*;

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
