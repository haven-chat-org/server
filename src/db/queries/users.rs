use uuid::Uuid;

use crate::db::Pool;
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

/// Lightweight user lookup excluding key material and auth fields.
/// Use when handler only needs display info (username, avatar, admin status).
pub async fn find_user_basic_by_id(pool: &Pool, id: Uuid) -> AppResult<Option<UserBasic>> {
    let user = sqlx::query_as::<_, UserBasic>(
        "SELECT id, username, display_name, avatar_url, about_me, \
         custom_status, custom_status_emoji, banner_url, dm_privacy, \
         is_instance_admin, is_system, created_at, updated_at \
         FROM users WHERE id = $1"
    )
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
