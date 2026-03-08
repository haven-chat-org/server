use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::Pool;
use crate::errors::AppResult;
use crate::models::*;

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
