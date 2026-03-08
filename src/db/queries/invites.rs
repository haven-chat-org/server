use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::Pool;
use crate::errors::AppResult;
use crate::models::*;

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

/// Check if a beta code already exists for the given email hash.
pub async fn beta_code_exists_for_email(pool: &Pool, email_hash: &str) -> AppResult<bool> {
    let row: (bool,) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM registration_invites WHERE email_hash = $1)",
    )
    .bind(email_hash)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Create a beta invite (created_by = NULL, with expiry and email hash).
pub async fn create_beta_invite(pool: &Pool, expiry_days: i64, email_hash: &str) -> AppResult<RegistrationInvite> {
    let code = crate::crypto::generate_invite_code();
    let invite = sqlx::query_as::<_, RegistrationInvite>(
        r#"INSERT INTO registration_invites (id, code, created_by, expires_at, created_at, email_hash)
           VALUES ($1, $2, NULL, NOW() + make_interval(days => $3), NOW(), $4)
           RETURNING *"#,
    )
    .bind(Uuid::new_v4())
    .bind(&code)
    .bind(expiry_days as i32)
    .bind(email_hash)
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
