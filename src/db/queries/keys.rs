use uuid::Uuid;

use crate::db::Pool;
use crate::errors::AppResult;
use crate::models::*;

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
