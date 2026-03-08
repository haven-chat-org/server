use uuid::Uuid;

use crate::db::Pool;
use crate::errors::AppResult;
use crate::models::*;

// ─── Pre-Keys ──────────────────────────────────────────

pub async fn insert_prekeys(pool: &Pool, user_id: Uuid, keys: &[(i32, Vec<u8>)]) -> AppResult<()> {
    // Batch insert using a transaction
    let mut tx = pool.begin().await?;

    for (key_id, public_key) in keys {
        sqlx::query(
            r#"
            INSERT INTO prekeys (id, user_id, key_id, public_key, used, created_at)
            VALUES ($1, $2, $3, $4, false, CURRENT_TIMESTAMP)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(key_id)
        .bind(public_key)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

/// Fetch and consume one unused one-time prekey (marks it as used atomically).
pub async fn consume_prekey(pool: &Pool, user_id: Uuid) -> AppResult<Option<PreKey>> {
    let prekey = sqlx::query_as::<_, PreKey>(
        r#"
        UPDATE prekeys SET used = true
        WHERE id = (
            SELECT id FROM prekeys
            WHERE user_id = $1 AND used = false
            ORDER BY created_at ASC
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        )
        RETURNING *
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(prekey)
}

pub async fn count_unused_prekeys(pool: &Pool, user_id: Uuid) -> AppResult<i64> {
    let row: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM prekeys WHERE user_id = $1 AND used = false")
            .bind(user_id)
            .fetch_one(pool)
            .await?;
    Ok(row.0)
}

/// Delete all unused one-time prekeys for a user.
/// Called on login before uploading fresh prekeys so the server only has
/// OTPs whose private keys exist in the client's current MemoryStore.
pub async fn delete_unused_prekeys(pool: &Pool, user_id: Uuid) -> AppResult<i64> {
    let result = sqlx::query("DELETE FROM prekeys WHERE user_id = $1 AND used = false")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() as i64)
}
