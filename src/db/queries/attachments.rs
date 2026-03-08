use uuid::Uuid;

use crate::db::Pool;
use crate::errors::AppResult;
use crate::models::*;

// ─── Attachments ───────────────────────────────────────

/// Link an attachment (uploaded via presigned URL) to a message.
pub async fn link_attachment(
    pool: &Pool,
    attachment_id: Uuid,
    message_id: Uuid,
    storage_key: &str,
    file_hash: Option<&str>,
) -> AppResult<Attachment> {
    let att = sqlx::query_as::<_, Attachment>(
        r#"
        INSERT INTO attachments (id, message_id, storage_key, encrypted_meta, size_bucket, created_at, file_hash)
        VALUES ($1, $2, $3, $4, 0, CURRENT_TIMESTAMP, $5)
        RETURNING *
        "#,
    )
    .bind(attachment_id)
    .bind(message_id)
    .bind(storage_key)
    .bind(&[] as &[u8])
    .bind(file_hash)
    .fetch_one(pool)
    .await?;
    Ok(att)
}

pub async fn find_attachment_by_id(pool: &Pool, id: Uuid) -> AppResult<Option<Attachment>> {
    let att = sqlx::query_as::<_, Attachment>("SELECT * FROM attachments WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(att)
}

pub async fn insert_attachment(
    pool: &Pool,
    message_id: Uuid,
    storage_key: &str,
    encrypted_meta: &[u8],
    size_bucket: i32,
    file_hash: Option<&str>,
) -> AppResult<Attachment> {
    let att = sqlx::query_as::<_, Attachment>(
        r#"
        INSERT INTO attachments (id, message_id, storage_key, encrypted_meta, size_bucket, created_at, file_hash)
        VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, $6)
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(message_id)
    .bind(storage_key)
    .bind(encrypted_meta)
    .bind(size_bucket)
    .bind(file_hash)
    .fetch_one(pool)
    .await?;
    Ok(att)
}

// ─── Blocked Hashes ──────────────────────────────────

pub async fn is_hash_blocked(pool: &Pool, hash: &str) -> AppResult<bool> {
    let row: (bool,) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM blocked_hashes WHERE hash = $1)",
    )
    .bind(hash)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn list_blocked_hashes(
    pool: &Pool,
    limit: i64,
    offset: i64,
) -> AppResult<Vec<BlockedHashResponse>> {
    let rows = sqlx::query_as::<_, (Uuid, String, Option<String>, Uuid, chrono::DateTime<chrono::Utc>, String)>(
        r#"
        SELECT bh.id, bh.hash, bh.description, bh.added_by, bh.created_at, u.username
        FROM blocked_hashes bh
        JOIN users u ON u.id = bh.added_by
        ORDER BY bh.created_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(id, hash, description, _added_by, created_at, username)| BlockedHashResponse {
            id,
            hash,
            description,
            added_by_username: username,
            created_at: created_at.to_rfc3339(),
        })
        .collect())
}

pub async fn create_blocked_hash(
    pool: &Pool,
    hash: &str,
    description: Option<&str>,
    added_by: Uuid,
) -> AppResult<BlockedHash> {
    let bh = sqlx::query_as::<_, BlockedHash>(
        r#"
        INSERT INTO blocked_hashes (hash, description, added_by)
        VALUES ($1, $2, $3)
        RETURNING *
        "#,
    )
    .bind(hash)
    .bind(description)
    .bind(added_by)
    .fetch_one(pool)
    .await?;
    Ok(bh)
}

pub async fn delete_blocked_hash(pool: &Pool, hash_id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM blocked_hashes WHERE id = $1")
        .bind(hash_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn count_blocked_hashes(pool: &Pool) -> AppResult<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM blocked_hashes")
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

pub async fn find_attachments_by_hash(pool: &Pool, hash: &str) -> AppResult<Vec<Attachment>> {
    let atts = sqlx::query_as::<_, Attachment>(
        "SELECT * FROM attachments WHERE file_hash = $1",
    )
    .bind(hash)
    .fetch_all(pool)
    .await?;
    Ok(atts)
}
