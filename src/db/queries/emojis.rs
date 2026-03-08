use uuid::Uuid;

use crate::db::Pool;
use crate::errors::{AppError, AppResult};
use crate::models::*;

// ─── Custom Emojis ───────────────────────────────────

pub async fn list_server_emojis(pool: &Pool, server_id: Uuid) -> AppResult<Vec<CustomEmoji>> {
    let emojis = sqlx::query_as::<_, CustomEmoji>(
        "SELECT * FROM custom_emojis WHERE server_id = $1 ORDER BY created_at",
    )
    .bind(server_id)
    .fetch_all(pool)
    .await?;
    Ok(emojis)
}

pub async fn get_emoji_by_id(pool: &Pool, emoji_id: Uuid) -> AppResult<Option<CustomEmoji>> {
    let emoji = sqlx::query_as::<_, CustomEmoji>("SELECT * FROM custom_emojis WHERE id = $1")
        .bind(emoji_id)
        .fetch_optional(pool)
        .await?;
    Ok(emoji)
}

/// Returns (static_count, animated_count) for a server's custom emojis.
pub async fn count_server_emojis(pool: &Pool, server_id: Uuid) -> AppResult<(i64, i64)> {
    let row: (i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE NOT animated),
            COUNT(*) FILTER (WHERE animated)
        FROM custom_emojis
        WHERE server_id = $1
        "#,
    )
    .bind(server_id)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

pub async fn create_emoji(
    pool: &Pool,
    id: Uuid,
    server_id: Uuid,
    name: &str,
    uploaded_by: Uuid,
    animated: bool,
    storage_key: &str,
) -> AppResult<CustomEmoji> {
    let emoji = sqlx::query_as::<_, CustomEmoji>(
        r#"
        INSERT INTO custom_emojis (id, server_id, name, uploaded_by, animated, storage_key)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(server_id)
    .bind(name)
    .bind(uploaded_by)
    .bind(animated)
    .bind(storage_key)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref db_err) if db_err.constraint() == Some("custom_emojis_server_id_name_key") => {
            AppError::Validation(format!("An emoji named '{}' already exists in this server", name))
        }
        other => AppError::Database(other),
    })?;
    Ok(emoji)
}

/// Delete an emoji and return it (for storage cleanup).
pub async fn delete_emoji(pool: &Pool, emoji_id: Uuid) -> AppResult<Option<CustomEmoji>> {
    let emoji = sqlx::query_as::<_, CustomEmoji>(
        "DELETE FROM custom_emojis WHERE id = $1 RETURNING *",
    )
    .bind(emoji_id)
    .fetch_optional(pool)
    .await?;
    Ok(emoji)
}

pub async fn rename_emoji(pool: &Pool, emoji_id: Uuid, new_name: &str) -> AppResult<CustomEmoji> {
    let emoji = sqlx::query_as::<_, CustomEmoji>(
        r#"
        UPDATE custom_emojis SET name = $2 WHERE id = $1 RETURNING *
        "#,
    )
    .bind(emoji_id)
    .bind(new_name)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Emoji not found".into()))?;
    Ok(emoji)
}
