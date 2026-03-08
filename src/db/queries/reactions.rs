use uuid::Uuid;

use crate::db::Pool;
use crate::errors::AppResult;
use crate::models::*;

// ─── Reactions ────────────────────────────────────────

/// Add a reaction. Returns the reaction (upsert — ignores if already exists).
pub async fn add_reaction(
    pool: &Pool,
    message_id: Uuid,
    user_id: Uuid,
    emoji: &str,
    sender_token: Option<&str>,
) -> AppResult<Reaction> {
    let reaction = sqlx::query_as::<_, Reaction>(
        r#"
        INSERT INTO reactions (message_id, user_id, emoji, sender_token)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (message_id, user_id, emoji) DO UPDATE SET created_at = reactions.created_at
        RETURNING *
        "#,
    )
    .bind(message_id)
    .bind(user_id)
    .bind(emoji)
    .bind(sender_token)
    .fetch_one(pool)
    .await?;
    Ok(reaction)
}

/// Remove a reaction. Returns true if a row was deleted.
pub async fn remove_reaction(
    pool: &Pool,
    message_id: Uuid,
    user_id: Uuid,
    emoji: &str,
) -> AppResult<bool> {
    let result = sqlx::query(
        "DELETE FROM reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3",
    )
    .bind(message_id)
    .bind(user_id)
    .bind(emoji)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Get all reactions for a set of message IDs, grouped by emoji.
pub async fn get_reactions_for_messages(
    pool: &Pool,
    message_ids: &[Uuid],
) -> AppResult<Vec<Reaction>> {
    if message_ids.is_empty() {
        return Ok(Vec::new());
    }

    // PostgreSQL supports ANY($1) with array binding; SQLite needs dynamic IN clause.
    #[cfg(feature = "postgres")]
    let reactions = sqlx::query_as::<_, Reaction>(
        "SELECT * FROM reactions WHERE message_id = ANY($1) ORDER BY created_at ASC",
    )
    .bind(message_ids)
    .fetch_all(pool)
    .await?;

    #[cfg(feature = "sqlite")]
    let reactions = {
        let placeholders: Vec<String> = (1..=message_ids.len()).map(|i| format!("${}", i)).collect();
        let sql = format!(
            "SELECT * FROM reactions WHERE message_id IN ({}) ORDER BY created_at ASC",
            placeholders.join(", ")
        );
        let mut query = sqlx::query_as::<_, Reaction>(&sql);
        for id in message_ids {
            query = query.bind(id);
        }
        query.fetch_all(pool).await?
    };

    Ok(reactions)
}

/// Get all reactions for a specific message (for resolving who reacted).
pub async fn get_reactions_for_message(
    pool: &Pool,
    message_id: Uuid,
) -> AppResult<Vec<Reaction>> {
    let reactions = sqlx::query_as::<_, Reaction>(
        "SELECT * FROM reactions WHERE message_id = $1 ORDER BY created_at ASC",
    )
    .bind(message_id)
    .fetch_all(pool)
    .await?;
    Ok(reactions)
}
