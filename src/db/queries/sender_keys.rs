use uuid::Uuid;

use crate::db::Pool;
use crate::errors::AppResult;
use crate::models::*;

// ─── Sender Key Distributions ─────────────────────────

/// Store a batch of encrypted SKDMs for a channel.
pub async fn insert_sender_key_distributions(
    pool: &Pool,
    channel_id: Uuid,
    from_user_id: Uuid,
    distributions: &[(Uuid, Uuid, Vec<u8>)], // (to_user_id, distribution_id, encrypted_skdm)
) -> AppResult<()> {
    let mut tx = pool.begin().await?;

    for (to_user_id, distribution_id, encrypted_skdm) in distributions {
        sqlx::query(
            r#"
            INSERT INTO sender_key_distributions
                (id, channel_id, from_user_id, to_user_id, distribution_id, encrypted_skdm, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
            ON CONFLICT (channel_id, from_user_id, to_user_id, distribution_id)
            DO UPDATE SET encrypted_skdm = EXCLUDED.encrypted_skdm, created_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(channel_id)
        .bind(from_user_id)
        .bind(to_user_id)
        .bind(distribution_id)
        .bind(encrypted_skdm)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

/// Fetch all pending SKDMs for a user in a specific channel.
pub async fn get_sender_key_distributions(
    pool: &Pool,
    channel_id: Uuid,
    to_user_id: Uuid,
) -> AppResult<Vec<SenderKeyDistribution>> {
    let rows = sqlx::query_as::<_, SenderKeyDistribution>(
        r#"
        SELECT * FROM sender_key_distributions
        WHERE channel_id = $1 AND to_user_id = $2
        ORDER BY created_at ASC
        "#,
    )
    .bind(channel_id)
    .bind(to_user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Delete all SKDMs targeting a user (used when their identity key changes).
pub async fn clear_sender_key_distributions_for_user(
    pool: &Pool,
    user_id: Uuid,
) -> AppResult<()> {
    sqlx::query("DELETE FROM sender_key_distributions WHERE to_user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete consumed SKDMs (after client has fetched them).
pub async fn delete_sender_key_distributions(
    pool: &Pool,
    ids: &[Uuid],
) -> AppResult<()> {
    if ids.is_empty() {
        return Ok(());
    }

    #[cfg(feature = "postgres")]
    {
        sqlx::query("DELETE FROM sender_key_distributions WHERE id = ANY($1)")
            .bind(ids)
            .execute(pool)
            .await?;
    }

    #[cfg(feature = "sqlite")]
    {
        let placeholders: Vec<String> = (1..=ids.len()).map(|i| format!("${}", i)).collect();
        let sql = format!(
            "DELETE FROM sender_key_distributions WHERE id IN ({})",
            placeholders.join(", ")
        );
        let mut query = sqlx::query(&sql);
        for id in ids {
            query = query.bind(id);
        }
        query.execute(pool).await?;
    }

    Ok(())
}

/// Get all channel member identity keys (for SKDM encryption).
/// Returns (user_id, identity_key) pairs for ALL members including the requester,
/// so users also receive their own SKDM and can decrypt their own messages after re-login.
/// For server channels, includes all server members (not just channel_members).
pub async fn get_channel_member_identity_keys(
    pool: &Pool,
    channel_id: Uuid,
    _requester_id: Uuid,
) -> AppResult<Vec<(Uuid, Vec<u8>)>> {
    let rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT DISTINCT u.id, u.identity_key FROM (
            SELECT cm.user_id FROM channel_members cm WHERE cm.channel_id = $1
            UNION
            SELECT sm.user_id FROM server_members sm
            JOIN channels c ON c.server_id = sm.server_id
            WHERE c.id = $1 AND c.server_id IS NOT NULL
        ) members
        JOIN users u ON u.id = members.user_id
        "#,
    )
    .bind(channel_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// ─── Profile Key Distribution ───────────────────────

pub async fn distribute_profile_keys_bulk(
    pool: &Pool,
    from_user_id: Uuid,
    distributions: &[(Uuid, Vec<u8>)],
) -> AppResult<()> {
    for (to_user_id, encrypted_key) in distributions {
        sqlx::query(
            r#"
            INSERT INTO profile_key_distributions (from_user_id, to_user_id, encrypted_profile_key)
            VALUES ($1, $2, $3)
            ON CONFLICT (from_user_id, to_user_id)
            DO UPDATE SET encrypted_profile_key = EXCLUDED.encrypted_profile_key,
                          created_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(from_user_id)
        .bind(to_user_id)
        .bind(encrypted_key)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn get_profile_key(
    pool: &Pool,
    from_user_id: Uuid,
    to_user_id: Uuid,
) -> AppResult<Option<ProfileKeyDistribution>> {
    let dist = sqlx::query_as::<_, ProfileKeyDistribution>(
        r#"
        SELECT id, from_user_id, to_user_id, encrypted_profile_key, created_at
        FROM profile_key_distributions
        WHERE from_user_id = $1 AND to_user_id = $2
        "#,
    )
    .bind(from_user_id)
    .bind(to_user_id)
    .fetch_optional(pool)
    .await?;
    Ok(dist)
}
