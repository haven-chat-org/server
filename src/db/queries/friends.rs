use uuid::Uuid;

use crate::db::Pool;
use crate::errors::{AppError, AppResult};
use crate::models::*;

// ─── Friends ──────────────────────────────────────────────

pub async fn send_friend_request(
    pool: &Pool,
    requester_id: Uuid,
    addressee_id: Uuid,
) -> AppResult<Friendship> {
    let friendship = sqlx::query_as::<_, Friendship>(
        r#"
        INSERT INTO friendships (requester_id, addressee_id, status)
        VALUES ($1, $2, 'pending')
        RETURNING *
        "#,
    )
    .bind(requester_id)
    .bind(addressee_id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref db_err) if db_err.constraint().is_some() => {
            AppError::Validation("Friend request already exists".into())
        }
        other => AppError::Database(other),
    })?;
    Ok(friendship)
}

pub async fn find_friendship_by_id(pool: &Pool, id: Uuid) -> AppResult<Option<Friendship>> {
    let f = sqlx::query_as::<_, Friendship>("SELECT * FROM friendships WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(f)
}

/// Find a friendship between two users (in either direction).
pub async fn find_friendship(pool: &Pool, user_a: Uuid, user_b: Uuid) -> AppResult<Option<Friendship>> {
    let f = sqlx::query_as::<_, Friendship>(
        r#"
        SELECT * FROM friendships
        WHERE (requester_id = $1 AND addressee_id = $2)
           OR (requester_id = $2 AND addressee_id = $1)
        LIMIT 1
        "#,
    )
    .bind(user_a)
    .bind(user_b)
    .fetch_optional(pool)
    .await?;
    Ok(f)
}

pub async fn accept_friend_request(pool: &Pool, friendship_id: Uuid) -> AppResult<Friendship> {
    let f = sqlx::query_as::<_, Friendship>(
        r#"
        UPDATE friendships SET status = 'accepted', updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(friendship_id)
    .fetch_one(pool)
    .await?;
    Ok(f)
}

pub async fn delete_friendship(pool: &Pool, friendship_id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM friendships WHERE id = $1")
        .bind(friendship_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn are_friends(pool: &Pool, user_a: Uuid, user_b: Uuid) -> AppResult<bool> {
    let row: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM friendships
            WHERE status = 'accepted'
              AND ((requester_id = $1 AND addressee_id = $2) OR (requester_id = $2 AND addressee_id = $1))
        )
        "#,
    )
    .bind(user_a)
    .bind(user_b)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Check if two users share any server.
pub async fn share_server(pool: &Pool, user_a: Uuid, user_b: Uuid) -> AppResult<bool> {
    let row: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM server_members sm1
            INNER JOIN server_members sm2 ON sm1.server_id = sm2.server_id
            WHERE sm1.user_id = $1 AND sm2.user_id = $2
        )
        "#,
    )
    .bind(user_a)
    .bind(user_b)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn get_friends_list(pool: &Pool, user_id: Uuid, limit: i64, offset: i64) -> AppResult<Vec<FriendResponse>> {
    let friends: Vec<FriendResponse> = sqlx::query_as::<_, FriendResponse>(
        r#"
        SELECT * FROM (
            SELECT f.id, f.addressee_id AS user_id, u.username, u.display_name, u.avatar_url,
                   f.status, FALSE AS is_incoming, f.created_at,
                   CASE WHEN u.is_system THEN TRUE ELSE NULL END AS is_system
            FROM friendships f
            INNER JOIN users u ON u.id = f.addressee_id
            WHERE f.requester_id = $1
            UNION ALL
            SELECT f.id, f.requester_id AS user_id, u.username, u.display_name, u.avatar_url,
                   f.status, TRUE AS is_incoming, f.created_at,
                   CASE WHEN u.is_system THEN TRUE ELSE NULL END AS is_system
            FROM friendships f
            INNER JOIN users u ON u.id = f.requester_id
            WHERE f.addressee_id = $1
        ) AS combined
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(friends)
}

pub async fn set_export_allowed(pool: &Pool, channel_id: Uuid, allowed: bool) -> AppResult<()> {
    sqlx::query("UPDATE channels SET export_allowed = $2 WHERE id = $1")
        .bind(channel_id)
        .bind(allowed)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_dm_status(pool: &Pool, channel_id: Uuid, status: &str) -> AppResult<()> {
    sqlx::query("UPDATE channels SET dm_status = $2 WHERE id = $1")
        .bind(channel_id)
        .bind(status)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_pending_dm_channels(pool: &Pool, user_id: Uuid) -> AppResult<Vec<Channel>> {
    let channels = sqlx::query_as::<_, Channel>(
        r#"
        SELECT c.* FROM channels c
        INNER JOIN channel_members cm ON c.id = cm.channel_id
        WHERE cm.user_id = $1 AND c.channel_type = 'dm' AND c.dm_status = 'pending'
        ORDER BY c.created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(channels)
}

// ─── Mutual Friends / Servers ───────────────────────────

pub async fn get_mutual_friends(
    pool: &Pool,
    viewer_id: Uuid,
    target_id: Uuid,
) -> AppResult<Vec<MutualFriendInfo>> {
    let friends = sqlx::query_as::<_, MutualFriendInfo>(
        r#"
        SELECT u.id AS user_id, u.username, u.display_name, u.avatar_url
        FROM users u
        WHERE u.id != $1 AND u.id != $2
          AND EXISTS (
            SELECT 1 FROM friendships f WHERE f.status = 'accepted'
              AND ((f.requester_id = $1 AND f.addressee_id = u.id)
                OR (f.requester_id = u.id AND f.addressee_id = $1))
          )
          AND EXISTS (
            SELECT 1 FROM friendships f WHERE f.status = 'accepted'
              AND ((f.requester_id = $2 AND f.addressee_id = u.id)
                OR (f.requester_id = u.id AND f.addressee_id = $2))
          )
        LIMIT 10
        "#,
    )
    .bind(viewer_id)
    .bind(target_id)
    .fetch_all(pool)
    .await?;
    Ok(friends)
}

pub async fn get_mutual_server_count(
    pool: &Pool,
    viewer_id: Uuid,
    target_id: Uuid,
) -> AppResult<i64> {
    let row: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM server_members sm1
        INNER JOIN server_members sm2 ON sm1.server_id = sm2.server_id
        WHERE sm1.user_id = $1 AND sm2.user_id = $2
        "#,
    )
    .bind(viewer_id)
    .bind(target_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn update_dm_privacy(pool: &Pool, user_id: Uuid, dm_privacy: &str) -> AppResult<()> {
    sqlx::query("UPDATE users SET dm_privacy = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1")
        .bind(user_id)
        .bind(dm_privacy)
        .execute(pool)
        .await?;
    Ok(())
}
