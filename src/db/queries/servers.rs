use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::Pool;
use crate::errors::AppResult;
use crate::models::*;

// ─── Servers ───────────────────────────────────────────

pub async fn create_server(
    pool: &Pool,
    owner_id: Uuid,
    encrypted_meta: &[u8],
) -> AppResult<Server> {
    let server = sqlx::query_as::<_, Server>(
        r#"
        INSERT INTO servers (id, encrypted_meta, owner_id, created_at)
        VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(encrypted_meta)
    .bind(owner_id)
    .fetch_one(pool)
    .await?;
    Ok(server)
}

pub async fn find_server_by_id(pool: &Pool, id: Uuid) -> AppResult<Option<Server>> {
    let server = sqlx::query_as::<_, Server>("SELECT * FROM servers WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(server)
}

/// Cached variant — checks cache first, falls back to DB, caches for 5 min.
pub async fn find_server_by_id_cached(
    pool: &Pool,
    redis: &mut Option<redis::aio::ConnectionManager>,
    memory: &crate::memory_store::MemoryStore,
    id: Uuid,
) -> AppResult<Option<Server>> {
    let key = format!("haven:server:{}", id);
    if let Some(server) = crate::cache::get_cached::<Server>(redis.as_mut(), memory, &key).await {
        return Ok(Some(server));
    }
    let server = find_server_by_id(pool, id).await?;
    if let Some(ref s) = server {
        crate::cache::set_cached(redis.as_mut(), memory, &key, s, 300).await;
    }
    Ok(server)
}

pub async fn get_user_servers(pool: &Pool, user_id: Uuid) -> AppResult<Vec<Server>> {
    let servers = sqlx::query_as::<_, Server>(
        r#"
        SELECT s.* FROM servers s
        INNER JOIN server_members sm ON s.id = sm.server_id
        WHERE sm.user_id = $1
        ORDER BY s.created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(servers)
}

pub async fn update_system_channel(
    pool: &Pool,
    server_id: Uuid,
    system_channel_id: Option<Uuid>,
) -> AppResult<()> {
    sqlx::query("UPDATE servers SET system_channel_id = $1 WHERE id = $2")
        .bind(system_channel_id)
        .bind(server_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_server_meta(
    pool: &Pool,
    server_id: Uuid,
    encrypted_meta: &[u8],
) -> AppResult<()> {
    sqlx::query("UPDATE servers SET encrypted_meta = $1 WHERE id = $2")
        .bind(encrypted_meta)
        .bind(server_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_server_icon(
    pool: &Pool,
    server_id: Uuid,
    icon_url: Option<&str>,
) -> AppResult<()> {
    sqlx::query("UPDATE servers SET icon_url = $1 WHERE id = $2")
        .bind(icon_url)
        .bind(server_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── Server Members ────────────────────────────────────

pub async fn add_server_member(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
    encrypted_role: &[u8],
) -> AppResult<ServerMember> {
    let member = sqlx::query_as::<_, ServerMember>(
        r#"
        INSERT INTO server_members (id, server_id, user_id, encrypted_role, joined_at)
        VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
        ON CONFLICT (server_id, user_id) DO UPDATE SET encrypted_role = EXCLUDED.encrypted_role
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(server_id)
    .bind(user_id)
    .bind(encrypted_role)
    .fetch_one(pool)
    .await?;
    Ok(member)
}

pub async fn is_server_member(pool: &Pool, server_id: Uuid, user_id: Uuid) -> AppResult<bool> {
    let row: (bool,) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM server_members WHERE server_id = $1 AND user_id = $2)",
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

// ─── Server Members (extended) ────────────────────────

pub async fn get_server_members(
    pool: &Pool,
    server_id: Uuid,
    limit: i64,
    offset: i64,
) -> AppResult<Vec<ServerMemberResponse>> {
    // Step 1: Get members (paginated)
    #[allow(clippy::type_complexity)]
    let rows: Vec<(Uuid, String, Option<String>, Option<String>, DateTime<Utc>, Option<String>, Option<DateTime<Utc>>, bool)> =
        sqlx::query_as(
            r#"
            SELECT sm.user_id, u.username, u.display_name, u.avatar_url, sm.joined_at, sm.nickname, sm.timed_out_until, u.is_system
            FROM server_members sm
            INNER JOIN users u ON u.id = sm.user_id
            WHERE sm.server_id = $1
            ORDER BY sm.joined_at ASC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(server_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

    // Step 2: Get all role assignments for this server in one query
    let role_assignments: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT user_id, role_id FROM member_roles WHERE server_id = $1",
    )
    .bind(server_id)
    .fetch_all(pool)
    .await?;

    // Build a map: user_id -> Vec<role_id>
    let mut role_map: std::collections::HashMap<Uuid, Vec<Uuid>> =
        std::collections::HashMap::new();
    for (uid, rid) in role_assignments {
        role_map.entry(uid).or_default().push(rid);
    }

    Ok(rows
        .into_iter()
        .map(
            |(user_id, username, display_name, avatar_url, joined_at, nickname, timed_out_until, is_sys)| {
                // Only include timed_out_until if it's still in the future
                let active_timeout = timed_out_until.filter(|t| *t > Utc::now());
                ServerMemberResponse {
                    user_id,
                    username,
                    display_name,
                    avatar_url,
                    joined_at,
                    nickname,
                    role_ids: role_map.remove(&user_id).unwrap_or_default(),
                    timed_out_until: active_timeout,
                    is_system: if is_sys { Some(true) } else { None },
                }
            },
        )
        .collect())
}

pub async fn get_server_member_ids(pool: &Pool, server_id: Uuid) -> AppResult<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> =
        sqlx::query_as("SELECT user_id FROM server_members WHERE server_id = $1")
            .bind(server_id)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

pub async fn remove_server_member(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
) -> AppResult<()> {
    // Remove from all server channels
    sqlx::query(
        r#"
        DELETE FROM channel_members
        WHERE user_id = $1
          AND channel_id IN (SELECT id FROM channels WHERE server_id = $2)
        "#,
    )
    .bind(user_id)
    .bind(server_id)
    .execute(pool)
    .await?;

    // Remove from server
    sqlx::query("DELETE FROM server_members WHERE server_id = $1 AND user_id = $2")
        .bind(server_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn count_server_members(pool: &Pool, server_id: Uuid) -> AppResult<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM server_members WHERE server_id = $1")
        .bind(server_id)
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

pub async fn delete_server(pool: &Pool, server_id: Uuid) -> AppResult<()> {
    // All child tables use ON DELETE CASCADE, so this single delete
    // removes server_members, channels (→ messages, channel_members, etc.),
    // roles, member_roles, invites, bans, categories, etc.
    sqlx::query("DELETE FROM servers WHERE id = $1")
        .bind(server_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── Servers (ownership) ────────────────────────────

pub async fn get_servers_owned_by(pool: &Pool, user_id: Uuid) -> AppResult<Vec<Server>> {
    let servers = sqlx::query_as::<_, Server>(
        "SELECT * FROM servers WHERE owner_id = $1",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(servers)
}
