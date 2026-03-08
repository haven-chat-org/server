use uuid::Uuid;

use crate::db::Pool;
use crate::errors::{AppError, AppResult};
use crate::models::*;

// ─── Roles ──────────────────────────────────────────────

pub async fn create_role(
    pool: &Pool,
    server_id: Uuid,
    name: &str,
    color: Option<&str>,
    permissions: i64,
    position: i32,
    is_default: bool,
) -> AppResult<Role> {
    let role = sqlx::query_as::<_, Role>(
        r#"
        INSERT INTO roles (server_id, name, color, permissions, position, is_default)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#,
    )
    .bind(server_id)
    .bind(name)
    .bind(color)
    .bind(permissions)
    .bind(position)
    .bind(is_default)
    .fetch_one(pool)
    .await?;
    Ok(role)
}

pub async fn get_server_roles(pool: &Pool, server_id: Uuid) -> AppResult<Vec<Role>> {
    let roles = sqlx::query_as::<_, Role>(
        "SELECT * FROM roles WHERE server_id = $1 ORDER BY position ASC",
    )
    .bind(server_id)
    .fetch_all(pool)
    .await?;
    Ok(roles)
}

pub async fn find_role_by_id(pool: &Pool, role_id: Uuid) -> AppResult<Option<Role>> {
    let role = sqlx::query_as::<_, Role>("SELECT * FROM roles WHERE id = $1")
        .bind(role_id)
        .fetch_optional(pool)
        .await?;
    Ok(role)
}

pub async fn find_default_role(pool: &Pool, server_id: Uuid) -> AppResult<Option<Role>> {
    let role = sqlx::query_as::<_, Role>(
        "SELECT * FROM roles WHERE server_id = $1 AND is_default = TRUE LIMIT 1",
    )
    .bind(server_id)
    .fetch_optional(pool)
    .await?;
    Ok(role)
}

pub async fn update_role(
    pool: &Pool,
    role_id: Uuid,
    name: Option<&str>,
    color: Option<Option<&str>>,
    permissions: Option<i64>,
    position: Option<i32>,
) -> AppResult<Role> {
    let role = sqlx::query_as::<_, Role>(
        r#"
        UPDATE roles
        SET name = COALESCE($2, name),
            color = CASE WHEN $3::bool THEN $4 ELSE color END,
            permissions = COALESCE($5, permissions),
            position = COALESCE($6, position)
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(role_id)
    .bind(name)
    .bind(color.is_some())                             // $3: should we update color?
    .bind(color.flatten())                             // $4: new color value (nullable)
    .bind(permissions)
    .bind(position)
    .fetch_one(pool)
    .await?;
    Ok(role)
}

pub async fn delete_role(pool: &Pool, role_id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM roles WHERE id = $1")
        .bind(role_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── Member Roles ────────────────────────────────────────

pub async fn assign_role(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
    role_id: Uuid,
) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO member_roles (server_id, user_id, role_id)
        VALUES ($1, $2, $3)
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(server_id)
    .bind(user_id)
    .bind(role_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn remove_role(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
    role_id: Uuid,
) -> AppResult<()> {
    sqlx::query(
        "DELETE FROM member_roles WHERE server_id = $1 AND user_id = $2 AND role_id = $3",
    )
    .bind(server_id)
    .bind(user_id)
    .bind(role_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_member_role_ids(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT role_id FROM member_roles WHERE server_id = $1 AND user_id = $2",
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

pub async fn get_member_roles(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<Role>> {
    let roles = sqlx::query_as::<_, Role>(
        r#"
        SELECT r.* FROM roles r
        INNER JOIN member_roles mr ON r.id = mr.role_id
        WHERE mr.server_id = $1 AND mr.user_id = $2
        ORDER BY r.position ASC
        "#,
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(roles)
}

// ─── Permission Computation ─────────────────────────────

/// Get a member's effective server-level permissions.
/// Returns (is_owner, effective_permissions).
pub async fn get_member_permissions(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
) -> AppResult<(bool, i64)> {
    use crate::permissions;

    let server = crate::db::queries::find_server_by_id(pool, server_id)
        .await?
        .ok_or(AppError::NotFound("Server not found".into()))?;

    let is_owner = server.owner_id == user_id;

    // Get @everyone role
    let everyone = find_default_role(pool, server_id).await?;
    let everyone_perms = everyone.as_ref().map(|r| r.permissions).unwrap_or(permissions::DEFAULT_PERMISSIONS);

    // Get member's additional roles
    let member_roles = get_member_roles(pool, server_id, user_id).await?;
    let member_role_perms: Vec<i64> = member_roles.iter().map(|r| r.permissions).collect();

    let effective = permissions::compute_server_permissions(is_owner, everyone_perms, &member_role_perms);
    Ok((is_owner, effective))
}

/// Cached variant — checks cache first, falls back to DB, caches for 2 min.
pub async fn get_member_permissions_cached(
    pool: &Pool,
    redis: &mut Option<redis::aio::ConnectionManager>,
    memory: &crate::memory_store::MemoryStore,
    server_id: Uuid,
    user_id: Uuid,
) -> AppResult<(bool, i64)> {
    let key = format!("haven:perms:{}:{}", server_id, user_id);
    if let Some((is_owner, perms)) = crate::cache::get_cached::<(bool, i64)>(redis.as_mut(), memory, &key).await {
        return Ok((is_owner, perms));
    }
    let result = get_member_permissions(pool, server_id, user_id).await?;
    crate::cache::set_cached(redis.as_mut(), memory, &key, &result, 120).await;
    Ok(result)
}

/// Check if a user has a required permission on a server. Returns error if not.
pub async fn require_server_permission(
    pool: &Pool,
    server_id: Uuid,
    user_id: Uuid,
    required: i64,
) -> AppResult<()> {
    use crate::permissions;

    let (_, effective) = get_member_permissions(pool, server_id, user_id).await?;
    if !permissions::has_permission(effective, required) {
        return Err(AppError::Forbidden("Missing required permission".into()));
    }
    Ok(())
}

// ─── Channel Permission Overwrites ──────────────────────

pub async fn get_channel_overwrites(
    pool: &Pool,
    channel_id: Uuid,
) -> AppResult<Vec<ChannelPermissionOverwrite>> {
    let rows = sqlx::query_as::<_, ChannelPermissionOverwrite>(
        "SELECT * FROM channel_permission_overwrites WHERE channel_id = $1",
    )
    .bind(channel_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn set_channel_overwrite(
    pool: &Pool,
    channel_id: Uuid,
    target_type: &str,
    target_id: Uuid,
    allow_bits: i64,
    deny_bits: i64,
) -> AppResult<ChannelPermissionOverwrite> {
    let row = sqlx::query_as::<_, ChannelPermissionOverwrite>(
        r#"
        INSERT INTO channel_permission_overwrites (channel_id, target_type, target_id, allow_bits, deny_bits)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (channel_id, target_type, target_id)
        DO UPDATE SET allow_bits = $4, deny_bits = $5
        RETURNING *
        "#,
    )
    .bind(channel_id)
    .bind(target_type)
    .bind(target_id)
    .bind(allow_bits)
    .bind(deny_bits)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

pub async fn delete_channel_overwrite(
    pool: &Pool,
    channel_id: Uuid,
    target_type: &str,
    target_id: Uuid,
) -> AppResult<()> {
    sqlx::query(
        "DELETE FROM channel_permission_overwrites WHERE channel_id = $1 AND target_type = $2 AND target_id = $3",
    )
    .bind(channel_id)
    .bind(target_type)
    .bind(target_id)
    .execute(pool)
    .await?;
    Ok(())
}
