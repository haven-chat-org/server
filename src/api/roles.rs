use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;

use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::models::*;
use crate::permissions;
use crate::AppState;

/// GET /api/v1/servers/:server_id/roles
pub async fn list_roles(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
) -> AppResult<Json<Vec<RoleResponse>>> {
    if !queries::is_server_member(state.db.read(), server_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this server".into()));
    }

    let roles = queries::get_server_roles(state.db.read(), server_id).await?;
    let responses: Vec<RoleResponse> = roles.into_iter().map(RoleResponse::from).collect();
    Ok(Json(responses))
}

/// POST /api/v1/servers/:server_id/roles
pub async fn create_role(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
    Json(req): Json<CreateRoleRequest>,
) -> AppResult<Json<RoleResponse>> {
    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::MANAGE_ROLES,
    )
    .await?;

    let perms: i64 = req
        .permissions
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let position = req.position.unwrap_or(0);

    let role = queries::create_role(
        state.db.write(),
        server_id,
        &req.name,
        req.color.as_deref(),
        perms,
        position,
        false,
    )
    .await?;

    // Audit log
    let _ = queries::insert_audit_log(
        state.db.write(), server_id, user_id, "role_create",
        Some("role"), Some(role.id),
        Some(&serde_json::json!({ "name": &role.name })), None,
    ).await;

    Ok(Json(RoleResponse::from(role)))
}

/// PUT /api/v1/servers/:server_id/roles/:role_id
pub async fn update_role(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path((server_id, role_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateRoleRequest>,
) -> AppResult<Json<RoleResponse>> {
    let (is_owner, _) = queries::get_member_permissions(state.db.read(), server_id, user_id).await?;
    if !is_owner {
        queries::require_server_permission(
            state.db.read(),
            server_id,
            user_id,
            permissions::MANAGE_ROLES,
        )
        .await?;
    }

    let target_role = queries::find_role_by_id(state.db.read(), role_id)
        .await?
        .ok_or(AppError::NotFound("Role not found".into()))?;
    if target_role.server_id != server_id {
        return Err(AppError::NotFound("Role not found".into()));
    }

    // Hierarchy check: non-owner can only edit roles below their highest position
    if !is_owner {
        let my_roles = queries::get_member_roles(state.db.read(), server_id, user_id).await?;
        let my_highest = my_roles.iter().map(|r| r.position).max().unwrap_or(0);
        if target_role.position >= my_highest {
            return Err(AppError::Forbidden("Cannot edit a role at or above your position".into()));
        }
    }

    let perms: Option<i64> = req.permissions.as_deref().and_then(|s| s.parse().ok());

    let updated = queries::update_role(
        state.db.write(),
        role_id,
        req.name.as_deref(),
        req.color.as_ref().map(|c| Some(c.as_str())),
        perms,
        req.position,
    )
    .await?;

    // Invalidate all permission caches for this server (role changed affects everyone)
    crate::cache::invalidate_pattern(
        state.redis.clone().as_mut(),
        &state.memory,
        &format!("haven:perms:{}:*", server_id),
    ).await;

    // Audit log
    let _ = queries::insert_audit_log(
        state.db.write(), server_id, user_id, "role_update",
        Some("role"), Some(role_id),
        Some(&serde_json::json!({ "name": &updated.name })), None,
    ).await;

    Ok(Json(RoleResponse::from(updated)))
}

/// DELETE /api/v1/servers/:server_id/roles/:role_id
pub async fn delete_role(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path((server_id, role_id)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<serde_json::Value>> {
    let (is_owner, _) = queries::get_member_permissions(state.db.read(), server_id, user_id).await?;
    if !is_owner {
        queries::require_server_permission(
            state.db.read(),
            server_id,
            user_id,
            permissions::MANAGE_ROLES,
        )
        .await?;
    }

    let target_role = queries::find_role_by_id(state.db.read(), role_id)
        .await?
        .ok_or(AppError::NotFound("Role not found".into()))?;
    if target_role.server_id != server_id {
        return Err(AppError::NotFound("Role not found".into()));
    }
    if target_role.is_default {
        return Err(AppError::Forbidden("Cannot delete the default role".into()));
    }

    if !is_owner {
        let my_roles = queries::get_member_roles(state.db.read(), server_id, user_id).await?;
        let my_highest = my_roles.iter().map(|r| r.position).max().unwrap_or(0);
        if target_role.position >= my_highest {
            return Err(AppError::Forbidden("Cannot delete a role at or above your position".into()));
        }
    }

    queries::delete_role(state.db.write(), role_id).await?;

    // Invalidate all permission caches for this server
    crate::cache::invalidate_pattern(
        state.redis.clone().as_mut(),
        &state.memory,
        &format!("haven:perms:{}:*", server_id),
    ).await;

    // Audit log
    let _ = queries::insert_audit_log(
        state.db.write(), server_id, user_id, "role_delete",
        Some("role"), Some(role_id),
        Some(&serde_json::json!({ "name": &target_role.name })), None,
    ).await;

    Ok(Json(serde_json::json!({ "message": "Role deleted" })))
}

/// PUT /api/v1/servers/:server_id/members/:target_user_id/roles
pub async fn assign_role(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path((server_id, target_user_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<AssignRoleRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let (is_owner, _) = queries::get_member_permissions(state.db.read(), server_id, user_id).await?;
    if !is_owner {
        queries::require_server_permission(
            state.db.read(),
            server_id,
            user_id,
            permissions::MANAGE_ROLES,
        )
        .await?;
    }

    let role = queries::find_role_by_id(state.db.read(), req.role_id)
        .await?
        .ok_or(AppError::NotFound("Role not found".into()))?;
    if role.server_id != server_id {
        return Err(AppError::NotFound("Role not found".into()));
    }

    if !is_owner {
        let my_roles = queries::get_member_roles(state.db.read(), server_id, user_id).await?;
        let my_highest = my_roles.iter().map(|r| r.position).max().unwrap_or(0);
        if role.position >= my_highest {
            return Err(AppError::Forbidden("Cannot assign a role at or above your position".into()));
        }
    }

    queries::assign_role(state.db.write(), server_id, target_user_id, req.role_id).await?;

    // Invalidate permission cache for target user
    crate::cache::invalidate(
        state.redis.clone().as_mut(),
        &state.memory,
        &format!("haven:perms:{}:{}", server_id, target_user_id),
    ).await;

    // Audit log
    let _ = queries::insert_audit_log(
        state.db.write(), server_id, user_id, "member_role_add",
        Some("member"), Some(target_user_id),
        Some(&serde_json::json!({ "role_id": req.role_id, "role_name": &role.name })), None,
    ).await;

    Ok(Json(serde_json::json!({ "message": "Role assigned" })))
}

/// DELETE /api/v1/servers/:server_id/members/:target_user_id/roles/:role_id
pub async fn unassign_role(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path((server_id, target_user_id, role_id)): Path<(Uuid, Uuid, Uuid)>,
) -> AppResult<Json<serde_json::Value>> {
    let (is_owner, _) = queries::get_member_permissions(state.db.read(), server_id, user_id).await?;
    if !is_owner {
        queries::require_server_permission(
            state.db.read(),
            server_id,
            user_id,
            permissions::MANAGE_ROLES,
        )
        .await?;
    }

    let role = queries::find_role_by_id(state.db.read(), role_id)
        .await?
        .ok_or(AppError::NotFound("Role not found".into()))?;
    if role.server_id != server_id {
        return Err(AppError::NotFound("Role not found".into()));
    }

    if !is_owner {
        let my_roles = queries::get_member_roles(state.db.read(), server_id, user_id).await?;
        let my_highest = my_roles.iter().map(|r| r.position).max().unwrap_or(0);
        if role.position >= my_highest {
            return Err(AppError::Forbidden("Cannot remove a role at or above your position".into()));
        }
    }

    queries::remove_role(state.db.write(), server_id, target_user_id, role_id).await?;

    // Invalidate permission cache for target user
    crate::cache::invalidate(
        state.redis.clone().as_mut(),
        &state.memory,
        &format!("haven:perms:{}:{}", server_id, target_user_id),
    ).await;

    // Audit log
    let _ = queries::insert_audit_log(
        state.db.write(), server_id, user_id, "member_role_remove",
        Some("member"), Some(target_user_id),
        Some(&serde_json::json!({ "role_id": role_id, "role_name": &role.name })), None,
    ).await;

    Ok(Json(serde_json::json!({ "message": "Role removed" })))
}

/// GET /api/v1/channels/:channel_id/overwrites
pub async fn list_overwrites(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
) -> AppResult<Json<Vec<OverwriteResponse>>> {
    let channel = queries::find_channel_by_id(state.db.read(), channel_id)
        .await?
        .ok_or(AppError::NotFound("Channel not found".into()))?;
    let server_id = channel.server_id
        .ok_or(AppError::Forbidden("Not a server channel".into()))?;

    if !queries::is_server_member(state.db.read(), server_id, user_id).await? {
        return Err(AppError::Forbidden("Not a server member".into()));
    }

    let overwrites = queries::get_channel_overwrites(state.db.read(), channel_id).await?;
    let responses: Vec<OverwriteResponse> = overwrites.into_iter().map(OverwriteResponse::from).collect();
    Ok(Json(responses))
}

/// PUT /api/v1/channels/:channel_id/overwrites
pub async fn set_overwrite(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
    Json(req): Json<SetOverwriteRequest>,
) -> AppResult<Json<OverwriteResponse>> {
    let channel = queries::find_channel_by_id(state.db.read(), channel_id)
        .await?
        .ok_or(AppError::NotFound("Channel not found".into()))?;
    let server_id = channel.server_id
        .ok_or(AppError::Forbidden("Not a server channel".into()))?;

    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::MANAGE_CHANNELS,
    )
    .await?;

    if req.target_type != "role" && req.target_type != "member" {
        return Err(AppError::Validation("target_type must be 'role' or 'member'".into()));
    }

    let allow: i64 = req.allow_bits.parse().map_err(|_| AppError::Validation("Invalid allow_bits".into()))?;
    let deny: i64 = req.deny_bits.parse().map_err(|_| AppError::Validation("Invalid deny_bits".into()))?;

    let overwrite = queries::set_channel_overwrite(
        state.db.write(),
        channel_id,
        &req.target_type,
        req.target_id,
        allow,
        deny,
    )
    .await?;

    // Audit log
    let _ = queries::insert_audit_log(
        state.db.write(), server_id, user_id, "overwrite_update",
        Some("channel"), Some(channel_id),
        Some(&serde_json::json!({ "target_type": &req.target_type, "target_id": req.target_id, "allow": &req.allow_bits, "deny": &req.deny_bits })),
        None,
    ).await;

    Ok(Json(OverwriteResponse::from(overwrite)))
}

/// DELETE /api/v1/channels/:channel_id/overwrites/:target_type/:target_id
pub async fn delete_overwrite(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path((channel_id, target_type, target_id)): Path<(Uuid, String, Uuid)>,
) -> AppResult<Json<serde_json::Value>> {
    let channel = queries::find_channel_by_id(state.db.read(), channel_id)
        .await?
        .ok_or(AppError::NotFound("Channel not found".into()))?;
    let server_id = channel.server_id
        .ok_or(AppError::Forbidden("Not a server channel".into()))?;

    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::MANAGE_CHANNELS,
    )
    .await?;

    queries::delete_channel_overwrite(state.db.write(), channel_id, &target_type, target_id).await?;

    // Audit log
    let _ = queries::insert_audit_log(
        state.db.write(), server_id, user_id, "overwrite_delete",
        Some("channel"), Some(channel_id),
        Some(&serde_json::json!({ "target_type": &target_type, "target_id": target_id })),
        None,
    ).await;

    Ok(Json(serde_json::json!({ "message": "Overwrite removed" })))
}
