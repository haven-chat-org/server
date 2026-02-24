use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Redirect},
    Json,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::models::*;
use crate::permissions;
use crate::storage;
use crate::AppState;

const MAX_ICON_SIZE: usize = 2 * 1024 * 1024; // 2MB

/// POST /api/v1/servers
pub async fn create_server(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<CreateServerRequest>,
) -> AppResult<Json<ServerResponse>> {
    let encrypted_meta = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.encrypted_meta,
    )
    .map_err(|_| AppError::Validation("Invalid encrypted_meta encoding".into()))?;

    if encrypted_meta.len() > 8192 {
        return Err(AppError::Validation("encrypted_meta exceeds maximum size (8KB)".into()));
    }

    let server = queries::create_server(state.db.write(), user_id, &encrypted_meta).await?;

    // Add creator as owner member
    let owner_role = b"owner"; // In practice, this would be encrypted
    queries::add_server_member(state.db.write(), server.id, user_id, owner_role).await?;

    // Create @everyone default role
    queries::create_role(
        state.db.write(),
        server.id,
        "@everyone",
        None,
        crate::permissions::DEFAULT_PERMISSIONS,
        0,
        true,
    )
    .await?;

    // Create a default "welcome" channel
    let default_channel_meta = b"welcome"; // Would be encrypted in practice
    let channel = queries::create_channel(
        state.db.write(),
        Some(server.id),
        default_channel_meta,
        "text",
        0,
        None,
        false,
        true,
    )
    .await?;

    // Add owner to the default channel
    queries::add_channel_member(state.db.write(), channel.id, user_id).await?;

    // Set the default channel as system channel
    queries::update_system_channel(state.db.write(), server.id, Some(channel.id)).await?;

    // Owner always has all permissions
    Ok(Json(ServerResponse {
        id: server.id,
        encrypted_meta: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &server.encrypted_meta,
        ),
        owner_id: server.owner_id,
        created_at: server.created_at,
        my_permissions: Some(i64::MAX.to_string()),
        system_channel_id: Some(channel.id),
        icon_url: None,
    }))
}

/// GET /api/v1/servers/:server_id
pub async fn get_server(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
) -> AppResult<Json<ServerResponse>> {
    // Verify membership
    if !queries::is_server_member(state.db.read(), server_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this server".into()));
    }

    let server = queries::find_server_by_id(state.db.read(), server_id)
        .await?
        .ok_or(AppError::NotFound("Server not found".into()))?;

    let (_, perms) = queries::get_member_permissions(state.db.read(), server_id, user_id).await?;

    Ok(Json(ServerResponse {
        id: server.id,
        encrypted_meta: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &server.encrypted_meta,
        ),
        owner_id: server.owner_id,
        created_at: server.created_at,
        my_permissions: Some(perms.to_string()),
        system_channel_id: server.system_channel_id,
        icon_url: server.icon_url.clone(),
    }))
}

/// GET /api/v1/servers
/// List servers the authenticated user is a member of.
pub async fn list_servers(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> AppResult<Json<Vec<ServerResponse>>> {
    let servers = queries::get_user_servers(state.db.read(), user_id).await?;

    let mut responses = Vec::with_capacity(servers.len());
    for s in servers {
        let (_, perms) = queries::get_member_permissions(state.db.read(), s.id, user_id).await?;
        responses.push(ServerResponse {
            id: s.id,
            encrypted_meta: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &s.encrypted_meta,
            ),
            owner_id: s.owner_id,
            created_at: s.created_at,
            my_permissions: Some(perms.to_string()),
            system_channel_id: s.system_channel_id,
            icon_url: s.icon_url.clone(),
        });
    }

    Ok(Json(responses))
}

/// GET /api/v1/servers/:server_id/channels
pub async fn list_server_channels(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
) -> AppResult<Json<Vec<ChannelResponse>>> {
    if !queries::is_server_member(state.db.read(), server_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this server".into()));
    }

    let channels = queries::get_server_channels(state.db.read(), server_id).await?;

    // For private channel filtering, compute member's base permissions and role IDs
    let (_is_owner, base_perms) = queries::get_member_permissions(state.db.read(), server_id, user_id).await?;
    let member_role_ids = queries::get_member_role_ids(state.db.read(), server_id, user_id).await?;
    let everyone_role = queries::find_default_role(state.db.read(), server_id).await?;
    let everyone_role_id = everyone_role.map(|r| r.id).unwrap_or(Uuid::nil());

    let mut responses = Vec::with_capacity(channels.len());
    for c in channels {
        // Filter out private channels the user can't see
        if c.is_private {
            let overwrites = queries::get_channel_overwrites(state.db.read(), c.id).await?;
            let ow_tuples: Vec<_> = overwrites.iter().map(|o| {
                let target = if o.target_type == "role" {
                    permissions::OverwriteTarget::Role(o.target_id)
                } else {
                    permissions::OverwriteTarget::Member(o.target_id)
                };
                (target, o.allow_bits, o.deny_bits)
            }).collect();
            let effective = permissions::apply_channel_overwrites(
                base_perms, &ow_tuples, &member_role_ids, user_id, everyone_role_id,
            );
            if !permissions::has_permission(effective, permissions::VIEW_CHANNELS) {
                continue;
            }
        }

        responses.push(ChannelResponse {
            id: c.id,
            server_id: c.server_id,
            encrypted_meta: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &c.encrypted_meta,
            ),
            channel_type: c.channel_type,
            position: c.position,
            created_at: c.created_at,
            category_id: c.category_id,
            dm_status: c.dm_status,
            last_message_id: None,
            encrypted: c.encrypted,
            is_private: c.is_private,
            export_allowed: c.export_allowed,
        });
    }

    Ok(Json(responses))
}

/// GET /api/v1/servers/:server_id/members/@me/permissions
/// Get the current user's effective permissions for a server.
pub async fn get_my_permissions(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    if !queries::is_server_member(state.db.read(), server_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this server".into()));
    }

    let (is_owner, perms) = queries::get_member_permissions(state.db.read(), server_id, user_id).await?;

    Ok(Json(serde_json::json!({
        "permissions": perms.to_string(),
        "is_owner": is_owner,
    })))
}

/// PATCH /api/v1/servers/:server_id
/// Update server settings (system channel, etc.).
pub async fn update_server(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
    Json(req): Json<UpdateServerRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if !queries::is_server_member(state.db.read(), server_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this server".into()));
    }

    // Require MANAGE_SERVER permission
    let (is_owner, perms) = queries::get_member_permissions(state.db.read(), server_id, user_id).await?;
    if !is_owner && !crate::permissions::has_permission(perms, crate::permissions::MANAGE_SERVER) {
        return Err(AppError::Forbidden("Missing MANAGE_SERVER permission".into()));
    }

    // Validate channel belongs to server if provided
    if let Some(channel_id) = req.system_channel_id {
        let channels = queries::get_server_channels(state.db.read(), server_id).await?;
        if !channels.iter().any(|c| c.id == channel_id) {
            return Err(AppError::Validation("Channel does not belong to this server".into()));
        }
    }

    // Update encrypted_meta (server name) if provided
    if let Some(ref meta) = req.encrypted_meta {
        let meta_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            meta.as_bytes(),
        ).map_err(|_| AppError::Validation("Invalid base64 for encrypted_meta".into()))?;
        if meta_bytes.is_empty() || meta_bytes.len() > 4096 {
            return Err(AppError::Validation("encrypted_meta must be between 1 and 4096 bytes".into()));
        }
        queries::update_server_meta(state.db.write(), server_id, &meta_bytes).await?;
    }

    if req.system_channel_id.is_some() {
        queries::update_system_channel(state.db.write(), server_id, req.system_channel_id).await?;
    }

    // Audit log
    let _ = queries::insert_audit_log(
        state.db.write(), server_id, user_id, "server_update",
        Some("server"), Some(server_id),
        Some(&serde_json::json!({
            "system_channel_id": req.system_channel_id,
            "encrypted_meta_updated": req.encrypted_meta.is_some(),
        })), None,
    ).await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// PUT /api/v1/servers/:server_id/nickname
/// Set or clear per-server nickname for the authenticated user.
pub async fn set_nickname(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
    Json(req): Json<UpdateNicknameRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if !queries::is_server_member(state.db.read(), server_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this server".into()));
    }

    if let Some(ref nick) = req.nickname {
        if nick.len() > 32 || nick.trim().is_empty() {
            return Err(AppError::Validation("Nickname must be 1-32 characters".into()));
        }
    }

    queries::update_member_nickname(state.db.write(), server_id, user_id, req.nickname.as_deref()).await?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// PUT /api/v1/servers/:server_id/members/:user_id/nickname
/// Set or clear a member's nickname (requires MANAGE_SERVER permission).
pub async fn set_member_nickname(
    State(state): State<AppState>,
    AuthUser(caller_id): AuthUser,
    Path((server_id, target_user_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateNicknameRequest>,
) -> AppResult<Json<serde_json::Value>> {
    // Require MANAGE_SERVER permission
    let (is_owner, perms) = queries::get_member_permissions(state.db.read(), server_id, caller_id).await?;
    if !is_owner && !crate::permissions::has_permission(perms, crate::permissions::MANAGE_SERVER) {
        return Err(AppError::Forbidden("Missing MANAGE_SERVER permission".into()));
    }

    if !queries::is_server_member(state.db.read(), server_id, target_user_id).await? {
        return Err(AppError::NotFound("Member not found".into()));
    }

    if let Some(ref nick) = req.nickname {
        if nick.len() > 32 || nick.trim().is_empty() {
            return Err(AppError::Validation("Nickname must be 1-32 characters".into()));
        }
    }

    queries::update_member_nickname(state.db.write(), server_id, target_user_id, req.nickname.as_deref()).await?;

    // Audit log
    let _ = queries::insert_audit_log(
        state.db.write(), server_id, caller_id, "member_nickname_update",
        Some("member"), Some(target_user_id),
        Some(&serde_json::json!({ "nickname": req.nickname })), None,
    ).await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// DELETE /api/v1/servers/:server_id/members/@me — leave a server
pub async fn leave_server(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let server = queries::find_server_by_id(state.db.read(), server_id)
        .await?
        .ok_or(AppError::NotFound("Server not found".into()))?;

    if !queries::is_server_member(state.db.read(), server_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this server".into()));
    }

    // If owner is leaving, only allow it if they're the sole member (auto-deletes server)
    if server.owner_id == user_id {
        let member_count = queries::count_server_members(state.db.read(), server_id).await?;
        if member_count > 1 {
            return Err(AppError::Validation(
                "Server owner cannot leave while other members remain. Transfer ownership or delete the server instead.".into(),
            ));
        }
        // Owner is the only member — delete the entire server
        queries::delete_server(state.db.write(), server_id).await?;
        crate::cache::invalidate(state.redis.clone().as_mut(), &state.memory, &format!("haven:server:{}", server_id)).await;
        return Ok(Json(serde_json::json!({ "ok": true })));
    }

    // Get username for system message before removing
    let user = queries::find_user_by_id(state.db.read(), user_id)
        .await?
        .ok_or(AppError::UserNotFound)?;

    queries::remove_server_member(state.db.write(), server_id, user_id).await?;

    // Post system message in system channel
    if let Some(system_channel_id) = server.system_channel_id {
        let body = serde_json::json!({
            "event": "member_left",
            "username": user.username,
            "user_id": user_id.to_string(),
        });
        if let Ok(sys_msg) = queries::insert_system_message(
            state.db.write(),
            system_channel_id,
            &body.to_string(),
        )
        .await
        {
            let response: MessageResponse = sys_msg.into();
            if let Some(broadcaster) = state.channel_broadcasts.get(&system_channel_id) {
                let _ = broadcaster.send(WsServerMessage::NewMessage(response));
            }
        }
    }

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// DELETE /api/v1/servers/:server_id — delete a server (owner only)
pub async fn delete_server(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let server = queries::find_server_by_id(state.db.read(), server_id)
        .await?
        .ok_or(AppError::NotFound("Server not found".into()))?;

    if server.owner_id != user_id {
        return Err(AppError::Forbidden(
            "Only the server owner can delete the server".into(),
        ));
    }

    // Cascade delete handles all child records
    queries::delete_server(state.db.write(), server_id).await?;

    // Invalidate cache
    crate::cache::invalidate(state.redis.clone().as_mut(), &state.memory, &format!("haven:server:{}", server_id)).await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

// ─── Server Icon ────────────────────────────────────────

/// POST /api/v1/servers/:server_id/icon — upload server icon (raw bytes)
pub async fn upload_icon(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
    body: Bytes,
) -> AppResult<Json<serde_json::Value>> {
    // Require MANAGE_SERVER permission
    let (is_owner, perms) = queries::get_member_permissions(state.db.read(), server_id, user_id).await?;
    if !is_owner && !crate::permissions::has_permission(perms, crate::permissions::MANAGE_SERVER) {
        return Err(AppError::Forbidden("Missing MANAGE_SERVER permission".into()));
    }

    if body.is_empty() {
        return Err(AppError::Validation("No image data provided".into()));
    }
    if body.len() > MAX_ICON_SIZE {
        return Err(AppError::Validation(format!(
            "Icon too large (max {}MB)",
            MAX_ICON_SIZE / 1024 / 1024
        )));
    }

    let storage_key = storage::obfuscated_key(&state.storage_key, &format!("server-icon:{}", server_id));
    if state.config.cdn_enabled {
        state.storage.store_blob_raw(&storage_key, &body).await
            .map_err(|e| AppError::BadRequest(format!("Failed to store icon: {}", e)))?;
    } else {
        state.storage.store_blob(&storage_key, &body).await
            .map_err(|e| AppError::BadRequest(format!("Failed to store icon: {}", e)))?;
    }

    let icon_url = format!("/api/v1/servers/{}/icon", server_id);
    queries::update_server_icon(state.db.write(), server_id, Some(&icon_url)).await?;

    // Invalidate cache
    crate::cache::invalidate(state.redis.clone().as_mut(), &state.memory, &format!("haven:server:{}", server_id)).await;

    Ok(Json(serde_json::json!({ "icon_url": icon_url })))
}

/// GET /api/v1/servers/:server_id/icon — serve server icon image (no auth for <img> src)
pub async fn get_icon(
    State(state): State<AppState>,
    Path(server_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let server = queries::find_server_by_id(state.db.read(), server_id)
        .await?
        .ok_or(AppError::NotFound("Server not found".into()))?;

    if server.icon_url.is_none() {
        return Err(AppError::NotFound("No icon set".into()));
    }

    let storage_key = storage::obfuscated_key(&state.storage_key, &format!("server-icon:{}", server_id));

    if state.config.cdn_enabled {
        if let Some(url) = state.storage.presign_url(
            &storage_key,
            state.config.cdn_presign_expiry_secs,
            &state.config.cdn_base_url,
        ).await {
            return Ok(Redirect::temporary(&url).into_response());
        }

        let data = state.storage.load_blob_raw(&storage_key).await
            .map_err(|_| AppError::NotFound("Icon file not found".into()))?;

        let content_type = detect_icon_type(&data);
        Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "public, max-age=86400".to_string()),
            ],
            data,
        ).into_response())
    } else {
        let data = state.storage.load_blob(&storage_key).await
            .map_err(|_| AppError::NotFound("Icon file not found".into()))?;

        let content_type = detect_icon_type(&data);
        Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "public, max-age=86400".to_string()),
            ],
            data,
        ).into_response())
    }
}

/// DELETE /api/v1/servers/:server_id/icon — remove server icon
pub async fn delete_icon(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let (is_owner, perms) = queries::get_member_permissions(state.db.read(), server_id, user_id).await?;
    if !is_owner && !crate::permissions::has_permission(perms, crate::permissions::MANAGE_SERVER) {
        return Err(AppError::Forbidden("Missing MANAGE_SERVER permission".into()));
    }

    // Delete the stored blob (best-effort)
    let storage_key = storage::obfuscated_key(&state.storage_key, &format!("server-icon:{}", server_id));
    let _ = state.storage.delete_blob(&storage_key).await;

    queries::update_server_icon(state.db.write(), server_id, None).await?;

    // Invalidate cache
    crate::cache::invalidate(state.redis.clone().as_mut(), &state.memory, &format!("haven:server:{}", server_id)).await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

// ─── Member Timeout ──────────────────────────────────

/// PUT /api/v1/servers/:server_id/members/:user_id/timeout
pub async fn timeout_member(
    State(state): State<AppState>,
    AuthUser(caller_id): AuthUser,
    Path((server_id, target_user_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<TimeoutMemberRequest>,
) -> AppResult<Json<serde_json::Value>> {
    queries::require_server_permission(
        state.db.read(),
        server_id,
        caller_id,
        crate::permissions::MODERATE_MEMBERS,
    )
    .await?;

    if target_user_id == caller_id {
        return Err(AppError::Validation("Cannot timeout yourself".into()));
    }

    // Verify target is a member
    if !queries::is_server_member(state.db.read(), server_id, target_user_id).await? {
        return Err(AppError::NotFound("Member not found".into()));
    }

    // Cannot timeout the server owner
    let server = queries::find_server_by_id(state.db.read(), server_id)
        .await?
        .ok_or(AppError::NotFound("Server not found".into()))?;
    if target_user_id == server.owner_id {
        return Err(AppError::Forbidden("Cannot timeout the server owner".into()));
    }

    // Hierarchy check: cannot timeout users with higher/equal role position
    let (is_owner, _) = queries::get_member_permissions(state.db.read(), server_id, caller_id).await?;
    if !is_owner {
        let my_roles = queries::get_member_roles(state.db.read(), server_id, caller_id).await?;
        let target_roles = queries::get_member_roles(state.db.read(), server_id, target_user_id).await?;
        let my_highest = my_roles.iter().map(|r| r.position).max().unwrap_or(0);
        let target_highest = target_roles.iter().map(|r| r.position).max().unwrap_or(0);
        if target_highest >= my_highest {
            return Err(AppError::Forbidden(
                "Cannot timeout a member with equal or higher role".into(),
            ));
        }
    }

    let timed_out_until = if req.duration_seconds > 0 {
        // Max 28 days
        let clamped = req.duration_seconds.min(28 * 24 * 3600);
        Some(chrono::Utc::now() + chrono::Duration::seconds(clamped))
    } else {
        None // Remove timeout
    };

    queries::set_member_timeout(state.db.write(), server_id, target_user_id, timed_out_until)
        .await?;

    // Broadcast to connected server members
    let ws_msg = WsServerMessage::MemberTimedOut {
        server_id,
        user_id: target_user_id,
        timed_out_until,
    };
    if let Ok(members) = queries::get_server_member_ids(state.db.read(), server_id).await {
        for member_id in members {
            if let Some(conns) = state.connections.get(&member_id) {
                for sender in conns.iter() {
                    let _ = sender.send(ws_msg.clone());
                }
            }
        }
    }

    // Audit log
    let _ = queries::insert_audit_log(
        state.db.write(),
        server_id,
        caller_id,
        "member_timeout",
        Some("member"),
        Some(target_user_id),
        Some(&serde_json::json!({ "duration_seconds": req.duration_seconds })),
        req.reason.as_deref(),
    )
    .await;

    Ok(Json(serde_json::json!({ "timed_out_until": timed_out_until })))
}

// ─── Audit Log ───────────────────────────────────────

/// GET /api/v1/servers/:server_id/audit-log
pub async fn get_audit_log(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
    Query(params): Query<AuditLogQuery>,
) -> AppResult<Json<Vec<AuditLogResponse>>> {
    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        crate::permissions::VIEW_AUDIT_LOG,
    )
    .await?;

    let limit = params.limit.unwrap_or(50).clamp(1, 100);
    let entries = queries::get_audit_log(state.db.read(), server_id, limit, params.before).await?;
    Ok(Json(entries))
}

fn detect_icon_type(data: &[u8]) -> String {
    if data.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        "image/png".into()
    } else if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        "image/jpeg".into()
    } else if data.starts_with(b"GIF8") {
        "image/gif".into()
    } else if data.starts_with(b"RIFF") && data.len() > 12 && &data[8..12] == b"WEBP" {
        "image/webp".into()
    } else {
        "application/octet-stream".into()
    }
}

// ─── Server Export ───────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct ServerExportQuery {
    pub after: Option<DateTime<Utc>>,
    pub before: Option<DateTime<Utc>>,
    #[serde(default)]
    pub include_attachments: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct ServerExportChannelData {
    pub channel_id: Uuid,
    pub channel_type: String,
    pub encrypted: bool,
    pub encrypted_meta: String,
    pub position: i32,
    pub category_id: Option<Uuid>,
    pub message_count: usize,
    pub messages: Vec<MessageResponse>,
}

#[derive(Debug, serde::Serialize)]
pub struct ServerExportResponse {
    pub server_id: Uuid,
    pub encrypted_meta: String,
    pub owner_id: Uuid,
    pub icon_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub exported_at: DateTime<Utc>,
    pub exported_by: Uuid,
    pub categories: Vec<CategoryResponse>,
    pub channels: Vec<ServerExportChannelData>,
    pub roles: Vec<RoleResponse>,
    pub permission_overwrites: Vec<OverwriteResponse>,
    pub members: Vec<ServerMemberResponse>,
    pub emojis: Vec<CustomEmojiResponse>,
    pub include_attachments: bool,
}

/// GET /api/v1/servers/:server_id/export
/// Bulk export server metadata, structure, and messages for accessible channels.
#[allow(clippy::too_many_lines)]
pub async fn export_server(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
    Query(params): Query<ServerExportQuery>,
) -> AppResult<Json<ServerExportResponse>> {
    // Verify membership
    if !queries::is_server_member(state.db.read(), server_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this server".into()));
    }

    let server = queries::find_server_by_id(state.db.read(), server_id)
        .await?
        .ok_or(AppError::NotFound("Server not found".into()))?;

    let (is_owner, base_perms) =
        queries::get_member_permissions(state.db.read(), server_id, user_id).await?;
    let member_role_ids =
        queries::get_member_role_ids(state.db.read(), server_id, user_id).await?;
    let everyone_role = queries::find_default_role(state.db.read(), server_id).await?;
    let everyone_role_id = everyone_role.map(|r| r.id).unwrap_or(Uuid::nil());

    // Get categories
    let categories: Vec<CategoryResponse> =
        queries::get_server_categories(state.db.read(), server_id)
            .await?
            .into_iter()
            .map(CategoryResponse::from)
            .collect();

    // Get all server channels (exclude DM-type channels)
    let all_channels = queries::get_server_channels(state.db.read(), server_id).await?;

    // Filter channels by access permissions
    let mut channel_data = Vec::new();
    let mut all_overwrites = Vec::new();

    for c in &all_channels {
        // Skip DM channels
        if c.channel_type == "dm" || c.channel_type == "group" {
            continue;
        }

        // For private channels, check if user has VIEW_CHANNELS permission
        if c.is_private && !is_owner {
            let overwrites = queries::get_channel_overwrites(state.db.read(), c.id).await?;
            let ow_tuples: Vec<_> = overwrites
                .iter()
                .map(|o| {
                    let target = if o.target_type == "role" {
                        permissions::OverwriteTarget::Role(o.target_id)
                    } else {
                        permissions::OverwriteTarget::Member(o.target_id)
                    };
                    (target, o.allow_bits, o.deny_bits)
                })
                .collect();
            let effective = permissions::apply_channel_overwrites(
                base_perms,
                &ow_tuples,
                &member_role_ids,
                user_id,
                everyone_role_id,
            );
            if !permissions::has_permission(effective, permissions::VIEW_CHANNELS) {
                continue;
            }
            // Collect overwrites for accessible channels
            for o in overwrites {
                all_overwrites.push(OverwriteResponse::from(o));
            }
        } else {
            // Collect overwrites for non-private channels too
            if let Ok(overwrites) = queries::get_channel_overwrites(state.db.read(), c.id).await {
                for o in overwrites {
                    all_overwrites.push(OverwriteResponse::from(o));
                }
            }
        }

        // Get messages for this channel
        let messages =
            queries::get_export_messages(state.db.read(), c.id, params.after, params.before)
                .await?;
        let message_count = messages.len();
        let msg_responses: Vec<MessageResponse> =
            messages.into_iter().map(|m| m.into()).collect();

        channel_data.push(ServerExportChannelData {
            channel_id: c.id,
            channel_type: c.channel_type.clone(),
            encrypted: c.encrypted,
            encrypted_meta: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &c.encrypted_meta,
            ),
            position: c.position,
            category_id: c.category_id,
            message_count,
            messages: msg_responses,
        });
    }

    // Get roles
    let roles: Vec<RoleResponse> = queries::get_server_roles(state.db.read(), server_id)
        .await?
        .into_iter()
        .map(RoleResponse::from)
        .collect();

    // Get members (all, no pagination for export)
    let members = queries::get_server_members(state.db.read(), server_id, 10000, 0).await?;

    // Get emojis
    let emojis: Vec<CustomEmojiResponse> =
        queries::list_server_emojis(state.db.read(), server_id)
            .await?
            .iter()
            .map(|e| e.to_response())
            .collect();

    // Audit log
    let _ = queries::insert_audit_log(
        state.db.write(),
        server_id,
        user_id,
        "server_export",
        Some("server"),
        Some(server_id),
        Some(&serde_json::json!({
            "channel_count": channel_data.len(),
        })),
        None,
    )
    .await;

    Ok(Json(ServerExportResponse {
        server_id,
        encrypted_meta: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &server.encrypted_meta,
        ),
        owner_id: server.owner_id,
        icon_url: server.icon_url,
        created_at: server.created_at,
        exported_at: Utc::now(),
        exported_by: user_id,
        categories,
        channels: channel_data,
        roles,
        permission_overwrites: all_overwrites,
        members,
        emojis,
        include_attachments: params.include_attachments,
    }))
}
