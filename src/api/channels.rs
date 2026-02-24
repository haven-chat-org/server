use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;

use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::models::*;
use crate::permissions;
use crate::ws::broadcast_to_server;
use crate::AppState;

/// POST /api/v1/servers/:server_id/channels
pub async fn create_channel(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
    Json(req): Json<CreateChannelRequest>,
) -> AppResult<Json<ChannelResponse>> {
    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::MANAGE_CHANNELS,
    )
    .await?;

    let encrypted_meta = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.encrypted_meta,
    )
    .map_err(|_| AppError::Validation("Invalid encrypted_meta encoding".into()))?;

    if encrypted_meta.len() > 8192 {
        return Err(AppError::Validation("encrypted_meta exceeds maximum size (8KB)".into()));
    }

    let channel_type = req.channel_type.as_deref().unwrap_or("text");
    let position = req.position.unwrap_or(0);
    let is_private = req.is_private.unwrap_or(false);
    let encrypted = req.encrypted.unwrap_or(true);

    let channel = queries::create_channel(
        state.db.write(),
        Some(server_id),
        &encrypted_meta,
        channel_type,
        position,
        req.category_id,
        is_private,
        encrypted,
    )
    .await?;

    // Add creator to the channel
    queries::add_channel_member(state.db.write(), channel.id, user_id).await?;

    // Audit log
    let _ = queries::insert_audit_log(
        state.db.write(), server_id, user_id, "channel_create",
        Some("channel"), Some(channel.id),
        Some(&serde_json::json!({ "channel_type": &channel.channel_type })), None,
    ).await;

    // Notify other server members so their channel list updates
    broadcast_to_server(&state, server_id, WsServerMessage::ServerUpdated { server_id }).await;

    Ok(Json(ChannelResponse {
        id: channel.id,
        server_id: channel.server_id,
        encrypted_meta: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &channel.encrypted_meta,
        ),
        channel_type: channel.channel_type,
        position: channel.position,
        created_at: channel.created_at,
        category_id: channel.category_id,
        dm_status: channel.dm_status,
        last_message_id: None,
        is_private: channel.is_private,
        encrypted: channel.encrypted,
        export_allowed: channel.export_allowed,
    }))
}

/// POST /api/v1/channels/:channel_id/join
pub async fn join_channel(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    // Verify the channel exists
    let channel = queries::find_channel_by_id(state.db.read(), channel_id)
        .await?
        .ok_or(AppError::NotFound("Channel not found".into()))?;

    // If the channel belongs to a server, verify server membership
    if let Some(server_id) = channel.server_id {
        if !queries::is_server_member(state.db.read(), server_id, user_id).await? {
            return Err(AppError::Forbidden("Not a member of the server".into()));
        }
    }

    queries::add_channel_member(state.db.write(), channel_id, user_id).await?;

    Ok(Json(serde_json::json!({ "message": "Joined channel" })))
}

/// POST /api/v1/dm
/// Create a DM channel between two users, or return existing one.
/// Enforces DM privacy: if the target has friends_only, creates a pending DM.
pub async fn create_dm(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<CreateDmRequest>,
) -> AppResult<Json<ChannelResponse>> {
    // Verify target user exists
    let target = queries::find_user_by_id(state.db.read(), req.target_user_id)
        .await?
        .ok_or(AppError::UserNotFound)?;

    // Check for existing DM channel between these two users
    if let Some(existing) = queries::find_dm_channel(state.db.read(), user_id, req.target_user_id).await? {
        return Ok(Json(ChannelResponse {
            id: existing.id,
            server_id: None,
            encrypted_meta: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &existing.encrypted_meta,
            ),
            channel_type: existing.channel_type,
            position: existing.position,
            created_at: existing.created_at,
            category_id: None,
            dm_status: existing.dm_status,
            last_message_id: None,
            is_private: false,
            encrypted: true,
            export_allowed: existing.export_allowed,
        }));
    }

    // Determine DM status based on target's privacy setting
    let dm_status = match target.dm_privacy.as_str() {
        "everyone" => "active",
        "friends_only" => {
            if queries::are_friends(state.db.read(), user_id, req.target_user_id).await? {
                "active"
            } else {
                "pending"
            }
        }
        "server_members" => {
            if queries::are_friends(state.db.read(), user_id, req.target_user_id).await?
                || queries::share_server(state.db.read(), user_id, req.target_user_id).await?
            {
                "active"
            } else {
                "pending"
            }
        }
        _ => "active",
    };

    // Create a new DM channel (no server association)
    let encrypted_meta = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.encrypted_meta,
    )
    .map_err(|_| AppError::Validation("Invalid encrypted_meta encoding".into()))?;

    if encrypted_meta.len() > 8192 {
        return Err(AppError::Validation("encrypted_meta exceeds maximum size (8KB)".into()));
    }

    let channel = queries::create_channel(state.db.write(), None, &encrypted_meta, "dm", 0, None, false, true).await?;

    // Set dm_status
    if dm_status != "active" {
        queries::set_dm_status(state.db.write(), channel.id, dm_status).await?;
    }

    // Add both users
    queries::add_channel_member(state.db.write(), channel.id, user_id).await?;
    queries::add_channel_member(state.db.write(), channel.id, req.target_user_id).await?;

    // If pending, notify the target user via WS
    if dm_status == "pending" {
        send_to_user(&state, req.target_user_id, WsServerMessage::DmRequestReceived {
            channel_id: channel.id,
            from_user_id: user_id,
        }).await;
    }

    Ok(Json(ChannelResponse {
        id: channel.id,
        server_id: None,
        encrypted_meta: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &channel.encrypted_meta,
        ),
        channel_type: channel.channel_type,
        position: channel.position,
        created_at: channel.created_at,
        category_id: None,
        dm_status: Some(dm_status.to_string()),
        last_message_id: None,
        is_private: false,
        encrypted: true,
        export_allowed: channel.export_allowed,
    }))
}

/// GET /api/v1/dm
/// List all DM channels for the authenticated user.
pub async fn list_dm_channels(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> AppResult<Json<Vec<ChannelResponse>>> {
    let channels = queries::get_user_dm_channels(state.db.read(), user_id).await?;
    let responses: Vec<ChannelResponse> = channels
        .into_iter()
        .map(|ch| ChannelResponse {
            id: ch.id,
            server_id: ch.server_id,
            encrypted_meta: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &ch.encrypted_meta,
            ),
            channel_type: ch.channel_type,
            position: ch.position,
            created_at: ch.created_at,
            category_id: ch.category_id,
            dm_status: ch.dm_status,
            last_message_id: None,
            is_private: ch.is_private,
            encrypted: ch.encrypted,
            export_allowed: ch.export_allowed,
        })
        .collect();
    Ok(Json(responses))
}

/// PUT /api/v1/channels/:channel_id
/// Rename a channel (update its encrypted_meta). Server owner only.
pub async fn update_channel(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
    Json(req): Json<UpdateChannelRequest>,
) -> AppResult<Json<ChannelResponse>> {
    let channel = queries::find_channel_by_id(state.db.read(), channel_id)
        .await?
        .ok_or(AppError::NotFound("Channel not found".into()))?;

    // Must be a server channel
    let server_id = channel.server_id
        .ok_or(AppError::Forbidden("Cannot rename DM channels".into()))?;

    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::MANAGE_CHANNELS,
    )
    .await?;

    let encrypted_meta = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.encrypted_meta,
    )
    .map_err(|_| AppError::Validation("Invalid encrypted_meta encoding".into()))?;

    if encrypted_meta.len() > 8192 {
        return Err(AppError::Validation("encrypted_meta exceeds maximum size (8KB)".into()));
    }

    let updated = queries::update_channel_meta(state.db.write(), channel_id, &encrypted_meta, req.encrypted).await?;

    // If encryption setting changed, insert a system message
    if let Some(new_encrypted) = req.encrypted {
        if new_encrypted != channel.encrypted {
            let user = queries::find_user_by_id(state.db.read(), user_id).await?;
            let username = user
                .as_ref()
                .map(|u| u.display_name.as_deref().unwrap_or(&u.username).to_string())
                .unwrap_or_else(|| "Someone".to_string());
            let event = if new_encrypted { "encryption_enabled" } else { "encryption_disabled" };
            let body = serde_json::json!({
                "event": event,
                "username": username,
                "user_id": user_id.to_string(),
            });
            if let Ok(sys_msg) = queries::insert_system_message(
                state.db.write(), channel_id, &body.to_string(),
            ).await {
                let response: MessageResponse = sys_msg.into();
                if let Some(broadcaster) = state.channel_broadcasts.get(&channel_id) {
                    let _ = broadcaster.send(WsServerMessage::NewMessage(response));
                }
            }
        }
    }

    // Audit log
    let _ = queries::insert_audit_log(
        state.db.write(), server_id, user_id, "channel_update",
        Some("channel"), Some(channel_id), None, None,
    ).await;

    broadcast_to_server(&state, server_id, WsServerMessage::ServerUpdated { server_id }).await;

    Ok(Json(ChannelResponse {
        id: updated.id,
        server_id: updated.server_id,
        encrypted_meta: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &updated.encrypted_meta,
        ),
        channel_type: updated.channel_type,
        position: updated.position,
        created_at: updated.created_at,
        category_id: updated.category_id,
        dm_status: updated.dm_status,
        last_message_id: None,
        is_private: updated.is_private,
        encrypted: updated.encrypted,
        export_allowed: updated.export_allowed,
    }))
}

/// PUT /api/v1/servers/:server_id/channels/reorder
/// Reorder channels within a server (position + category assignment).
pub async fn reorder_channels(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
    Json(req): Json<ReorderChannelsRequest>,
) -> AppResult<Json<serde_json::Value>> {
    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::MANAGE_CHANNELS,
    )
    .await?;

    let order: Vec<(Uuid, i32, Option<Uuid>)> = req
        .order
        .iter()
        .map(|p| (p.id, p.position, p.category_id))
        .collect();
    queries::reorder_channels(state.db.write(), server_id, &order).await?;

    broadcast_to_server(&state, server_id, WsServerMessage::ServerUpdated { server_id }).await;

    Ok(Json(serde_json::json!({ "message": "Channels reordered" })))
}

/// DELETE /api/v1/channels/:channel_id
/// Delete a channel. Server owner only.
pub async fn delete_channel(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let channel = queries::find_channel_by_id(state.db.read(), channel_id)
        .await?
        .ok_or(AppError::NotFound("Channel not found".into()))?;

    let server_id = channel.server_id
        .ok_or(AppError::Forbidden("Cannot delete DM channels".into()))?;

    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::MANAGE_CHANNELS,
    )
    .await?;

    queries::delete_channel(state.db.write(), channel_id).await?;

    // Audit log
    let _ = queries::insert_audit_log(
        state.db.write(), server_id, user_id, "channel_delete",
        Some("channel"), Some(channel_id), None, None,
    ).await;

    broadcast_to_server(&state, server_id, WsServerMessage::ServerUpdated { server_id }).await;

    Ok(Json(serde_json::json!({ "message": "Channel deleted" })))
}

/// GET /api/v1/channels/:channel_id/members
/// List members of a channel with user info (for DM/group member sidebar).
pub async fn list_channel_members(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
) -> AppResult<Json<Vec<ChannelMemberInfo>>> {
    // Verify caller can access the channel
    if !queries::can_access_channel(state.db.read(), channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    let members = queries::get_channel_members_info(state.db.read(), channel_id).await?;
    Ok(Json(members))
}

/// POST /api/v1/dm/group
/// Create a group DM channel with multiple friends.
pub async fn create_group_dm(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<CreateGroupDmRequest>,
) -> AppResult<Json<ChannelResponse>> {
    // Validate member count: need at least 2 others (3+ total), max 10 total
    if req.member_ids.len() < 2 {
        return Err(AppError::Validation("Group DM requires at least 2 other members".into()));
    }
    if req.member_ids.len() > 9 {
        return Err(AppError::Validation("Group DM can have at most 10 members total".into()));
    }

    // Verify all members are friends of the creator
    for &member_id in &req.member_ids {
        if member_id == user_id {
            continue; // Skip self if accidentally included
        }
        if !queries::are_friends(state.db.read(), user_id, member_id).await? {
            return Err(AppError::Validation(format!(
                "User {} is not your friend",
                member_id
            )));
        }
    }

    let encrypted_meta = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.encrypted_meta,
    )
    .map_err(|_| AppError::Validation("Invalid encrypted_meta encoding".into()))?;

    if encrypted_meta.len() > 8192 {
        return Err(AppError::Validation("encrypted_meta exceeds maximum size (8KB)".into()));
    }

    let channel = queries::create_channel(state.db.write(), None, &encrypted_meta, "group", 0, None, false, true).await?;

    // Add creator
    queries::add_channel_member(state.db.write(), channel.id, user_id).await?;

    // Add all other members
    for &member_id in &req.member_ids {
        if member_id == user_id {
            continue;
        }
        queries::add_channel_member(state.db.write(), channel.id, member_id).await?;
    }

    Ok(Json(ChannelResponse {
        id: channel.id,
        server_id: None,
        encrypted_meta: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &channel.encrypted_meta,
        ),
        channel_type: channel.channel_type,
        position: channel.position,
        created_at: channel.created_at,
        category_id: None,
        dm_status: Some("active".to_string()),
        last_message_id: None,
        is_private: false,
        encrypted: true,
        export_allowed: channel.export_allowed,
    }))
}

/// DELETE /api/v1/channels/:channel_id/leave
/// Leave a group DM channel.
pub async fn leave_channel(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let channel = queries::find_channel_by_id(state.db.read(), channel_id)
        .await?
        .ok_or(AppError::NotFound("Channel not found".into()))?;

    if channel.channel_type != "group" {
        return Err(AppError::Validation("Can only leave group DM channels".into()));
    }

    if !queries::is_channel_member(state.db.read(), channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    // Look up username before removing
    let user = queries::find_user_by_id(state.db.read(), user_id).await?;
    let username = user
        .as_ref()
        .map(|u| u.display_name.as_deref().unwrap_or(&u.username).to_string())
        .unwrap_or_else(|| "Someone".to_string());

    // Remove the user from the channel
    queries::remove_channel_member(state.db.write(), channel_id, user_id).await?;

    // Check if channel is now empty
    let remaining = queries::get_channel_member_ids(state.db.read(), channel_id).await?;
    if remaining.is_empty() {
        queries::delete_channel(state.db.write(), channel_id).await?;
    } else {
        // Insert system message about the user leaving
        let body = serde_json::json!({
            "event": "member_left",
            "username": username,
            "user_id": user_id.to_string(),
        });
        if let Ok(sys_msg) = queries::insert_system_message(
            state.db.write(), channel_id, &body.to_string(),
        ).await {
            let response: MessageResponse = sys_msg.into();
            if let Some(broadcaster) = state.channel_broadcasts.get(&channel_id) {
                let _ = broadcaster.send(WsServerMessage::NewMessage(response));
            }
        }
    }

    Ok(Json(serde_json::json!({ "message": "Left channel" })))
}

/// POST /api/v1/channels/:channel_id/members
/// Add a member to an existing group DM.
pub async fn add_group_member(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
    Json(body): Json<AddGroupMemberRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let channel = queries::find_channel_by_id(state.db.read(), channel_id)
        .await?
        .ok_or(AppError::NotFound("Channel not found".into()))?;

    if channel.channel_type != "group" {
        return Err(AppError::Validation("Can only add members to group DM channels".into()));
    }

    if !queries::is_channel_member(state.db.read(), channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    if queries::is_channel_member(state.db.read(), channel_id, body.user_id).await? {
        return Err(AppError::Validation("User is already a member".into()));
    }

    // Cap at 10 members
    let members = queries::get_channel_member_ids(state.db.read(), channel_id).await?;
    if members.len() >= 10 {
        return Err(AppError::Validation("Group DM cannot have more than 10 members".into()));
    }

    queries::add_channel_member(state.db.write(), channel_id, body.user_id).await?;

    Ok(Json(serde_json::json!({ "added": true })))
}

#[derive(Debug, serde::Deserialize)]
pub struct AddGroupMemberRequest {
    pub user_id: Uuid,
}

/// Helper request type for DM creation.
#[derive(Debug, serde::Deserialize)]
pub struct CreateDmRequest {
    pub target_user_id: Uuid,
    pub encrypted_meta: String, // base64
}

/// Request type for channel updates (rename, encryption toggle).
#[derive(Debug, serde::Deserialize)]
pub struct UpdateChannelRequest {
    pub encrypted_meta: String, // base64
    pub encrypted: Option<bool>,
}

/// Send a WS message to a specific user (all their connections + Redis pub/sub).
async fn send_to_user(state: &AppState, user_id: Uuid, msg: WsServerMessage) {
    if let Some(conns) = state.connections.get(&user_id) {
        for tx in conns.iter() {
            let _ = tx.send(msg.clone());
        }
    }
    crate::pubsub::publish_user_event(state.redis.clone().as_mut(), user_id, &msg).await;
}

/// PUT /api/v1/channels/:channel_id/read-state
/// Mark a channel as read (sets last_read_at to now).
pub async fn mark_channel_read(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
) -> AppResult<Json<ReadState>> {
    // Verify channel access
    if !queries::can_access_channel(state.db.read(), channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    // Upsert read state
    let read_state = queries::upsert_read_state(state.db.write(), user_id, channel_id).await?;

    // Broadcast to other connections of same user (multi-device sync)
    let sync_msg = WsServerMessage::ReadStateUpdated {
        channel_id,
        last_read_at: read_state.last_read_at,
    };
    if let Some(conns) = state.connections.get(&user_id) {
        for conn in conns.iter() {
            let _ = conn.send(sync_msg.clone());
        }
    }
    crate::pubsub::publish_user_event(state.redis.clone().as_mut(), user_id, &sync_msg).await;

    Ok(Json(read_state))
}

/// GET /api/v1/channels/read-states
/// Get unread info for all channels the user belongs to.
pub async fn get_read_states(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> AppResult<Json<Vec<ChannelUnreadInfo>>> {
    // Get all channel IDs the user has access to
    let all_channel_ids = queries::get_user_channel_ids(state.db.read(), user_id).await?;

    if all_channel_ids.is_empty() {
        return Ok(Json(vec![]));
    }

    // Fetch last message IDs and unread counts in parallel
    let (last_msgs, unread_counts) = tokio::try_join!(
        queries::get_channel_last_message_ids(state.db.read(), &all_channel_ids),
        queries::get_user_unread_counts(state.db.read(), user_id, &all_channel_ids),
    )?;

    // Build lookup maps
    let last_msg_map: HashMap<Uuid, (Uuid, chrono::DateTime<chrono::Utc>)> = last_msgs
        .into_iter()
        .map(|(ch_id, msg_id, ts)| (ch_id, (msg_id, ts)))
        .collect();
    let unread_map: HashMap<Uuid, i64> = unread_counts.into_iter().collect();

    // Only return channels that have unreads or recent messages
    let infos: Vec<ChannelUnreadInfo> = all_channel_ids
        .iter()
        .filter_map(|ch_id| {
            let (last_id, last_at) = last_msg_map.get(ch_id)?;
            Some(ChannelUnreadInfo {
                channel_id: *ch_id,
                last_message_id: Some(*last_id),
                last_message_at: Some(*last_at),
                unread_count: *unread_map.get(ch_id).unwrap_or(&0),
            })
        })
        .collect();

    Ok(Json(infos))
}

// ─── Channel Export ───────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct ChannelExportQuery {
    pub after: Option<DateTime<Utc>>,
    pub before: Option<DateTime<Utc>>,
    #[serde(default)]
    pub include_attachments: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct ChannelExportResponse {
    pub channel_id: Uuid,
    pub channel_type: String,
    pub encrypted: bool,
    pub exported_at: DateTime<Utc>,
    pub exported_by: Uuid,
    pub message_count: usize,
    pub messages: Vec<MessageResponse>,
    pub include_attachments: bool,
}

/// GET /api/v1/channels/:channel_id/export
/// Bulk export all messages from a channel (excludes disappearing messages).
pub async fn export_channel(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
    Query(params): Query<ChannelExportQuery>,
) -> AppResult<Json<ChannelExportResponse>> {
    // Verify membership
    if !queries::can_access_channel(state.db.read(), channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    let channel = queries::find_channel_by_id(state.db.read(), channel_id)
        .await?
        .ok_or(AppError::NotFound("Channel not found".into()))?;

    // Check export_allowed for DM channels
    if (channel.channel_type == "dm" || channel.channel_type == "group") && !channel.export_allowed {
        return Err(AppError::Forbidden("Export is disabled for this DM channel".into()));
    }

    let messages =
        queries::get_export_messages(state.db.read(), channel_id, params.after, params.before)
            .await?;

    let message_count = messages.len();
    let responses: Vec<MessageResponse> = messages.into_iter().map(|m| m.into()).collect();

    // Audit log for server channels
    if let Some(server_id) = channel.server_id {
        let _ = queries::insert_audit_log(
            state.db.write(),
            server_id,
            user_id,
            "channel_export",
            Some("channel"),
            Some(channel_id),
            Some(&serde_json::json!({ "message_count": message_count })),
            None,
        )
        .await;
    }

    Ok(Json(ChannelExportResponse {
        channel_id,
        channel_type: channel.channel_type,
        encrypted: channel.encrypted,
        exported_at: Utc::now(),
        exported_by: user_id,
        message_count,
        messages: responses,
        include_attachments: params.include_attachments,
    }))
}

// ─── DM Export Consent ──────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct ExportConsentRequest {
    pub export_allowed: bool,
}

/// PUT /api/v1/channels/:channel_id/export-consent
/// Toggle export_allowed for a DM channel. Either participant can toggle.
pub async fn set_export_consent(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
    Json(req): Json<ExportConsentRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let channel = queries::find_channel_by_id(state.db.read(), channel_id)
        .await?
        .ok_or(AppError::NotFound("Channel not found".into()))?;

    // Only works on DM/group channels
    if channel.channel_type != "dm" && channel.channel_type != "group" {
        return Err(AppError::Validation(
            "Export consent can only be changed on DM channels".into(),
        ));
    }

    // Verify caller is a member
    if !queries::is_channel_member(state.db.read(), channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    // No-op if already set to requested value
    if channel.export_allowed == req.export_allowed {
        return Ok(Json(serde_json::json!({ "export_allowed": req.export_allowed })));
    }

    // Update the column
    queries::set_export_allowed(state.db.write(), channel_id, req.export_allowed).await?;

    // Insert system message
    let user = queries::find_user_by_id(state.db.read(), user_id).await?;
    let username = user
        .as_ref()
        .map(|u| u.display_name.as_deref().unwrap_or(&u.username).to_string())
        .unwrap_or_else(|| "Someone".to_string());

    let event = if req.export_allowed {
        "export_consent_enabled"
    } else {
        "export_consent_disabled"
    };
    let body = serde_json::json!({
        "event": event,
        "username": username,
        "user_id": user_id.to_string(),
    });
    if let Ok(sys_msg) =
        queries::insert_system_message(state.db.write(), channel_id, &body.to_string()).await
    {
        let response: MessageResponse = sys_msg.into();
        if let Some(broadcaster) = state.channel_broadcasts.get(&channel_id) {
            let _ = broadcaster.send(WsServerMessage::NewMessage(response));
        }
    }

    Ok(Json(serde_json::json!({ "export_allowed": req.export_allowed })))
}

/// PUT /api/v1/channels/:channel_id/hide
/// Hide a DM/group channel from the user's sidebar. Channel still exists
/// and can be un-hidden when a new message arrives.
pub async fn hide_channel(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let channel = queries::find_channel_by_id(state.db.read(), channel_id)
        .await?
        .ok_or(AppError::NotFound("Channel not found".into()))?;

    if channel.channel_type != "dm" && channel.channel_type != "group" {
        return Err(AppError::Validation(
            "Only DM and group channels can be hidden".into(),
        ));
    }

    if !queries::is_channel_member(state.db.read(), channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    queries::set_channel_member_hidden(state.db.write(), channel_id, user_id, true).await?;

    Ok(Json(serde_json::json!({ "hidden": true })))
}
