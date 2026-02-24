use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::Utc;
use rand::Rng;
use uuid::Uuid;

use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::models::*;
use crate::permissions;
use crate::AppState;

/// POST /api/v1/servers/:server_id/invites
/// Create an invite code for a server (owner/admin only).
pub async fn create_invite(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
    Json(req): Json<CreateInviteRequest>,
) -> AppResult<Json<InviteResponse>> {
    // Per-user rate limit
    if !state.api_rate_limiter.check(user_id) {
        return Err(AppError::BadRequest("Rate limit exceeded — try again later".into()));
    }

    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::CREATE_INVITES,
    )
    .await?;

    // Generate a random 8-char invite code
    let code = generate_invite_code();

    let expires_at = req.expires_in_hours.map(|hours| {
        Utc::now() + chrono::Duration::seconds((hours * 3600.0) as i64)
    });

    let invite = queries::create_invite(
        state.db.write(),
        server_id,
        user_id,
        &code,
        req.max_uses,
        expires_at,
    )
    .await?;

    Ok(Json(InviteResponse::from(invite)))
}

/// GET /api/v1/servers/:server_id/invites
/// List all invites for a server (owner/admin only).
pub async fn list_invites(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
    Query(pagination): Query<PaginationQuery>,
) -> AppResult<Json<Vec<InviteResponse>>> {
    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::MANAGE_INVITES,
    )
    .await?;

    let (limit, offset) = pagination.resolve();
    let invites = queries::get_server_invites(state.db.read(), server_id, limit, offset).await?;
    let responses: Vec<InviteResponse> = invites.into_iter().map(InviteResponse::from).collect();

    Ok(Json(responses))
}

/// DELETE /api/v1/servers/:server_id/invites/:invite_id
/// Revoke an invite (owner/admin only).
pub async fn delete_invite(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path((server_id, invite_id)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<serde_json::Value>> {
    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::MANAGE_INVITES,
    )
    .await?;

    queries::delete_invite(state.db.write(), invite_id).await?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}

/// POST /api/v1/invites/:code/join
/// Join a server by invite code.
pub async fn join_by_invite(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(code): Path<String>,
) -> AppResult<Json<ServerResponse>> {
    // Find the invite
    let invite = queries::find_invite_by_code(state.db.read(), &code)
        .await?
        .ok_or(AppError::NotFound("Invalid invite code".into()))?;

    // Check expiry
    if let Some(expires_at) = invite.expires_at {
        if Utc::now() > expires_at {
            return Err(AppError::Validation("Invite has expired".into()));
        }
    }

    // Check max uses
    if let Some(max_uses) = invite.max_uses {
        if invite.use_count >= max_uses {
            return Err(AppError::Validation("Invite has reached max uses".into()));
        }
    }

    // Check if banned
    if queries::is_banned(state.db.read(), invite.server_id, user_id).await? {
        return Err(AppError::Forbidden("You are banned from this server".into()));
    }

    // Check if already a member
    if queries::is_server_member(state.db.read(), invite.server_id, user_id).await? {
        return Err(AppError::Validation("Already a member of this server".into()));
    }

    // Add user to the server
    let member_role = b"member";
    queries::add_server_member(state.db.write(), invite.server_id, user_id, member_role).await?;

    // Add user to all server channels (single bulk INSERT)
    queries::add_channel_members_bulk(state.db.write(), invite.server_id, user_id).await?;
    let channels = queries::get_server_channels(state.db.read(), invite.server_id).await?;

    // Increment invite use count
    queries::increment_invite_uses(state.db.write(), invite.id).await?;

    // Return the server info (need it for system_channel_id)
    let server = queries::find_server_by_id(state.db.read(), invite.server_id)
        .await?
        .ok_or(AppError::Internal(anyhow::anyhow!("Server not found after join")))?;

    // Insert system message in the system channel (or first channel as fallback)
    let sys_channel = server.system_channel_id
        .and_then(|id| channels.iter().find(|c| c.id == id))
        .or(channels.first());
    if let Some(target_channel) = sys_channel {
        let user = queries::find_user_by_id(state.db.read(), user_id).await?.unwrap();
        let username = user.display_name.as_deref().unwrap_or(&user.username);
        let body = serde_json::json!({
            "event": "member_joined",
            "username": username,
            "user_id": user_id.to_string(),
        });
        if let Ok(sys_msg) = queries::insert_system_message(
            state.db.write(), target_channel.id, &body.to_string(),
        ).await {
            let response: MessageResponse = sys_msg.into();
            if let Some(broadcaster) = state.channel_broadcasts.get(&target_channel.id) {
                let _ = broadcaster.send(WsServerMessage::NewMessage(response));
            }
        }
    }

    let (_, perms) = queries::get_member_permissions(state.db.read(), server.id, user_id).await?;

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

/// GET /api/v1/servers/:server_id/members
/// List members of a server.
pub async fn list_members(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
    Query(pagination): Query<PaginationQuery>,
) -> AppResult<Json<Vec<ServerMemberResponse>>> {
    if !queries::is_server_member(state.db.read(), server_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this server".into()));
    }

    let (limit, offset) = pagination.resolve();
    let members = queries::get_server_members(state.db.read(), server_id, limit, offset).await?;
    Ok(Json(members))
}

/// DELETE /api/v1/servers/:server_id/members/:target_user_id
/// Kick a member from the server (owner only).
pub async fn kick_member(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path((server_id, target_user_id)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<serde_json::Value>> {
    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::KICK_MEMBERS,
    )
    .await?;

    if target_user_id == user_id {
        return Err(AppError::Validation("Cannot kick yourself".into()));
    }

    // Look up username before removing
    let target_user = queries::find_user_by_id(state.db.read(), target_user_id).await?;
    let target_name = target_user
        .as_ref()
        .map(|u| u.display_name.as_deref().unwrap_or(&u.username))
        .unwrap_or("Unknown");

    queries::remove_server_member(state.db.write(), server_id, target_user_id).await?;

    // Insert system message in the first server channel
    let channels = queries::get_server_channels(state.db.read(), server_id).await?;
    if let Some(first_channel) = channels.first() {
        let body = serde_json::json!({
            "event": "member_kicked",
            "username": target_name,
            "user_id": target_user_id.to_string(),
        });
        if let Ok(sys_msg) = queries::insert_system_message(
            state.db.write(), first_channel.id, &body.to_string(),
        ).await {
            let response: MessageResponse = sys_msg.into();
            if let Some(broadcaster) = state.channel_broadcasts.get(&first_channel.id) {
                let _ = broadcaster.send(WsServerMessage::NewMessage(response));
            }
        }
    }

    // Audit log
    let _ = queries::insert_audit_log(
        state.db.write(), server_id, user_id, "member_kick",
        Some("member"), Some(target_user_id),
        Some(&serde_json::json!({ "username": target_name })), None,
    ).await;

    Ok(Json(serde_json::json!({ "kicked": true })))
}

fn generate_invite_code() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}
