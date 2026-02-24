use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::models::*;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct MessageQuery {
    pub before: Option<DateTime<Utc>>,
    pub after: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
}

/// GET /api/v1/channels/:channel_id/messages
/// Paginated message history (encrypted blobs).
pub async fn get_messages(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
    Query(params): Query<MessageQuery>,
) -> AppResult<Json<Vec<MessageResponse>>> {
    // Verify membership
    if !queries::can_access_channel(state.db.read(), channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    let limit = params.limit.unwrap_or(50).min(100); // Cap at 100

    let messages =
        queries::get_channel_messages(state.db.read(), channel_id, params.before, params.after, limit).await?;

    let responses: Vec<MessageResponse> = messages.into_iter().map(|m| m.into()).collect();

    Ok(Json(responses))
}

/// GET /api/v1/channels/:channel_id/reactions
/// Returns grouped reactions for the most recent messages in a channel.
pub async fn get_channel_reactions(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
) -> AppResult<Json<Vec<ReactionGroup>>> {
    // Verify membership
    if !queries::can_access_channel(state.db.read(), channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    // Get recent message IDs for this channel
    let messages = queries::get_channel_messages(state.db.read(), channel_id, None, None, 50).await?;
    let message_ids: Vec<Uuid> = messages.iter().map(|m| m.id).collect();

    let reactions = queries::get_reactions_for_messages(state.db.read(), &message_ids).await?;

    // Group by (message_id, emoji)
    let mut groups: std::collections::HashMap<(Uuid, String), Vec<Uuid>> = std::collections::HashMap::new();
    for r in &reactions {
        groups
            .entry((r.message_id, r.emoji.clone()))
            .or_default()
            .push(r.user_id);
    }

    // Flatten into a response format that includes message_id
    let result: Vec<ReactionGroup> = groups
        .into_iter()
        .map(|((message_id, emoji), user_ids)| ReactionGroup {
            message_id,
            emoji,
            count: user_ids.len() as i64,
            user_ids,
        })
        .collect();

    Ok(Json(result))
}

/// GET /api/v1/messages/:message_id/reactions — get who reacted to a message
pub async fn get_message_reactions(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(message_id): Path<Uuid>,
) -> AppResult<Json<Vec<ReactionGroup>>> {
    // Find the message to verify access
    let message = queries::find_message_by_id(state.db.read(), message_id)
        .await?
        .ok_or(AppError::NotFound("Message not found".into()))?;

    // Verify membership in the channel
    if !queries::can_access_channel(state.db.read(), message.channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    let reactions = queries::get_reactions_for_message(state.db.read(), message_id).await?;

    // Group by emoji
    let mut groups: std::collections::HashMap<String, Vec<Uuid>> = std::collections::HashMap::new();
    for r in &reactions {
        groups.entry(r.emoji.clone()).or_default().push(r.user_id);
    }

    let result: Vec<ReactionGroup> = groups
        .into_iter()
        .map(|(emoji, user_ids)| ReactionGroup {
            message_id,
            emoji,
            count: user_ids.len() as i64,
            user_ids,
        })
        .collect();

    Ok(Json(result))
}

/// POST /api/v1/channels/:channel_id/messages
/// REST fallback for sending messages (primary path is WebSocket).
pub async fn send_message(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
    Json(req): Json<SendMessageRequest>,
) -> AppResult<Json<MessageResponse>> {
    // Verify membership
    if !queries::can_access_channel(state.db.read(), channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    // Check if member is timed out (server channels only)
    if let Ok(Some(channel)) = queries::find_channel_by_id(state.db.read(), channel_id).await {
        if let Some(server_id) = channel.server_id {
            if queries::is_member_timed_out(state.db.read(), server_id, user_id)
                .await
                .unwrap_or(false)
            {
                return Err(AppError::Forbidden("You are timed out in this server".into()));
            }
        }
    }

    let sender_token = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.sender_token,
    )
    .map_err(|_| AppError::Validation("Invalid sender_token encoding".into()))?;

    let encrypted_body = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.encrypted_body,
    )
    .map_err(|_| AppError::Validation("Invalid encrypted_body encoding".into()))?;

    let message = queries::insert_message(
        state.db.write(),
        channel_id,
        &sender_token,
        &encrypted_body,
        req.expires_at,
        req.has_attachments,
        user_id,
        req.reply_to_id,
    )
    .await?;

    let response: MessageResponse = message.into();

    // Fan out via WebSocket to channel members
    if let Ok(member_ids) = queries::get_channel_member_ids(state.db.read(), channel_id).await {
        for member_id in member_ids {
            if let Some(conns) = state.connections.get(&member_id) {
                for sender in conns.iter() {
                    let _ = sender.send(WsServerMessage::NewMessage(response.clone()));
                }
            }
        }
    }
    // Also publish to Redis for cross-instance delivery
    let channel_msg = WsServerMessage::NewMessage(response.clone());
    crate::pubsub::publish_channel_event(state.redis.clone().as_mut(), channel_id, &channel_msg).await;

    Ok(Json(response))
}

/// GET /api/v1/channels/:channel_id/pins
/// Returns all pinned messages in a channel.
pub async fn get_pins(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
) -> AppResult<Json<Vec<MessageResponse>>> {
    if !queries::can_access_channel(state.db.read(), channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    let messages = queries::get_pinned_messages(state.db.read(), channel_id).await?;
    let responses: Vec<MessageResponse> = messages.into_iter().map(|m| m.into()).collect();
    Ok(Json(responses))
}

/// GET /api/v1/channels/:channel_id/pin-ids
/// Returns just the IDs of pinned messages (lightweight).
pub async fn get_pin_ids(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
) -> AppResult<Json<Vec<Uuid>>> {
    if !queries::can_access_channel(state.db.read(), channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    let ids = queries::get_pinned_message_ids(state.db.read(), channel_id).await?;
    Ok(Json(ids))
}

/// POST /api/v1/channels/:channel_id/messages/bulk-delete
/// Bulk delete messages. Requires MANAGE_MESSAGES permission.
pub async fn bulk_delete_messages(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
    Json(req): Json<BulkDeleteRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if req.message_ids.is_empty() || req.message_ids.len() > 100 {
        return Err(AppError::Validation(
            "Must provide 1-100 message IDs".into(),
        ));
    }

    // Get channel and verify it's a server channel
    let channel = queries::find_channel_by_id(state.db.read(), channel_id)
        .await?
        .ok_or(AppError::NotFound("Channel not found".into()))?;
    let server_id = channel
        .server_id
        .ok_or(AppError::Forbidden("Bulk delete only available in server channels".into()))?;

    // Check MANAGE_MESSAGES permission
    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        crate::permissions::MANAGE_MESSAGES,
    )
    .await?;

    // Execute bulk delete
    let deleted_ids =
        queries::bulk_delete_messages(state.db.write(), channel_id, &req.message_ids).await?;

    // Broadcast deletion
    let del_msg = WsServerMessage::BulkMessagesDeleted {
        channel_id,
        message_ids: deleted_ids.clone(),
    };
    if let Some(broadcaster) = state.channel_broadcasts.get(&channel_id) {
        let _ = broadcaster.send(del_msg.clone());
    }
    crate::pubsub::publish_channel_event(state.redis.clone().as_mut(), channel_id, &del_msg)
        .await;

    // Audit log
    let _ = queries::insert_audit_log(
        state.db.write(),
        server_id,
        user_id,
        "message_bulk_delete",
        Some("channel"),
        Some(channel_id),
        Some(&serde_json::json!({ "count": deleted_ids.len() })),
        None,
    )
    .await;

    Ok(Json(serde_json::json!({ "deleted": deleted_ids.len() })))
}
