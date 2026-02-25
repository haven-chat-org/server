use axum::{
    extract::{Path, Query, State},
    Json,
};
use uuid::Uuid;

use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::models::*;
use crate::AppState;

/// GET /api/v1/friends
/// List all friends and pending requests for the authenticated user.
pub async fn list_friends(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Query(pagination): Query<PaginationQuery>,
) -> AppResult<Json<Vec<FriendResponse>>> {
    let (limit, offset) = pagination.resolve();
    let friends = queries::get_friends_list(state.db.read(), user_id, limit, offset).await?;
    Ok(Json(friends))
}

/// POST /api/v1/friends/request
/// Send a friend request by username.
pub async fn send_friend_request(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<FriendRequestBody>,
) -> AppResult<Json<FriendResponse>> {
    // Find target user
    let target = queries::find_user_by_username(state.db.read(), &req.username)
        .await?
        .ok_or(AppError::UserNotFound)?;

    if target.id == user_id {
        return Err(AppError::Validation("Cannot send a friend request to yourself".into()));
    }

    // Check if blocked
    if queries::is_blocked(state.db.read(), target.id, user_id).await? {
        return Err(AppError::Forbidden("Cannot send friend request to this user".into()));
    }

    // Check for existing friendship
    if let Some(existing) = queries::find_friendship(state.db.read(), user_id, target.id).await? {
        if existing.status == "accepted" {
            return Err(AppError::Validation("Already friends".into()));
        }
        // If there's a pending request FROM them TO us, auto-accept
        if existing.requester_id == target.id && existing.status == "pending" {
            let accepted = queries::accept_friend_request(state.db.write(), existing.id).await?;
            let requester = queries::find_user_by_id(state.db.read(), accepted.requester_id)
                .await?
                .ok_or(AppError::UserNotFound)?;

            // Notify the original requester that we accepted
            send_to_user(&state, target.id, WsServerMessage::FriendRequestAccepted {
                user_id,
                username: queries::find_user_by_id(state.db.read(), user_id)
                    .await?
                    .map(|u| u.username.clone())
                    .unwrap_or_default(),
                friendship_id: accepted.id,
            }).await;

            return Ok(Json(FriendResponse {
                id: accepted.id,
                user_id: target.id,
                username: requester.username,
                display_name: requester.display_name,
                avatar_url: requester.avatar_url,
                status: "accepted".to_string(),
                is_incoming: false,
                created_at: accepted.created_at,
                is_system: if requester.is_system { Some(true) } else { None },
            }));
        }
        return Err(AppError::Validation("Friend request already pending".into()));
    }

    let friendship = queries::send_friend_request(state.db.write(), user_id, target.id).await?;

    // Look up our username
    let requester_user = queries::find_user_by_id(state.db.read(), user_id)
        .await?
        .ok_or(AppError::UserNotFound)?;

    // Notify the target via WS
    send_to_user(&state, target.id, WsServerMessage::FriendRequestReceived {
        from_user_id: user_id,
        from_username: requester_user.username.clone(),
        friendship_id: friendship.id,
    }).await;

    Ok(Json(FriendResponse {
        id: friendship.id,
        user_id: target.id,
        username: target.username,
        display_name: target.display_name,
        avatar_url: target.avatar_url,
        status: "pending".to_string(),
        is_incoming: false,
        created_at: friendship.created_at,
        is_system: if target.is_system { Some(true) } else { None },
    }))
}

/// POST /api/v1/friends/:friendship_id/accept
pub async fn accept_friend_request(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(friendship_id): Path<Uuid>,
) -> AppResult<Json<FriendResponse>> {
    let friendship = queries::find_friendship_by_id(state.db.read(), friendship_id)
        .await?
        .ok_or(AppError::NotFound("Friend request not found".into()))?;

    // Only the addressee can accept
    if friendship.addressee_id != user_id {
        return Err(AppError::Forbidden("Cannot accept this request".into()));
    }
    if friendship.status != "pending" {
        return Err(AppError::Validation("Request is not pending".into()));
    }

    let accepted = queries::accept_friend_request(state.db.write(), friendship_id).await?;

    let requester = queries::find_user_by_id(state.db.read(), accepted.requester_id)
        .await?
        .ok_or(AppError::UserNotFound)?;

    let accepter = queries::find_user_by_id(state.db.read(), user_id)
        .await?
        .ok_or(AppError::UserNotFound)?;

    // Notify the requester
    send_to_user(&state, accepted.requester_id, WsServerMessage::FriendRequestAccepted {
        user_id,
        username: accepter.username,
        friendship_id: accepted.id,
    }).await;

    Ok(Json(FriendResponse {
        id: accepted.id,
        user_id: requester.id,
        username: requester.username,
        display_name: requester.display_name,
        avatar_url: requester.avatar_url,
        status: "accepted".to_string(),
        is_incoming: true,
        created_at: accepted.created_at,
        is_system: if requester.is_system { Some(true) } else { None },
    }))
}

/// POST /api/v1/friends/:friendship_id/decline
pub async fn decline_friend_request(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(friendship_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let friendship = queries::find_friendship_by_id(state.db.read(), friendship_id)
        .await?
        .ok_or(AppError::NotFound("Friend request not found".into()))?;

    // Only the addressee can decline
    if friendship.addressee_id != user_id {
        return Err(AppError::Forbidden("Cannot decline this request".into()));
    }
    if friendship.status != "pending" {
        return Err(AppError::Validation("Request is not pending".into()));
    }

    queries::delete_friendship(state.db.write(), friendship_id).await?;
    Ok(Json(serde_json::json!({ "message": "Friend request declined" })))
}

/// DELETE /api/v1/friends/:friendship_id
/// Cancel a pending request (requester) or remove an existing friend.
pub async fn remove_friend(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(friendship_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let friendship = queries::find_friendship_by_id(state.db.read(), friendship_id)
        .await?
        .ok_or(AppError::NotFound("Friendship not found".into()))?;

    // Must be one of the two parties
    if friendship.requester_id != user_id && friendship.addressee_id != user_id {
        return Err(AppError::Forbidden("Not part of this friendship".into()));
    }

    let other_user_id = if friendship.requester_id == user_id {
        friendship.addressee_id
    } else {
        friendship.requester_id
    };

    queries::delete_friendship(state.db.write(), friendship_id).await?;

    // Notify the other user
    send_to_user(&state, other_user_id, WsServerMessage::FriendRemoved {
        user_id,
    }).await;

    Ok(Json(serde_json::json!({ "message": "Friend removed" })))
}

/// GET /api/v1/dm/requests
/// List pending DM channels for the authenticated user.
pub async fn list_dm_requests(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> AppResult<Json<Vec<ChannelResponse>>> {
    let channels = queries::get_pending_dm_channels(state.db.read(), user_id).await?;
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
            is_private: false,
            encrypted: true,
            export_allowed: ch.export_allowed,
        })
        .collect();
    Ok(Json(responses))
}

/// POST /api/v1/dm/:channel_id/request
/// Accept or decline a DM request.
pub async fn handle_dm_request(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
    Json(req): Json<DmRequestAction>,
) -> AppResult<Json<serde_json::Value>> {
    let channel = queries::find_channel_by_id(state.db.read(), channel_id)
        .await?
        .ok_or(AppError::NotFound("Channel not found".into()))?;

    if channel.channel_type != "dm" {
        return Err(AppError::Validation("Not a DM channel".into()));
    }
    if channel.dm_status.as_deref() != Some("pending") {
        return Err(AppError::Validation("DM is not pending".into()));
    }

    // Verify user is a member
    if !queries::is_channel_member(state.db.read(), channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    match req.action.as_str() {
        "accept" => {
            queries::set_dm_status(state.db.write(), channel_id, "active").await?;
            Ok(Json(serde_json::json!({ "message": "DM request accepted" })))
        }
        "decline" => {
            queries::set_dm_status(state.db.write(), channel_id, "declined").await?;
            Ok(Json(serde_json::json!({ "message": "DM request declined" })))
        }
        _ => Err(AppError::Validation("action must be 'accept' or 'decline'".into())),
    }
}

/// PUT /api/v1/users/dm-privacy
pub async fn update_dm_privacy(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<UpdateDmPrivacyRequest>,
) -> AppResult<Json<serde_json::Value>> {
    match req.dm_privacy.as_str() {
        "everyone" | "friends_only" | "server_members" => {}
        _ => {
            return Err(AppError::Validation(
                "dm_privacy must be 'everyone', 'friends_only', or 'server_members'".into(),
            ));
        }
    }

    queries::update_dm_privacy(state.db.write(), user_id, &req.dm_privacy).await?;
    Ok(Json(serde_json::json!({ "dm_privacy": req.dm_privacy })))
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
