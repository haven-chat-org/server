use axum::{
    extract::{Path, State},
    Json,
};
use livekit_api::access_token::{AccessToken, VideoGrants};
use std::collections::HashSet;
use std::time::Duration;
use uuid::Uuid;

use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::models::{VoiceDeafenRequest, VoiceMuteRequest, VoiceParticipantResponse, VoiceTokenResponse, WsServerMessage};
use crate::{pubsub, AppState};

/// POST /api/v1/voice/:channel_id/join
///
/// Join a voice channel. Returns a LiveKit token for the client to connect with.
/// Automatically leaves any previously joined voice channel.
pub async fn join_voice(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
) -> AppResult<Json<VoiceTokenResponse>> {
    // Verify LiveKit is configured
    if !state.config.livekit_enabled() {
        return Err(AppError::BadRequest("Voice chat is not configured".into()));
    }

    // Verify channel exists and is type "voice"
    let channel = queries::find_channel_by_id(state.db.read(), channel_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Channel not found".into()))?;

    if !matches!(channel.channel_type.as_str(), "voice" | "dm" | "group") {
        return Err(AppError::BadRequest("Channel does not support voice".into()));
    }

    // Verify user can access this channel
    if !queries::can_access_channel(state.db.read(), channel_id, user_id).await? {
        return Err(AppError::Forbidden(
            "Not a member of this channel".into(),
        ));
    }

    // Remove user from any current voice channel
    let mut old_channels = Vec::new();
    for entry in state.memory.voice_participants.iter() {
        if entry.value().contains(&user_id) {
            old_channels.push(*entry.key());
        }
    }
    for old_ch in &old_channels {
        if let Some(mut participants) = state.memory.voice_participants.get_mut(old_ch) {
            participants.remove(&user_id);
        }
        if *old_ch != channel_id {
            // Clean up mute/deafen for old channel
            if let Some(mut muted) = state.memory.voice_muted.get_mut(old_ch) {
                muted.remove(&user_id);
            }
            if let Some(mut deafened) = state.memory.voice_deafened.get_mut(old_ch) {
                deafened.remove(&user_id);
            }
            broadcast_voice_state(&state, *old_ch, user_id, &user_id.to_string(), false).await;
        }
    }

    // Add user to the new voice channel
    state.memory.voice_participants
        .entry(channel_id)
        .or_insert_with(HashSet::new)
        .insert(user_id);

    // Look up display name for LiveKit participant metadata
    let participant_name = match queries::find_user_by_id(state.db.read(), user_id).await {
        Ok(Some(u)) => u.display_name.unwrap_or(u.username),
        _ => user_id.to_string(),
    };

    // Generate LiveKit token
    let token = AccessToken::with_api_key(
        &state.config.livekit_api_key,
        &state.config.livekit_api_secret,
    )
    .with_identity(&user_id.to_string())
    .with_name(&participant_name)
    .with_ttl(Duration::from_secs(6 * 3600)) // 6 hours
    .with_grants(VideoGrants {
        room_join: true,
        room: channel_id.to_string(),
        can_publish: true,
        can_subscribe: true,
        ..Default::default()
    })
    .to_jwt()
    .map_err(|e| AppError::BadRequest(format!("Failed to generate voice token: {}", e)))?;

    // Broadcast join to channel subscribers
    broadcast_voice_state(&state, channel_id, user_id, &user_id.to_string(), true).await;

    Ok(Json(VoiceTokenResponse {
        token,
        url: state.config.livekit_url_for_client().to_string(),
        channel_id,
    }))
}

/// POST /api/v1/voice/:channel_id/leave
///
/// Leave a voice channel.
pub async fn leave_voice(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let removed = state.memory.voice_participants
        .get_mut(&channel_id)
        .map(|mut set| set.remove(&user_id))
        .unwrap_or(false);

    if removed {
        // Clean up server mute/deafen state
        if let Some(mut muted) = state.memory.voice_muted.get_mut(&channel_id) {
            muted.remove(&user_id);
        }
        if let Some(mut deafened) = state.memory.voice_deafened.get_mut(&channel_id) {
            deafened.remove(&user_id);
        }
        broadcast_voice_state(&state, channel_id, user_id, &user_id.to_string(), false).await;
    }

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /api/v1/voice/:channel_id/participants
///
/// List users currently in a voice channel.
pub async fn get_participants(
    State(state): State<AppState>,
    AuthUser(_user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
) -> AppResult<Json<Vec<VoiceParticipantResponse>>> {
    let member_ids: Vec<Uuid> = state.memory.voice_participants
        .get(&channel_id)
        .map(|set| set.iter().cloned().collect())
        .unwrap_or_default();

    let muted_ids: HashSet<Uuid> = state.memory.voice_muted
        .get(&channel_id)
        .map(|set| set.clone())
        .unwrap_or_default();

    let deafened_ids: HashSet<Uuid> = state.memory.voice_deafened
        .get(&channel_id)
        .map(|set| set.clone())
        .unwrap_or_default();

    let mut participants = Vec::new();
    for uid in &member_ids {
        if let Ok(Some(user)) = queries::find_user_by_id(state.db.read(), *uid).await {
            participants.push(VoiceParticipantResponse {
                user_id: *uid,
                username: user.username,
                display_name: user.display_name,
                avatar_url: user.avatar_url,
                server_muted: muted_ids.contains(uid),
                server_deafened: deafened_ids.contains(uid),
            });
        }
    }

    Ok(Json(participants))
}

/// PUT /api/v1/voice/:channel_id/members/:user_id/mute
///
/// Server-mute a user in a voice channel. Requires MUTE_MEMBERS permission.
pub async fn server_mute(
    State(state): State<AppState>,
    AuthUser(caller_id): AuthUser,
    Path((channel_id, target_user_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<VoiceMuteRequest>,
) -> AppResult<Json<serde_json::Value>> {
    // Get channel to find server_id
    let channel = queries::find_channel_by_id(state.db.read(), channel_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Channel not found".into()))?;
    let server_id = channel.server_id
        .ok_or_else(|| AppError::BadRequest("Not a server channel".into()))?;

    // Check MUTE_MEMBERS permission
    let (is_owner, perms) = queries::get_member_permissions(state.db.read(), server_id, caller_id).await?;
    if !is_owner && !crate::permissions::has_permission(perms, crate::permissions::MUTE_MEMBERS) {
        return Err(AppError::Forbidden("Missing MUTE_MEMBERS permission".into()));
    }

    // Verify target is in the voice channel
    let in_channel = state.memory.voice_participants
        .get(&channel_id)
        .map(|set| set.contains(&target_user_id))
        .unwrap_or(false);
    if !in_channel {
        return Err(AppError::BadRequest("User is not in this voice channel".into()));
    }

    if req.muted {
        state.memory.voice_muted
            .entry(channel_id)
            .or_insert_with(HashSet::new)
            .insert(target_user_id);
    } else if let Some(mut set) = state.memory.voice_muted.get_mut(&channel_id) {
        set.remove(&target_user_id);
    }

    // Get current deafen state
    let is_deafened = state.memory.voice_deafened
        .get(&channel_id)
        .map(|set| set.contains(&target_user_id))
        .unwrap_or(false);

    // Broadcast to channel
    broadcast_voice_mute_state(&state, channel_id, target_user_id, req.muted, is_deafened).await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// PUT /api/v1/voice/:channel_id/members/:user_id/deafen
///
/// Server-deafen a user in a voice channel. Requires MUTE_MEMBERS permission.
pub async fn server_deafen(
    State(state): State<AppState>,
    AuthUser(caller_id): AuthUser,
    Path((channel_id, target_user_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<VoiceDeafenRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let channel = queries::find_channel_by_id(state.db.read(), channel_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Channel not found".into()))?;
    let server_id = channel.server_id
        .ok_or_else(|| AppError::BadRequest("Not a server channel".into()))?;

    let (is_owner, perms) = queries::get_member_permissions(state.db.read(), server_id, caller_id).await?;
    if !is_owner && !crate::permissions::has_permission(perms, crate::permissions::MUTE_MEMBERS) {
        return Err(AppError::Forbidden("Missing MUTE_MEMBERS permission".into()));
    }

    let in_channel = state.memory.voice_participants
        .get(&channel_id)
        .map(|set| set.contains(&target_user_id))
        .unwrap_or(false);
    if !in_channel {
        return Err(AppError::BadRequest("User is not in this voice channel".into()));
    }

    if req.deafened {
        state.memory.voice_deafened
            .entry(channel_id)
            .or_insert_with(HashSet::new)
            .insert(target_user_id);
    } else if let Some(mut set) = state.memory.voice_deafened.get_mut(&channel_id) {
        set.remove(&target_user_id);
    }

    // Get current mute state
    let is_muted = state.memory.voice_muted
        .get(&channel_id)
        .map(|set| set.contains(&target_user_id))
        .unwrap_or(false);

    broadcast_voice_mute_state(&state, channel_id, target_user_id, is_muted, req.deafened).await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Remove a user from all voice channels and broadcast their departure.
/// Called during WebSocket disconnect cleanup.
pub async fn cleanup_voice_state(state: &AppState, user_id: Uuid) {
    let mut left_channels = Vec::new();

    for mut entry in state.memory.voice_participants.iter_mut() {
        if entry.value_mut().remove(&user_id) {
            left_channels.push(*entry.key());
        }
    }

    // Clean up mute/deafen state
    for ch_id in &left_channels {
        if let Some(mut muted) = state.memory.voice_muted.get_mut(ch_id) {
            muted.remove(&user_id);
        }
        if let Some(mut deafened) = state.memory.voice_deafened.get_mut(ch_id) {
            deafened.remove(&user_id);
        }
        broadcast_voice_state(state, *ch_id, user_id, &user_id.to_string(), false).await;
    }
}

/// Broadcast a VoiceStateUpdate event to all subscribers of a channel.
async fn broadcast_voice_state(
    state: &AppState,
    channel_id: Uuid,
    user_id: Uuid,
    _user_id_str: &str,
    joined: bool,
) {
    // Look up username for the event
    let username = match queries::find_user_by_id(state.db.read(), user_id).await {
        Ok(Some(user)) => user.display_name.unwrap_or(user.username),
        _ => return,
    };

    let msg = WsServerMessage::VoiceStateUpdate {
        channel_id,
        user_id,
        username,
        joined,
    };

    if let Some(broadcaster) = state.channel_broadcasts.get(&channel_id) {
        let _ = broadcaster.send(msg.clone());
    }

    // Also broadcast to all channels in the same server so sidebar can update
    if let Ok(Some(channel)) = queries::find_channel_by_id(state.db.read(), channel_id).await {
        if let Some(server_id) = channel.server_id {
            if let Ok(channels) = queries::get_server_channels(state.db.read(), server_id).await {
                for ch in channels {
                    if ch.id != channel_id {
                        if let Some(broadcaster) = state.channel_broadcasts.get(&ch.id) {
                            let _ = broadcaster.send(msg.clone());
                        }
                    }
                }
            }
        } else {
            // DM/group channels: deliver directly to channel members (no server siblings)
            if let Ok(member_ids) = queries::get_channel_member_ids(state.db.read(), channel_id).await {
                for mid in member_ids {
                    if mid == user_id { continue; }
                    if let Some(conns) = state.connections.get(&mid) {
                        for tx in conns.iter() {
                            let _ = tx.send(msg.clone());
                        }
                    }
                    pubsub::publish_user_event(state.redis.clone().as_mut(), mid, &msg).await;
                }
            }
        }
    }
}

/// Broadcast a VoiceMuteUpdate event to the voice channel.
async fn broadcast_voice_mute_state(
    state: &AppState,
    channel_id: Uuid,
    user_id: Uuid,
    server_muted: bool,
    server_deafened: bool,
) {
    let msg = WsServerMessage::VoiceMuteUpdate {
        channel_id,
        user_id,
        server_muted,
        server_deafened,
    };

    if let Some(broadcaster) = state.channel_broadcasts.get(&channel_id) {
        let _ = broadcaster.send(msg.clone());
    }

    // Broadcast to all channels in the same server
    if let Ok(Some(channel)) = queries::find_channel_by_id(state.db.read(), channel_id).await {
        if let Some(server_id) = channel.server_id {
            if let Ok(channels) = queries::get_server_channels(state.db.read(), server_id).await {
                for ch in channels {
                    if ch.id != channel_id {
                        if let Some(broadcaster) = state.channel_broadcasts.get(&ch.id) {
                            let _ = broadcaster.send(msg.clone());
                        }
                    }
                }
            }
        }
    }
}
