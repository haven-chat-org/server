use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;

use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::models::*;
use crate::AppState;

/// POST /api/v1/channels/:channel_id/sender-keys
/// Distribute encrypted sender keys to channel members.
pub async fn distribute_sender_keys(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
    Json(req): Json<DistributeSenderKeyRequest>,
) -> AppResult<Json<serde_json::Value>> {
    // Verify membership
    if !queries::can_access_channel(state.db.read(), channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    if req.distributions.is_empty() {
        return Err(AppError::Validation("No distributions provided".into()));
    }

    // Decode and prepare batch
    let distributions: Result<Vec<(Uuid, Uuid, Vec<u8>)>, AppError> = req
        .distributions
        .iter()
        .map(|d| {
            let bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &d.encrypted_skdm,
            )
            .map_err(|_| AppError::Validation("Invalid encrypted_skdm encoding".into()))?;
            Ok((d.to_user_id, d.distribution_id, bytes))
        })
        .collect();

    let distributions = distributions?;
    let count = distributions.len();

    queries::insert_sender_key_distributions(
        state.db.write(),
        channel_id,
        user_id,
        &distributions,
    )
    .await?;

    // Notify affected recipients via their WebSocket connections + Redis pub/sub
    let sk_msg = WsServerMessage::SenderKeysUpdated { channel_id };
    for (to_user_id, _, _) in &distributions {
        if let Some(conns) = state.connections.get(to_user_id) {
            for sender in conns.iter() {
                let _ = sender.send(sk_msg.clone());
            }
        }
        crate::pubsub::publish_user_event(state.redis.clone().as_mut(), *to_user_id, &sk_msg).await;
    }

    Ok(Json(serde_json::json!({ "distributed": count })))
}

/// GET /api/v1/channels/:channel_id/sender-keys
/// Fetch all sender key distributions for the authenticated user in this channel.
/// SKDMs are retained so clients can re-fetch after page reloads or on new devices.
/// The INSERT uses ON CONFLICT ... DO UPDATE, so rows are bounded to one per
/// (channel, sender, recipient, distributionId).
pub async fn get_sender_keys(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
) -> AppResult<Json<Vec<SenderKeyDistributionResponse>>> {
    // Verify membership
    if !queries::can_access_channel(state.db.read(), channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    let skdms = queries::get_sender_key_distributions(state.db.read(), channel_id, user_id).await?;

    let responses: Vec<SenderKeyDistributionResponse> = skdms
        .iter()
        .map(|s| SenderKeyDistributionResponse {
            id: s.id,
            channel_id: s.channel_id,
            from_user_id: s.from_user_id,
            distribution_id: s.distribution_id,
            encrypted_skdm: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &s.encrypted_skdm,
            ),
            created_at: s.created_at,
        })
        .collect();

    Ok(Json(responses))
}

/// GET /api/v1/channels/:channel_id/members/keys
/// Fetch identity keys for all members of a channel (for encrypting SKDMs).
/// Excludes the requesting user (they don't need to encrypt to themselves).
pub async fn get_channel_member_keys(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
) -> AppResult<Json<Vec<ChannelMemberKeyInfo>>> {
    if !queries::can_access_channel(state.db.read(), channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    let member_keys =
        queries::get_channel_member_identity_keys(state.db.read(), channel_id, user_id).await?;

    let results: Vec<ChannelMemberKeyInfo> = member_keys
        .iter()
        .map(|(uid, key)| ChannelMemberKeyInfo {
            user_id: *uid,
            identity_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                key,
            ),
        })
        .collect();

    Ok(Json(results))
}
