use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Redirect},
    Json,
};
use uuid::Uuid;

use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::models::*;
use crate::permissions;
use crate::storage;
use crate::AppState;

const MAX_EMOJI_SIZE: usize = 256 * 1024; // 256KB
const MAX_STATIC_EMOJIS: i64 = 25;
const MAX_ANIMATED_EMOJIS: i64 = 10;

/// GET /api/v1/servers/:server_id/emojis — list all custom emojis (requires membership)
pub async fn list_emojis(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
) -> AppResult<Json<Vec<CustomEmojiResponse>>> {
    if !queries::is_server_member(state.db.read(), server_id, user_id).await? {
        return Err(AppError::Forbidden("Not a server member".into()));
    }

    let emojis = queries::list_server_emojis(state.db.read(), server_id).await?;
    let responses: Vec<CustomEmojiResponse> = emojis.iter().map(|e| e.to_response()).collect();
    Ok(Json(responses))
}

/// POST /api/v1/servers/:server_id/emojis?name=xxx — upload a custom emoji (binary body)
pub async fn upload_emoji(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
    Query(query): Query<CreateEmojiQuery>,
    body: Bytes,
) -> AppResult<Json<CustomEmojiResponse>> {
    // Per-user rate limit
    if !state.api_rate_limiter.check(user_id) {
        return Err(AppError::BadRequest("Rate limit exceeded — try again later".into()));
    }

    // Permission check
    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::MANAGE_EMOJIS,
    )
    .await?;

    // Validate name
    let name = query.name.trim();
    if name.len() < 2 {
        return Err(AppError::Validation("Emoji name must be at least 2 characters".into()));
    }
    if name.len() > 64 {
        return Err(AppError::Validation("Emoji name is too long (max 64 characters)".into()));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(AppError::Validation(
            "Emoji name can only contain letters, numbers, and underscores".into(),
        ));
    }

    // Validate body
    if body.is_empty() {
        return Err(AppError::Validation("No image data provided".into()));
    }
    if body.len() > MAX_EMOJI_SIZE {
        return Err(AppError::Validation(format!(
            "Emoji too large (max {}KB)",
            MAX_EMOJI_SIZE / 1024
        )));
    }

    // Validate image type via magic bytes
    let content_type = detect_image_type(&body);
    if content_type == "application/octet-stream" {
        return Err(AppError::Validation(
            "Invalid image format. Only PNG, JPEG, and GIF are supported".into(),
        ));
    }

    // Detect animated
    let animated = body.starts_with(b"GIF8");

    // Check slot limits
    let (static_count, animated_count) =
        queries::count_server_emojis(state.db.read(), server_id).await?;
    if animated {
        if animated_count >= MAX_ANIMATED_EMOJIS {
            return Err(AppError::Validation(format!(
                "Server has reached the animated emoji limit ({}/{})",
                animated_count, MAX_ANIMATED_EMOJIS
            )));
        }
    } else if static_count >= MAX_STATIC_EMOJIS {
        return Err(AppError::Validation(format!(
            "Server has reached the static emoji limit ({}/{})",
            static_count, MAX_STATIC_EMOJIS
        )));
    }

    // Store the emoji image
    let emoji_id = Uuid::new_v4();
    let storage_key = storage::obfuscated_key(
        &state.storage_key,
        &format!("emoji:{}:{}", server_id, emoji_id),
    );

    if state.config.cdn_enabled {
        state
            .storage
            .store_blob_raw(&storage_key, &body)
            .await
            .map_err(|e| AppError::BadRequest(format!("Failed to store emoji: {}", e)))?;
    } else {
        state
            .storage
            .store_blob(&storage_key, &body)
            .await
            .map_err(|e| AppError::BadRequest(format!("Failed to store emoji: {}", e)))?;
    }

    // Insert DB record
    let emoji = queries::create_emoji(
        state.db.write(),
        emoji_id,
        server_id,
        name,
        user_id,
        animated,
        &storage_key,
    )
    .await?;

    let response = emoji.to_response();

    // Broadcast to server members
    broadcast_to_server(&state, server_id, WsServerMessage::EmojiCreated {
        server_id,
        emoji: emoji.to_response(),
    })
    .await;

    Ok(Json(response))
}

/// PATCH /api/v1/servers/:server_id/emojis/:emoji_id — rename an emoji
pub async fn update_emoji(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path((server_id, emoji_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<RenameEmojiRequest>,
) -> AppResult<Json<CustomEmojiResponse>> {
    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::MANAGE_EMOJIS,
    )
    .await?;

    let name = body.name.trim();
    if name.len() < 2 {
        return Err(AppError::Validation("Emoji name must be at least 2 characters".into()));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(AppError::Validation(
            "Emoji name can only contain letters, numbers, and underscores".into(),
        ));
    }

    // Verify emoji belongs to this server
    let existing = queries::get_emoji_by_id(state.db.read(), emoji_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Emoji not found".into()))?;
    if existing.server_id != server_id {
        return Err(AppError::NotFound("Emoji not found".into()));
    }

    let emoji = queries::rename_emoji(state.db.write(), emoji_id, name).await?;
    Ok(Json(emoji.to_response()))
}

/// DELETE /api/v1/servers/:server_id/emojis/:emoji_id — delete an emoji
pub async fn delete_emoji(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path((server_id, emoji_id)): Path<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::MANAGE_EMOJIS,
    )
    .await?;

    // Delete from DB (returns the row for storage cleanup)
    let emoji = queries::delete_emoji(state.db.write(), emoji_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Emoji not found".into()))?;

    if emoji.server_id != server_id {
        return Err(AppError::NotFound("Emoji not found".into()));
    }

    // Clean up stored file
    let _ = state.storage.delete_blob(&emoji.storage_key).await;

    // Broadcast to server members
    broadcast_to_server(&state, server_id, WsServerMessage::EmojiDeleted {
        server_id,
        emoji_id,
    })
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/v1/servers/:server_id/emojis/:emoji_id/image — serve emoji image (no auth)
pub async fn get_emoji_image(
    State(state): State<AppState>,
    Path((server_id, emoji_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    let emoji = queries::get_emoji_by_id(state.db.read(), emoji_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Emoji not found".into()))?;

    if emoji.server_id != server_id {
        return Err(AppError::NotFound("Emoji not found".into()));
    }

    let storage_key = &emoji.storage_key;

    if state.config.cdn_enabled {
        if let Some(url) = state
            .storage
            .presign_url(
                storage_key,
                state.config.cdn_presign_expiry_secs,
                &state.config.cdn_base_url,
            )
            .await
        {
            return Ok(Redirect::temporary(&url).into_response());
        }

        let data = state
            .storage
            .load_blob_raw(storage_key)
            .await
            .map_err(|_| AppError::NotFound("Emoji file not found".into()))?;

        let content_type = detect_image_type(&data);
        Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "public, max-age=86400".to_string()),
            ],
            data,
        )
            .into_response())
    } else {
        let data = state
            .storage
            .load_blob(storage_key)
            .await
            .map_err(|_| AppError::NotFound("Emoji file not found".into()))?;

        let content_type = detect_image_type(&data);
        Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "public, max-age=86400".to_string()),
            ],
            data,
        )
            .into_response())
    }
}

fn detect_image_type(data: &[u8]) -> String {
    if data.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        "image/png".into()
    } else if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        "image/jpeg".into()
    } else if data.starts_with(b"GIF8") {
        "image/gif".into()
    } else {
        "application/octet-stream".into()
    }
}

/// Broadcast a WS message to all members of a server by iterating their connections.
async fn broadcast_to_server(state: &AppState, server_id: Uuid, msg: WsServerMessage) {
    // Get all server channels and broadcast via channel subscriptions
    if let Ok(channels) = queries::get_server_channels(state.db.read(), server_id).await {
        for ch in channels {
            if let Some(broadcaster) = state.channel_broadcasts.get(&ch.id) {
                let _ = broadcaster.send(msg.clone());
            }
        }
    }
}
