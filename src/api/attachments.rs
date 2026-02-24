use axum::{
    body::Bytes,
    extract::{Path as AxumPath, State},
    http::{header, StatusCode},
    response::{IntoResponse, Redirect},
    Json,
};
use uuid::Uuid;

use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::models::*;
use crate::storage;
use crate::AppState;

/// POST /api/v1/attachments/upload
/// Receives encrypted blob bytes, stores them.
/// When CDN is enabled, stores raw (no server-side encryption — client-side E2EE is sufficient).
/// When CDN is disabled, applies server-side AES-256-GCM encryption at rest.
pub async fn upload(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    body: Bytes,
) -> AppResult<Json<UploadResponse>> {
    // Per-user rate limit
    if !state.api_rate_limiter.check(user_id) {
        return Err(AppError::BadRequest("Rate limit exceeded — try again later".into()));
    }

    // Validate file size
    if body.len() as u64 > state.config.max_upload_size_bytes {
        return Err(AppError::BadRequest(format!(
            "File too large (max {} bytes)",
            state.config.max_upload_size_bytes
        )));
    }

    if body.is_empty() {
        return Err(AppError::Validation("Empty upload body".into()));
    }

    let attachment_id = Uuid::new_v4();
    let storage_key = storage::obfuscated_key(&state.storage_key, &attachment_id.to_string());

    if state.config.cdn_enabled {
        // CDN mode: store raw bytes (client-side E2EE is sufficient)
        state
            .storage
            .store_blob_raw(&storage_key, &body)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to store attachment: {}", e)))?;
    } else {
        // Standard mode: encrypt at rest with server-side AES
        state
            .storage
            .store_blob(&storage_key, &body)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to store attachment: {}", e)))?;
    }

    tracing::debug!("Stored attachment {} ({} bytes, cdn={})", attachment_id, body.len(), state.config.cdn_enabled);

    Ok(Json(UploadResponse {
        attachment_id,
        storage_key,
    }))
}

/// GET /api/v1/attachments/:attachment_id
/// When CDN is enabled, returns a presigned S3 URL redirect (or raw bytes for local storage).
/// When CDN is disabled, decrypts server-side encryption and returns raw bytes.
pub async fn download(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    AxumPath(attachment_id): AxumPath<Uuid>,
) -> AppResult<impl IntoResponse> {
    // Look up the attachment
    let att = queries::find_attachment_by_id(state.db.read(), attachment_id)
        .await?
        .ok_or(AppError::NotFound("Attachment not found".into()))?;

    // Verify the user has access to the message's channel
    let message = queries::find_message_by_id(state.db.read(), att.message_id)
        .await?
        .ok_or(AppError::NotFound("Message not found".into()))?;

    if !queries::can_access_channel(state.db.read(), message.channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    if state.config.cdn_enabled {
        // CDN mode: try to return a presigned URL redirect
        if let Some(url) = state
            .storage
            .presign_url(
                &att.storage_key,
                state.config.cdn_presign_expiry_secs,
                &state.config.cdn_base_url,
            )
            .await
        {
            return Ok(Redirect::temporary(&url).into_response());
        }

        // Fallback for local storage: serve raw bytes directly
        let data = state
            .storage
            .load_blob_raw(&att.storage_key)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to load attachment: {}", e)))?;

        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            data,
        )
            .into_response())
    } else {
        // Standard mode: decrypt server-side encryption and return bytes
        let data = state
            .storage
            .load_blob(&att.storage_key)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to load attachment: {}", e)))?;

        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            data,
        )
            .into_response())
    }
}
