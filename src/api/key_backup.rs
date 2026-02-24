use axum::{extract::State, Json};

use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::models::*;
use crate::AppState;

const MAX_BACKUP_SIZE: usize = 512 * 1024; // 512 KB

/// PUT /api/v1/keys/backup
pub async fn upload_key_backup(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<UploadKeyBackupRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let encrypted_data = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.encrypted_data,
    )
    .map_err(|_| AppError::Validation("Invalid encrypted_data encoding".into()))?;

    let nonce = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.nonce,
    )
    .map_err(|_| AppError::Validation("Invalid nonce encoding".into()))?;

    let salt = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.salt,
    )
    .map_err(|_| AppError::Validation("Invalid salt encoding".into()))?;

    if nonce.len() != 24 {
        return Err(AppError::Validation("Nonce must be 24 bytes".into()));
    }
    if salt.len() != 16 {
        return Err(AppError::Validation("Salt must be 16 bytes".into()));
    }
    if encrypted_data.len() > MAX_BACKUP_SIZE {
        return Err(AppError::Validation(format!(
            "Backup too large (max {}KB)",
            MAX_BACKUP_SIZE / 1024
        )));
    }

    let version = req.version.unwrap_or(1);

    queries::upsert_key_backup(
        state.db.write(),
        user_id,
        &encrypted_data,
        &nonce,
        &salt,
        version,
    )
    .await?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /api/v1/keys/backup
pub async fn get_key_backup(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> AppResult<Json<KeyBackupResponse>> {
    let backup = queries::get_key_backup(state.db.read(), user_id)
        .await?
        .ok_or(AppError::NotFound("No key backup found".into()))?;

    Ok(Json(KeyBackupResponse {
        encrypted_data: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &backup.encrypted_data,
        ),
        nonce: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &backup.nonce,
        ),
        salt: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &backup.salt,
        ),
        version: backup.version,
        updated_at: backup.updated_at,
    }))
}

/// GET /api/v1/keys/backup/status
pub async fn get_key_backup_status(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> AppResult<Json<KeyBackupStatusResponse>> {
    let backup = queries::get_key_backup(state.db.read(), user_id).await?;

    Ok(Json(KeyBackupStatusResponse {
        has_backup: backup.is_some(),
        version: backup.as_ref().map(|b| b.version),
        updated_at: backup.map(|b| b.updated_at),
    }))
}

/// DELETE /api/v1/keys/backup
pub async fn delete_key_backup(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> AppResult<Json<serde_json::Value>> {
    queries::delete_key_backup(state.db.write(), user_id).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
