use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Redirect},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::models::*;
use crate::storage;
use crate::AppState;

const MAX_AVATAR_SIZE: usize = 2 * 1024 * 1024; // 2MB
const MAX_BANNER_SIZE: usize = 8 * 1024 * 1024; // 8MB

#[derive(Debug, Deserialize)]
pub struct UserSearchQuery {
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub struct ProfileQuery {
    pub server_id: Option<Uuid>,
}

/// GET /api/v1/users/search?username=Mork
pub async fn get_user_by_username(
    State(state): State<AppState>,
    AuthUser(_user_id): AuthUser,
    Query(query): Query<UserSearchQuery>,
) -> AppResult<Json<UserPublic>> {
    let user = queries::find_user_by_username(state.db.read(), &query.username).await?;
    let user = user.ok_or(AppError::UserNotFound)?;
    Ok(Json(UserPublic::from(user)))
}

/// GET /api/v1/users/:user_id/profile
pub async fn get_profile(
    State(state): State<AppState>,
    AuthUser(requester_id): AuthUser,
    Path(user_id): Path<Uuid>,
    Query(query): Query<ProfileQuery>,
) -> AppResult<Json<UserProfileResponse>> {
    let user = queries::find_user_by_id_cached(state.db.read(), &mut state.redis.clone(), &state.memory, user_id)
        .await?
        .ok_or(AppError::UserNotFound)?;

    let is_blocked = queries::is_blocked(state.db.read(), requester_id, user_id).await?;

    // Friendship status
    let mut is_friend = false;
    let mut friend_request_status: Option<String> = None;
    let mut friendship_id: Option<Uuid> = None;

    if requester_id != user_id {
        if let Some(friendship) = queries::find_friendship(state.db.read(), requester_id, user_id).await? {
            friendship_id = Some(friendship.id);
            if friendship.status == "accepted" {
                is_friend = true;
            } else {
                // Pending — determine direction
                if friendship.requester_id == requester_id {
                    friend_request_status = Some("pending_outgoing".to_string());
                } else {
                    friend_request_status = Some("pending_incoming".to_string());
                }
            }
        }
    }

    // Mutual friends & servers (skip for own profile)
    let (mutual_friend_count, mutual_friends, mutual_server_count) = if requester_id != user_id {
        let friends = queries::get_mutual_friends(state.db.read(), requester_id, user_id).await?;
        let count = friends.len() as i64;
        let server_count = queries::get_mutual_server_count(state.db.read(), requester_id, user_id).await?;
        (count, friends, server_count)
    } else {
        (0, vec![], 0)
    };

    // Server roles (only when server_id provided)
    let roles = if let Some(server_id) = query.server_id {
        let member_roles = queries::get_member_roles(state.db.read(), server_id, user_id).await?;
        Some(member_roles.into_iter().map(RoleResponse::from).collect())
    } else {
        None
    };

    let encrypted_profile = user.encrypted_profile.as_ref().map(|v| {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, v)
    });

    Ok(Json(UserProfileResponse {
        id: user.id,
        username: user.username,
        display_name: user.display_name,
        about_me: user.about_me,
        avatar_url: user.avatar_url,
        banner_url: user.banner_url,
        custom_status: user.custom_status,
        custom_status_emoji: user.custom_status_emoji,
        created_at: user.created_at,
        is_blocked,
        is_friend,
        friend_request_status,
        friendship_id,
        mutual_friend_count,
        mutual_friends,
        mutual_server_count,
        roles,
        encrypted_profile,
    }))
}

/// PUT /api/v1/users/profile
pub async fn update_profile(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<UpdateProfileRequest>,
) -> AppResult<Json<UserPublic>> {
    // Decode encrypted_profile if provided
    let encrypted_profile_bytes = if let Some(ref ep) = req.encrypted_profile {
        Some(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, ep)
                .map_err(|_| AppError::Validation("Invalid encrypted_profile encoding".into()))?,
        )
    } else {
        None
    };

    let user = queries::update_user_profile(
        state.db.write(),
        user_id,
        req.display_name.as_deref(),
        req.about_me.as_deref(),
        req.custom_status.as_deref(),
        req.custom_status_emoji.as_deref(),
        encrypted_profile_bytes.as_deref(),
    )
    .await?;

    // Invalidate user cache
    crate::cache::invalidate(state.redis.clone().as_mut(), &state.memory, &format!("haven:user:{}", user_id)).await;

    Ok(Json(UserPublic::from(user)))
}

/// POST /api/v1/users/avatar — upload avatar image (raw bytes)
pub async fn upload_avatar(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    body: Bytes,
) -> AppResult<Json<UserPublic>> {
    if body.is_empty() {
        return Err(AppError::Validation("No image data provided".into()));
    }
    if body.len() > MAX_AVATAR_SIZE {
        return Err(AppError::Validation(format!(
            "Avatar too large (max {}MB)",
            MAX_AVATAR_SIZE / 1024 / 1024
        )));
    }

    // Store using user_id-based storage key
    let storage_key = storage::obfuscated_key(&state.storage_key, &format!("avatar:{}", user_id));
    if state.config.cdn_enabled {
        state
            .storage
            .store_blob_raw(&storage_key, &body)
            .await
            .map_err(|e| AppError::BadRequest(format!("Failed to store avatar: {}", e)))?;
    } else {
        state
            .storage
            .store_blob(&storage_key, &body)
            .await
            .map_err(|e| AppError::BadRequest(format!("Failed to store avatar: {}", e)))?;
    }

    // Update avatar_url in DB to the download endpoint
    let avatar_url = format!("/api/v1/users/{}/avatar", user_id);
    let user = queries::update_user_avatar(state.db.write(), user_id, &avatar_url).await?;

    // Invalidate user cache
    crate::cache::invalidate(state.redis.clone().as_mut(), &state.memory, &format!("haven:user:{}", user_id)).await;

    Ok(Json(UserPublic::from(user)))
}

/// GET /api/v1/users/:user_id/avatar — download avatar image (no auth required for <img> src)
pub async fn get_avatar(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    // Verify user exists and has an avatar
    let user = queries::find_user_by_id(state.db.read(), user_id)
        .await?
        .ok_or(AppError::UserNotFound)?;

    if user.avatar_url.is_none() {
        return Err(AppError::NotFound("No avatar set".into()));
    }

    let storage_key = storage::obfuscated_key(&state.storage_key, &format!("avatar:{}", user_id));

    if state.config.cdn_enabled {
        // CDN mode: try to return a presigned URL redirect
        if let Some(url) = state
            .storage
            .presign_url(
                &storage_key,
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
            .load_blob_raw(&storage_key)
            .await
            .map_err(|_| AppError::NotFound("Avatar file not found".into()))?;

        let content_type = detect_image_type(&data);
        Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "public, max-age=3600".to_string()),
            ],
            data,
        )
            .into_response())
    } else {
        // Standard mode: decrypt server-side and return
        let data = state
            .storage
            .load_blob(&storage_key)
            .await
            .map_err(|_| AppError::NotFound("Avatar file not found".into()))?;

        let content_type = detect_image_type(&data);
        Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "public, max-age=3600".to_string()),
            ],
            data,
        )
            .into_response())
    }
}

/// POST /api/v1/users/banner — upload banner image (raw bytes)
pub async fn upload_banner(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    body: Bytes,
) -> AppResult<Json<UserPublic>> {
    if body.is_empty() {
        return Err(AppError::Validation("No image data provided".into()));
    }
    if body.len() > MAX_BANNER_SIZE {
        return Err(AppError::Validation(format!(
            "Banner too large (max {}MB)",
            MAX_BANNER_SIZE / 1024 / 1024
        )));
    }

    let storage_key = storage::obfuscated_key(&state.storage_key, &format!("banner:{}", user_id));
    if state.config.cdn_enabled {
        state
            .storage
            .store_blob_raw(&storage_key, &body)
            .await
            .map_err(|e| AppError::BadRequest(format!("Failed to store banner: {}", e)))?;
    } else {
        state
            .storage
            .store_blob(&storage_key, &body)
            .await
            .map_err(|e| AppError::BadRequest(format!("Failed to store banner: {}", e)))?;
    }

    let banner_url = format!("/api/v1/users/{}/banner", user_id);
    let user = queries::update_user_banner(state.db.write(), user_id, &banner_url).await?;

    crate::cache::invalidate(state.redis.clone().as_mut(), &state.memory, &format!("haven:user:{}", user_id)).await;

    Ok(Json(UserPublic::from(user)))
}

/// GET /api/v1/users/:user_id/banner — download banner image (no auth required for <img> src)
pub async fn get_banner(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = queries::find_user_by_id(state.db.read(), user_id)
        .await?
        .ok_or(AppError::UserNotFound)?;

    if user.banner_url.is_none() {
        return Err(AppError::NotFound("No banner set".into()));
    }

    let storage_key = storage::obfuscated_key(&state.storage_key, &format!("banner:{}", user_id));

    if state.config.cdn_enabled {
        if let Some(url) = state
            .storage
            .presign_url(
                &storage_key,
                state.config.cdn_presign_expiry_secs,
                &state.config.cdn_base_url,
            )
            .await
        {
            return Ok(Redirect::temporary(&url).into_response());
        }

        let data = state
            .storage
            .load_blob_raw(&storage_key)
            .await
            .map_err(|_| AppError::NotFound("Banner file not found".into()))?;

        let content_type = detect_image_type(&data);
        Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "public, max-age=3600".to_string()),
            ],
            data,
        )
            .into_response())
    } else {
        let data = state
            .storage
            .load_blob(&storage_key)
            .await
            .map_err(|_| AppError::NotFound("Banner file not found".into()))?;

        let content_type = detect_image_type(&data);
        Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "public, max-age=3600".to_string()),
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
    } else if data.starts_with(b"RIFF") && data.len() > 12 && &data[8..12] == b"WEBP" {
        "image/webp".into()
    } else {
        "application/octet-stream".into()
    }
}

/// POST /api/v1/users/:user_id/block
pub async fn block_user(
    State(state): State<AppState>,
    AuthUser(blocker_id): AuthUser,
    Path(blocked_id): Path<Uuid>,
) -> AppResult<Json<()>> {
    if blocker_id == blocked_id {
        return Err(AppError::Validation("Cannot block yourself".into()));
    }

    // Verify target user exists
    queries::find_user_by_id(state.db.read(), blocked_id)
        .await?
        .ok_or(AppError::UserNotFound)?;

    queries::block_user(state.db.write(), blocker_id, blocked_id).await?;
    Ok(Json(()))
}

/// DELETE /api/v1/users/:user_id/block
pub async fn unblock_user(
    State(state): State<AppState>,
    AuthUser(blocker_id): AuthUser,
    Path(blocked_id): Path<Uuid>,
) -> AppResult<Json<()>> {
    queries::unblock_user(state.db.write(), blocker_id, blocked_id).await?;
    Ok(Json(()))
}

/// GET /api/v1/users/blocked
pub async fn get_blocked_users(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Query(pagination): Query<PaginationQuery>,
) -> AppResult<Json<Vec<BlockedUserResponse>>> {
    let (limit, offset) = pagination.resolve();
    let blocked = queries::get_blocked_users(state.db.read(), user_id, limit, offset).await?;
    Ok(Json(blocked))
}

/// PUT /api/v1/users/profile-keys — distribute profile keys to contacts
pub async fn distribute_profile_keys(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<DistributeProfileKeysRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let mut distributions = Vec::new();
    for entry in &req.distributions {
        let key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &entry.encrypted_profile_key,
        )
        .map_err(|_| AppError::Validation("Invalid encrypted_profile_key encoding".into()))?;
        distributions.push((entry.to_user_id, key_bytes));
    }

    queries::distribute_profile_keys_bulk(state.db.write(), user_id, &distributions).await?;
    Ok(Json(serde_json::json!({ "distributed": distributions.len() })))
}

/// GET /api/v1/users/:user_id/profile-key — get the profile key for a specific user
pub async fn get_profile_key(
    State(state): State<AppState>,
    AuthUser(requester_id): AuthUser,
    Path(from_user_id): Path<Uuid>,
) -> AppResult<Json<ProfileKeyResponse>> {
    let dist = queries::get_profile_key(state.db.read(), from_user_id, requester_id)
        .await?
        .ok_or(AppError::NotFound("Profile key not found".into()))?;

    Ok(Json(ProfileKeyResponse {
        from_user_id: dist.from_user_id,
        encrypted_profile_key: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &dist.encrypted_profile_key,
        ),
    }))
}
