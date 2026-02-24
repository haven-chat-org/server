use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;

use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::models::*;
use crate::permissions;
use crate::ws::broadcast_to_server;
use crate::AppState;

/// GET /api/v1/servers/:server_id/categories
pub async fn list_categories(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
) -> AppResult<Json<Vec<CategoryResponse>>> {
    if !queries::is_server_member(state.db.read(), server_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this server".into()));
    }

    let cats = queries::get_server_categories(state.db.read(), server_id).await?;
    let responses: Vec<CategoryResponse> = cats.into_iter().map(CategoryResponse::from).collect();
    Ok(Json(responses))
}

/// POST /api/v1/servers/:server_id/categories
pub async fn create_category(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
    Json(req): Json<CreateCategoryRequest>,
) -> AppResult<Json<CategoryResponse>> {
    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::MANAGE_CHANNELS,
    )
    .await?;

    let position = req.position.unwrap_or(0);
    let cat = queries::create_category(state.db.write(), server_id, &req.name, position).await?;

    broadcast_to_server(&state, server_id, WsServerMessage::ServerUpdated { server_id }).await;

    Ok(Json(CategoryResponse::from(cat)))
}

/// PUT /api/v1/servers/:server_id/categories/reorder
pub async fn reorder_categories(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
    Json(req): Json<ReorderCategoriesRequest>,
) -> AppResult<Json<serde_json::Value>> {
    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::MANAGE_CHANNELS,
    )
    .await?;

    let order: Vec<(Uuid, i32)> = req.order.iter().map(|p| (p.id, p.position)).collect();
    queries::reorder_categories(state.db.write(), server_id, &order).await?;

    broadcast_to_server(&state, server_id, WsServerMessage::ServerUpdated { server_id }).await;

    Ok(Json(serde_json::json!({ "message": "Categories reordered" })))
}

/// PUT /api/v1/servers/:server_id/categories/:category_id
pub async fn update_category(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path((server_id, category_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateCategoryRequest>,
) -> AppResult<Json<CategoryResponse>> {
    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::MANAGE_CHANNELS,
    )
    .await?;

    let cat = queries::find_category_by_id(state.db.read(), category_id)
        .await?
        .ok_or(AppError::NotFound("Category not found".into()))?;
    if cat.server_id != server_id {
        return Err(AppError::NotFound("Category not found".into()));
    }

    let updated = queries::update_category(
        state.db.write(),
        category_id,
        req.name.as_deref(),
        req.position,
    )
    .await?;

    broadcast_to_server(&state, server_id, WsServerMessage::ServerUpdated { server_id }).await;

    Ok(Json(CategoryResponse::from(updated)))
}

/// DELETE /api/v1/servers/:server_id/categories/:category_id
pub async fn delete_category(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path((server_id, category_id)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<serde_json::Value>> {
    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::MANAGE_CHANNELS,
    )
    .await?;

    let cat = queries::find_category_by_id(state.db.read(), category_id)
        .await?
        .ok_or(AppError::NotFound("Category not found".into()))?;
    if cat.server_id != server_id {
        return Err(AppError::NotFound("Category not found".into()));
    }

    queries::delete_category(state.db.write(), category_id).await?;

    broadcast_to_server(&state, server_id, WsServerMessage::ServerUpdated { server_id }).await;

    Ok(Json(serde_json::json!({ "message": "Category deleted" })))
}

/// PUT /api/v1/channels/:channel_id/category
pub async fn set_channel_category(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
    Json(req): Json<SetChannelCategoryRequest>,
) -> AppResult<Json<ChannelResponse>> {
    let channel = queries::find_channel_by_id(state.db.read(), channel_id)
        .await?
        .ok_or(AppError::NotFound("Channel not found".into()))?;

    let server_id = channel.server_id
        .ok_or(AppError::Forbidden("Cannot set category on DM channels".into()))?;

    queries::require_server_permission(
        state.db.read(),
        server_id,
        user_id,
        permissions::MANAGE_CHANNELS,
    )
    .await?;

    // If setting a category, verify it exists and belongs to same server
    if let Some(cat_id) = req.category_id {
        let cat = queries::find_category_by_id(state.db.read(), cat_id)
            .await?
            .ok_or(AppError::NotFound("Category not found".into()))?;
        if cat.server_id != server_id {
            return Err(AppError::Forbidden("Category does not belong to this server".into()));
        }
    }

    let updated = queries::set_channel_category(state.db.write(), channel_id, req.category_id).await?;

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
