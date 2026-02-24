use axum::{
    extract::{Path, Query, State},
    Json,
};
use uuid::Uuid;

use crate::db::queries;
use crate::errors::AppResult;
use crate::middleware::AdminUser;
use crate::models::{AdminSearchQuery, AdminStats, AdminUserResponse, SetAdminRequest};
use crate::AppState;

/// GET /api/v1/admin/stats
pub async fn get_stats(
    AdminUser(_user_id): AdminUser,
    State(state): State<AppState>,
) -> AppResult<Json<AdminStats>> {
    let (users, servers, channels, messages) = tokio::try_join!(
        queries::count_all_users(state.db.read()),
        queries::count_all_servers(state.db.read()),
        queries::count_all_channels(state.db.read()),
        queries::count_all_messages(state.db.read()),
    )?;

    let active_connections = state.connections.len();

    Ok(Json(AdminStats {
        total_users: users,
        total_servers: servers,
        total_channels: channels,
        total_messages: messages,
        active_connections,
    }))
}

/// GET /api/v1/admin/users
pub async fn list_users(
    AdminUser(_user_id): AdminUser,
    State(state): State<AppState>,
    Query(params): Query<AdminSearchQuery>,
) -> AppResult<Json<Vec<AdminUserResponse>>> {
    let limit = params.limit.unwrap_or(50).clamp(1, 100);
    let offset = params.offset.unwrap_or(0).max(0);

    let users = queries::search_users_admin(
        state.db.read(),
        params.search.as_deref(),
        limit,
        offset,
    )
    .await?;

    Ok(Json(users))
}

/// PUT /api/v1/admin/users/:user_id/admin
pub async fn set_admin(
    AdminUser(admin_id): AdminUser,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(req): Json<SetAdminRequest>,
) -> AppResult<Json<serde_json::Value>> {
    // Prevent self-demotion
    if user_id == admin_id && !req.is_admin {
        return Err(crate::errors::AppError::BadRequest(
            "Cannot remove your own admin status".into(),
        ));
    }

    // Verify target user exists
    queries::find_user_by_id(state.db.read(), user_id)
        .await?
        .ok_or(crate::errors::AppError::NotFound("User not found".into()))?;

    queries::set_instance_admin(state.db.write(), user_id, req.is_admin).await?;

    Ok(Json(serde_json::json!({
        "user_id": user_id,
        "is_instance_admin": req.is_admin,
    })))
}

/// DELETE /api/v1/admin/users/:user_id
pub async fn delete_user(
    AdminUser(admin_id): AdminUser,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    // Prevent self-deletion via admin panel
    if user_id == admin_id {
        return Err(crate::errors::AppError::BadRequest(
            "Cannot delete your own account via admin panel".into(),
        ));
    }

    // Verify target user exists
    queries::find_user_by_id(state.db.read(), user_id)
        .await?
        .ok_or(crate::errors::AppError::NotFound("User not found".into()))?;

    queries::delete_user_account(state.db.write(), user_id).await?;

    Ok(Json(serde_json::json!({
        "deleted": true,
        "user_id": user_id,
    })))
}
