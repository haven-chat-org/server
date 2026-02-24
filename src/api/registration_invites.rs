use axum::{
    extract::{Path, Query, State},
    Json,
};
use uuid::Uuid;

use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::middleware::{AdminUser, AuthUser};
use crate::models::*;
use crate::AppState;

/// GET /api/v1/auth/invite-required
/// Public: check whether registration requires an invite code.
pub async fn invite_required(
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    Ok(Json(serde_json::json!({
        "invite_required": state.config.registration_invite_only,
    })))
}

/// GET /api/v1/registration-invites
/// List the authenticated user's registration invites.
pub async fn list_my_invites(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> AppResult<Json<Vec<RegistrationInviteResponse>>> {
    let invites = queries::list_registration_invites_by_user(state.db.read(), user_id).await?;
    Ok(Json(invites.into_iter().map(Into::into).collect()))
}

/// GET /api/v1/admin/registration-invites
/// Admin: list all registration invites (paginated).
pub async fn admin_list_invites(
    AdminUser(_): AdminUser,
    State(state): State<AppState>,
    Query(params): Query<AdminSearchQuery>,
) -> AppResult<Json<Vec<RegistrationInviteResponse>>> {
    let limit = params.limit.unwrap_or(50).min(200);
    let offset = params.offset.unwrap_or(0);
    let invites = queries::list_all_registration_invites(state.db.read(), limit, offset).await?;
    Ok(Json(invites.into_iter().map(Into::into).collect()))
}

/// POST /api/v1/admin/registration-invites
/// Admin: create registration invites (not tied to any specific user).
pub async fn admin_create_invites(
    AdminUser(admin_id): AdminUser,
    State(state): State<AppState>,
    Json(req): Json<AdminCreateInvitesRequest>,
) -> AppResult<Json<Vec<RegistrationInviteResponse>>> {
    let count = req.count.unwrap_or(1).min(50);
    let invites =
        queries::create_registration_invites(state.db.write(), Some(admin_id), count).await?;
    Ok(Json(invites.into_iter().map(Into::into).collect()))
}

/// DELETE /api/v1/admin/registration-invites/:invite_id
/// Admin: revoke an unused registration invite.
pub async fn admin_delete_invite(
    AdminUser(_): AdminUser,
    State(state): State<AppState>,
    Path(invite_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let deleted = queries::delete_registration_invite(state.db.write(), invite_id).await?;
    if !deleted {
        return Err(AppError::NotFound(
            "Invite not found or already used".into(),
        ));
    }
    Ok(Json(serde_json::json!({ "deleted": true })))
}
