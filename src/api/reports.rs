use axum::{extract::State, Json};

use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::models::*;
use crate::AppState;

/// POST /api/v1/reports
pub async fn create_report(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<CreateReportRequest>,
) -> AppResult<Json<ReportResponse>> {
    // Verify user can access the channel
    if !queries::can_access_channel(state.db.read(), req.channel_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this channel".into()));
    }

    if req.reason.len() < 10 {
        return Err(AppError::Validation("Reason must be at least 10 characters".into()));
    }

    let report = queries::create_report(
        state.db.write(),
        user_id,
        req.message_id,
        req.channel_id,
        &req.reason,
    )
    .await?;

    Ok(Json(ReportResponse {
        id: report.id,
        message_id: report.message_id,
        reason: report.reason,
        status: report.status,
        created_at: report.created_at,
    }))
}
