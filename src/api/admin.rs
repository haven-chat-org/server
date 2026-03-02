use axum::{
    extract::{Path, Query, State},
    Json,
};
use uuid::Uuid;

use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::middleware::AdminUser;
use crate::models::{
    AdminSearchQuery, AdminStats, AdminUserResponse, CreateBlockedHashRequest,
    CreateInstanceBanRequest, PaginationQuery, ReportCounts, ReportFilterQuery, SetAdminRequest,
    UpdateReportRequest, WsServerMessage,
};
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

    // 1. Delete servers owned by this user (CASCADE handles members, channels, etc.)
    let owned_servers = queries::get_servers_owned_by(state.db.read(), user_id).await?;
    for server in &owned_servers {
        let emojis = queries::list_server_emojis(state.db.read(), server.id)
            .await
            .unwrap_or_default();
        for emoji in &emojis {
            let _ = state.storage.delete_blob(&emoji.storage_key).await;
        }
        sqlx::query("DELETE FROM servers WHERE id = $1")
            .bind(server.id)
            .execute(state.db.write())
            .await
            .ok();
    }

    // 2. Clean up message children (no FK cascade on partitioned tables in PG < 17)
    sqlx::query("DELETE FROM attachments WHERE message_id IN (SELECT id FROM messages WHERE sender_id = $1)")
        .bind(user_id)
        .execute(state.db.write())
        .await
        .ok();
    sqlx::query("DELETE FROM reactions WHERE message_id IN (SELECT id FROM messages WHERE sender_id = $1)")
        .bind(user_id)
        .execute(state.db.write())
        .await
        .ok();
    sqlx::query("DELETE FROM pinned_messages WHERE message_id IN (SELECT id FROM messages WHERE sender_id = $1)")
        .bind(user_id)
        .execute(state.db.write())
        .await
        .ok();
    sqlx::query("DELETE FROM reports WHERE message_id IN (SELECT id FROM messages WHERE sender_id = $1)")
        .bind(user_id)
        .execute(state.db.write())
        .await
        .ok();

    // 3. Delete user's messages
    sqlx::query("DELETE FROM messages WHERE sender_id = $1")
        .bind(user_id)
        .execute(state.db.write())
        .await
        .ok();

    // 4. Delete reactions by this user on other messages
    sqlx::query("DELETE FROM reactions WHERE user_id = $1")
        .bind(user_id)
        .execute(state.db.write())
        .await
        .ok();

    // 5. Nullify non-cascading admin references (bans, reports, content_filters, etc.)
    sqlx::query("UPDATE invites SET created_by = $1 WHERE created_by = $2")
        .bind(admin_id)
        .bind(user_id)
        .execute(state.db.write())
        .await
        .ok();
    sqlx::query("UPDATE bans SET banned_by = $1 WHERE banned_by = $2")
        .bind(admin_id)
        .bind(user_id)
        .execute(state.db.write())
        .await
        .ok();
    sqlx::query("UPDATE pinned_messages SET pinned_by = $1 WHERE pinned_by = $2")
        .bind(admin_id)
        .bind(user_id)
        .execute(state.db.write())
        .await
        .ok();
    sqlx::query("DELETE FROM reports WHERE reporter_id = $1")
        .bind(user_id)
        .execute(state.db.write())
        .await
        .ok();
    sqlx::query("UPDATE reports SET reviewed_by = NULL WHERE reviewed_by = $1")
        .bind(user_id)
        .execute(state.db.write())
        .await
        .ok();
    sqlx::query("UPDATE reports SET escalated_by = NULL WHERE escalated_by = $1")
        .bind(user_id)
        .execute(state.db.write())
        .await
        .ok();
    sqlx::query("DELETE FROM instance_bans WHERE banned_by = $1")
        .bind(user_id)
        .execute(state.db.write())
        .await
        .ok();
    sqlx::query("DELETE FROM content_filters WHERE created_by = $1")
        .bind(user_id)
        .execute(state.db.write())
        .await
        .ok();
    sqlx::query("DELETE FROM blocked_hashes WHERE added_by = $1")
        .bind(user_id)
        .execute(state.db.write())
        .await
        .ok();

    // 6. Revoke tokens, broadcast offline, clean up voice
    queries::revoke_all_user_refresh_tokens(state.db.write(), user_id)
        .await
        .ok();
    crate::ws::broadcast_presence(user_id, "offline", &state).await;
    crate::api::voice::cleanup_voice_state(&state, user_id).await;

    // 7. Close active WS connections
    if let Some((_, conns)) = state.connections.remove(&user_id) {
        for tx in conns {
            let _ = tx.send(WsServerMessage::Error {
                message: "Account deleted by admin".into(),
            });
        }
    }

    // 8. Delete user (FK CASCADE handles server_members, channel_members,
    //    friendships, blocks, prekeys, key_backups, sender_key_distributions, etc.)
    queries::delete_user_account(state.db.write(), user_id).await?;

    // 9. Clean up stored files (avatar, banner)
    let avatar_key = crate::storage::obfuscated_key(
        &state.storage_key,
        &format!("avatar:{}", user_id),
    );
    let banner_key = crate::storage::obfuscated_key(
        &state.storage_key,
        &format!("banner:{}", user_id),
    );
    let _ = state.storage.delete_blob(&avatar_key).await;
    let _ = state.storage.delete_blob(&banner_key).await;

    // 10. Invalidate caches
    crate::cache::invalidate(
        state.redis.clone().as_mut(),
        &state.memory,
        &format!("haven:user:{}", user_id),
    )
    .await;

    Ok(Json(serde_json::json!({
        "deleted": true,
        "user_id": user_id,
    })))
}

// ─── Report Triage ───────────────────────────────────

/// GET /api/v1/admin/reports
pub async fn list_reports(
    AdminUser(_admin_id): AdminUser,
    State(state): State<AppState>,
    Query(params): Query<ReportFilterQuery>,
) -> AppResult<Json<Vec<crate::models::AdminReportResponse>>> {
    let limit = params.limit.unwrap_or(50).clamp(1, 100);
    let offset = params.offset.unwrap_or(0).max(0);
    let reports =
        queries::list_reports_admin(state.db.read(), params.status.as_deref(), limit, offset)
            .await?;
    Ok(Json(reports))
}

/// GET /api/v1/admin/reports/counts
pub async fn report_counts(
    AdminUser(_admin_id): AdminUser,
    State(state): State<AppState>,
) -> AppResult<Json<ReportCounts>> {
    let counts = queries::count_reports_by_status(state.db.read()).await?;
    Ok(Json(counts))
}

/// GET /api/v1/admin/reports/:report_id
pub async fn get_report(
    AdminUser(_admin_id): AdminUser,
    State(state): State<AppState>,
    Path(report_id): Path<Uuid>,
) -> AppResult<Json<crate::models::AdminReportResponse>> {
    let report = queries::get_report_admin(state.db.read(), report_id)
        .await?
        .ok_or(AppError::NotFound("Report not found".into()))?;
    Ok(Json(report))
}

/// PUT /api/v1/admin/reports/:report_id
pub async fn update_report(
    AdminUser(admin_id): AdminUser,
    State(state): State<AppState>,
    Path(report_id): Path<Uuid>,
    Json(req): Json<UpdateReportRequest>,
) -> AppResult<Json<crate::models::AdminReportResponse>> {
    // Validate status
    let valid_statuses = ["pending", "reviewed", "dismissed", "escalated_ncmec"];
    if !valid_statuses.contains(&req.status.as_str()) {
        return Err(AppError::Validation(format!(
            "Invalid status. Must be one of: {}",
            valid_statuses.join(", ")
        )));
    }

    // Verify report exists
    let existing = queries::get_report_admin(state.db.read(), report_id)
        .await?
        .ok_or(AppError::NotFound("Report not found".into()))?;

    if req.status == "escalated_ncmec" {
        // Can only escalate from pending or reviewed
        if existing.status != "pending" && existing.status != "reviewed" {
            return Err(AppError::Validation(
                "Can only escalate reports with 'pending' or 'reviewed' status".into(),
            ));
        }
        queries::escalate_report(state.db.write(), report_id, admin_id).await?;
    } else {
        queries::update_report_status(
            state.db.write(),
            report_id,
            &req.status,
            admin_id,
            req.admin_notes.as_deref(),
        )
        .await?;
    }

    // Fetch updated report
    let report = queries::get_report_admin(state.db.read(), report_id)
        .await?
        .ok_or(AppError::NotFound("Report not found".into()))?;
    Ok(Json(report))
}

// ─── Instance Bans ───────────────────────────────────

/// GET /api/v1/admin/bans
pub async fn list_instance_bans(
    AdminUser(_admin_id): AdminUser,
    State(state): State<AppState>,
    Query(pagination): Query<PaginationQuery>,
) -> AppResult<Json<Vec<crate::models::InstanceBanResponse>>> {
    let (limit, offset) = pagination.resolve();
    let bans = queries::list_instance_bans(state.db.read(), limit, offset).await?;
    Ok(Json(bans))
}

/// POST /api/v1/admin/bans/:user_id
pub async fn instance_ban_user(
    AdminUser(admin_id): AdminUser,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(req): Json<CreateInstanceBanRequest>,
) -> AppResult<Json<crate::models::InstanceBanResponse>> {
    // Prevent self-ban
    if user_id == admin_id {
        return Err(AppError::BadRequest("Cannot ban yourself".into()));
    }

    // Verify target user exists
    let target = queries::find_user_by_id(state.db.read(), user_id)
        .await?
        .ok_or(AppError::NotFound("User not found".into()))?;

    // Prevent banning other admins
    if target.is_instance_admin {
        return Err(AppError::BadRequest(
            "Cannot ban an instance admin. Remove their admin status first.".into(),
        ));
    }

    let ban = queries::create_instance_ban(
        state.db.write(),
        user_id,
        req.reason.as_deref(),
        admin_id,
    )
    .await?;

    // Force-disconnect user's WS connections
    if let Some((_, senders)) = state.connections.remove(&user_id) {
        for sender in senders {
            let _ = sender.send(crate::models::WsServerMessage::Error {
                message: "Your account has been banned from this platform".into(),
            });
        }
    }

    // Invalidate refresh tokens in Redis
    if let Some(ref redis) = state.redis {
        let pattern = format!("refresh_token:{}:*", user_id);
        let mut conn = redis.clone();
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(&pattern)
            .query_async(&mut conn)
            .await
            .unwrap_or_default();
        for key in keys {
            let _: Result<(), _> = redis::cmd("DEL")
                .arg(&key)
                .query_async(&mut conn)
                .await;
        }
    }

    let admin_user = queries::find_user_by_id(state.db.read(), admin_id)
        .await?
        .ok_or(AppError::NotFound("Admin user not found".into()))?;

    Ok(Json(crate::models::InstanceBanResponse {
        id: ban.id,
        user_id: ban.user_id,
        username: target.username,
        reason: ban.reason,
        banned_by: ban.banned_by,
        banned_by_username: admin_user.username,
        created_at: ban.created_at.to_rfc3339(),
    }))
}

/// DELETE /api/v1/admin/bans/:user_id
pub async fn instance_revoke_ban(
    AdminUser(_admin_id): AdminUser,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    queries::remove_instance_ban(state.db.write(), user_id).await?;
    Ok(Json(serde_json::json!({ "unbanned": true })))
}

// ─── Blocked Hashes ─────────────────────────────────

/// GET /api/v1/admin/blocked-hashes
pub async fn list_blocked_hashes(
    AdminUser(_admin_id): AdminUser,
    State(state): State<AppState>,
    Query(pagination): Query<PaginationQuery>,
) -> AppResult<Json<Vec<crate::models::BlockedHashResponse>>> {
    let (limit, offset) = pagination.resolve();
    let hashes = queries::list_blocked_hashes(state.db.read(), limit, offset).await?;
    Ok(Json(hashes))
}

/// POST /api/v1/admin/blocked-hashes
pub async fn create_blocked_hash(
    AdminUser(admin_id): AdminUser,
    State(state): State<AppState>,
    Json(req): Json<CreateBlockedHashRequest>,
) -> AppResult<Json<crate::models::BlockedHashResponse>> {
    // Validate hash format: 64 hex characters (SHA-256)
    let hash = req.hash.to_lowercase();
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::Validation(
            "Invalid hash format (expected 64 hex characters)".into(),
        ));
    }

    let bh = queries::create_blocked_hash(
        state.db.write(),
        &hash,
        req.description.as_deref(),
        admin_id,
    )
    .await?;

    let admin_user = queries::find_user_by_id(state.db.read(), admin_id)
        .await?
        .ok_or(AppError::NotFound("Admin user not found".into()))?;

    Ok(Json(crate::models::BlockedHashResponse {
        id: bh.id,
        hash: bh.hash,
        description: bh.description,
        added_by_username: admin_user.username,
        created_at: bh.created_at.to_rfc3339(),
    }))
}

/// DELETE /api/v1/admin/blocked-hashes/:hash_id
pub async fn delete_blocked_hash(
    AdminUser(_admin_id): AdminUser,
    State(state): State<AppState>,
    Path(hash_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    queries::delete_blocked_hash(state.db.write(), hash_id).await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}
