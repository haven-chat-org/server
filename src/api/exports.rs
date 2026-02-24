use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    Json,
};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::models::{
    ChannelCategory, ImportMessagesResponse, RestoreServerRequest, RestoreServerResponse, Role,
};
use crate::ws::broadcast_to_server;
use crate::AppState;
use crate::models::WsServerMessage;

#[derive(Debug, Deserialize)]
pub struct ExportManifestExporter {
    pub user_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct ExportManifest {
    pub exported_by: ExportManifestExporter,
    #[serde(flatten)]
    pub rest: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct VerifyExportRequest {
    pub manifest: serde_json::Value,
    pub signature: String, // base64-encoded Ed25519 signature
}

#[derive(Debug, Serialize)]
pub struct VerifyExportSigner {
    pub user_id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyExportResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<VerifyExportSigner>,
    pub identity_key_matches: bool,
}

/// POST /api/v1/exports/verify
/// Verifies an Ed25519 signature over a manifest's canonical JSON.
/// Does not require authentication — anyone with a manifest can verify.
pub async fn verify_export(
    State(state): State<AppState>,
    Json(req): Json<VerifyExportRequest>,
) -> AppResult<Json<VerifyExportResponse>> {
    // Extract user_id from manifest
    let exported_by = req
        .manifest
        .get("exported_by")
        .and_then(|v| v.get("user_id"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Uuid>().ok())
        .ok_or_else(|| {
            AppError::Validation("manifest.exported_by.user_id is required".into())
        })?;

    // Decode signature
    let sig_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.signature,
    )
    .map_err(|_| AppError::Validation("Invalid base64 signature".into()))?;

    if sig_bytes.len() != 64 {
        return Err(AppError::Validation(
            "Signature must be 64 bytes (Ed25519)".into(),
        ));
    }

    // Look up user
    let user = queries::find_user_by_id(state.db.read(), exported_by)
        .await?
        .ok_or(AppError::NotFound("Signer not found".into()))?;

    let signer = VerifyExportSigner {
        user_id: user.id,
        username: user.username.clone(),
        display_name: user.display_name.clone(),
    };

    // Canonical JSON of manifest (sorted keys via serde_json)
    let canonical = serde_json::to_vec(&req.manifest)
        .map_err(|_| AppError::Validation("Failed to serialize manifest".into()))?;

    // Try to parse the identity_key as an Ed25519 public key
    // The identity_key stored in DB might be X25519 (32 bytes for key exchange).
    // Ed25519 public keys are also 32 bytes. The client must provide the Ed25519
    // signing key; we verify against the stored identity_key.
    let identity_key = &user.identity_key;

    let sig = ed25519_dalek::Signature::from_bytes(
        sig_bytes.as_slice().try_into().map_err(|_| {
            AppError::Validation("Invalid signature length".into())
        })?,
    );

    let valid = if identity_key.len() == 32 {
        match ed25519_dalek::VerifyingKey::from_bytes(
            identity_key.as_slice().try_into().unwrap(),
        ) {
            Ok(verifying_key) => {
                use ed25519_dalek::Verifier;
                verifying_key.verify(&canonical, &sig).is_ok()
            }
            Err(_) => false,
        }
    } else {
        false
    };

    Ok(Json(VerifyExportResponse {
        valid,
        signer: Some(signer),
        identity_key_matches: valid,
    }))
}

#[derive(Debug, Deserialize)]
pub struct LogExportRequest {
    pub scope: String, // "server", "channel", or "dm"
    pub server_id: Option<Uuid>,
    pub channel_id: Option<Uuid>,
    pub message_count: i64,
}

/// POST /api/v1/exports/log
/// Records an export event in the server's audit log.
/// Called by the client after a successful client-side export.
pub async fn log_export(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<LogExportRequest>,
) -> AppResult<Json<serde_json::Value>> {
    // Only log if we have a server_id (DM exports have no server audit log)
    if let Some(server_id) = req.server_id {
        let action = match req.scope.as_str() {
            "server" => "server_export",
            "channel" => "channel_export",
            _ => "export",
        };
        let _ = queries::insert_audit_log(
            state.db.write(),
            server_id,
            user_id,
            action,
            req.channel_id.map(|_| "channel"),
            req.channel_id,
            Some(&serde_json::json!({
                "message_count": req.message_count,
                "scope": req.scope,
            })),
            None,
        )
        .await;
    }

    Ok(Json(serde_json::json!({ "logged": true })))
}

/// POST /api/v1/servers/:server_id/restore
/// Restores server structure (categories, channels, roles, permission overwrites)
/// from a parsed .haven backup. Requires MANAGE_SERVER permission or owner.
pub async fn restore_server(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(server_id): Path<Uuid>,
    Json(req): Json<RestoreServerRequest>,
) -> AppResult<Json<RestoreServerResponse>> {
    // Verify membership
    if !queries::is_server_member(state.db.read(), server_id, user_id).await? {
        return Err(AppError::Forbidden("Not a member of this server".into()));
    }

    // Check MANAGE_SERVER permission
    let (is_owner, perms) =
        queries::get_member_permissions(state.db.read(), server_id, user_id).await?;
    if !is_owner && !crate::permissions::has_permission(perms, crate::permissions::MANAGE_SERVER) {
        return Err(AppError::Forbidden(
            "Missing MANAGE_SERVER permission".into(),
        ));
    }

    // Validate limits
    if req.categories.len() > 50 {
        return Err(AppError::Validation(
            "Too many categories (max 50)".into(),
        ));
    }
    if req.channels.len() > 500 {
        return Err(AppError::Validation(
            "Too many channels (max 500)".into(),
        ));
    }
    if req.roles.len() > 250 {
        return Err(AppError::Validation("Too many roles (max 250)".into()));
    }

    // Begin transaction
    let pool = state.db.write();
    let mut tx = pool.begin().await?;

    // ── Wipe existing server structure before restore ──
    // Clean up orphaned records (FK constraints to messages were dropped
    // during partition migration, so these won't cascade from channel deletion)
    sqlx::query(
        r#"DELETE FROM attachments WHERE message_id IN (
             SELECT m.id FROM messages m
             JOIN channels c ON c.id = m.channel_id
             WHERE c.server_id = $1
           )"#,
    )
    .bind(server_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"DELETE FROM reactions WHERE message_id IN (
             SELECT m.id FROM messages m
             JOIN channels c ON c.id = m.channel_id
             WHERE c.server_id = $1
           )"#,
    )
    .bind(server_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"DELETE FROM reports WHERE message_id IN (
             SELECT m.id FROM messages m
             JOIN channels c ON c.id = m.channel_id
             WHERE c.server_id = $1
           )"#,
    )
    .bind(server_id)
    .execute(&mut *tx)
    .await?;

    // Null out system_channel_id before deleting channels
    sqlx::query("UPDATE servers SET system_channel_id = NULL WHERE id = $1")
        .bind(server_id)
        .execute(&mut *tx)
        .await?;

    // Delete all channels (cascades to messages, channel_members,
    // channel_permission_overwrites, sender_key_distributions, pinned_messages, read_states)
    sqlx::query("DELETE FROM channels WHERE server_id = $1")
        .bind(server_id)
        .execute(&mut *tx)
        .await?;

    // Delete all categories
    sqlx::query("DELETE FROM channel_categories WHERE server_id = $1")
        .bind(server_id)
        .execute(&mut *tx)
        .await?;

    // Delete non-default roles (cascades to member_roles)
    sqlx::query("DELETE FROM roles WHERE server_id = $1 AND is_default = FALSE")
        .bind(server_id)
        .execute(&mut *tx)
        .await?;

    // ID Mapping: old backup ID → new DB UUID
    let mut category_map: HashMap<String, Uuid> = HashMap::new();
    let mut role_map: HashMap<String, Uuid> = HashMap::new();
    let mut channel_map: HashMap<String, Uuid> = HashMap::new();

    let mut categories_created = 0usize;
    let mut channels_created = 0usize;
    let mut roles_created = 0usize;
    let mut roles_updated = 0usize;
    let mut overwrites_applied = 0usize;

    // Step 1: Create categories
    for cat in &req.categories {
        let new_cat = sqlx::query_as::<_, ChannelCategory>(
            r#"INSERT INTO channel_categories (server_id, name, position)
               VALUES ($1, $2, $3) RETURNING *"#,
        )
        .bind(server_id)
        .bind(&cat.name)
        .bind(cat.position)
        .fetch_one(&mut *tx)
        .await?;

        category_map.insert(cat.id.clone(), new_cat.id);
        categories_created += 1;
    }

    // Step 2: Create channels
    for ch in &req.channels {
        // Skip DM/group channels
        if ch.channel_type == "dm" || ch.channel_type == "group_dm" {
            continue;
        }

        // Map old category_id to new one
        let new_category_id = ch
            .category_id
            .as_ref()
            .and_then(|old_id| category_map.get(old_id))
            .copied();

        let new_channel_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO channels (id, server_id, encrypted_meta, channel_type, position,
                                     category_id, is_private, encrypted, created_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, false, CURRENT_TIMESTAMP)"#,
        )
        .bind(new_channel_id)
        .bind(Some(server_id))
        .bind(ch.name.as_bytes())
        .bind(&ch.channel_type)
        .bind(ch.position)
        .bind(new_category_id)
        .bind(ch.is_private)
        .execute(&mut *tx)
        .await?;

        // Add restoring user as channel member
        sqlx::query(
            r#"INSERT INTO channel_members (id, channel_id, user_id, joined_at)
               VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
               ON CONFLICT (channel_id, user_id) DO NOTHING"#,
        )
        .bind(Uuid::new_v4())
        .bind(new_channel_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        channel_map.insert(ch.id.clone(), new_channel_id);
        channels_created += 1;
    }

    // Step 3: Roles
    // Find existing @everyone role to update its permissions
    let existing_everyone = sqlx::query_as::<_, Role>(
        "SELECT * FROM roles WHERE server_id = $1 AND is_default = TRUE LIMIT 1",
    )
    .bind(server_id)
    .fetch_optional(&mut *tx)
    .await?;

    for role in &req.roles {
        if role.is_default {
            // Update existing @everyone role permissions
            if let Some(ref everyone) = existing_everyone {
                sqlx::query("UPDATE roles SET permissions = $1 WHERE id = $2")
                    .bind(role.permissions)
                    .bind(everyone.id)
                    .execute(&mut *tx)
                    .await?;
                role_map.insert(role.id.clone(), everyone.id);
                roles_updated += 1;
            }
        } else {
            // Create non-default roles
            let new_role = sqlx::query_as::<_, Role>(
                r#"INSERT INTO roles (server_id, name, color, permissions, position, is_default)
                   VALUES ($1, $2, $3, $4, $5, FALSE) RETURNING *"#,
            )
            .bind(server_id)
            .bind(&role.name)
            .bind(role.color.as_deref())
            .bind(role.permissions)
            .bind(role.position)
            .fetch_one(&mut *tx)
            .await?;

            role_map.insert(role.id.clone(), new_role.id);
            roles_created += 1;
        }
    }

    // Step 4: Permission overwrites (role-type only)
    for ow in &req.permission_overwrites {
        // Skip member-specific overwrites (old user IDs don't apply)
        if ow.target_type == "member" {
            continue;
        }

        let new_channel_id = match channel_map.get(&ow.channel_id) {
            Some(id) => *id,
            None => continue,
        };
        let new_target_id = match role_map.get(&ow.target_id) {
            Some(id) => *id,
            None => continue,
        };

        sqlx::query(
            r#"INSERT INTO channel_permission_overwrites
                 (channel_id, target_type, target_id, allow_bits, deny_bits)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (channel_id, target_type, target_id)
               DO UPDATE SET allow_bits = $4, deny_bits = $5"#,
        )
        .bind(new_channel_id)
        .bind(&ow.target_type)
        .bind(new_target_id)
        .bind(ow.allow)
        .bind(ow.deny)
        .execute(&mut *tx)
        .await?;

        overwrites_applied += 1;
    }

    // Commit transaction
    tx.commit().await?;

    // Audit log (best effort, outside transaction)
    let _ = queries::insert_audit_log(
        state.db.write(),
        server_id,
        user_id,
        "server_restore",
        Some("server"),
        Some(server_id),
        Some(&serde_json::json!({
            "source_server_name": req.server.name,
            "categories_created": categories_created,
            "channels_created": channels_created,
            "roles_created": roles_created,
        })),
        None,
    )
    .await;

    // Notify connected members
    broadcast_to_server(
        &state,
        server_id,
        WsServerMessage::ServerUpdated { server_id },
    )
    .await;

    // Build channel_id_map as String→String for JSON serialization
    let channel_id_map: HashMap<String, String> = channel_map
        .into_iter()
        .map(|(old, new)| (old, new.to_string()))
        .collect();

    Ok(Json(RestoreServerResponse {
        categories_created,
        channels_created,
        roles_created,
        roles_updated,
        overwrites_applied,
        channel_id_map,
    }))
}

/// POST /api/v1/channels/:channel_id/import-messages
/// Imports a batch of messages into a channel (used during server restore).
/// Messages are stored with their original timestamps.
/// Requires MANAGE_SERVER permission on the channel's server.
pub async fn import_messages(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(channel_id): Path<Uuid>,
    Json(req): Json<crate::models::ImportMessagesRequest>,
) -> AppResult<Json<ImportMessagesResponse>> {
    // Validate batch size
    if req.messages.len() > 200 {
        return Err(AppError::Validation(
            "Too many messages per batch (max 200)".into(),
        ));
    }

    // Look up the channel to find its server_id
    let channel = queries::find_channel_by_id(state.db.read(), channel_id)
        .await?
        .ok_or(AppError::NotFound("Channel not found".into()))?;

    let server_id = channel
        .server_id
        .ok_or(AppError::Validation("Cannot import messages to DM channel".into()))?;

    // Check MANAGE_SERVER permission
    let (is_owner, perms) =
        queries::get_member_permissions(state.db.read(), server_id, user_id).await?;
    if !is_owner && !crate::permissions::has_permission(perms, crate::permissions::MANAGE_SERVER) {
        return Err(AppError::Forbidden(
            "Missing MANAGE_SERVER permission".into(),
        ));
    }

    let pool = state.db.write();
    let mut tx = pool.begin().await?;
    let mut imported = 0usize;

    for msg in &req.messages {
        // Decode base64 fields
        let sender_token = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &msg.sender_token,
        )
        .map_err(|_| AppError::Validation("Invalid base64 sender_token".into()))?;

        let encrypted_body = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &msg.encrypted_body,
        )
        .map_err(|_| AppError::Validation("Invalid base64 encrypted_body".into()))?;

        // Parse timestamp
        let timestamp = DateTime::parse_from_rfc3339(&msg.timestamp)
            .or_else(|_| DateTime::parse_from_str(&msg.timestamp, "%Y-%m-%dT%H:%M:%S%.fZ"))
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .map_err(|_| AppError::Validation(format!("Invalid timestamp: {}", msg.timestamp)))?;

        // Parse optional sender_id
        let sender_id = msg
            .sender_id
            .as_ref()
            .and_then(|s| s.parse::<Uuid>().ok());

        // Parse optional reply_to_id
        let reply_to_id = msg
            .reply_to_id
            .as_ref()
            .and_then(|s| s.parse::<Uuid>().ok());

        sqlx::query(
            r#"INSERT INTO messages (id, channel_id, sender_token, encrypted_body,
                                     timestamp, has_attachments, sender_id, reply_to_id, message_type)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(Uuid::new_v4())
        .bind(channel_id)
        .bind(&sender_token)
        .bind(&encrypted_body)
        .bind(timestamp)
        .bind(msg.has_attachments)
        .bind(sender_id)
        .bind(reply_to_id)
        .bind(&msg.message_type)
        .execute(&mut *tx)
        .await?;

        imported += 1;
    }

    tx.commit().await?;

    Ok(Json(ImportMessagesResponse { imported }))
}
