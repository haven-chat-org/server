use axum::{extract::State, http::{HeaderMap, StatusCode}, Json};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use validator::Validate;

use crate::auth;
use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::models::*;
use crate::storage;
use crate::AppState;

/// Parse a User-Agent header into a short device name like "Chrome on macOS".
fn parse_device_name(ua: &str) -> String {
    let browser = if ua.contains("Firefox") {
        "Firefox"
    } else if ua.contains("Edg/") {
        "Edge"
    } else if ua.contains("Chrome") {
        "Chrome"
    } else if ua.contains("Safari") {
        "Safari"
    } else {
        "Unknown Browser"
    };
    let os = if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Mac OS") || ua.contains("Macintosh") {
        "macOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        "iOS"
    } else {
        "Unknown OS"
    };
    format!("{} on {}", browser, os)
}

/// Extract client IP from headers (X-Forwarded-For or X-Real-IP).
fn extract_ip_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
}

/// Cloudflare Turnstile siteverify endpoint.
const TURNSTILE_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/// Verify a Cloudflare Turnstile token. Returns Ok(()) on success.
async fn verify_turnstile(secret: &str, token: &str) -> AppResult<()> {
    let client = reqwest::Client::new();
    let res = client
        .post(TURNSTILE_VERIFY_URL)
        .form(&[("secret", secret), ("response", token)])
        .send()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Turnstile verification request failed: {}", e)))?;

    let body: serde_json::Value = res
        .json()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Turnstile response parse failed: {}", e)))?;

    if body.get("success").and_then(|v| v.as_bool()) == Some(true) {
        Ok(())
    } else {
        Err(AppError::Validation("CAPTCHA verification failed — please try again".into()))
    }
}

/// Number of leading zero bits required for PoW (20 ≈ ~1M hashes, sub-second on modern hardware)
const POW_DIFFICULTY: u32 = 20;
/// TTL for PoW challenges in Redis (seconds)
const POW_CHALLENGE_TTL: u64 = 300;

/// GET /api/v1/auth/challenge — generate a PoW challenge for registration
pub async fn pow_challenge(
    State(state): State<AppState>,
) -> AppResult<Json<PowChallengeResponse>> {
    // Generate a random 32-byte challenge
    let challenge = Uuid::new_v4().to_string();

    // Store challenge with TTL
    if let Some(mut redis) = state.redis.clone() {
        let redis_key = format!("haven:pow:{}", challenge);
        let _: Result<(), redis::RedisError> = redis::cmd("SET")
            .arg(&redis_key)
            .arg("1")
            .arg("EX")
            .arg(POW_CHALLENGE_TTL)
            .query_async(&mut redis)
            .await;
    } else {
        let expiry = std::time::Instant::now() + std::time::Duration::from_secs(POW_CHALLENGE_TTL);
        state.memory.pow_challenges.insert(challenge.clone(), expiry);
    }

    let turnstile_site_key = if state.config.turnstile_enabled() {
        Some(state.config.turnstile_site_key.clone())
    } else {
        None
    };

    Ok(Json(PowChallengeResponse {
        challenge,
        difficulty: POW_DIFFICULTY,
        turnstile_site_key,
    }))
}

/// Verify a Proof-of-Work solution: SHA-256(challenge + nonce) must have `difficulty` leading zero bits.
fn verify_pow(challenge: &str, nonce: &str, difficulty: u32) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(challenge.as_bytes());
    hasher.update(nonce.as_bytes());
    let hash = hasher.finalize();

    // Check leading zero bits
    let mut zero_bits = 0u32;
    for &byte in hash.as_slice() {
        if byte == 0 {
            zero_bits += 8;
        } else {
            zero_bits += byte.leading_zeros();
            break;
        }
        if zero_bits >= difficulty {
            break;
        }
    }
    zero_bits >= difficulty
}

/// POST /api/v1/auth/register
pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> AppResult<Json<AuthResponse>> {
    // Validate request
    req.validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    // Verify Proof-of-Work challenge exists and consume it (single-use)
    let challenge_valid = if let Some(mut redis) = state.redis.clone() {
        let redis_key = format!("haven:pow:{}", req.pow_challenge);
        let exists: Option<String> = redis::cmd("GET")
            .arg(&redis_key)
            .query_async(&mut redis)
            .await
            .unwrap_or(None);
        if exists.is_some() {
            let _: Result<(), redis::RedisError> = redis::cmd("DEL")
                .arg(&redis_key)
                .query_async(&mut redis)
                .await;
            true
        } else {
            false
        }
    } else {
        // In-memory: remove and check expiry
        state.memory.pow_challenges.remove(&req.pow_challenge)
            .map(|(_, expiry)| std::time::Instant::now() < expiry)
            .unwrap_or(false)
    };

    if !challenge_valid {
        return Err(AppError::Validation(
            "Invalid or expired PoW challenge — request a new one from /auth/challenge".into(),
        ));
    }

    if !verify_pow(&req.pow_challenge, &req.pow_nonce, POW_DIFFICULTY) {
        return Err(AppError::Validation("Invalid Proof-of-Work solution".into()));
    }

    // Verify Cloudflare Turnstile CAPTCHA (if enabled)
    if state.config.turnstile_enabled() {
        let token = req.turnstile_token.as_deref()
            .ok_or(AppError::Validation("CAPTCHA token required".into()))?;
        verify_turnstile(&state.config.turnstile_secret_key, token).await?;
    }

    // Validate registration invite code (if invite-only mode is enabled)
    let is_first = queries::is_first_user_precheck(state.db.read()).await.unwrap_or(false);
    let invite_to_consume = if state.config.registration_invite_only && !is_first {
        let code = req.invite_code.as_deref()
            .ok_or(AppError::Validation("Registration invite code required".into()))?;

        let invite = queries::find_registration_invite_by_code(state.db.read(), code)
            .await?
            .ok_or(AppError::Validation("Invalid registration invite code".into()))?;

        if invite.used_by.is_some() {
            return Err(AppError::Validation("This invite code has already been used".into()));
        }

        if let Some(expires_at) = invite.expires_at {
            if Utc::now() > expires_at {
                return Err(AppError::Validation("This invite code has expired".into()));
            }
        }

        Some(invite)
    } else {
        None
    };

    // Hash password
    let password_hash = auth::hash_password(&req.password)?;

    // Hash email if provided (HMAC-SHA256 with server secret to resist rainbow tables)
    let email_hash = req.email.as_deref().map(|e| auth::hash_email(e, &state.config.jwt_secret));

    // Decode crypto keys from base64
    let identity_key = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.identity_key,
    )
    .map_err(|_| AppError::Validation("Invalid identity_key encoding".into()))?;

    let signed_prekey = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.signed_prekey,
    )
    .map_err(|_| AppError::Validation("Invalid signed_prekey encoding".into()))?;

    let signed_prekey_sig = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.signed_prekey_signature,
    )
    .map_err(|_| AppError::Validation("Invalid signed_prekey_signature encoding".into()))?;

    // Create user
    let user = queries::create_user(
        state.db.write(),
        &req.username,
        req.display_name.as_deref(),
        email_hash.as_deref(),
        &password_hash,
        &identity_key,
        &signed_prekey,
        &signed_prekey_sig,
    )
    .await?;

    // Auto-grant instance admin to the first registered user
    if queries::is_first_user(state.db.read()).await.unwrap_or(false) {
        let _ = queries::set_instance_admin(state.db.write(), user.id, true).await;
        tracing::info!("First user {} auto-granted instance admin", user.username);
        // First user gets invite codes even without using one
        if state.config.registration_invite_only {
            let _ = queries::create_registration_invites(
                state.db.write(),
                Some(user.id),
                state.config.registration_invites_per_user,
            ).await;
        }
    }

    // Consume registration invite and grant new invites to the new user
    if let Some(invite) = invite_to_consume {
        queries::consume_registration_invite(state.db.write(), invite.id, user.id).await?;
        let _ = queries::create_registration_invites(
            state.db.write(),
            Some(user.id),
            state.config.registration_invites_per_user,
        ).await;
    }

    // Store one-time prekeys
    if !req.one_time_prekeys.is_empty() {
        let prekeys: Result<Vec<(i32, Vec<u8>)>, _> = req
            .one_time_prekeys
            .iter()
            .enumerate()
            .map(|(i, key_b64)| {
                base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    key_b64,
                )
                .map(|bytes| (i as i32, bytes))
                .map_err(|_| AppError::Validation(format!("Invalid prekey encoding at index {}", i)))
            })
            .collect();

        queries::insert_prekeys(state.db.write(), user.id, &prekeys?).await?;
    }

    // Create a personal Haven server and befriend the Haven system user
    if let Ok(Some(system_user)) = queries::find_system_user(state.db.read()).await {
        // Auto-friend the system user
        let _ = queries::create_accepted_friendship(
            state.db.write(), system_user.id, user.id,
        ).await;

        // Create personal Haven server owned by the new user
        let server_meta = r#"{"name":"Haven"}"#;
        if let Ok(server) = queries::create_server(
            state.db.write(), user.id, server_meta.as_bytes(),
        ).await {
            // Add new user as server member (owner)
            let _ = queries::add_server_member(
                state.db.write(), server.id, user.id, b"owner",
            ).await;
            // Add Haven system user as server member
            let _ = queries::add_server_member(
                state.db.write(), server.id, system_user.id, b"member",
            ).await;

            // Create #welcome channel (unencrypted, position 0)
            if let Ok(welcome_ch) = queries::create_channel(
                state.db.write(), Some(server.id),
                r#"{"name":"welcome"}"#.as_bytes(), "text", 0, None, false, false,
            ).await {
                let _ = queries::add_channel_member(state.db.write(), welcome_ch.id, user.id).await;
                let _ = queries::add_channel_member(state.db.write(), welcome_ch.id, system_user.id).await;
                // Welcome message from Haven (wire format: 0x00 + JSON payload)
                let welcome_body = format!(
                    "\x00{{\"text\":\"Welcome to Haven! This is your home for private, encrypted communication. Explore the channels, add friends, and make yourself at home.\",\"sender_id\":\"{}\"}}",
                    system_user.id,
                );
                let _ = queries::insert_message(
                    state.db.write(), welcome_ch.id, &[0u8],
                    welcome_body.as_bytes(),
                    None, false, system_user.id, None,
                ).await;
                // Set as system channel
                let _ = queries::set_server_system_channel(
                    state.db.write(), server.id, welcome_ch.id,
                ).await;
            }

            // Create #general channel (unencrypted, position 1)
            if let Ok(general_ch) = queries::create_channel(
                state.db.write(), Some(server.id),
                r#"{"name":"general"}"#.as_bytes(), "text", 1, None, false, false,
            ).await {
                let _ = queries::add_channel_member(state.db.write(), general_ch.id, user.id).await;
                let _ = queries::add_channel_member(state.db.write(), general_ch.id, system_user.id).await;
            }
        }

        // Create a DM channel from Haven to the new user
        let display = user.display_name.as_deref().unwrap_or(&user.username);
        let dm_meta = format!(
            r#"{{"type":"dm","participants":["{}","{}"],"names":{{"{}":"Haven","{}":"{}"}}}}"#,
            system_user.id, user.id, system_user.id, user.id, display,
        );
        if let Ok(dm_channel) = queries::create_channel(
            state.db.write(), None, dm_meta.as_bytes(), "dm", 0, None, false, false,
        ).await {
            let _ = queries::add_channel_member(state.db.write(), dm_channel.id, system_user.id).await;
            let _ = queries::add_channel_member(state.db.write(), dm_channel.id, user.id).await;
            // DM message (wire format: 0x00 + JSON payload)
            let dm_body = format!(
                "\x00{{\"text\":\"Hey! Welcome to Haven. If you ever need help, check out the #welcome channel in your Haven server. Happy chatting!\",\"sender_id\":\"{}\"}}",
                system_user.id,
            );
            let _ = queries::insert_message(
                state.db.write(), dm_channel.id, &[0u8],
                dm_body.as_bytes(),
                None, false, system_user.id, None,
            ).await;
        }
    }

    // Generate tokens with a new token family
    let family_id = Uuid::new_v4();
    let access_token = auth::generate_access_token(user.id, &state.config)?;
    let refresh_token = auth::generate_refresh_token();
    let refresh_hash = auth::hash_refresh_token(&refresh_token);

    let device = headers.get("user-agent").and_then(|v| v.to_str().ok()).map(parse_device_name);
    let ip = extract_ip_from_headers(&headers);
    let expiry = Utc::now() + Duration::days(state.config.refresh_token_expiry_days);
    queries::store_refresh_token_with_metadata(
        state.db.write(), user.id, &refresh_hash, expiry, Some(family_id),
        device.as_deref(), ip.as_deref(),
    ).await?;

    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
        user: user.into(),
    }))
}

/// POST /api/v1/auth/login
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> AppResult<LoginResponse> {
    // Find user
    let user = queries::find_user_by_username(state.db.read(), &req.username)
        .await?
        .ok_or(AppError::AuthError("Invalid username or password".into()))?;

    // System users cannot log in
    if user.is_system {
        return Err(AppError::AuthError("Invalid username or password".into()));
    }

    // Verify password
    if !auth::verify_password(&req.password, &user.password_hash)? {
        return Err(AppError::AuthError("Invalid username or password".into()));
    }

    // Verify TOTP if enabled
    if let Some(ref secret) = user.totp_secret {
        match req.totp_code.as_deref() {
            None => {
                // Credentials valid, but TOTP is required — return challenge
                return Ok(LoginResponse::TotpRequired { totp_required: true });
            }
            Some(code) => {
                if !auth::verify_totp(secret, code)? {
                    return Err(AppError::AuthError("Invalid TOTP code".into()));
                }
            }
        }
    }

    // Generate tokens with a new token family
    let family_id = Uuid::new_v4();
    let access_token = auth::generate_access_token(user.id, &state.config)?;
    let refresh_token = auth::generate_refresh_token();
    let refresh_hash = auth::hash_refresh_token(&refresh_token);

    let device = headers.get("user-agent").and_then(|v| v.to_str().ok()).map(parse_device_name);
    let ip = extract_ip_from_headers(&headers);
    let expiry = Utc::now() + Duration::days(state.config.refresh_token_expiry_days);
    queries::store_refresh_token_with_metadata(
        state.db.write(), user.id, &refresh_hash, expiry, Some(family_id),
        device.as_deref(), ip.as_deref(),
    ).await?;

    Ok(LoginResponse::Success(Box::new(AuthResponse {
        access_token,
        refresh_token,
        user: user.into(),
    })))
}

/// POST /api/v1/auth/refresh
/// Implements token family rotation with theft detection:
/// - If the token is valid and not revoked: rotate normally, mark old as revoked
/// - If the token was already revoked (replayed): THEFT DETECTED — revoke entire family
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> AppResult<Json<AuthResponse>> {
    let token_hash = auth::hash_refresh_token(&req.refresh_token);

    // Find the token (including revoked ones for theft detection)
    let stored_token = queries::find_refresh_token(state.db.read(), &token_hash)
        .await?
        .ok_or(AppError::AuthError("Invalid or expired refresh token".into()))?;

    // THEFT DETECTION: if this token was already revoked, someone is replaying it.
    // Revoke the entire token family to protect the user.
    if stored_token.revoked {
        tracing::warn!(
            "Refresh token reuse detected for user {}! Revoking token family {:?}",
            stored_token.user_id,
            stored_token.family_id,
        );
        if let Some(family_id) = stored_token.family_id {
            queries::revoke_token_family(state.db.write(), family_id).await?;
        }
        // Also revoke all tokens for this user as a safety measure
        queries::revoke_all_user_refresh_tokens(state.db.write(), stored_token.user_id).await?;
        return Err(AppError::AuthError(
            "Token reuse detected — all sessions revoked for security. Please log in again.".into(),
        ));
    }

    // Mark old token as revoked (soft-delete — kept for theft detection)
    queries::revoke_refresh_token(state.db.write(), &token_hash).await?;

    // Get user
    let user = queries::find_user_by_id(state.db.read(), stored_token.user_id)
        .await?
        .ok_or(AppError::UserNotFound)?;

    // Generate new token in the same family
    let access_token = auth::generate_access_token(user.id, &state.config)?;
    let new_refresh_token = auth::generate_refresh_token();
    let new_refresh_hash = auth::hash_refresh_token(&new_refresh_token);

    let expiry = Utc::now() + Duration::days(state.config.refresh_token_expiry_days);
    queries::store_refresh_token_with_family(
        state.db.write(), user.id, &new_refresh_hash, expiry, stored_token.family_id,
    ).await?;

    // Update last_activity for the session family
    if let Some(family_id) = stored_token.family_id {
        let _ = queries::update_session_activity(state.db.write(), family_id).await;
    }

    Ok(Json(AuthResponse {
        access_token,
        refresh_token: new_refresh_token,
        user: user.into(),
    }))
}

/// POST /api/v1/auth/logout
pub async fn logout(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> AppResult<Json<serde_json::Value>> {
    // Revoke all refresh tokens for this user
    queries::revoke_all_user_refresh_tokens(state.db.write(), user_id).await?;

    // Broadcast offline presence and clean up voice state
    crate::ws::broadcast_presence(user_id, "offline", &state).await;
    crate::api::voice::cleanup_voice_state(&state, user_id).await;

    Ok(Json(serde_json::json!({ "message": "Logged out" })))
}

/// GET /api/v1/auth/sessions — list active sessions for current user
pub async fn list_sessions(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> AppResult<Json<Vec<SessionResponse>>> {
    let tokens = queries::list_user_sessions(state.db.read(), user_id).await?;

    // Determine current session by looking at the most recently created token
    // (the one from the latest refresh for the current request is "current").
    // We approximate by just marking the most recently active session.
    let sessions: Vec<SessionResponse> = tokens
        .into_iter()
        .map(|t| SessionResponse {
            id: t.id,
            family_id: t.family_id,
            device_name: t.device_name,
            ip_address: t.ip_address.map(|ip| mask_ip(&ip)),
            last_activity: t.last_activity,
            created_at: t.created_at,
            is_current: false, // Will be determined client-side or via a cookie
        })
        .collect();

    Ok(Json(sessions))
}

/// DELETE /api/v1/auth/sessions/:family_id — revoke a specific session
pub async fn revoke_session(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    axum::extract::Path(family_id): axum::extract::Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let deleted = queries::revoke_session(state.db.write(), user_id, family_id).await?;
    if deleted == 0 {
        return Err(AppError::NotFound("Session not found".into()));
    }
    Ok(Json(serde_json::json!({ "message": "Session revoked" })))
}

/// Partially mask an IP address for privacy (show first two octets).
fn mask_ip(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        format!("{}.{}.x.x", parts[0], parts[1])
    } else {
        // IPv6 or other — just show first segment
        ip.split(':').next().unwrap_or("*").to_string() + ":***"
    }
}

/// POST /api/v1/auth/totp/setup
pub async fn totp_setup(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> AppResult<Json<TotpSetupResponse>> {
    let user = queries::find_user_by_id(state.db.read(), user_id)
        .await?
        .ok_or(AppError::UserNotFound)?;

    if user.totp_secret.is_some() {
        return Err(AppError::BadRequest("TOTP already enabled".into()));
    }

    let (secret, uri) = auth::generate_totp_secret(&user.username)?;

    // Store in pending column — NOT active until user verifies with a valid code.
    // This prevents lockout if the setup dialog is closed before scanning the QR.
    queries::set_pending_totp_secret(state.db.write(), user_id, &secret).await?;

    Ok(Json(TotpSetupResponse {
        secret,
        qr_code_uri: uri,
    }))
}

/// POST /api/v1/auth/totp/verify
/// Verifies the user can produce a valid TOTP code, then promotes the
/// pending secret to active.
pub async fn totp_verify(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<TotpVerifyRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let user = queries::find_user_by_id(state.db.read(), user_id)
        .await?
        .ok_or(AppError::UserNotFound)?;

    // Check pending secret first (setup flow), then active secret (re-verify flow)
    let secret = user
        .pending_totp_secret
        .or(user.totp_secret)
        .ok_or(AppError::BadRequest("TOTP not set up".into()))?;

    if !auth::verify_totp(&secret, &req.code)? {
        return Err(AppError::AuthError("Invalid TOTP code".into()));
    }

    // Promote pending secret to active (idempotent if already active)
    queries::promote_pending_totp(state.db.write(), user_id).await?;

    Ok(Json(serde_json::json!({ "message": "TOTP verified and enabled" })))
}

/// PUT /api/v1/auth/password
pub async fn change_password(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<ChangePasswordRequest>,
) -> AppResult<Json<serde_json::Value>> {
    // Validate new password length
    if req.new_password.len() < 8 || req.new_password.len() > 128 {
        return Err(AppError::Validation("New password must be 8-128 characters".into()));
    }

    // Fetch user and verify current password
    let user = queries::find_user_by_id(state.db.read(), user_id)
        .await?
        .ok_or(AppError::UserNotFound)?;

    if !auth::verify_password(&req.current_password, &user.password_hash)? {
        return Err(AppError::AuthError("Current password is incorrect".into()));
    }

    // Hash and save new password
    let new_hash = auth::hash_password(&req.new_password)?;
    queries::update_user_password(state.db.write(), user_id, &new_hash).await?;

    // Revoke all refresh tokens (force re-login everywhere)
    queries::revoke_all_user_refresh_tokens(state.db.write(), user_id).await?;

    Ok(Json(serde_json::json!({ "message": "Password changed" })))
}

/// DELETE /api/v1/auth/totp
pub async fn totp_disable(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> AppResult<Json<serde_json::Value>> {
    queries::clear_user_totp_secret(state.db.write(), user_id).await?;
    Ok(Json(serde_json::json!({ "message": "TOTP disabled" })))
}

/// POST /api/v1/auth/delete-account — permanently delete the user's account
pub async fn delete_account(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<DeleteAccountRequest>,
) -> AppResult<StatusCode> {
    // Verify password
    let user = queries::find_user_by_id(state.db.read(), user_id)
        .await?
        .ok_or(AppError::UserNotFound)?;

    if !auth::verify_password(&req.password, &user.password_hash)? {
        return Err(AppError::AuthError("Incorrect password".into()));
    }

    // 1. Delete servers owned by this user (cascade removes channels, members, etc.)
    let owned_servers = queries::get_servers_owned_by(state.db.read(), user_id).await?;
    for server in &owned_servers {
        // Clean up custom emoji storage for this server
        let emojis = queries::list_server_emojis(state.db.read(), server.id).await.unwrap_or_default();
        for emoji in &emojis {
            let _ = state.storage.delete_blob(&emoji.storage_key).await;
        }
        // Delete server (CASCADE handles members, channels, emojis, etc.)
        sqlx::query("DELETE FROM servers WHERE id = $1")
            .bind(server.id)
            .execute(state.db.write())
            .await
            .ok();
    }

    // 2. Clean up message children that reference the partitioned messages table
    //    (no FK cascade on partitioned tables in PG < 17)
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

    // 4. Also delete reactions by this user on other messages
    sqlx::query("DELETE FROM reactions WHERE user_id = $1")
        .bind(user_id)
        .execute(state.db.write())
        .await
        .ok();

    // 5. Revoke tokens, broadcast offline, clean up voice
    queries::revoke_all_user_refresh_tokens(state.db.write(), user_id).await.ok();
    crate::ws::broadcast_presence(user_id, "offline", &state).await;
    crate::api::voice::cleanup_voice_state(&state, user_id).await;

    // 6. Close active WS connections
    if let Some((_, conns)) = state.connections.remove(&user_id) {
        for tx in conns {
            let _ = tx.send(WsServerMessage::Error {
                message: "Account deleted".into(),
            });
        }
    }

    // 7. Delete user (FK CASCADE handles server_members, channel_members,
    //    friendships, blocks, prekeys, key_backups, sender_key_distributions, etc.)
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(state.db.write())
        .await
        .map_err(AppError::Database)?;

    // 8. Clean up stored files (avatar, banner)
    let avatar_key = storage::obfuscated_key(&state.storage_key, &format!("avatar:{}", user_id));
    let banner_key = storage::obfuscated_key(&state.storage_key, &format!("banner:{}", user_id));
    let _ = state.storage.delete_blob(&avatar_key).await;
    let _ = state.storage.delete_blob(&banner_key).await;

    // 9. Invalidate caches
    crate::cache::invalidate(state.redis.clone().as_mut(), &state.memory, &format!("haven:user:{}", user_id)).await;

    Ok(StatusCode::NO_CONTENT)
}
