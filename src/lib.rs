// Library re-exports for integration tests.
// The binary crate (main.rs) uses these modules directly via `mod`.
// Integration tests in tests/ import them from this lib crate.

pub mod api;
pub mod auth;
pub mod cache;
pub mod config;
pub mod crypto;
pub mod db;
pub mod errors;
pub mod memory_store;
pub mod middleware;
pub mod models;
pub mod permissions;
pub mod pubsub;
pub mod storage;
pub mod tls;
pub mod livekit_proc;
pub mod ws;
#[cfg(feature = "embed-ui")]
pub mod embedded_ui;

use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderValue, Method},
    middleware as axum_mw,
    routing::{delete, get, post, put},
    Router,
};
use tower_http::{
    compression::CompressionLayer,
    cors::{AllowOrigin, CorsLayer},
    set_header::SetResponseHeaderLayer,
    trace::{DefaultOnResponse, TraceLayer},
};

use middleware::{rate_limit_middleware, RateLimiter, UserRateLimiter};

use config::AppConfig;
use ws::{ChannelBroadcastMap, ConnectionMap};

// ─── Application State ─────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub db: db::DbPools,
    pub redis: Option<redis::aio::ConnectionManager>,
    pub config: AppConfig,
    pub storage_key: [u8; 32],
    pub storage: storage::Storage,
    pub connections: ConnectionMap,
    pub channel_broadcasts: ChannelBroadcastMap,
    pub pubsub_subscriptions: pubsub::PubSubSubscriptions,
    pub memory: memory_store::MemoryStore,
    /// Per-user rate limiter for WebSocket message sending (30 msg / 10s)
    pub ws_rate_limiter: UserRateLimiter,
    /// Per-user rate limiter for write API endpoints (30 req / 60s)
    pub api_rate_limiter: UserRateLimiter,
    /// WebSocket sessions for resume support
    pub sessions: ws::SessionMap,
}

// ─── Router ────────────────────────────────────────────

pub fn build_router(state: AppState) -> Router {
    // ─── CORS ──────────────────────────────────────────
    let cors = if state.config.cors_origins == "*" {
        // Dev/test mode: allow all origins
        CorsLayer::new()
            .allow_origin(AllowOrigin::any())
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
    } else {
        // Production: whitelist specific origins
        let origins: Vec<HeaderValue> = state
            .config
            .cors_origins
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
    };

    // ─── Rate Limiting ─────────────────────────────────
    // Global: per-IP, based on config max_requests_per_minute
    let global_limiter = RateLimiter::new(state.config.max_requests_per_minute, 60);
    middleware::spawn_rate_limit_cleanup(global_limiter.clone());

    // Stricter limit for auth endpoints (10 req/min per IP to resist brute-force)
    let auth_limiter = RateLimiter::new(10, 60);

    // Auth routes (no authentication required) — stricter rate limit
    let auth_limiter_clone = auth_limiter.clone();
    let auth_routes = Router::new()
        .route("/challenge", get(api::auth_routes::pow_challenge))
        .route("/register", post(api::auth_routes::register))
        .route("/login", post(api::auth_routes::login))
        .route("/refresh", post(api::auth_routes::refresh_token))
        .route("/invite-required", get(api::registration_invites::invite_required))
        .layer(axum_mw::from_fn(move |req, next| {
            let limiter = auth_limiter_clone.clone();
            rate_limit_middleware(limiter, req, next)
        }));

    // Auth routes (authentication required)
    let auth_protected = Router::new()
        .route("/logout", post(api::auth_routes::logout))
        .route("/password", put(api::auth_routes::change_password))
        .route("/sessions", get(api::auth_routes::list_sessions))
        .route("/sessions/:family_id", delete(api::auth_routes::revoke_session))
        .route("/totp/setup", post(api::auth_routes::totp_setup))
        .route("/totp/verify", post(api::auth_routes::totp_verify))
        .route("/totp", delete(api::auth_routes::totp_disable))
        .route("/delete-account", post(api::auth_routes::delete_account));

    // Key management routes
    let key_routes = Router::new()
        .route("/identity", put(api::keys::update_identity_keys))
        .route("/prekeys", post(api::keys::upload_prekeys).delete(api::keys::delete_prekeys))
        .route("/prekeys/count", get(api::keys::prekey_count))
        .route(
            "/backup",
            put(api::key_backup::upload_key_backup)
                .get(api::key_backup::get_key_backup)
                .delete(api::key_backup::delete_key_backup),
        )
        .route("/backup/status", get(api::key_backup::get_key_backup_status));

    // User routes
    let user_routes = Router::new()
        .route("/:user_id/keys", get(api::keys::get_key_bundle))
        .route("/:user_id/profile", get(api::users::get_profile))
        .route("/:user_id/avatar", get(api::users::get_avatar))
        .route("/:user_id/banner", get(api::users::get_banner))
        .route(
            "/:user_id/block",
            post(api::users::block_user).delete(api::users::unblock_user),
        )
        .route("/search", get(api::users::get_user_by_username))
        .route("/profile", put(api::users::update_profile))
        .route("/avatar", post(api::users::upload_avatar))
        .route("/banner", post(api::users::upload_banner))
        .route("/blocked", get(api::users::get_blocked_users))
        .route("/profile-keys", put(api::users::distribute_profile_keys))
        .route("/:user_id/profile-key", get(api::users::get_profile_key));

    // Server routes
    let server_routes = Router::new()
        .route("/", get(api::servers::list_servers))
        .route("/", post(api::servers::create_server))
        .route("/:server_id", get(api::servers::get_server).patch(api::servers::update_server).delete(api::servers::delete_server))
        .route(
            "/:server_id/channels",
            get(api::servers::list_server_channels),
        )
        .route(
            "/:server_id/channels",
            post(api::channels::create_channel),
        )
        .route(
            "/:server_id/channels/reorder",
            put(api::channels::reorder_channels),
        )
        .route(
            "/:server_id/categories",
            get(api::categories::list_categories)
                .post(api::categories::create_category),
        )
        .route(
            "/:server_id/categories/reorder",
            put(api::categories::reorder_categories),
        )
        .route(
            "/:server_id/categories/:category_id",
            put(api::categories::update_category)
                .delete(api::categories::delete_category),
        )
        .route(
            "/:server_id/invites",
            get(api::invites::list_invites),
        )
        .route(
            "/:server_id/invites",
            post(api::invites::create_invite),
        )
        .route(
            "/:server_id/invites/:invite_id",
            delete(api::invites::delete_invite),
        )
        .route(
            "/:server_id/members/@me/permissions",
            get(api::servers::get_my_permissions),
        )
        .route(
            "/:server_id/members/@me",
            delete(api::servers::leave_server),
        )
        .route(
            "/:server_id/members",
            get(api::invites::list_members),
        )
        .route(
            "/:server_id/members/:user_id",
            delete(api::invites::kick_member),
        )
        .route(
            "/:server_id/roles",
            get(api::roles::list_roles).post(api::roles::create_role),
        )
        .route(
            "/:server_id/roles/:role_id",
            put(api::roles::update_role).delete(api::roles::delete_role),
        )
        .route(
            "/:server_id/members/:user_id/roles",
            put(api::roles::assign_role),
        )
        .route(
            "/:server_id/members/:user_id/roles/:role_id",
            delete(api::roles::unassign_role),
        )
        .route(
            "/:server_id/bans",
            get(api::bans::list_bans),
        )
        .route(
            "/:server_id/bans/:user_id",
            post(api::bans::ban_member).delete(api::bans::revoke_ban),
        )
        .route(
            "/:server_id/nickname",
            put(api::servers::set_nickname),
        )
        .route(
            "/:server_id/members/:user_id/nickname",
            put(api::servers::set_member_nickname),
        )
        .route(
            "/:server_id/members/:user_id/timeout",
            put(api::servers::timeout_member),
        )
        .route(
            "/:server_id/export",
            get(api::servers::export_server),
        )
        .route(
            "/:server_id/restore",
            post(api::exports::restore_server),
        )
        .route(
            "/:server_id/audit-log",
            get(api::servers::get_audit_log),
        )
        .route(
            "/:server_id/icon",
            post(api::servers::upload_icon)
                .get(api::servers::get_icon)
                .delete(api::servers::delete_icon),
        )
        .route(
            "/:server_id/emojis",
            get(api::emojis::list_emojis).post(api::emojis::upload_emoji),
        )
        .route(
            "/:server_id/emojis/:emoji_id",
            axum::routing::patch(api::emojis::update_emoji)
                .delete(api::emojis::delete_emoji),
        )
        .route(
            "/:server_id/emojis/:emoji_id/image",
            get(api::emojis::get_emoji_image),
        );

    // Channel routes
    let channel_routes = Router::new()
        .route("/read-states", get(api::channels::get_read_states))
        .route("/:channel_id/read-state", put(api::channels::mark_channel_read))
        .route("/:channel_id", put(api::channels::update_channel))
        .route("/:channel_id", delete(api::channels::delete_channel))
        .route("/:channel_id/join", post(api::channels::join_channel))
        .route("/:channel_id/category", put(api::categories::set_channel_category))
        .route(
            "/:channel_id/overwrites",
            get(api::roles::list_overwrites).put(api::roles::set_overwrite),
        )
        .route(
            "/:channel_id/overwrites/:target_type/:target_id",
            delete(api::roles::delete_overwrite),
        )
        .route(
            "/:channel_id/import-messages",
            post(api::exports::import_messages),
        )
        .route(
            "/:channel_id/messages",
            get(api::messages::get_messages),
        )
        .route(
            "/:channel_id/messages",
            post(api::messages::send_message),
        )
        .route(
            "/:channel_id/messages/bulk-delete",
            post(api::messages::bulk_delete_messages),
        )
        .route(
            "/:channel_id/sender-keys",
            get(api::sender_keys::get_sender_keys)
                .post(api::sender_keys::distribute_sender_keys),
        )
        .route(
            "/:channel_id/members/keys",
            get(api::sender_keys::get_channel_member_keys),
        )
        .route(
            "/:channel_id/reactions",
            get(api::messages::get_channel_reactions),
        )
        .route(
            "/:channel_id/members",
            get(api::channels::list_channel_members)
                .post(api::channels::add_group_member),
        )
        .route(
            "/:channel_id/leave",
            delete(api::channels::leave_channel),
        )
        .route(
            "/:channel_id/export",
            get(api::channels::export_channel),
        )
        .route(
            "/:channel_id/export-consent",
            put(api::channels::set_export_consent),
        )
        .route(
            "/:channel_id/hide",
            put(api::channels::hide_channel),
        )
        .route(
            "/:channel_id/pins",
            get(api::messages::get_pins),
        )
        .route(
            "/:channel_id/pin-ids",
            get(api::messages::get_pin_ids),
        );

    // Friend routes
    let friend_routes = Router::new()
        .route("/", get(api::friends::list_friends))
        .route("/request", post(api::friends::send_friend_request))
        .route("/:friendship_id/accept", post(api::friends::accept_friend_request))
        .route("/:friendship_id/decline", post(api::friends::decline_friend_request))
        .route("/:friendship_id", delete(api::friends::remove_friend));

    // DM routes
    let dm_routes = Router::new()
        .route("/", get(api::channels::list_dm_channels))
        .route("/", post(api::channels::create_dm))
        .route("/group", post(api::channels::create_group_dm))
        .route("/requests", get(api::friends::list_dm_requests))
        .route("/:channel_id/request", post(api::friends::handle_dm_request));

    // Invite join route
    let invite_routes = Router::new()
        .route("/:code/join", post(api::invites::join_by_invite));

    // Attachment routes
    let attachment_routes = Router::new()
        .route("/upload", post(api::attachments::upload))
        .route("/:attachment_id", get(api::attachments::download))
        .layer(DefaultBodyLimit::max(state.config.max_upload_size_bytes as usize));

    // Link preview
    let link_preview_routes = Router::new()
        .route("/link-preview", get(api::link_preview::fetch_link_preview));

    // Presence routes
    let presence_routes = Router::new()
        .route("/presence", get(api::presence::get_presence));

    // DM privacy route
    let dm_privacy_routes = Router::new()
        .route("/users/dm-privacy", put(api::friends::update_dm_privacy));

    // Report routes
    let report_routes = Router::new()
        .route("/", post(api::reports::create_report));

    // Voice routes
    let voice_routes = Router::new()
        .route("/:channel_id/join", post(api::voice::join_voice))
        .route("/:channel_id/leave", post(api::voice::leave_voice))
        .route(
            "/:channel_id/participants",
            get(api::voice::get_participants),
        )
        .route("/:channel_id/members/:user_id/mute", put(api::voice::server_mute))
        .route("/:channel_id/members/:user_id/deafen", put(api::voice::server_deafen));

    // Background task: prune broadcast channels with no subscribers
    {
        let broadcasts = state.channel_broadcasts.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                broadcasts.retain(|_, tx| tx.receiver_count() > 0);
            }
        });
    }

    // Background task: prune expired WebSocket sessions
    {
        let sessions = state.sessions.clone();
        let session_ttl_secs = state.config.ws_session_ttl_secs;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let ttl = std::time::Duration::from_secs(session_ttl_secs);
                let mut removed = 0u32;
                sessions.retain(|_, session| {
                    // Use try_lock to avoid blocking the cleanup task
                    match session.last_active.try_lock() {
                        Ok(last) => {
                            if last.elapsed() <= ttl {
                                true
                            } else {
                                removed += 1;
                                false
                            }
                        }
                        Err(_) => true, // Session is in use, keep it
                    }
                });
                if removed > 0 {
                    tracing::debug!("Pruned {} expired WebSocket sessions", removed);
                }
            }
        });
    }

    // Registration invite routes (authenticated)
    let registration_invite_routes = Router::new()
        .route("/", get(api::registration_invites::list_my_invites));

    // Admin routes (requires instance admin)
    let admin_routes = Router::new()
        .route("/stats", get(api::admin::get_stats))
        .route("/users", get(api::admin::list_users))
        .route("/users/:user_id/admin", put(api::admin::set_admin))
        .route("/users/:user_id", delete(api::admin::delete_user))
        .route(
            "/registration-invites",
            get(api::registration_invites::admin_list_invites)
                .post(api::registration_invites::admin_create_invites),
        )
        .route(
            "/registration-invites/:invite_id",
            delete(api::registration_invites::admin_delete_invite),
        );

    // Beta code request (public, strict rate limit: 3 req/min per IP)
    let beta_limiter = RateLimiter::new(3, 60);
    let beta_limiter_clone = beta_limiter.clone();
    let beta_routes = Router::new()
        .route("/request-code", post(api::beta::request_beta_code))
        .layer(axum_mw::from_fn(move |req, next| {
            let limiter = beta_limiter_clone.clone();
            rate_limit_middleware(limiter, req, next)
        }));

    // GIF proxy routes
    let gif_routes = Router::new()
        .route("/search", get(api::gifs::search_gifs))
        .route("/trending", get(api::gifs::trending_gifs));

    let message_routes = Router::new()
        .route("/:message_id/reactions", get(api::messages::get_message_reactions));

    // Export routes
    let export_routes = Router::new()
        .route("/verify", post(api::exports::verify_export))
        .route("/log", post(api::exports::log_export));

    // Assemble the full API
    let api = Router::new()
        .nest("/auth", auth_routes.merge(auth_protected))
        .nest("/admin", admin_routes)
        .nest("/keys", key_routes)
        .nest("/users", user_routes)
        .nest("/servers", server_routes)
        .nest("/channels", channel_routes)
        .nest("/messages", message_routes)
        .nest("/dm", dm_routes)
        .nest("/friends", friend_routes)
        .nest("/invites", invite_routes)
        .nest("/attachments", attachment_routes)
        .merge(link_preview_routes)
        .merge(presence_routes)
        .merge(dm_privacy_routes)
        .nest("/reports", report_routes)
        .nest("/voice", voice_routes)
        .nest("/gifs", gif_routes)
        .nest("/beta", beta_routes)
        .nest("/registration-invites", registration_invite_routes)
        .nest("/exports", export_routes);

    Router::new()
        .route("/api/v1/ws", get(ws::ws_handler))
        .nest("/api/v1", api)
        .route("/health", get(health_check))
        .layer(CompressionLayer::new())
        // TraceLayer: custom span excludes remote_addr (IP privacy)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|req: &axum::extract::Request| {
                    tracing::info_span!(
                        "http_request",
                        method = %req.method(),
                        uri = %req.uri(),
                        version = ?req.version(),
                    )
                })
                .on_response(DefaultOnResponse::new().level(tracing::Level::DEBUG)),
        )
        .layer(axum_mw::from_fn(move |req, next| {
            let limiter = global_limiter.clone();
            rate_limit_middleware(limiter, req, next)
        }))
        .layer(cors)
        // ─── Security Headers ──────────────────────────
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("1; mode=block"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), microphone=(self), geolocation=(), interest-cohort=(), browsing-topics=()"),
        ))
        // ─── Privacy Headers ──────────────────────────────
        .layer(SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("tk"),
            HeaderValue::from_static("N"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self' wss:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
            ),
        ))
        .with_state(state)
}

async fn health_check() -> &'static str {
    "ok"
}
