use std::sync::Arc;

use dashmap::DashMap;

use haven_backend::{
    build_router,
    config::AppConfig,
    db::{self, DbPools},
    livekit_proc,
    memory_store::MemoryStore,
    middleware::{spawn_user_rate_limit_cleanup, UserRateLimiter},
    pubsub,
    storage::Storage,
    AppState,
};

// ─── Main ──────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Install rustls crypto provider before any TLS usage
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Load .env file if present
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "haven_backend=debug,tower_http=debug".into()),
        )
        .json()
        .init();

    // Load configuration
    // SQLite mode: use TOML config file (auto-generated if missing)
    // PostgreSQL mode: use environment variables (existing behavior)
    #[cfg(feature = "sqlite")]
    let config = {
        let config_path = std::env::var("HAVEN_CONFIG")
            .unwrap_or_else(|_| "./data/haven.toml".into());
        AppConfig::from_file_or_generate(&config_path)
    };

    #[cfg(feature = "postgres")]
    let config = AppConfig::from_env();

    // ─── Bundled LiveKit SFU ─────────────────────────────
    // When no external LiveKit is configured, auto-discover and start a local
    // livekit-server binary as a managed subprocess with ephemeral credentials.
    let mut config = config;
    let _livekit_process = if config.livekit_url.is_empty() && config.livekit_bundled {
        match livekit_proc::start_bundled_livekit(config.livekit_port).await {
            Some(bundled) => {
                config.livekit_url = bundled.url;
                config.livekit_api_key = bundled.api_key;
                config.livekit_api_secret = bundled.api_secret;
                tracing::info!("Managed LiveKit on port {} — voice enabled", config.livekit_port);
                Some(bundled.process)
            }
            None => {
                tracing::warn!("LiveKit binary not found — voice disabled");
                None
            }
        }
    } else if !config.livekit_url.is_empty() {
        tracing::info!("Using external LiveKit at {}", config.livekit_url);
        None
    } else {
        None
    };

    tracing::info!("Starting Haven backend on {}:{}", config.host, config.port);

    // Initialize database pools (primary + optional replica)
    let db = DbPools::init(&config).await;

    // Initialize Redis (optional — if redis_url is empty, use in-memory stores only)
    let redis = if config.redis_url.is_empty() {
        tracing::info!("Redis not configured — using in-memory stores (single-instance mode)");
        None
    } else {
        let redis_client = redis::Client::open(config.redis_url.as_str())
            .expect("Failed to create Redis client");
        let conn = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("Failed to connect to Redis");
        tracing::info!("Redis connected");

        // Clear stale presence from previous server runs
        {
            let mut redis_cleanup = conn.clone();
            let _: Result<(), redis::RedisError> = redis::cmd("DEL")
                .arg("haven:presence")
                .query_async(&mut redis_cleanup)
                .await;
            tracing::info!("Cleared stale presence entries");
        }

        Some(conn)
    };

    // In-memory stores (always created — used for local caching even with Redis)
    let memory = MemoryStore::new();
    memory.spawn_cleanup_task();

    // Initialize storage backend (local or S3 based on config)
    let storage = Storage::from_config(&config).await;
    let storage_key = *storage.encryption_key();

    // Per-user rate limiters
    let ws_rate_limiter = UserRateLimiter::new(30, 10); // 30 messages per 10 seconds
    let api_rate_limiter = UserRateLimiter::new(30, 60); // 30 write ops per minute
    spawn_user_rate_limit_cleanup(ws_rate_limiter.clone());
    spawn_user_rate_limit_cleanup(api_rate_limiter.clone());

    // Build application state (pubsub_subscriptions added after start_subscriber)
    let mut state = AppState {
        db: db.clone(),
        redis,
        config: config.clone(),
        storage_key,
        storage,
        connections: Arc::new(DashMap::new()),
        channel_broadcasts: Arc::new(DashMap::new()),
        pubsub_subscriptions: pubsub::empty_subscriptions(),
        memory,
        ws_rate_limiter,
        api_rate_limiter,
        sessions: Arc::new(DashMap::new()),
    };

    // Start Redis pub/sub subscriber and store the subscriptions handle
    state.pubsub_subscriptions = pubsub::start_subscriber(state.clone());

    // Spawn background workers
    spawn_background_workers(db.clone(), &config);

    // Worker: Clean stale Redis presence entries every 60 seconds
    // If the server crashes without graceful shutdown, presence entries persist.
    // This cross-references against active WebSocket connections and removes orphans.
    {
        let state_clone = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let Some(mut redis) = state_clone.redis.clone() else {
                    continue;
                };

                // Get all presence entries
                let all: Vec<String> = match redis::cmd("HKEYS")
                    .arg("haven:presence")
                    .query_async(&mut redis)
                    .await
                {
                    Ok(keys) => keys,
                    Err(_) => continue,
                };

                let mut removed = 0u32;
                for user_id_str in &all {
                    let Ok(uid) = user_id_str.parse::<uuid::Uuid>() else {
                        continue;
                    };
                    // If user has no active WebSocket connections, remove their presence
                    let has_connections = state_clone
                        .connections
                        .get(&uid)
                        .map(|v| !v.is_empty())
                        .unwrap_or(false);
                    if !has_connections {
                        let _: Result<(), redis::RedisError> = redis::cmd("HDEL")
                            .arg("haven:presence")
                            .arg(user_id_str.as_str())
                            .query_async(&mut redis)
                            .await;
                        removed += 1;
                    }
                }
                if removed > 0 {
                    tracing::info!("Cleaned {} stale presence entries", removed);
                }
            }
        });
    }

    // Build router
    let app = build_router(state);

    // ─── Embedded Web UI ──────────────────────────────────
    #[cfg(feature = "embed-ui")]
    let app = {
        tracing::info!("Embedded web UI: enabled");
        app.merge(haven_backend::embedded_ui::router())
    };
    #[cfg(not(feature = "embed-ui"))]
    tracing::info!("Embedded web UI: disabled (API-only mode)");

    // ─── TLS / HTTPS setup ────────────────────────────────
    let tls_rustls_config = if config.tls_enabled {
        match haven_backend::tls::ensure_certs(
            &config.tls_cert_path,
            &config.tls_key_path,
            config.tls_auto_generate,
        ).await {
            Ok(cfg) => {
                tracing::info!("TLS enabled on port {}", config.tls_port);
                Some(cfg)
            }
            Err(e) => {
                tracing::warn!("TLS setup failed, HTTPS disabled: {}", e);
                None
            }
        }
    } else {
        tracing::info!("TLS disabled");
        None
    };

    // ─── Start server(s) ──────────────────────────────────
    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind to address");
    tracing::info!("Haven backend listening on http://{}", addr);

    if let Some(rustls_config) = tls_rustls_config {
        // Run HTTP and HTTPS concurrently
        let tls_addr: std::net::SocketAddr = format!("{}:{}", config.host, config.tls_port)
            .parse()
            .expect("Invalid TLS address");
        tracing::info!("Haven backend listening on https://{}", tls_addr);

        let app_https = app
            .clone()
            .layer(axum::middleware::from_fn(inject_https_proto));

        let http_server = axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .with_graceful_shutdown(shutdown_signal());

        let https_server = axum_server::bind_rustls(tls_addr, rustls_config)
            .serve(app_https.into_make_service());

        tokio::select! {
            result = http_server => {
                result.expect("HTTP server error");
            }
            result = https_server => {
                result.expect("HTTPS server error");
            }
        }
    } else {
        // HTTP only
        axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .with_graceful_shutdown(shutdown_signal())
            .await
            .expect("Server error");
    }

    tracing::info!("Haven backend shut down gracefully");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("Received Ctrl+C, shutting down..."),
        _ = terminate => tracing::info!("Received SIGTERM, shutting down..."),
    }
}

/// Middleware: inject `X-Forwarded-Proto: https` on requests via the HTTPS listener.
async fn inject_https_proto(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    req.headers_mut().insert(
        "x-forwarded-proto",
        axum::http::HeaderValue::from_static("https"),
    );
    next.run(req).await
}

// ─── Background Workers ────────────────────────────────

fn spawn_background_workers(db: DbPools, config: &AppConfig) {
    let pool = db.primary().clone();
    let pool2 = pool.clone();
    let pool3 = pool.clone();

    // Worker: Purge expired messages every 60 seconds
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            match db::queries::purge_expired_messages(&pool).await {
                Ok(count) if count > 0 => {
                    tracing::info!("Purged {} expired messages", count);
                }
                Err(e) => {
                    tracing::error!("Failed to purge expired messages: {}", e);
                }
                _ => {}
            }
        }
    });

    // Worker: Purge expired refresh tokens every 5 minutes
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            match db::queries::purge_expired_refresh_tokens(&pool2).await {
                Ok(count) if count > 0 => {
                    tracing::info!("Purged {} expired refresh tokens", count);
                }
                Err(e) => {
                    tracing::error!("Failed to purge expired refresh tokens: {}", e);
                }
                _ => {}
            }
        }
    });

    // Worker: Ensure message partitions exist 3 months ahead (runs daily)
    // PostgreSQL only — SQLite ensure_future_partitions is a no-op
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(86400));
        loop {
            interval.tick().await;
            match db::queries::ensure_future_partitions(&pool3).await {
                Ok(()) => {
                    tracing::debug!("Partition maintenance completed");
                }
                Err(e) => {
                    tracing::error!("Partition maintenance failed: {}", e);
                }
            }
        }
    });

    // Worker: Purge old audit log entries (daily, metadata minimization)
    if config.audit_log_retention_days > 0 {
        let pool = db.primary().clone();
        let days = config.audit_log_retention_days;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(86400));
            loop {
                interval.tick().await;
                match db::queries::purge_old_audit_logs(&pool, days).await {
                    Ok(count) if count > 0 => tracing::info!("Purged {} old audit log entries", count),
                    Err(e) => tracing::error!("Failed to purge audit logs: {}", e),
                    _ => {}
                }
            }
        });
    }

    // Worker: Purge old resolved reports (daily, metadata minimization)
    if config.resolved_report_retention_days > 0 {
        let pool = db.primary().clone();
        let days = config.resolved_report_retention_days;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(86400));
            loop {
                interval.tick().await;
                match db::queries::purge_old_resolved_reports(&pool, days).await {
                    Ok(count) if count > 0 => tracing::info!("Purged {} old resolved reports", count),
                    Err(e) => tracing::error!("Failed to purge resolved reports: {}", e),
                    _ => {}
                }
            }
        });
    }

    // Worker: Purge expired invites (hourly)
    if config.expired_invite_cleanup {
        let pool = db.primary().clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                match db::queries::purge_expired_invites(&pool).await {
                    Ok(count) if count > 0 => tracing::info!("Purged {} expired invites", count),
                    Err(e) => tracing::error!("Failed to purge expired invites: {}", e),
                    _ => {}
                }
            }
        });
    }
}
