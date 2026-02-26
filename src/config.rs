use std::env;
use std::path::Path;

use serde::{Deserialize, Serialize};

// ─── TOML Config File ─────────────────────────────────

/// TOML-serializable config file format. Only fields that make sense
/// in a config file are included; runtime-only fields stay on AppConfig.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigFile {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default)]
    pub database_url: String,
    #[serde(default)]
    pub database_replica_url: String,
    #[serde(default = "default_db_max_connections")]
    pub db_max_connections: u32,

    #[serde(default)]
    pub redis_url: String,

    #[serde(default)]
    pub jwt_secret: String,
    #[serde(default = "default_jwt_expiry_hours")]
    pub jwt_expiry_hours: i64,
    #[serde(default = "default_refresh_token_expiry_days")]
    pub refresh_token_expiry_days: i64,

    #[serde(default = "default_storage_backend")]
    pub storage_backend: String,
    #[serde(default = "default_storage_dir")]
    pub storage_dir: String,
    #[serde(default)]
    pub storage_encryption_key: String,

    #[serde(default)]
    pub s3_endpoint: String,
    #[serde(default)]
    pub s3_bucket: String,
    #[serde(default)]
    pub s3_access_key: String,
    #[serde(default)]
    pub s3_secret_key: String,
    #[serde(default = "default_s3_region")]
    pub s3_region: String,

    #[serde(default = "default_cors_origins")]
    pub cors_origins: String,

    #[serde(default = "default_max_requests_per_minute")]
    pub max_requests_per_minute: u32,
    #[serde(default = "default_max_ws_connections_per_user")]
    pub max_ws_connections_per_user: u32,

    #[serde(default = "default_broadcast_channel_capacity")]
    pub broadcast_channel_capacity: usize,

    #[serde(default = "default_ws_heartbeat_timeout_secs")]
    pub ws_heartbeat_timeout_secs: u64,

    #[serde(default = "default_ws_session_buffer_size")]
    pub ws_session_buffer_size: usize,

    #[serde(default = "default_ws_session_ttl_secs")]
    pub ws_session_ttl_secs: u64,

    #[serde(default = "default_max_upload_size_bytes")]
    pub max_upload_size_bytes: u64,

    #[serde(default)]
    pub cdn_enabled: bool,
    #[serde(default)]
    pub cdn_base_url: String,
    #[serde(default = "default_cdn_presign_expiry_secs")]
    pub cdn_presign_expiry_secs: u64,

    #[serde(default)]
    pub livekit_url: String,
    #[serde(default)]
    pub livekit_client_url: String,
    #[serde(default)]
    pub livekit_api_key: String,
    #[serde(default)]
    pub livekit_api_secret: String,
    #[serde(default = "default_livekit_bundled")]
    pub livekit_bundled: bool,
    #[serde(default = "default_livekit_port")]
    pub livekit_port: u16,

    #[serde(default)]
    pub tls: TlsConfig,

    // Data Retention (days, 0 = keep forever)
    #[serde(default = "default_audit_log_retention_days")]
    pub audit_log_retention_days: u32,
    #[serde(default = "default_resolved_report_retention_days")]
    pub resolved_report_retention_days: u32,
    #[serde(default = "default_expired_invite_cleanup")]
    pub expired_invite_cleanup: bool,

    // Registration gating
    #[serde(default)]
    pub registration_invite_only: bool,
    #[serde(default = "default_registration_invites_per_user")]
    pub registration_invites_per_user: u32,

    // External APIs
    #[serde(default)]
    pub giphy_api_key: String,

    // Cloudflare Turnstile (CAPTCHA) — disabled when empty
    #[serde(default)]
    pub turnstile_site_key: String,
    #[serde(default)]
    pub turnstile_secret_key: String,

    // SMTP (beta code email delivery) — disabled when smtp_host is empty
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password: String,
    #[serde(default)]
    pub smtp_from: String,

    // Beta code system
    #[serde(default = "default_beta_code_limit")]
    pub beta_code_limit: u32,
    #[serde(default = "default_beta_code_expiry_days")]
    pub beta_code_expiry_days: i64,
}

// ─── TLS Config ───────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default = "default_tls_enabled")]
    pub enabled: bool,
    #[serde(default = "default_tls_port")]
    pub port: u16,
    #[serde(default = "default_tls_cert_path")]
    pub cert_path: String,
    #[serde(default = "default_tls_key_path")]
    pub key_path: String,
    #[serde(default = "default_tls_auto_generate")]
    pub auto_generate: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: default_tls_enabled(),
            port: default_tls_port(),
            cert_path: default_tls_cert_path(),
            key_path: default_tls_key_path(),
            auto_generate: default_tls_auto_generate(),
        }
    }
}

fn default_host() -> String { "0.0.0.0".into() }
fn default_port() -> u16 { 8080 }
fn default_db_max_connections() -> u32 { 50 }
fn default_jwt_expiry_hours() -> i64 { 24 }
fn default_refresh_token_expiry_days() -> i64 { 30 }
fn default_storage_backend() -> String { "local".into() }
fn default_storage_dir() -> String { "./data/attachments".into() }
fn default_s3_region() -> String { "us-east-1".into() }
fn default_cors_origins() -> String { "*".into() }
fn default_max_requests_per_minute() -> u32 { 1200 }
fn default_max_ws_connections_per_user() -> u32 { 5 }
fn default_broadcast_channel_capacity() -> usize { 4096 }
fn default_ws_heartbeat_timeout_secs() -> u64 { 90 }
fn default_ws_session_buffer_size() -> usize { 500 }
fn default_ws_session_ttl_secs() -> u64 { 300 }
fn default_max_upload_size_bytes() -> u64 { 524_288_000 }
fn default_cdn_presign_expiry_secs() -> u64 { 3600 }
fn default_livekit_bundled() -> bool { true }
fn default_livekit_port() -> u16 { 7880 }
fn default_tls_enabled() -> bool { true }
fn default_tls_port() -> u16 { 8443 }
fn default_tls_cert_path() -> String { "./data/certs/cert.pem".into() }
fn default_tls_key_path() -> String { "./data/certs/key.pem".into() }
fn default_tls_auto_generate() -> bool { true }
fn default_audit_log_retention_days() -> u32 { 90 }
fn default_resolved_report_retention_days() -> u32 { 180 }
fn default_expired_invite_cleanup() -> bool { true }
fn default_registration_invites_per_user() -> u32 { 3 }
fn default_smtp_port() -> u16 { 587 }
fn default_beta_code_limit() -> u32 { 50 }
fn default_beta_code_expiry_days() -> i64 { 7 }

// ─── Application Config ───────────────────────────────

#[derive(Clone, Debug)]
pub struct AppConfig {
    // Server
    pub host: String,
    pub port: u16,

    // Database
    pub database_url: String,
    pub database_replica_url: String, // empty = no replica, all queries go to primary
    pub db_max_connections: u32,

    // Redis
    pub redis_url: String,

    // JWT
    pub jwt_secret: String,
    pub jwt_expiry_hours: i64,
    pub refresh_token_expiry_days: i64,

    // Storage
    pub storage_backend: String, // "local" or "s3"
    pub storage_dir: String,
    pub storage_encryption_key: String, // 64-char hex → 32-byte AES-256-GCM key

    // S3 (only needed when storage_backend = "s3")
    pub s3_endpoint: String,
    pub s3_bucket: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    pub s3_region: String,

    // CORS — comma-separated list of allowed origins (e.g. "http://localhost:5173,https://app.haven.example")
    pub cors_origins: String,

    // Rate Limiting
    pub max_requests_per_minute: u32,
    pub max_ws_connections_per_user: u32,

    // WebSocket
    pub broadcast_channel_capacity: usize,
    pub ws_heartbeat_timeout_secs: u64,
    pub ws_session_buffer_size: usize,
    pub ws_session_ttl_secs: u64,

    // File Upload
    pub max_upload_size_bytes: u64,

    // CDN — optional, disabled by default
    pub cdn_enabled: bool,
    pub cdn_base_url: String,          // e.g. "https://cdn.haven.example"
    pub cdn_presign_expiry_secs: u64,  // default 3600

    // LiveKit (voice channels) — all optional, voice disabled if empty
    pub livekit_url: String,
    pub livekit_client_url: String, // URL returned to browsers (external); falls back to livekit_url
    pub livekit_api_key: String,
    pub livekit_api_secret: String,
    pub livekit_bundled: bool,
    pub livekit_port: u16,

    // TLS — auto-generated self-signed certs by default
    pub tls_enabled: bool,
    pub tls_port: u16,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub tls_auto_generate: bool,

    // Data Retention (days, 0 = keep forever)
    pub audit_log_retention_days: u32,
    pub resolved_report_retention_days: u32,
    pub expired_invite_cleanup: bool,

    // Registration gating
    pub registration_invite_only: bool,
    pub registration_invites_per_user: u32,

    // External APIs
    pub giphy_api_key: String,

    // Cloudflare Turnstile (CAPTCHA) — disabled when empty
    pub turnstile_site_key: String,
    pub turnstile_secret_key: String,

    // SMTP (beta code email delivery) — disabled when smtp_host is empty
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_from: String,

    // Beta code system
    pub beta_code_limit: u32,
    pub beta_code_expiry_days: i64,
}

impl AppConfig {
    /// Returns true if SMTP is configured for beta code delivery.
    pub fn smtp_enabled(&self) -> bool {
        !self.smtp_host.is_empty() && !self.smtp_username.is_empty()
    }

    /// Returns true if Cloudflare Turnstile CAPTCHA is configured.
    pub fn turnstile_enabled(&self) -> bool {
        !self.turnstile_site_key.is_empty() && !self.turnstile_secret_key.is_empty()
    }

    /// Returns true if LiveKit voice is configured.
    pub fn livekit_enabled(&self) -> bool {
        !self.livekit_url.is_empty()
            && !self.livekit_api_key.is_empty()
            && !self.livekit_api_secret.is_empty()
    }

    /// Returns the LiveKit URL to send to browser clients.
    /// Prefers `livekit_client_url` (external), falls back to `livekit_url` (for local dev).
    pub fn livekit_url_for_client(&self) -> &str {
        if self.livekit_client_url.is_empty() {
            &self.livekit_url
        } else {
            &self.livekit_client_url
        }
    }

    /// Config with test-appropriate defaults (no env vars needed).
    #[cfg(test)]
    pub fn test_default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 0,
            database_url: String::new(), // not used — pool comes from #[sqlx::test]
            database_replica_url: String::new(),
            db_max_connections: 5,
            redis_url: "redis://127.0.0.1:6379".into(),
            jwt_secret: "test-jwt-secret-that-is-long-enough-for-hmac".into(),
            jwt_expiry_hours: 24,
            refresh_token_expiry_days: 30,
            storage_backend: "local".into(),
            storage_dir: "/tmp/haven-test-storage".into(),
            storage_encryption_key: "0".repeat(64), // 32 zero bytes in hex
            s3_endpoint: String::new(),
            s3_bucket: String::new(),
            s3_access_key: String::new(),
            s3_secret_key: String::new(),
            s3_region: String::new(),
            cors_origins: "*".into(),
            max_requests_per_minute: 1000,
            max_ws_connections_per_user: 10,
            broadcast_channel_capacity: 4096,
            ws_heartbeat_timeout_secs: 90,
            ws_session_buffer_size: 500,
            ws_session_ttl_secs: 300,
            max_upload_size_bytes: 10_000_000,
            cdn_enabled: false,
            cdn_base_url: String::new(),
            cdn_presign_expiry_secs: 3600,
            livekit_url: String::new(),
            livekit_client_url: String::new(),
            livekit_api_key: String::new(),
            livekit_api_secret: String::new(),
            livekit_bundled: false,
            livekit_port: 7880,
            tls_enabled: false,
            tls_port: 8443,
            tls_cert_path: "./data/certs/cert.pem".into(),
            tls_key_path: "./data/certs/key.pem".into(),
            tls_auto_generate: false,

            audit_log_retention_days: 90,
            resolved_report_retention_days: 180,
            expired_invite_cleanup: true,

            registration_invite_only: false,
            registration_invites_per_user: 3,

            giphy_api_key: String::new(),

            turnstile_site_key: String::new(),
            turnstile_secret_key: String::new(),

            smtp_host: String::new(),
            smtp_port: 587,
            smtp_username: String::new(),
            smtp_password: String::new(),
            smtp_from: String::new(),

            beta_code_limit: 50,
            beta_code_expiry_days: 7,
        }
    }

    /// Load config from environment variables (existing behavior for PostgreSQL mode).
    pub fn from_env() -> Self {
        Self {
            host: env::var("HAVEN_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: env::var("HAVEN_PORT")
                .unwrap_or_else(|_| "8080".into())
                .parse()
                .expect("HAVEN_PORT must be a valid u16"),

            database_url: env::var("DATABASE_URL")
                .expect("DATABASE_URL must be set"),
            database_replica_url: env::var("DATABASE_REPLICA_URL").unwrap_or_default(),
            db_max_connections: env::var("DB_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "50".into())
                .parse()
                .unwrap_or(50),

            redis_url: env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".into()),

            jwt_secret: env::var("JWT_SECRET")
                .expect("JWT_SECRET must be set"),
            jwt_expiry_hours: env::var("JWT_EXPIRY_HOURS")
                .unwrap_or_else(|_| "24".into())
                .parse()
                .unwrap_or(24),
            refresh_token_expiry_days: env::var("REFRESH_TOKEN_EXPIRY_DAYS")
                .unwrap_or_else(|_| "30".into())
                .parse()
                .unwrap_or(30),

            storage_backend: env::var("STORAGE_BACKEND")
                .unwrap_or_else(|_| "local".into()),
            storage_dir: env::var("STORAGE_DIR")
                .unwrap_or_else(|_| "./data/attachments".into()),
            storage_encryption_key: env::var("STORAGE_ENCRYPTION_KEY")
                .expect("STORAGE_ENCRYPTION_KEY must be set (64-char hex string)"),
            s3_endpoint: env::var("S3_ENDPOINT").unwrap_or_default(),
            s3_bucket: env::var("S3_BUCKET").unwrap_or_default(),
            s3_access_key: env::var("S3_ACCESS_KEY").unwrap_or_default(),
            s3_secret_key: env::var("S3_SECRET_KEY").unwrap_or_default(),
            s3_region: env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".into()),

            cors_origins: env::var("CORS_ORIGINS")
                .unwrap_or_else(|_| "http://localhost:5173".into()),

            max_requests_per_minute: env::var("MAX_REQUESTS_PER_MINUTE")
                .unwrap_or_else(|_| "300".into())
                .parse()
                .unwrap_or(300),
            max_ws_connections_per_user: env::var("MAX_WS_CONNECTIONS_PER_USER")
                .unwrap_or_else(|_| "5".into())
                .parse()
                .unwrap_or(5),

            broadcast_channel_capacity: env::var("BROADCAST_CHANNEL_CAPACITY")
                .unwrap_or_else(|_| "4096".into())
                .parse()
                .unwrap_or(4096),

            ws_heartbeat_timeout_secs: default_ws_heartbeat_timeout_secs(),
            ws_session_buffer_size: default_ws_session_buffer_size(),
            ws_session_ttl_secs: default_ws_session_ttl_secs(),

            max_upload_size_bytes: env::var("MAX_UPLOAD_SIZE_BYTES")
                .unwrap_or_else(|_| "524288000".into()) // 500MB
                .parse()
                .unwrap_or(524_288_000),

            cdn_enabled: env::var("CDN_ENABLED")
                .unwrap_or_else(|_| "false".into())
                .parse()
                .unwrap_or(false),
            cdn_base_url: env::var("CDN_BASE_URL").unwrap_or_default(),
            cdn_presign_expiry_secs: env::var("CDN_PRESIGN_EXPIRY_SECS")
                .unwrap_or_else(|_| "3600".into())
                .parse()
                .unwrap_or(3600),

            livekit_url: env::var("LIVEKIT_URL").unwrap_or_default(),
            livekit_client_url: env::var("LIVEKIT_CLIENT_URL").unwrap_or_default(),
            livekit_api_key: env::var("LIVEKIT_API_KEY").unwrap_or_default(),
            livekit_api_secret: env::var("LIVEKIT_API_SECRET").unwrap_or_default(),
            livekit_bundled: env::var("LIVEKIT_BUNDLED")
                .unwrap_or_else(|_| "true".into())
                .parse()
                .unwrap_or(true),
            livekit_port: env::var("LIVEKIT_PORT")
                .unwrap_or_else(|_| "7880".into())
                .parse()
                .unwrap_or(7880),

            tls_enabled: env::var("TLS_ENABLED")
                .unwrap_or_else(|_| "true".into())
                .parse()
                .unwrap_or(true),
            tls_port: env::var("TLS_PORT")
                .unwrap_or_else(|_| "8443".into())
                .parse()
                .unwrap_or(8443),
            tls_cert_path: env::var("TLS_CERT_PATH")
                .unwrap_or_else(|_| default_tls_cert_path()),
            tls_key_path: env::var("TLS_KEY_PATH")
                .unwrap_or_else(|_| default_tls_key_path()),
            tls_auto_generate: env::var("TLS_AUTO_GENERATE")
                .unwrap_or_else(|_| "true".into())
                .parse()
                .unwrap_or(true),

            audit_log_retention_days: env::var("AUDIT_LOG_RETENTION_DAYS")
                .unwrap_or_else(|_| "90".into())
                .parse()
                .unwrap_or(90),
            resolved_report_retention_days: env::var("RESOLVED_REPORT_RETENTION_DAYS")
                .unwrap_or_else(|_| "180".into())
                .parse()
                .unwrap_or(180),
            expired_invite_cleanup: env::var("EXPIRED_INVITE_CLEANUP")
                .unwrap_or_else(|_| "true".into())
                .parse()
                .unwrap_or(true),

            registration_invite_only: env::var("REGISTRATION_INVITE_ONLY")
                .unwrap_or_else(|_| "false".into())
                .parse()
                .unwrap_or(false),
            registration_invites_per_user: env::var("REGISTRATION_INVITES_PER_USER")
                .unwrap_or_else(|_| "3".into())
                .parse()
                .unwrap_or(3),

            giphy_api_key: env::var("GIPHY_API_KEY").unwrap_or_default(),

            turnstile_site_key: env::var("TURNSTILE_SITE_KEY").unwrap_or_default(),
            turnstile_secret_key: env::var("TURNSTILE_SECRET_KEY").unwrap_or_default(),

            smtp_host: env::var("SMTP_HOST").unwrap_or_default(),
            smtp_port: env::var("SMTP_PORT")
                .unwrap_or_else(|_| "587".into())
                .parse()
                .unwrap_or(587),
            smtp_username: env::var("SMTP_USERNAME").unwrap_or_default(),
            smtp_password: env::var("SMTP_PASSWORD").unwrap_or_default(),
            smtp_from: env::var("SMTP_FROM").unwrap_or_default(),

            beta_code_limit: env::var("BETA_CODE_LIMIT")
                .unwrap_or_else(|_| "50".into())
                .parse()
                .unwrap_or(50),
            beta_code_expiry_days: env::var("BETA_CODE_EXPIRY_DAYS")
                .unwrap_or_else(|_| "7".into())
                .parse()
                .unwrap_or(7),
        }
    }

    /// Load config from TOML file, auto-generating one with secure defaults if it doesn't exist.
    /// Used for zero-config SQLite mode: `./haven-server` just works.
    pub fn from_file_or_generate(path: &str) -> Self {
        if Path::new(path).exists() {
            Self::from_toml_file(path)
        } else {
            tracing::info!("No config file found at {}, generating with secure defaults...", path);
            let config = Self::generate_default_config(path);
            tracing::info!("Config file written to {}", path);
            config
        }
    }

    /// Parse a TOML config file into AppConfig.
    fn from_toml_file(path: &str) -> Self {
        let content = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("Failed to read config file {}: {}", path, e));
        let file: ConfigFile = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("Failed to parse config file {}: {}", path, e));

        Self {
            host: file.host,
            port: file.port,
            database_url: file.database_url,
            database_replica_url: file.database_replica_url,
            db_max_connections: file.db_max_connections,
            redis_url: file.redis_url,
            jwt_secret: file.jwt_secret,
            jwt_expiry_hours: file.jwt_expiry_hours,
            refresh_token_expiry_days: file.refresh_token_expiry_days,
            storage_backend: file.storage_backend,
            storage_dir: file.storage_dir,
            storage_encryption_key: file.storage_encryption_key,
            s3_endpoint: file.s3_endpoint,
            s3_bucket: file.s3_bucket,
            s3_access_key: file.s3_access_key,
            s3_secret_key: file.s3_secret_key,
            s3_region: file.s3_region,
            cors_origins: file.cors_origins,
            max_requests_per_minute: file.max_requests_per_minute,
            max_ws_connections_per_user: file.max_ws_connections_per_user,
            broadcast_channel_capacity: file.broadcast_channel_capacity,
            ws_heartbeat_timeout_secs: file.ws_heartbeat_timeout_secs,
            ws_session_buffer_size: file.ws_session_buffer_size,
            ws_session_ttl_secs: file.ws_session_ttl_secs,
            max_upload_size_bytes: file.max_upload_size_bytes,
            cdn_enabled: file.cdn_enabled,
            cdn_base_url: file.cdn_base_url,
            cdn_presign_expiry_secs: file.cdn_presign_expiry_secs,
            livekit_url: file.livekit_url,
            livekit_client_url: file.livekit_client_url,
            livekit_api_key: file.livekit_api_key,
            livekit_api_secret: file.livekit_api_secret,
            livekit_bundled: file.livekit_bundled,
            livekit_port: file.livekit_port,
            tls_enabled: file.tls.enabled,
            tls_port: file.tls.port,
            tls_cert_path: file.tls.cert_path,
            tls_key_path: file.tls.key_path,
            tls_auto_generate: file.tls.auto_generate,

            audit_log_retention_days: file.audit_log_retention_days,
            resolved_report_retention_days: file.resolved_report_retention_days,
            expired_invite_cleanup: file.expired_invite_cleanup,

            registration_invite_only: file.registration_invite_only,
            registration_invites_per_user: file.registration_invites_per_user,

            giphy_api_key: file.giphy_api_key,

            turnstile_site_key: file.turnstile_site_key,
            turnstile_secret_key: file.turnstile_secret_key,

            smtp_host: file.smtp_host,
            smtp_port: file.smtp_port,
            smtp_username: file.smtp_username,
            smtp_password: file.smtp_password,
            smtp_from: file.smtp_from,

            beta_code_limit: file.beta_code_limit,
            beta_code_expiry_days: file.beta_code_expiry_days,
        }
    }

    /// Generate a config file with secure random secrets and sane defaults.
    fn generate_default_config(path: &str) -> Self {
        use rand::Rng;

        let mut rng = rand::thread_rng();

        // Generate 64-char hex strings (32 bytes of entropy)
        let jwt_secret: String = (0..32).map(|_| format!("{:02x}", rng.gen::<u8>())).collect();
        let storage_key: String = (0..32).map(|_| format!("{:02x}", rng.gen::<u8>())).collect();

        // Ensure data directory exists
        std::fs::create_dir_all("./data").ok();

        let file = ConfigFile {
            host: default_host(),
            port: default_port(),
            #[cfg(feature = "sqlite")]
            database_url: "sqlite:./data/haven.db?mode=rwc".into(),
            #[cfg(feature = "postgres")]
            database_url: String::new(),
            database_replica_url: String::new(),
            db_max_connections: default_db_max_connections(),
            redis_url: String::new(),
            jwt_secret,
            jwt_expiry_hours: default_jwt_expiry_hours(),
            refresh_token_expiry_days: default_refresh_token_expiry_days(),
            storage_backend: default_storage_backend(),
            storage_dir: default_storage_dir(),
            storage_encryption_key: storage_key,
            s3_endpoint: String::new(),
            s3_bucket: String::new(),
            s3_access_key: String::new(),
            s3_secret_key: String::new(),
            s3_region: default_s3_region(),
            cors_origins: default_cors_origins(),
            max_requests_per_minute: default_max_requests_per_minute(),
            max_ws_connections_per_user: default_max_ws_connections_per_user(),
            broadcast_channel_capacity: default_broadcast_channel_capacity(),
            ws_heartbeat_timeout_secs: default_ws_heartbeat_timeout_secs(),
            ws_session_buffer_size: default_ws_session_buffer_size(),
            ws_session_ttl_secs: default_ws_session_ttl_secs(),
            max_upload_size_bytes: default_max_upload_size_bytes(),
            cdn_enabled: false,
            cdn_base_url: String::new(),
            cdn_presign_expiry_secs: default_cdn_presign_expiry_secs(),
            livekit_url: String::new(),
            livekit_client_url: String::new(),
            livekit_api_key: String::new(),
            livekit_api_secret: String::new(),
            livekit_bundled: default_livekit_bundled(),
            livekit_port: default_livekit_port(),
            tls: TlsConfig::default(),

            audit_log_retention_days: default_audit_log_retention_days(),
            resolved_report_retention_days: default_resolved_report_retention_days(),
            expired_invite_cleanup: default_expired_invite_cleanup(),

            registration_invite_only: false,
            registration_invites_per_user: default_registration_invites_per_user(),

            giphy_api_key: String::new(),

            turnstile_site_key: String::new(),
            turnstile_secret_key: String::new(),

            smtp_host: String::new(),
            smtp_port: default_smtp_port(),
            smtp_username: String::new(),
            smtp_password: String::new(),
            smtp_from: String::new(),

            beta_code_limit: default_beta_code_limit(),
            beta_code_expiry_days: default_beta_code_expiry_days(),
        };

        // Write the TOML file
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let toml_string = toml::to_string_pretty(&file)
            .expect("Failed to serialize config to TOML");
        std::fs::write(path, &toml_string)
            .unwrap_or_else(|e| panic!("Failed to write config file {}: {}", path, e));

        // Convert to AppConfig
        Self {
            host: file.host,
            port: file.port,
            database_url: file.database_url,
            database_replica_url: file.database_replica_url,
            db_max_connections: file.db_max_connections,
            redis_url: file.redis_url,
            jwt_secret: file.jwt_secret,
            jwt_expiry_hours: file.jwt_expiry_hours,
            refresh_token_expiry_days: file.refresh_token_expiry_days,
            storage_backend: file.storage_backend,
            storage_dir: file.storage_dir,
            storage_encryption_key: file.storage_encryption_key,
            s3_endpoint: file.s3_endpoint,
            s3_bucket: file.s3_bucket,
            s3_access_key: file.s3_access_key,
            s3_secret_key: file.s3_secret_key,
            s3_region: file.s3_region,
            cors_origins: file.cors_origins,
            max_requests_per_minute: file.max_requests_per_minute,
            max_ws_connections_per_user: file.max_ws_connections_per_user,
            broadcast_channel_capacity: file.broadcast_channel_capacity,
            ws_heartbeat_timeout_secs: file.ws_heartbeat_timeout_secs,
            ws_session_buffer_size: file.ws_session_buffer_size,
            ws_session_ttl_secs: file.ws_session_ttl_secs,
            max_upload_size_bytes: file.max_upload_size_bytes,
            cdn_enabled: file.cdn_enabled,
            cdn_base_url: file.cdn_base_url,
            cdn_presign_expiry_secs: file.cdn_presign_expiry_secs,
            livekit_url: file.livekit_url,
            livekit_client_url: file.livekit_client_url,
            livekit_api_key: file.livekit_api_key,
            livekit_api_secret: file.livekit_api_secret,
            livekit_bundled: file.livekit_bundled,
            livekit_port: file.livekit_port,
            tls_enabled: file.tls.enabled,
            tls_port: file.tls.port,
            tls_cert_path: file.tls.cert_path,
            tls_key_path: file.tls.key_path,
            tls_auto_generate: file.tls.auto_generate,

            audit_log_retention_days: file.audit_log_retention_days,
            resolved_report_retention_days: file.resolved_report_retention_days,
            expired_invite_cleanup: file.expired_invite_cleanup,

            registration_invite_only: file.registration_invite_only,
            registration_invites_per_user: file.registration_invites_per_user,

            giphy_api_key: file.giphy_api_key,

            turnstile_site_key: file.turnstile_site_key,
            turnstile_secret_key: file.turnstile_secret_key,

            smtp_host: file.smtp_host,
            smtp_port: file.smtp_port,
            smtp_username: file.smtp_username,
            smtp_password: file.smtp_password,
            smtp_from: file.smtp_from,

            beta_code_limit: file.beta_code_limit,
            beta_code_expiry_days: file.beta_code_expiry_days,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_has_sensible_values() {
        let config = AppConfig::test_default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 0);
        assert_eq!(config.db_max_connections, 5);
        assert_eq!(config.jwt_expiry_hours, 24);
        assert_eq!(config.refresh_token_expiry_days, 30);
        assert_eq!(config.storage_backend, "local");
        assert_eq!(config.cors_origins, "*");
        assert_eq!(config.max_ws_connections_per_user, 10);
        assert_eq!(config.broadcast_channel_capacity, 4096);
        assert!(!config.cdn_enabled);
    }

    #[test]
    fn livekit_enabled_when_all_set() {
        let mut config = AppConfig::test_default();
        config.livekit_url = "wss://lk.example.com".into();
        config.livekit_api_key = "key".into();
        config.livekit_api_secret = "secret".into();
        assert!(config.livekit_enabled());
    }

    #[test]
    fn livekit_disabled_when_url_empty() {
        let mut config = AppConfig::test_default();
        config.livekit_url = String::new();
        config.livekit_api_key = "key".into();
        config.livekit_api_secret = "secret".into();
        assert!(!config.livekit_enabled());
    }

    #[test]
    fn livekit_disabled_when_key_empty() {
        let mut config = AppConfig::test_default();
        config.livekit_url = "wss://lk.example.com".into();
        config.livekit_api_key = String::new();
        config.livekit_api_secret = "secret".into();
        assert!(!config.livekit_enabled());
    }

    #[test]
    fn livekit_disabled_when_secret_empty() {
        let mut config = AppConfig::test_default();
        config.livekit_url = "wss://lk.example.com".into();
        config.livekit_api_key = "key".into();
        config.livekit_api_secret = String::new();
        assert!(!config.livekit_enabled());
    }

    #[test]
    fn livekit_disabled_by_default() {
        let config = AppConfig::test_default();
        assert!(!config.livekit_enabled());
    }

    #[test]
    fn config_roundtrip_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_haven.toml");
        let path_str = path.to_str().unwrap();

        // Generate config
        let config = AppConfig::generate_default_config(path_str);
        assert!(!config.jwt_secret.is_empty());
        assert_eq!(config.jwt_secret.len(), 64);
        assert!(!config.storage_encryption_key.is_empty());
        assert_eq!(config.storage_encryption_key.len(), 64);

        // Re-read it
        let config2 = AppConfig::from_toml_file(path_str);
        assert_eq!(config.jwt_secret, config2.jwt_secret);
        assert_eq!(config.storage_encryption_key, config2.storage_encryption_key);
        assert_eq!(config.host, config2.host);
        assert_eq!(config.port, config2.port);
    }
}
