use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{ConnectInfo, Request},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Hash an IP address so we never store raw IPs in memory.
/// Uses HMAC-SHA256 with a per-instance random key generated at startup.
fn hash_ip(ip: IpAddr, key: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(ip.to_string().as_bytes());
    mac.finalize().into_bytes().into()
}

/// Per-IP rate limiter using a sliding window counter.
/// IP addresses are HMAC-hashed before storage — raw IPs are never retained.
#[derive(Clone)]
pub struct RateLimiter {
    /// hashed_ip -> (request count, window start)
    state: Arc<DashMap<[u8; 32], (u32, Instant)>>,
    max_requests: u32,
    window_secs: u64,
    /// Random key for HMAC — generated once at creation, never persisted.
    ip_hash_key: Arc<[u8; 32]>,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        let mut key = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut key);
        Self {
            state: Arc::new(DashMap::new()),
            max_requests,
            window_secs,
            ip_hash_key: Arc::new(key),
        }
    }

    /// Returns true if the request should be allowed.
    pub fn check(&self, ip: IpAddr) -> bool {
        let hashed = hash_ip(ip, &*self.ip_hash_key);
        let now = Instant::now();
        let mut entry = self.state.entry(hashed).or_insert((0, now));
        let (count, window_start) = entry.value_mut();

        // Reset window if expired
        if now.duration_since(*window_start).as_secs() >= self.window_secs {
            *count = 0;
            *window_start = now;
        }

        *count += 1;
        *count <= self.max_requests
    }

    /// Periodic cleanup of expired entries to prevent unbounded growth.
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.state.retain(|_, (_, window_start)| {
            now.duration_since(*window_start).as_secs() < self.window_secs * 2
        });
    }
}

/// Per-user rate limiter keyed by user UUID (for authenticated endpoints).
#[derive(Clone)]
pub struct UserRateLimiter {
    state: Arc<DashMap<Uuid, (u32, Instant)>>,
    max_requests: u32,
    window_secs: u64,
}

impl UserRateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            state: Arc::new(DashMap::new()),
            max_requests,
            window_secs,
        }
    }

    /// Returns true if the request should be allowed for this user.
    pub fn check(&self, user_id: Uuid) -> bool {
        let now = Instant::now();
        let mut entry = self.state.entry(user_id).or_insert((0, now));
        let (count, window_start) = entry.value_mut();

        if now.duration_since(*window_start).as_secs() >= self.window_secs {
            *count = 0;
            *window_start = now;
        }

        *count += 1;
        *count <= self.max_requests
    }

    pub fn cleanup(&self) {
        let now = Instant::now();
        self.state.retain(|_, (_, window_start)| {
            now.duration_since(*window_start).as_secs() < self.window_secs * 2
        });
    }
}

/// Extract the client IP from the request (ConnectInfo or X-Forwarded-For).
pub fn extract_ip(req: &Request) -> IpAddr {
    req.extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
        .or_else(|| {
            req.headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .and_then(|s| s.trim().parse().ok())
        })
        .unwrap_or(IpAddr::from([127, 0, 0, 1]))
}

/// Middleware that enforces rate limits. Returns 429 if limit exceeded.
pub async fn rate_limit_middleware(
    rate_limiter: RateLimiter,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let ip = extract_ip(&req);

    if !rate_limiter.check(ip) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(req).await)
}

/// Spawn a background task that cleans up stale rate limit entries every 5 minutes.
pub fn spawn_rate_limit_cleanup(limiter: RateLimiter) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            limiter.cleanup();
        }
    });
}

/// Spawn cleanup for user rate limiter.
pub fn spawn_user_rate_limit_cleanup(limiter: UserRateLimiter) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            limiter.cleanup();
        }
    });
}
