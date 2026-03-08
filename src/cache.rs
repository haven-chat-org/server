use std::time::{Duration, Instant};

use redis::AsyncCommands;
use serde::{de::DeserializeOwned, Serialize};

use crate::memory_store::MemoryStore;

/// Try to get a cached value. Checks Redis if available, otherwise uses in-memory store.
pub async fn get_cached<T: DeserializeOwned>(
    redis: Option<&mut redis::aio::ConnectionManager>,
    memory: &MemoryStore,
    key: &str,
) -> Option<T> {
    if let Some(redis) = redis {
        let data: Option<String> = redis.get(key).await.ok()?;
        return data.and_then(|s| serde_json::from_str(&s).ok());
    }

    // In-memory fallback
    let entry = memory.cache.get(key)?;
    let (json, expiry) = entry.value();
    if *expiry < Instant::now() {
        drop(entry);
        memory.cache.remove(key);
        return None;
    }
    serde_json::from_str(json).ok()
}

/// Store a value with a TTL. Uses Redis if available, always writes to in-memory store.
pub async fn set_cached<T: Serialize>(
    redis: Option<&mut redis::aio::ConnectionManager>,
    memory: &MemoryStore,
    key: &str,
    value: &T,
    ttl_secs: u64,
) {
    if let Ok(json) = serde_json::to_string(value) {
        if let Some(redis) = redis {
            let _: Result<(), _> = redis.set_ex(key, &json, ttl_secs).await;
        }
        // Always write to memory store for fast local access
        let expiry = Instant::now() + Duration::from_secs(ttl_secs);
        memory.cache.insert(key.to_string(), (json, expiry));
    }
}

/// Delete a cached key from both Redis and in-memory store.
pub async fn invalidate(
    redis: Option<&mut redis::aio::ConnectionManager>,
    memory: &MemoryStore,
    key: &str,
) {
    if let Some(redis) = redis {
        let _: Result<(), _> = redis.del(key).await;
    }
    memory.cache.remove(key);
}

/// Delete all keys matching a pattern. Uses Redis SCAN cursor loop if
/// available, and also scans in-memory store.
pub async fn invalidate_pattern(
    redis: Option<&mut redis::aio::ConnectionManager>,
    memory: &MemoryStore,
    pattern: &str,
) {
    if let Some(redis) = redis {
        let mut cursor: u64 = 0;
        loop {
            let result: Result<(u64, Vec<String>), _> = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(redis)
                .await;

            match result {
                Ok((next_cursor, keys)) => {
                    if !keys.is_empty() {
                        let _: Result<(), _> =
                            redis::cmd("DEL").arg(&keys).query_async(redis).await;
                    }
                    cursor = next_cursor;
                    if cursor == 0 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }

    // In-memory: convert glob pattern to prefix match (patterns are always "haven:something:*")
    if let Some(prefix) = pattern.strip_suffix('*') {
        memory.cache.retain(|k, _| !k.starts_with(prefix));
    }
}

// ─── Ban Status Cache ────────────────────────────────

use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

/// In-memory cache for instance ban status. Avoids a DB query on every
/// authenticated request. TTL ensures staleness is bounded to 60 seconds.
#[derive(Clone)]
pub struct BanCache {
    cache: Arc<DashMap<Uuid, (bool, Instant)>>,
    ttl: Duration,
}

impl BanCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Returns cached ban status, or None if not cached or expired.
    pub fn get(&self, user_id: &Uuid) -> Option<bool> {
        let entry = self.cache.get(user_id)?;
        let (banned, inserted) = entry.value();
        if inserted.elapsed() > self.ttl {
            drop(entry);
            self.cache.remove(user_id);
            return None;
        }
        Some(*banned)
    }

    /// Set ban status for a user (called on ban action for immediate consistency).
    pub fn set(&self, user_id: Uuid, banned: bool) {
        self.cache.insert(user_id, (banned, Instant::now()));
    }

    /// Remove cached entry (called on unban so next check falls through to DB).
    pub fn invalidate(&self, user_id: &Uuid) {
        self.cache.remove(user_id);
    }
}
