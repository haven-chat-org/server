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

/// Delete all keys matching a pattern. Uses Redis KEYS+DEL if available,
/// and also scans in-memory store.
pub async fn invalidate_pattern(
    redis: Option<&mut redis::aio::ConnectionManager>,
    memory: &MemoryStore,
    pattern: &str,
) {
    if let Some(redis) = redis {
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(pattern)
            .query_async(redis)
            .await
            .unwrap_or_default();
        if !keys.is_empty() {
            let _: Result<(), _> = redis::cmd("DEL")
                .arg(&keys)
                .query_async(redis)
                .await;
        }
    }

    // In-memory: convert glob pattern to prefix match (patterns are always "haven:something:*")
    if let Some(prefix) = pattern.strip_suffix('*') {
        memory.cache.retain(|k, _| !k.starts_with(prefix));
    }
}
