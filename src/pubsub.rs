use std::collections::HashSet;
use std::sync::Arc;

use futures::StreamExt;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::models::WsServerMessage;
use crate::AppState;

/// Publish a channel-scoped WS event via Redis for cross-instance delivery.
/// No-op if Redis is not configured (single-instance mode uses local broadcasts).
pub async fn publish_channel_event(
    redis: Option<&mut redis::aio::ConnectionManager>,
    channel_id: Uuid,
    msg: &WsServerMessage,
) {
    let Some(redis) = redis else { return };
    let channel = format!("haven:ws:ch:{}", channel_id);
    if let Ok(payload) = serde_json::to_string(msg) {
        let _: Result<(), _> = redis::cmd("PUBLISH")
            .arg(&channel)
            .arg(&payload)
            .query_async(redis)
            .await;
    }
}

/// Publish a user-directed WS event via Redis for cross-instance delivery.
/// No-op if Redis is not configured.
pub async fn publish_user_event(
    redis: Option<&mut redis::aio::ConnectionManager>,
    user_id: Uuid,
    msg: &WsServerMessage,
) {
    let Some(redis) = redis else { return };
    let channel = format!("haven:ws:user:{}", user_id);
    if let Ok(payload) = serde_json::to_string(msg) {
        let _: Result<(), _> = redis::cmd("PUBLISH")
            .arg(&channel)
            .arg(&payload)
            .query_async(redis)
            .await;
    }
}

/// Tracks which Redis channels this instance is subscribed to.
pub type PubSubSubscriptions = Arc<Mutex<HashSet<String>>>;

/// Create an empty subscriptions set (used for initial AppState construction).
pub fn empty_subscriptions() -> PubSubSubscriptions {
    Arc::new(Mutex::new(HashSet::new()))
}

/// Start the Redis subscriber background task.
/// Returns empty subscriptions immediately if Redis is not configured.
pub fn start_subscriber(state: AppState) -> PubSubSubscriptions {
    let subscriptions: PubSubSubscriptions = Arc::new(Mutex::new(HashSet::new()));

    // No Redis → no pub/sub subscriber needed (single-instance mode)
    let Some(_) = &state.redis else {
        tracing::info!("Redis not configured — pub/sub disabled (single-instance mode)");
        return subscriptions;
    };

    let subs_clone = subscriptions.clone();

    tokio::spawn(async move {
        // Create a dedicated Redis client for pub/sub (can't reuse ConnectionManager)
        let client = match redis::Client::open(state.config.redis_url.as_str()) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to create Redis pub/sub client: {}", e);
                return;
            }
        };

        loop {
            match client.get_async_pubsub().await {
                Ok(mut pubsub) => {
                    tracing::info!("Redis pub/sub subscriber connected");

                    // Re-subscribe to all tracked channels on reconnect
                    {
                        let subs = subs_clone.lock().await;
                        for channel in subs.iter() {
                            if let Err(e) = pubsub.subscribe(channel).await {
                                tracing::error!("Failed to resubscribe to {}: {}", channel, e);
                            }
                        }
                    }

                    // Process incoming messages
                    let mut msg_stream = pubsub.on_message();
                    while let Some(msg) = msg_stream.next().await {
                        let payload: String = match msg.get_payload() {
                            Ok(p) => p,
                            Err(_) => continue,
                        };

                        let ws_msg: WsServerMessage = match serde_json::from_str(&payload) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };

                        let redis_channel: String = msg.get_channel_name().to_string();

                        if let Some(channel_id_str) = redis_channel.strip_prefix("haven:ws:ch:") {
                            // Channel-scoped event — forward to local broadcast
                            if let Ok(channel_id) = Uuid::parse_str(channel_id_str) {
                                if let Some(broadcaster) = state.channel_broadcasts.get(&channel_id) {
                                    let _ = broadcaster.send(ws_msg);
                                }
                            }
                        } else if let Some(user_id_str) = redis_channel.strip_prefix("haven:ws:user:") {
                            // User-directed event — forward to user's connections
                            if let Ok(user_id) = Uuid::parse_str(user_id_str) {
                                if let Some(conns) = state.connections.get(&user_id) {
                                    for tx in conns.iter() {
                                        let _ = tx.send(ws_msg.clone());
                                    }
                                }
                            }
                        }
                    }
                    tracing::warn!("Redis pub/sub stream ended, reconnecting...");
                }
                Err(e) => {
                    tracing::error!("Failed to connect Redis pub/sub: {}, retrying in 5s", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    });

    subscriptions
}

/// Subscribe this instance to a Redis channel (called when a local user subscribes).
/// No-op if Redis is not configured.
pub async fn subscribe_redis_channel(
    state: &AppState,
    channel_id: Uuid,
) {
    if state.redis.is_none() { return; }
    let channel = format!("haven:ws:ch:{}", channel_id);
    let mut subs = state.pubsub_subscriptions.lock().await;
    if subs.insert(channel.clone()) {
        tracing::debug!("Tracked Redis subscription: {}", channel);
    }
}

/// Subscribe this instance to a user's Redis channel (called on WS connect).
/// No-op if Redis is not configured.
pub async fn subscribe_redis_user(
    state: &AppState,
    user_id: Uuid,
) {
    if state.redis.is_none() { return; }
    let channel = format!("haven:ws:user:{}", user_id);
    let mut subs = state.pubsub_subscriptions.lock().await;
    if subs.insert(channel.clone()) {
        tracing::debug!("Tracked Redis user subscription: {}", channel);
    }
}

/// Unsubscribe from a user's Redis channel (called on WS disconnect).
/// No-op if Redis is not configured.
pub async fn unsubscribe_redis_user(
    state: &AppState,
    user_id: Uuid,
) {
    if state.redis.is_none() { return; }
    // Only unsubscribe if no local connections remain
    if state.connections.get(&user_id).is_some() {
        return;
    }
    let channel = format!("haven:ws:user:{}", user_id);
    let mut subs = state.pubsub_subscriptions.lock().await;
    subs.remove(&channel);
}
