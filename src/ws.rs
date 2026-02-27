use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::auth::{validate_access_token, user_id_from_claims};
use crate::db::queries;
use crate::errors::AppError;
use crate::memory_store::{ActiveCall, ConnectedCall};
use crate::models::{MessageResponse, WsClientMessage, WsServerMessage};
use crate::pubsub;
use crate::AppState;

/// Tracks all connected clients. Maps user_id -> list of sender channels.
/// Each user can have multiple connections (multi-device).
pub type ConnectionMap = Arc<DashMap<Uuid, Vec<mpsc::UnboundedSender<WsServerMessage>>>>;

/// Tracks channel subscriptions. Maps channel_id -> broadcast sender.
pub type ChannelBroadcastMap = Arc<DashMap<Uuid, broadcast::Sender<WsServerMessage>>>;

/// Represents a WebSocket session that can survive brief disconnections.
pub struct WsSession {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub event_buffer: tokio::sync::Mutex<VecDeque<WsServerMessage>>,
    pub buffer_capacity: usize,
    pub created_at: Instant,
    pub last_active: tokio::sync::Mutex<Instant>,
    pub subscribed_channels: tokio::sync::Mutex<HashSet<Uuid>>,
}

/// Maps session_id -> Session for resume support.
pub type SessionMap = Arc<DashMap<Uuid, Arc<WsSession>>>;

/// Query params for WebSocket upgrade — token passed as query param
/// since WebSocket doesn't support custom headers in browsers.
#[derive(Debug, Deserialize)]
pub struct WsAuthQuery {
    pub token: String,
}

/// WebSocket upgrade handler.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(auth): Query<WsAuthQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    // Authenticate before upgrading
    let claims = validate_access_token(&auth.token, &state.config)?;
    let user_id = user_id_from_claims(&claims)?;

    // Check connection limit
    let conn_count = state
        .connections
        .get(&user_id)
        .map(|v| v.len())
        .unwrap_or(0);

    if conn_count >= state.config.max_ws_connections_per_user as usize {
        return Err(AppError::BadRequest(format!(
            "Maximum {} connections per user exceeded",
            state.config.max_ws_connections_per_user
        )));
    }

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, user_id, state)))
}

/// Handles an individual WebSocket connection.
async fn handle_socket(socket: WebSocket, user_id: Uuid, state: AppState) {
    let (mut ws_sink, mut ws_stream) = socket.split();

    // Create a channel for sending messages to this specific connection
    let (tx, mut rx) = mpsc::unbounded_channel::<WsServerMessage>();

    // Track subscription tasks so we can cancel them on disconnect/unsubscribe
    let subscriptions: Arc<tokio::sync::Mutex<HashMap<Uuid, JoinHandle<()>>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    // --- Session management ---
    let session_id = Uuid::new_v4();
    let buffer_capacity = state.config.ws_session_buffer_size;
    let session = Arc::new(WsSession {
        session_id,
        user_id,
        event_buffer: tokio::sync::Mutex::new(VecDeque::with_capacity(buffer_capacity)),
        buffer_capacity,
        created_at: Instant::now(),
        last_active: tokio::sync::Mutex::new(Instant::now()),
        subscribed_channels: tokio::sync::Mutex::new(HashSet::new()),
    });
    state.sessions.insert(session_id, session.clone());

    // Register this connection
    state
        .connections
        .entry(user_id)
        .or_default()
        .push(tx.clone());

    tracing::info!("WebSocket connected: user={}, session={}", user_id, session_id);

    // Send Hello immediately
    let hello = WsServerMessage::Hello {
        session_id,
        heartbeat_interval_ms: (state.config.ws_heartbeat_timeout_secs * 1000) / 3,
    };
    let _ = tx.send(hello);

    // Track this user in Redis pub/sub for cross-instance delivery
    pubsub::subscribe_redis_user(&state, user_id).await;

    // Always broadcast online — handles reconnect-before-disconnect race on page refresh
    broadcast_presence(user_id, "online", &state).await;

    // Task: forward messages from our channel to the WebSocket sink,
    // and buffer events in the session for resume support.
    let session_for_send = session.clone();
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            // Buffer the event for resume (skip Hello/Resumed/InvalidSession/Pong)
            if should_buffer_event(&msg) {
                let mut buf = session_for_send.event_buffer.lock().await;
                if buf.len() >= session_for_send.buffer_capacity {
                    buf.pop_front();
                }
                buf.push_back(msg.clone());
            }

            let text = match serde_json::to_string(&msg) {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!("Failed to serialize WS message: {}", e);
                    continue;
                }
            };
            if ws_sink.send(Message::Text(text)).await.is_err() {
                break;
            }
        }
    });

    // Task: read messages from the WebSocket and process them, with heartbeat timeout.
    let heartbeat_timeout = Duration::from_secs(state.config.ws_heartbeat_timeout_secs);
    let state_clone = state.clone();
    let tx_clone = tx.clone();
    let subs_clone = subscriptions.clone();
    let session_for_recv = session.clone();
    let recv_task = tokio::spawn(async move {
        loop {
            match tokio::time::timeout(heartbeat_timeout, ws_stream.next()).await {
                Ok(Some(Ok(msg))) => {
                    // Update session last_active on any message
                    *session_for_recv.last_active.lock().await = Instant::now();
                    match msg {
                        Message::Text(text) => {
                            handle_client_message(&text, user_id, &state_clone, &tx_clone, &subs_clone).await;
                        }
                        Message::Close(_) => break,
                        Message::Ping(_) => {} // axum auto-responds with pong
                        _ => {}
                    }
                }
                Ok(Some(Err(_))) => break, // WebSocket error
                Ok(None) => break,         // Stream ended
                Err(_) => {
                    // Heartbeat timeout — client is dead
                    tracing::info!("WebSocket heartbeat timeout: user={}, session={}", user_id, session_id);
                    break;
                }
            }
        }
    });

    // Wait for either task to finish (connection closed)
    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    // Snapshot subscribed channels into the session for resume
    {
        let subs = subscriptions.lock().await;
        let mut session_subs = session.subscribed_channels.lock().await;
        *session_subs = subs.keys().copied().collect();
    }

    // Cleanup: abort all subscription tasks and prune empty broadcasts
    let subscribed_channels: Vec<Uuid> = {
        let mut subs = subscriptions.lock().await;
        let channel_ids: Vec<Uuid> = subs.keys().copied().collect();
        for (_, handle) in subs.drain() {
            handle.abort();
        }
        channel_ids
    };

    // Remove broadcast entries that have no remaining subscribers
    for channel_id in subscribed_channels {
        state.channel_broadcasts.remove_if(&channel_id, |_, tx| tx.receiver_count() == 0);
    }

    // Cleanup: remove this connection
    let was_last_connection = {
        let mut is_last = false;
        if let Some(mut conns) = state.connections.get_mut(&user_id) {
            conns.retain(|sender| !sender.is_closed());
            if conns.is_empty() {
                is_last = true;
                drop(conns);
                state.connections.remove(&user_id);
            }
        }
        is_last
    };

    if was_last_connection {
        broadcast_presence(user_id, "offline", &state).await;
        // Clean up voice state — remove from any voice channel
        crate::api::voice::cleanup_voice_state(&state, user_id).await;
        // Clean up any active calls this user initiated
        cleanup_call_state(&state, user_id).await;
        // Unsubscribe from Redis user channel
        pubsub::unsubscribe_redis_user(&state, user_id).await;
    }

    tracing::info!("WebSocket disconnected: user={}, session={}", user_id, session_id);
}

/// Returns true if this event type should be buffered for resume support.
/// Transient control messages (Hello, Pong, Resumed, InvalidSession) are not buffered.
fn should_buffer_event(msg: &WsServerMessage) -> bool {
    !matches!(
        msg,
        WsServerMessage::Hello { .. }
            | WsServerMessage::Pong
            | WsServerMessage::Resumed { .. }
            | WsServerMessage::InvalidSession
            | WsServerMessage::Subscribed { .. }
            | WsServerMessage::Error { .. }
            | WsServerMessage::CallRinging { .. }
    )
}

/// Process an incoming client message.
async fn handle_client_message(
    text: &str,
    user_id: Uuid,
    state: &AppState,
    reply_tx: &mpsc::UnboundedSender<WsServerMessage>,
    subscriptions: &Arc<tokio::sync::Mutex<HashMap<Uuid, JoinHandle<()>>>>,
) {
    let client_msg: WsClientMessage = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(e) => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: format!("Invalid message format: {}", e),
            });
            return;
        }
    };

    match client_msg {
        WsClientMessage::SendMessage {
            channel_id,
            sender_token,
            encrypted_body,
            expires_at,
            attachment_ids,
            reply_to_id,
        } => {
            // Per-user rate limit on message sending
            if !state.ws_rate_limiter.check(user_id) {
                let _ = reply_tx.send(WsServerMessage::Error {
                    message: "Rate limit exceeded — slow down".into(),
                });
                return;
            }
            handle_send_message(
                user_id,
                channel_id,
                &sender_token,
                &encrypted_body,
                expires_at,
                attachment_ids,
                reply_to_id,
                state,
                reply_tx,
            )
            .await;
        }

        WsClientMessage::EditMessage {
            message_id,
            encrypted_body,
        } => {
            handle_edit_message(
                user_id,
                message_id,
                &encrypted_body,
                state,
                reply_tx,
            )
            .await;
        }

        WsClientMessage::Subscribe { channel_id } => {
            handle_subscribe(user_id, channel_id, state, reply_tx, subscriptions).await;
        }

        WsClientMessage::Unsubscribe { channel_id } => {
            handle_unsubscribe(channel_id, subscriptions).await;
        }

        WsClientMessage::DeleteMessage { message_id } => {
            handle_delete_message(user_id, message_id, state, reply_tx).await;
        }

        WsClientMessage::AddReaction { message_id, emoji } => {
            handle_add_reaction(user_id, message_id, &emoji, state, reply_tx).await;
        }

        WsClientMessage::RemoveReaction { message_id, emoji } => {
            handle_remove_reaction(user_id, message_id, &emoji, state, reply_tx).await;
        }

        WsClientMessage::SetStatus { status } => {
            handle_set_status(user_id, &status, state, reply_tx).await;
        }

        WsClientMessage::Typing { channel_id } => {
            handle_typing(user_id, channel_id, state).await;
        }

        WsClientMessage::PinMessage { channel_id, message_id } => {
            handle_pin_message(user_id, channel_id, message_id, state, reply_tx).await;
        }

        WsClientMessage::UnpinMessage { channel_id, message_id } => {
            handle_unpin_message(user_id, channel_id, message_id, state, reply_tx).await;
        }

        WsClientMessage::MarkRead { channel_id } => {
            handle_mark_read(user_id, channel_id, state, reply_tx).await;
        }

        WsClientMessage::CallInvite { channel_id } => {
            handle_call_invite(user_id, channel_id, state, reply_tx).await;
        }

        WsClientMessage::CallAccept { channel_id } => {
            handle_call_accept(user_id, channel_id, state, reply_tx).await;
        }

        WsClientMessage::CallReject { channel_id } => {
            handle_call_reject(user_id, channel_id, state, reply_tx).await;
        }

        WsClientMessage::CallEnd { channel_id } => {
            handle_call_end(user_id, channel_id, state).await;
        }

        WsClientMessage::Resume { session_id } => {
            handle_resume(session_id, user_id, state, reply_tx).await;
        }

        WsClientMessage::Ping => {
            let _ = reply_tx.send(WsServerMessage::Pong);
            // Refresh presence on each ping to handle stale entries
            if let Some(mut redis) = state.redis.clone() {
                let current: Option<String> = redis::cmd("HGET")
                    .arg("haven:presence")
                    .arg(user_id.to_string())
                    .query_async(&mut redis)
                    .await
                    .unwrap_or(None);
                if let Some(status) = current {
                    let _: Result<(), _> = redis::cmd("HSET")
                        .arg("haven:presence")
                        .arg(user_id.to_string())
                        .arg(status)
                        .query_async(&mut redis)
                        .await;
                }
            }
            // In-memory presence is always kept up-to-date via broadcast_presence
        }
    }
}

/// Handle a MarkRead command: update read state and sync across devices.
async fn handle_mark_read(
    user_id: Uuid,
    channel_id: Uuid,
    state: &AppState,
    reply_tx: &mpsc::UnboundedSender<WsServerMessage>,
) {
    // Verify channel access
    match queries::can_access_channel(state.db.read(), channel_id, user_id).await {
        Ok(true) => {}
        _ => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: "Cannot access this channel".into(),
            });
            return;
        }
    }

    // Upsert read state
    match queries::upsert_read_state(state.db.write(), user_id, channel_id).await {
        Ok(read_state) => {
            // Broadcast to other connections of the same user (multi-device sync)
            let sync_msg = WsServerMessage::ReadStateUpdated {
                channel_id,
                last_read_at: read_state.last_read_at,
            };
            if let Some(conns) = state.connections.get(&user_id) {
                for conn in conns.iter() {
                    // Send to all connections (including this one for confirmation)
                    let _ = conn.send(sync_msg.clone());
                }
            }
            pubsub::publish_user_event(state.redis.clone().as_mut(), user_id, &sync_msg).await;
        }
        Err(e) => {
            tracing::warn!("Failed to upsert read state: {}", e);
        }
    }
}

/// Handle a Resume command: replay buffered events from a previous session.
async fn handle_resume(
    session_id: Uuid,
    user_id: Uuid,
    state: &AppState,
    reply_tx: &mpsc::UnboundedSender<WsServerMessage>,
) {
    let session = match state.sessions.get(&session_id) {
        Some(s) => s.clone(),
        None => {
            let _ = reply_tx.send(WsServerMessage::InvalidSession);
            return;
        }
    };

    // Verify session belongs to this user
    if session.user_id != user_id {
        let _ = reply_tx.send(WsServerMessage::InvalidSession);
        return;
    }

    // Check if session has expired
    let ttl = Duration::from_secs(state.config.ws_session_ttl_secs);
    if session.last_active.lock().await.elapsed() > ttl {
        state.sessions.remove(&session_id);
        let _ = reply_tx.send(WsServerMessage::InvalidSession);
        return;
    }

    // Replay buffered events
    let events: Vec<WsServerMessage> = {
        let mut buf = session.event_buffer.lock().await;
        buf.drain(..).collect()
    };
    let replayed_count = events.len() as u32;

    for event in events {
        let _ = reply_tx.send(event);
    }

    // Update last_active
    *session.last_active.lock().await = Instant::now();

    let _ = reply_tx.send(WsServerMessage::Resumed { replayed_count });
    tracing::info!(
        "WebSocket session resumed: user={}, session={}, replayed={}",
        user_id, session_id, replayed_count
    );
}

/// Handle a SendMessage command: persist and fan out.
#[allow(clippy::too_many_arguments)]
async fn handle_send_message(
    user_id: Uuid,
    channel_id: Uuid,
    sender_token: &str,
    encrypted_body: &str,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    attachment_ids: Option<Vec<Uuid>>,
    reply_to_id: Option<Uuid>,
    state: &AppState,
    reply_tx: &mpsc::UnboundedSender<WsServerMessage>,
) {
    // Verify user can access the channel (channel member or server member)
    match queries::can_access_channel(state.db.read(), channel_id, user_id).await {
        Ok(true) => {}
        Ok(false) => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: "Not a member of this channel".into(),
            });
            return;
        }
        Err(e) => {
            tracing::error!("DB error checking channel access: {}", e);
            let _ = reply_tx.send(WsServerMessage::Error {
                message: "Internal error".into(),
            });
            return;
        }
    }

    // Check if member is timed out (server channels only)
    if let Ok(Some(channel)) = queries::find_channel_by_id(state.db.read(), channel_id).await {
        if let Some(server_id) = channel.server_id {
            if queries::is_member_timed_out(state.db.read(), server_id, user_id)
                .await
                .unwrap_or(false)
            {
                let _ = reply_tx.send(WsServerMessage::Error {
                    message: "You are timed out in this server".into(),
                });
                return;
            }
        }
    }

    // Decode base64 payloads
    let sender_token_bytes = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        sender_token,
    ) {
        Ok(b) => b,
        Err(_) => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: "Invalid sender_token encoding".into(),
            });
            return;
        }
    };

    let encrypted_body_bytes = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        encrypted_body,
    ) {
        Ok(b) => b,
        Err(_) => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: "Invalid encrypted_body encoding".into(),
            });
            return;
        }
    };

    // Reject messages that are too large (roughly 4000 chars + E2EE overhead)
    if encrypted_body_bytes.len() > 8192 {
        let _ = reply_tx.send(WsServerMessage::Error {
            message: "Message too large".into(),
        });
        return;
    }

    let has_attachments = attachment_ids.as_ref().is_some_and(|ids| !ids.is_empty());

    // Persist message
    let message = match queries::insert_message(
        state.db.write(),
        channel_id,
        &sender_token_bytes,
        &encrypted_body_bytes,
        expires_at,
        has_attachments,
        user_id,
        reply_to_id,
    )
    .await
    {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("Failed to persist message: {}", e);
            let _ = reply_tx.send(WsServerMessage::Error {
                message: "Failed to save message".into(),
            });
            return;
        }
    };

    // Link attachments to the message
    if let Some(ids) = attachment_ids {
        for att_id in ids {
            let storage_key = crate::storage::obfuscated_key(&state.storage_key, &att_id.to_string());
            if let Err(e) = queries::link_attachment(state.db.write(), att_id, message.id, &storage_key).await {
                tracing::error!("Failed to link attachment {}: {}", att_id, e);
            }
        }
    }

    let msg_response: MessageResponse = message.into();

    // Send ACK to sender
    let _ = reply_tx.send(WsServerMessage::MessageAck {
        message_id: msg_response.id,
    });

    // Fan out to all channel subscribers via broadcast
    let new_msg = WsServerMessage::NewMessage(msg_response);
    if let Some(broadcaster) = state.channel_broadcasts.get(&channel_id) {
        let _ = broadcaster.send(new_msg.clone());
    }
    // Publish to Redis for cross-instance delivery
    pubsub::publish_channel_event(state.redis.clone().as_mut(), channel_id, &new_msg).await;

    // For DM/group channels, also deliver directly to all member connections.
    // Members may not have subscribed to the channel broadcast yet (e.g., new DM
    // from someone they haven't messaged before). Client deduplicates by message ID.
    if let Ok(Some(channel)) = queries::find_channel_by_id(state.db.read(), channel_id).await {
        if channel.channel_type == "dm" || channel.channel_type == "group" {
            // Un-hide the channel for all members when a new message arrives
            let _ = queries::unhide_channel_for_members(state.db.write(), channel_id).await;
            if let Ok(member_ids) = queries::get_channel_member_ids(state.db.read(), channel_id).await {
                for member_id in member_ids {
                    if member_id == user_id { continue; } // Skip the sender
                    if let Some(conns) = state.connections.get(&member_id) {
                        for conn in conns.iter() {
                            let _ = conn.send(new_msg.clone());
                        }
                    }
                }
            }
        }
    }
}

/// Handle a Subscribe command: join a channel broadcast group.
async fn handle_subscribe(
    user_id: Uuid,
    channel_id: Uuid,
    state: &AppState,
    reply_tx: &mpsc::UnboundedSender<WsServerMessage>,
    subscriptions: &Arc<tokio::sync::Mutex<HashMap<Uuid, JoinHandle<()>>>>,
) {
    // Verify membership (channel member or server member)
    match queries::can_access_channel(state.db.read(), channel_id, user_id).await {
        Ok(true) => {}
        Ok(false) => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: "Not a member of this channel".into(),
            });
            return;
        }
        Err(_) => return,
    }

    // Cancel existing subscription for this channel (prevents duplicate tasks)
    {
        let mut subs = subscriptions.lock().await;
        if let Some(old_handle) = subs.remove(&channel_id) {
            old_handle.abort();
        }
    }

    // Ensure a broadcast channel exists for this channel
    state
        .channel_broadcasts
        .entry(channel_id)
        .or_insert_with(|| {
            let (tx, _) = broadcast::channel(state.config.broadcast_channel_capacity);
            tx
        });

    // Subscribe this connection to the broadcast
    if let Some(broadcaster) = state.channel_broadcasts.get(&channel_id) {
        let mut rx = broadcaster.subscribe();
        let reply_tx = reply_tx.clone();

        // Spawn a task to forward broadcast messages to this connection
        let handle = tokio::spawn(async move {
            while let Ok(msg) = rx.recv().await {
                if reply_tx.send(msg).is_err() {
                    break;
                }
            }
        });

        subscriptions.lock().await.insert(channel_id, handle);
    }

    // Track in Redis pub/sub for cross-instance delivery
    pubsub::subscribe_redis_channel(state, channel_id).await;

    let _ = reply_tx.send(WsServerMessage::Subscribed { channel_id });
}

/// Handle Unsubscribe — cancel the subscription task for this channel.
async fn handle_unsubscribe(
    channel_id: Uuid,
    subscriptions: &Arc<tokio::sync::Mutex<HashMap<Uuid, JoinHandle<()>>>>,
) {
    let mut subs = subscriptions.lock().await;
    if let Some(handle) = subs.remove(&channel_id) {
        handle.abort();
    }
}

/// Handle a SetStatus command: update presence status.
async fn handle_set_status(
    user_id: Uuid,
    status: &str,
    state: &AppState,
    reply_tx: &mpsc::UnboundedSender<WsServerMessage>,
) {
    let valid_statuses = ["online", "idle", "dnd", "invisible"];
    if !valid_statuses.contains(&status) {
        let _ = reply_tx.send(WsServerMessage::Error {
            message: format!("Invalid status: {}. Valid: online, idle, dnd, invisible", status),
        });
        return;
    }

    // For invisible, we store it in Redis but broadcast as "offline"
    let broadcast_status = if status == "invisible" { "offline" } else { status };

    // Update presence store
    if let Some(mut redis) = state.redis.clone() {
        let _: Result<(), _> = redis::cmd("HSET")
            .arg("haven:presence")
            .arg(user_id.to_string())
            .arg(status)
            .query_async(&mut redis)
            .await;
    }
    state.memory.presence.insert(user_id, status.to_string());

    // Broadcast to all channels this user belongs to
    let channel_ids = match queries::get_user_channel_ids(state.db.read(), user_id).await {
        Ok(ids) => ids,
        Err(_) => return,
    };

    let msg = WsServerMessage::PresenceUpdate {
        user_id,
        status: broadcast_status.to_string(),
    };

    for channel_id in &channel_ids {
        if let Some(broadcaster) = state.channel_broadcasts.get(channel_id) {
            let _ = broadcaster.send(msg.clone());
        }
    }
    for channel_id in channel_ids {
        pubsub::publish_channel_event(state.redis.clone().as_mut(), channel_id, &msg).await;
    }
}

/// Handle typing indicator — ephemeral, no persistence.
async fn handle_typing(user_id: Uuid, channel_id: Uuid, state: &AppState) {
    // Look up username for display (cached)
    let username = match queries::find_user_by_id_cached(state.db.read(), &mut state.redis.clone(), &state.memory, user_id).await {
        Ok(Some(user)) => user.display_name.unwrap_or(user.username),
        _ => return, // Can't resolve user — skip
    };

    let typing_msg = WsServerMessage::UserTyping {
        channel_id,
        user_id,
        username,
    };
    if let Some(broadcaster) = state.channel_broadcasts.get(&channel_id) {
        let _ = broadcaster.send(typing_msg.clone());
    }
    pubsub::publish_channel_event(state.redis.clone().as_mut(), channel_id, &typing_msg).await;
}

/// Handle an EditMessage command: verify ownership, update DB, broadcast.
async fn handle_edit_message(
    user_id: Uuid,
    message_id: Uuid,
    encrypted_body: &str,
    state: &AppState,
    reply_tx: &mpsc::UnboundedSender<WsServerMessage>,
) {
    let encrypted_body_bytes = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        encrypted_body,
    ) {
        Ok(b) => b,
        Err(_) => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: "Invalid encrypted_body encoding".into(),
            });
            return;
        }
    };

    let message = match queries::update_message_body(
        state.db.write(),
        message_id,
        user_id,
        &encrypted_body_bytes,
    )
    .await
    {
        Ok(m) => m,
        Err(e) => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: format!("Failed to edit message: {}", e),
            });
            return;
        }
    };

    let edited_body = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &message.encrypted_body,
    );

    // Broadcast edit to all channel subscribers
    let edit_msg = WsServerMessage::MessageEdited {
        message_id: message.id,
        channel_id: message.channel_id,
        encrypted_body: edited_body,
    };
    if let Some(broadcaster) = state.channel_broadcasts.get(&message.channel_id) {
        let _ = broadcaster.send(edit_msg.clone());
    }
    pubsub::publish_channel_event(state.redis.clone().as_mut(), message.channel_id, &edit_msg).await;
}

/// Handle a DeleteMessage command: verify ownership or server admin, delete from DB, broadcast.
async fn handle_delete_message(
    user_id: Uuid,
    message_id: Uuid,
    state: &AppState,
    reply_tx: &mpsc::UnboundedSender<WsServerMessage>,
) {
    // Try deleting as sender first (fast path)
    let message = match queries::delete_message(state.db.write(), message_id, user_id).await {
        Ok(m) => m,
        Err(_) => {
            // Sender check failed — check if user is the server owner
            let msg = match queries::find_message_by_id(state.db.read(), message_id).await {
                Ok(Some(m)) => m,
                Ok(None) => {
                    let _ = reply_tx.send(WsServerMessage::Error {
                        message: "Message not found".into(),
                    });
                    return;
                }
                Err(e) => {
                    let _ = reply_tx.send(WsServerMessage::Error {
                        message: format!("Failed to find message: {}", e),
                    });
                    return;
                }
            };

            // Get the channel's server_id
            let channel = match queries::find_channel_by_id(state.db.read(), msg.channel_id).await {
                Ok(Some(c)) => c,
                _ => {
                    let _ = reply_tx.send(WsServerMessage::Error {
                        message: "Cannot delete this message".into(),
                    });
                    return;
                }
            };

            // Only server channels have a server_id
            let server_id = match channel.server_id {
                Some(sid) => sid,
                None => {
                    let _ = reply_tx.send(WsServerMessage::Error {
                        message: "Cannot delete this message".into(),
                    });
                    return;
                }
            };

            // Check if user is the server owner or has MANAGE_MESSAGES
            let (is_owner, perms) = match queries::get_member_permissions(state.db.read(), server_id, user_id).await {
                Ok(p) => p,
                _ => {
                    let _ = reply_tx.send(WsServerMessage::Error {
                        message: "Cannot delete this message".into(),
                    });
                    return;
                }
            };
            if !is_owner && !crate::permissions::has_permission(perms, crate::permissions::MANAGE_MESSAGES) {
                let _ = reply_tx.send(WsServerMessage::Error {
                    message: "Cannot delete this message".into(),
                });
                return;
            }

            // User is owner or has MANAGE_MESSAGES — delete unconditionally
            match queries::delete_message_admin(state.db.write(), message_id).await {
                Ok(m) => {
                    // Audit log for moderator delete (not the sender)
                    let _ = queries::insert_audit_log(
                        state.db.write(), server_id, user_id, "message_delete",
                        Some("message"), Some(message_id),
                        Some(&serde_json::json!({ "channel_id": msg.channel_id.to_string() })), None,
                    ).await;
                    m
                }
                Err(e) => {
                    let _ = reply_tx.send(WsServerMessage::Error {
                        message: format!("Failed to delete message: {}", e),
                    });
                    return;
                }
            }
        }
    };

    // Broadcast deletion to all channel subscribers
    let del_msg = WsServerMessage::MessageDeleted {
        message_id: message.id,
        channel_id: message.channel_id,
    };
    if let Some(broadcaster) = state.channel_broadcasts.get(&message.channel_id) {
        let _ = broadcaster.send(del_msg.clone());
    }
    pubsub::publish_channel_event(state.redis.clone().as_mut(), message.channel_id, &del_msg).await;
}

/// Handle an AddReaction command: persist and broadcast.
async fn handle_add_reaction(
    user_id: Uuid,
    message_id: Uuid,
    emoji: &str,
    state: &AppState,
    reply_tx: &mpsc::UnboundedSender<WsServerMessage>,
) {
    // Look up the message to get its channel_id
    let message = match queries::find_message_by_id(state.db.read(), message_id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: "Message not found".into(),
            });
            return;
        }
        Err(e) => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: format!("Failed to find message: {}", e),
            });
            return;
        }
    };

    // Check if member is timed out (server channels only)
    if let Ok(Some(channel)) = queries::find_channel_by_id(state.db.read(), message.channel_id).await {
        if let Some(server_id) = channel.server_id {
            if queries::is_member_timed_out(state.db.read(), server_id, user_id)
                .await
                .unwrap_or(false)
            {
                let _ = reply_tx.send(WsServerMessage::Error {
                    message: "You are timed out in this server".into(),
                });
                return;
            }
        }
    }

    // Generate a random sender token for sealed sender
    let sender_token = Uuid::new_v4().to_string();

    // Persist the reaction
    if let Err(e) = queries::add_reaction(state.db.write(), message_id, user_id, emoji, Some(&sender_token)).await {
        let _ = reply_tx.send(WsServerMessage::Error {
            message: format!("Failed to add reaction: {}", e),
        });
        return;
    }

    // Broadcast to all channel subscribers
    let react_msg = WsServerMessage::ReactionAdded {
        message_id,
        channel_id: message.channel_id,
        user_id,
        sender_token,
        emoji: emoji.to_string(),
    };
    if let Some(broadcaster) = state.channel_broadcasts.get(&message.channel_id) {
        let _ = broadcaster.send(react_msg.clone());
    }
    pubsub::publish_channel_event(state.redis.clone().as_mut(), message.channel_id, &react_msg).await;
}

/// Handle a RemoveReaction command: delete and broadcast.
async fn handle_remove_reaction(
    user_id: Uuid,
    message_id: Uuid,
    emoji: &str,
    state: &AppState,
    reply_tx: &mpsc::UnboundedSender<WsServerMessage>,
) {
    // Look up the message to get its channel_id
    let message = match queries::find_message_by_id(state.db.read(), message_id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: "Message not found".into(),
            });
            return;
        }
        Err(e) => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: format!("Failed to find message: {}", e),
            });
            return;
        }
    };

    // Delete the reaction
    match queries::remove_reaction(state.db.write(), message_id, user_id, emoji).await {
        Ok(false) => return, // Didn't exist — no-op
        Err(e) => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: format!("Failed to remove reaction: {}", e),
            });
            return;
        }
        Ok(true) => {}
    }

    // Broadcast to all channel subscribers
    let sender_token = Uuid::new_v4().to_string();
    let unreact_msg = WsServerMessage::ReactionRemoved {
        message_id,
        channel_id: message.channel_id,
        user_id,
        sender_token,
        emoji: emoji.to_string(),
    };
    if let Some(broadcaster) = state.channel_broadcasts.get(&message.channel_id) {
        let _ = broadcaster.send(unreact_msg.clone());
    }
    pubsub::publish_channel_event(state.redis.clone().as_mut(), message.channel_id, &unreact_msg).await;
}

/// Broadcast a presence update (online/offline) to all channels the user belongs to,
/// and track the state in Redis for multi-instance queries.
pub(crate) async fn broadcast_presence(user_id: Uuid, status: &str, state: &AppState) {
    // Update presence stores
    if let Some(mut redis) = state.redis.clone() {
        let redis_result: Result<(), _> = if status == "offline" {
            redis::cmd("HDEL")
                .arg("haven:presence")
                .arg(user_id.to_string())
                .query_async(&mut redis)
                .await
        } else {
            redis::cmd("HSET")
                .arg("haven:presence")
                .arg(user_id.to_string())
                .arg(status)
                .query_async(&mut redis)
                .await
        };
        if let Err(e) = redis_result {
            tracing::warn!("Failed to update presence in Redis: {}", e);
        }
    }
    // Always update in-memory presence
    if status == "offline" {
        state.memory.presence.remove(&user_id);
    } else {
        state.memory.presence.insert(user_id, status.to_string());
    }

    // Get all channels this user belongs to and broadcast
    let channel_ids = match queries::get_user_channel_ids(state.db.read(), user_id).await {
        Ok(ids) => ids,
        Err(e) => {
            tracing::warn!("Failed to get user channels for presence: {}", e);
            return;
        }
    };

    let msg = WsServerMessage::PresenceUpdate {
        user_id,
        status: status.to_string(),
    };

    for ch_id in &channel_ids {
        if let Some(broadcaster) = state.channel_broadcasts.get(ch_id) {
            let _ = broadcaster.send(msg.clone());
        }
    }
    // Publish presence to all subscribed channels via Redis
    for ch_id in channel_ids {
        pubsub::publish_channel_event(state.redis.clone().as_mut(), ch_id, &msg).await;
    }
}

/// Handle PinMessage: verify permissions and broadcast.
async fn handle_pin_message(
    user_id: Uuid,
    channel_id: Uuid,
    message_id: Uuid,
    state: &AppState,
    reply_tx: &mpsc::UnboundedSender<WsServerMessage>,
) {
    match queries::can_access_channel(state.db.read(), channel_id, user_id).await {
        Ok(true) => {}
        Ok(false) => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: "Not a member of this channel".into(),
            });
            return;
        }
        Err(_) => {
            let _ = reply_tx.send(WsServerMessage::Error { message: "Internal error".into() });
            return;
        }
    }

    // Verify the message belongs to this channel
    match queries::find_message_by_id(state.db.read(), message_id).await {
        Ok(Some(m)) if m.channel_id == channel_id => {}
        _ => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: "Message not found in this channel".into(),
            });
            return;
        }
    }

    match queries::pin_message(state.db.write(), channel_id, message_id, user_id).await {
        Ok(_) => {
            let pin_msg = WsServerMessage::MessagePinned {
                channel_id,
                message_id,
                pinned_by: user_id,
            };
            if let Some(broadcaster) = state.channel_broadcasts.get(&channel_id) {
                let _ = broadcaster.send(pin_msg.clone());
            }
            pubsub::publish_channel_event(state.redis.clone().as_mut(), channel_id, &pin_msg).await;

            // Insert system message for pin
            if let Ok(Some(user)) = queries::find_user_by_id(state.db.read(), user_id).await {
                let username = user.display_name.as_deref().unwrap_or(&user.username);
                let body = serde_json::json!({
                    "event": "message_pinned",
                    "username": username,
                    "user_id": user_id.to_string(),
                    "message_id": message_id.to_string(),
                });
                if let Ok(sys_msg) = queries::insert_system_message(
                    state.db.write(), channel_id, &body.to_string(),
                ).await {
                    let response: MessageResponse = sys_msg.into();
                    let sys_ws_msg = WsServerMessage::NewMessage(response);
                    if let Some(broadcaster) = state.channel_broadcasts.get(&channel_id) {
                        let _ = broadcaster.send(sys_ws_msg.clone());
                    }
                    pubsub::publish_channel_event(state.redis.clone().as_mut(), channel_id, &sys_ws_msg).await;
                }
            }
        }
        Err(e) => {
            let _ = reply_tx.send(WsServerMessage::Error { message: e.to_string() });
        }
    }
}

/// Handle UnpinMessage: verify permissions and broadcast.
async fn handle_unpin_message(
    user_id: Uuid,
    channel_id: Uuid,
    message_id: Uuid,
    state: &AppState,
    reply_tx: &mpsc::UnboundedSender<WsServerMessage>,
) {
    match queries::can_access_channel(state.db.read(), channel_id, user_id).await {
        Ok(true) => {}
        Ok(false) => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: "Not a member of this channel".into(),
            });
            return;
        }
        Err(_) => {
            let _ = reply_tx.send(WsServerMessage::Error { message: "Internal error".into() });
            return;
        }
    }

    match queries::unpin_message(state.db.write(), channel_id, message_id).await {
        Ok(true) => {
            let unpin_msg = WsServerMessage::MessageUnpinned {
                channel_id,
                message_id,
            };
            if let Some(broadcaster) = state.channel_broadcasts.get(&channel_id) {
                let _ = broadcaster.send(unpin_msg.clone());
            }
            pubsub::publish_channel_event(state.redis.clone().as_mut(), channel_id, &unpin_msg).await;

            // Insert system message for unpin
            if let Ok(Some(user)) = queries::find_user_by_id(state.db.read(), user_id).await {
                let username = user.display_name.as_deref().unwrap_or(&user.username);
                let body = serde_json::json!({
                    "event": "message_unpinned",
                    "username": username,
                    "user_id": user_id.to_string(),
                    "message_id": message_id.to_string(),
                });
                if let Ok(sys_msg) = queries::insert_system_message(
                    state.db.write(), channel_id, &body.to_string(),
                ).await {
                    let response: MessageResponse = sys_msg.into();
                    let sys_ws_msg = WsServerMessage::NewMessage(response);
                    if let Some(broadcaster) = state.channel_broadcasts.get(&channel_id) {
                        let _ = broadcaster.send(sys_ws_msg.clone());
                    }
                    pubsub::publish_channel_event(state.redis.clone().as_mut(), channel_id, &sys_ws_msg).await;
                }
            }
        }
        Ok(false) => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: "Message is not pinned".into(),
            });
        }
        Err(e) => {
            let _ = reply_tx.send(WsServerMessage::Error { message: e.to_string() });
        }
    }
}

/// Broadcast a WS message to all subscribers of a server's channels.
pub async fn broadcast_to_server(state: &AppState, server_id: Uuid, msg: WsServerMessage) {
    if let Ok(channels) = queries::get_server_channels(state.db.read(), server_id).await {
        for ch in channels {
            if let Some(broadcaster) = state.channel_broadcasts.get(&ch.id) {
                let _ = broadcaster.send(msg.clone());
            }
        }
    }
}

// ─── DM/Group Call Signaling ────────────────────────────

/// Send a WS message to all members of a channel (direct connections + Redis pubsub).
async fn send_to_channel_members(
    state: &AppState,
    channel_id: Uuid,
    exclude_user_id: Option<Uuid>,
    msg: WsServerMessage,
) {
    if let Ok(member_ids) = queries::get_channel_member_ids(state.db.read(), channel_id).await {
        for mid in member_ids {
            if Some(mid) == exclude_user_id {
                continue;
            }
            if let Some(conns) = state.connections.get(&mid) {
                for tx in conns.iter() {
                    let _ = tx.send(msg.clone());
                }
            }
            pubsub::publish_user_event(state.redis.clone().as_mut(), mid, &msg).await;
        }
    }
}

/// Handle CallInvite: start ringing for a DM/group call.
async fn handle_call_invite(
    user_id: Uuid,
    channel_id: Uuid,
    state: &AppState,
    reply_tx: &mpsc::UnboundedSender<WsServerMessage>,
) {
    // Verify channel exists and is DM or group
    let channel = match queries::find_channel_by_id(state.db.read(), channel_id).await {
        Ok(Some(ch)) => ch,
        _ => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: "Channel not found".into(),
            });
            return;
        }
    };

    if !matches!(channel.channel_type.as_str(), "dm" | "group") {
        let _ = reply_tx.send(WsServerMessage::Error {
            message: "Calls are only supported in DMs and group DMs".into(),
        });
        return;
    }

    // Verify caller is a member
    match queries::can_access_channel(state.db.read(), channel_id, user_id).await {
        Ok(true) => {}
        _ => {
            let _ = reply_tx.send(WsServerMessage::Error {
                message: "Not a member of this channel".into(),
            });
            return;
        }
    }

    // Check no active call already exists for this channel
    if state.memory.active_calls.contains_key(&channel_id) {
        let _ = reply_tx.send(WsServerMessage::Error {
            message: "A call is already active in this channel".into(),
        });
        return;
    }

    // Look up caller name
    let caller_name = match queries::find_user_by_id(state.db.read(), user_id).await {
        Ok(Some(u)) => u.display_name.unwrap_or(u.username),
        _ => return,
    };

    // Register the active call
    state.memory.active_calls.insert(channel_id, ActiveCall {
        caller_id: user_id,
        started_at: Instant::now(),
    });

    // Send CallRinging to all other channel members
    let msg = WsServerMessage::CallRinging {
        channel_id,
        caller_id: user_id,
        caller_name,
    };
    send_to_channel_members(state, channel_id, Some(user_id), msg).await;

    // Spawn a 30-second ring timeout
    let state_clone = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(30)).await;

        // If the call is still ringing (not accepted/rejected/ended), end it
        if state_clone.memory.active_calls.remove(&channel_id).is_some() {
            let end_msg = WsServerMessage::CallEnded {
                channel_id,
                ended_by: user_id,
            };
            send_to_channel_members(&state_clone, channel_id, None, end_msg).await;
        }
    });
}

/// Handle CallAccept: callee accepts an incoming call.
async fn handle_call_accept(
    user_id: Uuid,
    channel_id: Uuid,
    state: &AppState,
    reply_tx: &mpsc::UnboundedSender<WsServerMessage>,
) {
    // Remove from active_calls (prevents timeout from firing)
    if state.memory.active_calls.remove(&channel_id).is_none() {
        let _ = reply_tx.send(WsServerMessage::Error {
            message: "No active call in this channel".into(),
        });
        return;
    }

    // Track the connected call start time for duration calculation
    state.memory.connected_calls.insert(channel_id, ConnectedCall {
        started_at: Instant::now(),
    });

    // Notify all channel members
    let msg = WsServerMessage::CallAccepted {
        channel_id,
        user_id,
    };
    send_to_channel_members(state, channel_id, None, msg).await;
}

/// Handle CallReject: callee rejects an incoming call.
async fn handle_call_reject(
    user_id: Uuid,
    channel_id: Uuid,
    state: &AppState,
    reply_tx: &mpsc::UnboundedSender<WsServerMessage>,
) {
    // Remove the call (any reject ends the ringing)
    if state.memory.active_calls.remove(&channel_id).is_none() {
        let _ = reply_tx.send(WsServerMessage::Error {
            message: "No active call in this channel".into(),
        });
        return;
    }

    // Notify all channel members
    let msg = WsServerMessage::CallRejected {
        channel_id,
        user_id,
    };
    send_to_channel_members(state, channel_id, None, msg).await;
}

/// Handle CallEnd: either party ends an active call.
async fn handle_call_end(
    user_id: Uuid,
    channel_id: Uuid,
    state: &AppState,
) {
    // Remove from active_calls if still ringing
    state.memory.active_calls.remove(&channel_id);

    // Remove connected call and calculate duration
    let duration_secs = state.memory.connected_calls.remove(&channel_id)
        .map(|(_, cc)| cc.started_at.elapsed().as_secs());

    // Insert a system message with call duration (only if the call was connected)
    if let Some(secs) = duration_secs {
        let caller_name = match queries::find_user_by_id(state.db.read(), user_id).await {
            Ok(Some(u)) => u.display_name.unwrap_or(u.username),
            _ => "Someone".to_string(),
        };
        let body = serde_json::json!({
            "event": "call_ended",
            "username": caller_name,
            "user_id": user_id.to_string(),
            "duration_secs": secs,
        });
        if let Ok(sys_msg) = queries::insert_system_message(
            state.db.write(), channel_id, &body.to_string(),
        ).await {
            let response: MessageResponse = sys_msg.into();
            let sys_ws_msg = WsServerMessage::NewMessage(response);
            // Broadcast via channel + direct delivery for DMs
            if let Some(broadcaster) = state.channel_broadcasts.get(&channel_id) {
                let _ = broadcaster.send(sys_ws_msg.clone());
            }
            if let Ok(member_ids) = queries::get_channel_member_ids(state.db.read(), channel_id).await {
                for mid in member_ids {
                    if let Some(conns) = state.connections.get(&mid) {
                        for tx in conns.iter() {
                            let _ = tx.send(sys_ws_msg.clone());
                        }
                    }
                }
            }
            pubsub::publish_channel_event(state.redis.clone().as_mut(), channel_id, &sys_ws_msg).await;
        }
    }

    // Notify all channel members
    let msg = WsServerMessage::CallEnded {
        channel_id,
        ended_by: user_id,
    };
    send_to_channel_members(state, channel_id, None, msg).await;
}

/// Clean up any active calls when a user disconnects.
/// Called alongside voice cleanup on WebSocket disconnect.
pub async fn cleanup_call_state(state: &AppState, user_id: Uuid) {
    // Find calls where this user is the caller and still ringing
    let mut to_end = Vec::new();
    for entry in state.memory.active_calls.iter() {
        if entry.value().caller_id == user_id {
            to_end.push(*entry.key());
        }
    }
    for channel_id in to_end {
        if state.memory.active_calls.remove(&channel_id).is_some() {
            let msg = WsServerMessage::CallEnded {
                channel_id,
                ended_by: user_id,
            };
            send_to_channel_members(state, channel_id, None, msg).await;
        }
    }

    // Also end any connected calls this user is part of
    // Check voice participants to find connected calls the user was in
    let mut connected_channels = Vec::new();
    for entry in state.memory.connected_calls.iter() {
        let ch_id = *entry.key();
        // Check if this user was a voice participant in this channel
        if let Some(participants) = state.memory.voice_participants.get(&ch_id) {
            if participants.contains(&user_id) {
                connected_channels.push(ch_id);
            }
        }
    }
    for channel_id in connected_channels {
        handle_call_end(user_id, channel_id, state).await;
    }
}
