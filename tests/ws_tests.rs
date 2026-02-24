mod common;

use base64::Engine;
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use haven_backend::db::Pool;
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use common::TestApp;

const B64: &base64::engine::GeneralPurpose = &base64::engine::general_purpose::STANDARD;

/// Helper: start the router on a random port, return the base URL.
async fn start_server(app: &TestApp) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = app.router_clone();

    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    format!("127.0.0.1:{}", addr.port())
}

/// Helper: connect a WebSocket client with authentication.
async fn ws_connect(
    addr: &str,
    token: &str,
) -> (
    futures::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
    futures::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) {
    let url = format!("ws://{}/api/v1/ws?token={}", addr, token);
    let (ws_stream, _) = connect_async(&url).await.expect("WS connect failed");
    ws_stream.split()
}

/// Helper: send a JSON message over WS.
async fn ws_send(
    sink: &mut futures::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
    msg: Value,
) {
    sink.send(Message::Text(msg.to_string().into()))
        .await
        .unwrap();
}

/// Helper: receive the next text message with a timeout.
async fn ws_recv(
    stream: &mut futures::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) -> Value {
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("WS recv timed out")
        .expect("WS stream ended")
        .expect("WS recv error");

    match msg {
        Message::Text(text) => serde_json::from_str(&text).unwrap(),
        other => panic!("Expected text message, got {:?}", other),
    }
}

/// Helper: drain messages looking for one matching a predicate.
async fn ws_recv_matching(
    stream: &mut futures::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    predicate: impl Fn(&Value) -> bool,
) -> Value {
    for _ in 0..20 {
        let msg =
            tokio::time::timeout(std::time::Duration::from_secs(3), stream.next()).await;
        match msg {
            Ok(Some(Ok(Message::Text(text)))) => {
                let v: Value = serde_json::from_str(&text).unwrap();
                if predicate(&v) {
                    return v;
                }
            }
            _ => break,
        }
    }
    panic!("No matching WS message received");
}

// ─── Ping / Pong ────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn ws_ping_returns_pong(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("ws_ping").await;
    let addr = start_server(&app).await;

    let (mut sink, mut stream) = ws_connect(&addr, &token).await;

    ws_send(&mut sink, json!({"type": "Ping"})).await;

    let msg = ws_recv_matching(&mut stream, |v| v["type"] == "Pong").await;
    assert_eq!(msg["type"].as_str(), Some("Pong"));
}

// ─── Subscribe / Subscribed ─────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn ws_subscribe_returns_subscribed(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("ws_sub").await;
    let server_id = app.create_server(&token, "WS Sub Test").await;
    let channel_id = app.create_channel(&token, server_id, "general").await;
    let addr = start_server(&app).await;

    let (mut sink, mut stream) = ws_connect(&addr, &token).await;

    ws_send(
        &mut sink,
        json!({"type": "Subscribe", "payload": {"channel_id": channel_id}}),
    )
    .await;

    let msg = ws_recv_matching(&mut stream, |v| v["type"].as_str() == Some("Subscribed")).await;
    assert_eq!(msg["payload"]["channel_id"].as_str().unwrap(), channel_id.to_string());
}

// ─── Subscribe to unauthorized channel ──────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn ws_subscribe_unauthorized_channel(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("ws_sub_own").await;
    let (token_other, _) = app.register_user("ws_sub_other").await;
    let server_id = app.create_server(&token_owner, "Private").await;
    let channel_id = app.create_channel(&token_owner, server_id, "secret").await;
    let addr = start_server(&app).await;

    // Other user tries to subscribe to a channel they're not in
    let (mut sink, mut stream) = ws_connect(&addr, &token_other).await;

    ws_send(
        &mut sink,
        json!({"type": "Subscribe", "payload": {"channel_id": channel_id}}),
    )
    .await;

    let msg = ws_recv_matching(&mut stream, |v| v["type"].as_str() == Some("Error")).await;
    assert!(msg["payload"]["message"]
        .as_str()
        .unwrap()
        .contains("Not a member"));
}

// ─── Send Message via WS ────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn ws_send_message_returns_ack(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("ws_msg").await;
    let server_id = app.create_server(&token, "WS Msg Test").await;
    let channel_id = app.create_channel(&token, server_id, "general").await;
    let addr = start_server(&app).await;

    let (mut sink, mut stream) = ws_connect(&addr, &token).await;

    // Subscribe first
    ws_send(
        &mut sink,
        json!({"type": "Subscribe", "payload": {"channel_id": channel_id}}),
    )
    .await;
    // Wait for Subscribed
    ws_recv_matching(&mut stream, |v| v["type"].as_str() == Some("Subscribed")).await;

    // Send a message
    ws_send(
        &mut sink,
        json!({
            "type": "SendMessage",
            "payload": {
                "channel_id": channel_id,
                "sender_token": B64.encode(b"test-sender-token"),
                "encrypted_body": B64.encode(b"hello encrypted"),
                "expires_at": null,
                "attachment_ids": null,
                "reply_to_id": null
            }
        }),
    )
    .await;

    // Should get MessageAck
    let ack = ws_recv_matching(&mut stream, |v| v["type"].as_str() == Some("MessageAck")).await;
    assert!(ack["payload"]["message_id"].as_str().is_some());
}

// ─── Send Message to unauthorized channel ───────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn ws_send_message_unauthorized(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("ws_unauth_own").await;
    let (token_other, _) = app.register_user("ws_unauth_oth").await;
    let server_id = app.create_server(&token_owner, "Private").await;
    let channel_id = app.create_channel(&token_owner, server_id, "secret").await;
    let addr = start_server(&app).await;

    let (mut sink, mut stream) = ws_connect(&addr, &token_other).await;

    ws_send(
        &mut sink,
        json!({
            "type": "SendMessage",
            "payload": {
                "channel_id": channel_id,
                "sender_token": B64.encode(b"token"),
                "encrypted_body": B64.encode(b"body"),
                "expires_at": null,
                "attachment_ids": null,
                "reply_to_id": null
            }
        }),
    )
    .await;

    let msg = ws_recv_matching(&mut stream, |v| v["type"].as_str() == Some("Error")).await;
    assert!(msg["payload"]["message"]
        .as_str()
        .unwrap()
        .contains("Not a member"));
}

// ─── Invalid message format ─────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn ws_invalid_message_returns_error(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("ws_invalid").await;
    let addr = start_server(&app).await;

    let (mut sink, mut stream) = ws_connect(&addr, &token).await;

    // Send garbage JSON
    sink.send(Message::Text("{\"bad\": true}".into()))
        .await
        .unwrap();

    let msg = ws_recv_matching(&mut stream, |v| v["type"].as_str() == Some("Error")).await;
    assert!(msg["payload"]["message"]
        .as_str()
        .unwrap()
        .contains("Invalid message format"));
}

// ─── SetStatus ──────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn ws_set_status_invalid(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("ws_status").await;
    let addr = start_server(&app).await;

    let (mut sink, mut stream) = ws_connect(&addr, &token).await;

    ws_send(
        &mut sink,
        json!({"type": "SetStatus", "payload": {"status": "bogus"}}),
    )
    .await;

    let msg = ws_recv_matching(&mut stream, |v| v["type"].as_str() == Some("Error")).await;
    assert!(msg["payload"]["message"]
        .as_str()
        .unwrap()
        .contains("Invalid status"));
}

// ─── Typing indicator ───────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn ws_typing_broadcasts_to_subscribers(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("ws_type_a").await;
    let (token_b, _) = app.register_user("ws_type_b").await;
    let server_id = app.create_server(&token_a, "Type Test").await;
    app.invite_and_join(&token_a, &token_b, server_id).await;
    let channel_id = app.create_channel(&token_a, server_id, "general").await;
    let addr = start_server(&app).await;

    // B subscribes to the channel
    let (mut sink_b, mut stream_b) = ws_connect(&addr, &token_b).await;
    ws_send(
        &mut sink_b,
        json!({"type": "Subscribe", "payload": {"channel_id": channel_id}}),
    )
    .await;
    ws_recv_matching(&mut stream_b, |v| v["type"].as_str() == Some("Subscribed")).await;

    // A connects and sends typing
    let (mut sink_a, _stream_a) = ws_connect(&addr, &token_a).await;
    ws_send(
        &mut sink_a,
        json!({"type": "Typing", "payload": {"channel_id": channel_id}}),
    )
    .await;

    // B should receive the typing indicator
    let msg = ws_recv_matching(&mut stream_b, |v| v["type"].as_str() == Some("UserTyping")).await;
    assert_eq!(
        msg["payload"]["channel_id"].as_str().unwrap(),
        channel_id.to_string()
    );
    assert_eq!(msg["payload"]["username"].as_str(), Some("ws_type_a"));
}

// ─── Message broadcast to subscribers ───────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn ws_message_broadcast_to_subscriber(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("ws_bc_a").await;
    let (token_b, _) = app.register_user("ws_bc_b").await;
    let server_id = app.create_server(&token_a, "Broadcast").await;
    app.invite_and_join(&token_a, &token_b, server_id).await;
    let channel_id = app.create_channel(&token_a, server_id, "general").await;
    let addr = start_server(&app).await;

    // B subscribes
    let (mut sink_b, mut stream_b) = ws_connect(&addr, &token_b).await;
    ws_send(
        &mut sink_b,
        json!({"type": "Subscribe", "payload": {"channel_id": channel_id}}),
    )
    .await;
    ws_recv_matching(&mut stream_b, |v| v["type"].as_str() == Some("Subscribed")).await;

    // A subscribes and sends a message
    let (mut sink_a, mut stream_a) = ws_connect(&addr, &token_a).await;
    ws_send(
        &mut sink_a,
        json!({"type": "Subscribe", "payload": {"channel_id": channel_id}}),
    )
    .await;
    ws_recv_matching(&mut stream_a, |v| v["type"].as_str() == Some("Subscribed")).await;

    ws_send(
        &mut sink_a,
        json!({
            "type": "SendMessage",
            "payload": {
                "channel_id": channel_id,
                "sender_token": B64.encode(b"sender-tok"),
                "encrypted_body": B64.encode(b"broadcast body"),
                "expires_at": null,
                "attachment_ids": null,
                "reply_to_id": null
            }
        }),
    )
    .await;

    // B should receive NewMessage
    let msg = ws_recv_matching(&mut stream_b, |v| v["type"].as_str() == Some("NewMessage")).await;
    assert_eq!(
        msg["payload"]["channel_id"].as_str().unwrap(),
        channel_id.to_string()
    );
}

// ─── Invalid base64 in SendMessage ──────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn ws_send_message_invalid_base64(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("ws_b64").await;
    let server_id = app.create_server(&token, "B64 Test").await;
    let channel_id = app.create_channel(&token, server_id, "ch").await;
    let addr = start_server(&app).await;

    let (mut sink, mut stream) = ws_connect(&addr, &token).await;

    ws_send(
        &mut sink,
        json!({
            "type": "SendMessage",
            "payload": {
                "channel_id": channel_id,
                "sender_token": "not!!valid!!base64",
                "encrypted_body": B64.encode(b"body"),
                "expires_at": null,
                "attachment_ids": null,
                "reply_to_id": null
            }
        }),
    )
    .await;

    let msg = ws_recv_matching(&mut stream, |v| v["type"].as_str() == Some("Error")).await;
    assert!(msg["payload"]["message"]
        .as_str()
        .unwrap()
        .contains("Invalid sender_token"));
}
