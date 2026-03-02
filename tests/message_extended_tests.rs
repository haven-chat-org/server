mod common;

use axum::http::{Method, StatusCode};
use base64::Engine;
use haven_backend::db::Pool;
use serde_json::json;
use uuid::Uuid;

use common::TestApp;

const B64: &base64::engine::GeneralPurpose = &base64::engine::general_purpose::STANDARD;

// ─── Bulk Delete Messages ─────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn bulk_delete_messages(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("bulk1").await;
    let server_id = app.create_server(&token, "Bulk Server").await;
    let channel_id = app.create_channel(&token, server_id, "bulk-ch").await;

    // Send messages
    let (msg1, _) = app.send_message(&token, channel_id).await;
    let (msg2, _) = app.send_message(&token, channel_id).await;

    let uri = format!("/api/v1/channels/{}/messages/bulk-delete", channel_id);
    let (status, value) = app
        .request(
            Method::POST,
            &uri,
            Some(&token),
            Some(json!({ "message_ids": [msg1, msg2] })),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["deleted"].as_i64(), Some(2));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn bulk_delete_empty_list_returns_400(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("bulk2").await;
    let server_id = app.create_server(&token, "Bulk Server2").await;
    let channel_id = app.create_channel(&token, server_id, "bulk-ch2").await;

    let uri = format!("/api/v1/channels/{}/messages/bulk-delete", channel_id);
    let (status, _) = app
        .request(
            Method::POST,
            &uri,
            Some(&token),
            Some(json!({ "message_ids": [] })),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn bulk_delete_no_permission_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("bulk3").await;
    let (token_member, _) = app.register_user("bulk4").await;
    let server_id = app.create_server(&token_owner, "Bulk Server3").await;
    let channel_id = app
        .create_channel(&token_owner, server_id, "bulk-ch3")
        .await;

    app.invite_and_join(&token_owner, &token_member, server_id)
        .await;

    // Send a message as owner
    let (msg_id, _) = app.send_message(&token_owner, channel_id).await;

    // Member tries to bulk delete
    let uri = format!("/api/v1/channels/{}/messages/bulk-delete", channel_id);
    let (status, _) = app
        .request(
            Method::POST,
            &uri,
            Some(&token_member),
            Some(json!({ "message_ids": [msg_id] })),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── Message Reactions ────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn get_message_reactions_nonexistent_returns_404(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("react1").await;

    let fake_id = Uuid::new_v4();
    let uri = format!("/api/v1/messages/{}/reactions", fake_id);
    let (status, _) = app.request(Method::GET, &uri, Some(&token), None).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn get_message_reactions_empty(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("react2").await;
    let server_id = app.create_server(&token, "React Server").await;
    let channel_id = app.create_channel(&token, server_id, "react-ch").await;

    let (msg_id, _) = app.send_message(&token, channel_id).await;

    let uri = format!("/api/v1/messages/{}/reactions", msg_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;

    assert_eq!(status, StatusCode::OK);
    assert!(value.as_array().unwrap().is_empty());
}

// ─── Cursor Pagination ────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn get_messages_with_before_cursor(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("page1").await;
    let server_id = app.create_server(&token, "Page Server").await;
    let channel_id = app.create_channel(&token, server_id, "page-ch").await;

    // Send 5 messages
    for _ in 0..5 {
        app.send_message(&token, channel_id).await;
    }

    // Get all messages to get a timestamp for cursor
    let uri = format!("/api/v1/channels/{}/messages?limit=5", channel_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let messages = value.as_array().unwrap();
    assert_eq!(messages.len(), 5);

    // Use the timestamp of the most recent message as "before" cursor
    let latest_ts = messages[0]["timestamp"].as_str().unwrap();
    let uri = format!(
        "/api/v1/channels/{}/messages?before={}&limit=10",
        channel_id, latest_ts
    );
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let older = value.as_array().unwrap();
    // Should have messages before the latest one
    assert!(older.len() < 5);
}

// ─── Send Message via REST ────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn send_message_via_rest(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("send1").await;
    let server_id = app.create_server(&token, "Send Server").await;
    let channel_id = app.create_channel(&token, server_id, "send-ch").await;

    let (msg_id, value) = app.send_message(&token, channel_id).await;

    assert!(!msg_id.is_nil());
    assert_eq!(
        value["channel_id"].as_str().unwrap(),
        channel_id.to_string()
    );
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn send_message_non_member_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("send2").await;
    let (token_outsider, _) = app.register_user("send3").await;
    let server_id = app.create_server(&token_owner, "Send Server2").await;
    let channel_id = app
        .create_channel(&token_owner, server_id, "send-ch2")
        .await;

    let body = json!({
        "channel_id": channel_id,
        "sender_token": B64.encode(b"token"),
        "encrypted_body": B64.encode(b"body"),
        "has_attachments": false
    });
    let uri = format!("/api/v1/channels/{}/messages", channel_id);
    let (status, _) = app
        .request(Method::POST, &uri, Some(&token_outsider), Some(body))
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}
