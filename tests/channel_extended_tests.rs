mod common;

use axum::http::{Method, StatusCode};
use base64::Engine;
use haven_backend::db::Pool;
use serde_json::json;

use common::TestApp;

const B64: &base64::engine::GeneralPurpose = &base64::engine::general_purpose::STANDARD;

// ─── Read States ──────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn get_read_states_returns_ok(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("rs1").await;

    let (status, value) = app
        .request(
            Method::GET,
            "/api/v1/channels/read-states",
            Some(&token),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    // May include auto-created Haven server channels from system user migration
    assert!(value.as_array().is_some());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn mark_channel_read_and_verify(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("rs2").await;
    let server_id = app.create_server(&token, "RS Server").await;
    let channel_id = app.create_channel(&token, server_id, "rs-ch").await;

    // Send a message so there's something to read
    app.send_message(&token, channel_id).await;

    // Mark channel as read
    let uri = format!("/api/v1/channels/{}/read-state", channel_id);
    let (status, value) = app.request(Method::PUT, &uri, Some(&token), None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        value["channel_id"].as_str().unwrap(),
        channel_id.to_string()
    );
    assert!(value["last_read_at"].is_string());
}

// ─── Message TTL ──────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn set_message_ttl_on_server_channel(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("ttl1").await;
    let server_id = app.create_server(&token, "TTL Server").await;
    let channel_id = app.create_channel(&token, server_id, "ttl-ch").await;

    let uri = format!("/api/v1/channels/{}/message-ttl", channel_id);
    let (status, value) = app
        .request(
            Method::PUT,
            &uri,
            Some(&token),
            Some(json!({ "message_ttl": 3600 })),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["message_ttl"].as_i64(), Some(3600));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn clear_message_ttl(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("ttl2").await;
    let server_id = app.create_server(&token, "TTL Server2").await;
    let channel_id = app.create_channel(&token, server_id, "ttl-ch2").await;

    let uri = format!("/api/v1/channels/{}/message-ttl", channel_id);

    // Set TTL first
    app.request(
        Method::PUT,
        &uri,
        Some(&token),
        Some(json!({ "message_ttl": 86400 })),
    )
    .await;

    // Clear TTL
    let (status, value) = app
        .request(
            Method::PUT,
            &uri,
            Some(&token),
            Some(json!({ "message_ttl": null })),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(value["message_ttl"].is_null());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn set_message_ttl_invalid_value_returns_400(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("ttl3").await;
    let server_id = app.create_server(&token, "TTL Server3").await;
    let channel_id = app.create_channel(&token, server_id, "ttl-ch3").await;

    let uri = format!("/api/v1/channels/{}/message-ttl", channel_id);
    let (status, _) = app
        .request(
            Method::PUT,
            &uri,
            Some(&token),
            Some(json!({ "message_ttl": 12345 })), // Not in allowed set
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn set_message_ttl_no_permission_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("ttl4").await;
    let (token_member, _) = app.register_user("ttl5").await;
    let server_id = app.create_server(&token_owner, "TTL Server4").await;
    let channel_id = app.create_channel(&token_owner, server_id, "ttl-ch4").await;

    app.invite_and_join(&token_owner, &token_member, server_id)
        .await;

    let uri = format!("/api/v1/channels/{}/message-ttl", channel_id);
    let (status, _) = app
        .request(
            Method::PUT,
            &uri,
            Some(&token_member),
            Some(json!({ "message_ttl": 3600 })),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn dm_member_can_set_message_ttl(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("ttl6").await;
    let (_, user_b_id) = app.register_user("ttl7").await;

    let channel_id = app.create_dm(&token_a, user_b_id).await;

    let uri = format!("/api/v1/channels/{}/message-ttl", channel_id);
    let (status, value) = app
        .request(
            Method::PUT,
            &uri,
            Some(&token_a),
            Some(json!({ "message_ttl": 300 })),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["message_ttl"].as_i64(), Some(300));
}

// ─── Channel Export ───────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn export_server_channel(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("cexp1").await;
    let server_id = app.create_server(&token, "CExp Server").await;
    let channel_id = app.create_channel(&token, server_id, "cexp-ch").await;

    // Send some messages
    app.send_message(&token, channel_id).await;
    app.send_message(&token, channel_id).await;

    let uri = format!("/api/v1/channels/{}/export", channel_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        value["channel_id"].as_str().unwrap(),
        channel_id.to_string()
    );
    assert!(value["messages"].as_array().unwrap().len() >= 2);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn export_channel_non_member_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("cexp2").await;
    let (token_outsider, _) = app.register_user("cexp3").await;
    let server_id = app.create_server(&token_owner, "CExp Server2").await;
    let channel_id = app.create_channel(&token_owner, server_id, "cexp-ch2").await;

    let uri = format!("/api/v1/channels/{}/export", channel_id);
    let (status, _) = app
        .request(Method::GET, &uri, Some(&token_outsider), None)
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── Export Consent ───────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn set_export_consent_on_dm(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("consent1").await;
    let (_, user_b_id) = app.register_user("consent2").await;

    let channel_id = app.create_dm(&token_a, user_b_id).await;

    let uri = format!("/api/v1/channels/{}/export-consent", channel_id);
    let (status, value) = app
        .request(
            Method::PUT,
            &uri,
            Some(&token_a),
            Some(json!({ "export_allowed": true })),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["export_allowed"].as_bool(), Some(true));
}

// ─── Hide Channel ─────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn hide_dm_channel(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("hide1").await;
    let (_, user_b_id) = app.register_user("hide2").await;

    let channel_id = app.create_dm(&token_a, user_b_id).await;

    let uri = format!("/api/v1/channels/{}/hide", channel_id);
    let (status, value) = app
        .request(Method::PUT, &uri, Some(&token_a), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["hidden"].as_bool(), Some(true));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn hide_server_channel_returns_400(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("hide3").await;
    let server_id = app.create_server(&token, "Hide Server").await;
    let channel_id = app.create_channel(&token, server_id, "hide-ch").await;

    let uri = format!("/api/v1/channels/{}/hide", channel_id);
    let (status, _) = app
        .request(Method::PUT, &uri, Some(&token), None)
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ─── Import Messages ──────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn import_messages_as_owner(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("import1").await;
    let server_id = app.create_server(&token, "Import Server").await;
    let channel_id = app.create_channel(&token, server_id, "import-ch").await;

    let uri = format!("/api/v1/channels/{}/import-messages", channel_id);
    let (status, value) = app
        .request(
            Method::POST,
            &uri,
            Some(&token),
            Some(json!({
                "messages": [
                    {
                        "sender_token": B64.encode(b"token1"),
                        "encrypted_body": B64.encode(b"body1"),
                        "timestamp": "2024-01-01T00:00:00.000Z",
                        "message_type": "user",
                        "has_attachments": false
                    },
                    {
                        "sender_token": B64.encode(b"token2"),
                        "encrypted_body": B64.encode(b"body2"),
                        "timestamp": "2024-01-01T00:01:00.000Z",
                        "message_type": "user",
                        "has_attachments": false
                    }
                ]
            })),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["imported"].as_i64(), Some(2));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn import_messages_no_permission_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("import2").await;
    let (token_member, _) = app.register_user("import3").await;
    let server_id = app.create_server(&token_owner, "Import Server2").await;
    let channel_id = app
        .create_channel(&token_owner, server_id, "import-ch2")
        .await;

    app.invite_and_join(&token_owner, &token_member, server_id)
        .await;

    let uri = format!("/api/v1/channels/{}/import-messages", channel_id);
    let (status, _) = app
        .request(
            Method::POST,
            &uri,
            Some(&token_member),
            Some(json!({
                "messages": [{
                    "sender_token": B64.encode(b"token"),
                    "encrypted_body": B64.encode(b"body"),
                    "timestamp": "2024-01-01T00:00:00.000Z",
                    "message_type": "user",
                    "has_attachments": false
                }]
            })),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── Channel Members ──────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn list_channel_members(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("cm1").await;
    let (token_member, _) = app.register_user("cm2").await;
    let server_id = app.create_server(&token_owner, "CM Server").await;
    let channel_id = app.create_channel(&token_owner, server_id, "cm-ch").await;

    app.invite_and_join(&token_owner, &token_member, server_id)
        .await;

    // Join the channel
    let join_uri = format!("/api/v1/channels/{}/join", channel_id);
    app.request(Method::POST, &join_uri, Some(&token_member), None)
        .await;

    let uri = format!("/api/v1/channels/{}/members", channel_id);
    let (status, value) = app
        .request(Method::GET, &uri, Some(&token_owner), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    let members = value.as_array().unwrap();
    assert!(members.len() >= 1);
}
