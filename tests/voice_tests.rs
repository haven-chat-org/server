mod common;

use axum::http::{Method, StatusCode};
use haven_backend::db::Pool;
use serde_json::json;

use common::TestApp;

// ─── Voice Join ───────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn voice_join_not_configured_returns_400(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("voice1").await;
    let server_id = app.create_server(&token, "Voice Server").await;
    let channel_id = app.create_voice_channel(&token, server_id, "vc").await;

    let uri = format!("/api/v1/voice/{}/join", channel_id);
    let (status, value) = app.request(Method::POST, &uri, Some(&token), None).await;

    // LiveKit is not configured in test env
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(value["error"]
        .as_str()
        .unwrap_or("")
        .contains("not configured"));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn voice_join_non_voice_channel_returns_400(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("voice2").await;
    let server_id = app.create_server(&token, "Voice Server2").await;
    let text_channel_id = app.create_channel(&token, server_id, "text-ch").await;

    let uri = format!("/api/v1/voice/{}/join", text_channel_id);
    let (status, _) = app.request(Method::POST, &uri, Some(&token), None).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn voice_join_non_member_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("voice3").await;
    let (token_outsider, _) = app.register_user("voice4").await;
    let server_id = app.create_server(&token_owner, "Voice Server3").await;
    let channel_id = app
        .create_voice_channel(&token_owner, server_id, "vc2")
        .await;

    let uri = format!("/api/v1/voice/{}/join", channel_id);
    let (status, _) = app
        .request(Method::POST, &uri, Some(&token_outsider), None)
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── Voice Leave ──────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn voice_leave_returns_ok(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("voice5").await;
    let server_id = app.create_server(&token, "Voice Server4").await;
    let channel_id = app.create_voice_channel(&token, server_id, "vc3").await;

    // Leave without being in the channel — should still succeed
    let uri = format!("/api/v1/voice/{}/leave", channel_id);
    let (status, value) = app.request(Method::POST, &uri, Some(&token), None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["ok"].as_bool(), Some(true));
}

// ─── Voice Participants ───────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn voice_participants_empty(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("voice6").await;
    let server_id = app.create_server(&token, "Voice Server5").await;
    let channel_id = app.create_voice_channel(&token, server_id, "vc4").await;

    let uri = format!("/api/v1/voice/{}/participants", channel_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;

    assert_eq!(status, StatusCode::OK);
    assert!(value.as_array().unwrap().is_empty());
}

// ─── Voice Server Mute ────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn voice_mute_not_in_channel_returns_400(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("voice7").await;
    let (_, member_id) = app.register_user("voice8").await;
    let server_id = app.create_server(&token_owner, "Voice Server6").await;
    let channel_id = app
        .create_voice_channel(&token_owner, server_id, "vc5")
        .await;

    let uri = format!("/api/v1/voice/{}/members/{}/mute", channel_id, member_id);
    let (status, _) = app
        .request(
            Method::PUT,
            &uri,
            Some(&token_owner),
            Some(json!({ "muted": true })),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn voice_mute_no_permission_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("voice9").await;
    let (token_member, member_id) = app.register_user("voice10").await;
    let server_id = app.create_server(&token_owner, "Voice Server7").await;
    let channel_id = app
        .create_voice_channel(&token_owner, server_id, "vc6")
        .await;

    // Invite member to server
    app.invite_and_join(&token_owner, &token_member, server_id)
        .await;

    // Member tries to mute owner — should fail (no permission)
    let uri = format!(
        "/api/v1/voice/{}/members/{}/mute",
        channel_id, member_id
    );
    let (status, _) = app
        .request(
            Method::PUT,
            &uri,
            Some(&token_member),
            Some(json!({ "muted": true })),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── Voice Server Deafen ──────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn voice_deafen_no_permission_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, owner_id) = app.register_user("voice11").await;
    let (token_member, _) = app.register_user("voice12").await;
    let server_id = app.create_server(&token_owner, "Voice Server8").await;
    let channel_id = app
        .create_voice_channel(&token_owner, server_id, "vc7")
        .await;

    app.invite_and_join(&token_owner, &token_member, server_id)
        .await;

    let uri = format!(
        "/api/v1/voice/{}/members/{}/deafen",
        channel_id, owner_id
    );
    let (status, _) = app
        .request(
            Method::PUT,
            &uri,
            Some(&token_member),
            Some(json!({ "deafened": true })),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}
