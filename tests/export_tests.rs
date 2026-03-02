mod common;

use axum::http::{Method, StatusCode};
use base64::Engine;
use haven_backend::db::Pool;
use serde_json::json;
use uuid::Uuid;

use common::TestApp;

const B64: &base64::engine::GeneralPurpose = &base64::engine::general_purpose::STANDARD;

// ─── Verify Export ────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn verify_export_missing_user_id_returns_400(pool: Pool) {
    let app = TestApp::new(pool).await;

    let (status, _) = app
        .request(
            Method::POST,
            "/api/v1/exports/verify",
            None,
            Some(json!({
                "manifest": { "exported_by": {} },
                "signature": B64.encode([0u8; 64])
            })),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn verify_export_invalid_signature_length_returns_400(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (_, user_id) = app.register_user("verify1").await;

    let (status, _) = app
        .request(
            Method::POST,
            "/api/v1/exports/verify",
            None,
            Some(json!({
                "manifest": { "exported_by": { "user_id": user_id.to_string() } },
                "signature": B64.encode([0u8; 32])  // Wrong size, should be 64
            })),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn verify_export_nonexistent_user_returns_404(pool: Pool) {
    let app = TestApp::new(pool).await;

    let fake_id = Uuid::new_v4();
    let (status, _) = app
        .request(
            Method::POST,
            "/api/v1/exports/verify",
            None,
            Some(json!({
                "manifest": { "exported_by": { "user_id": fake_id.to_string() } },
                "signature": B64.encode([0u8; 64])
            })),
        )
        .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ─── Log Export ───────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn log_export(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("log1").await;

    let (status, value) = app
        .request(
            Method::POST,
            "/api/v1/exports/log",
            Some(&token),
            Some(json!({
                "scope": "channel",
                "channel_id": Uuid::new_v4(),
                "message_count": 42
            })),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["logged"].as_bool(), Some(true));
}

// ─── Restore Server ───────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn restore_server_as_owner(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("restore1").await;
    let server_id = app.create_server(&token, "Restore Server").await;

    let uri = format!("/api/v1/servers/{}/restore", server_id);
    let (status, value) = app
        .request(
            Method::POST,
            &uri,
            Some(&token),
            Some(json!({
                "server": { "id": server_id.to_string(), "name": "Restored" },
                "categories": [{ "id": "cat-1", "name": "General", "position": 0 }],
                "channels": [{
                    "id": "ch-1",
                    "name": "general",
                    "type": "text",
                    "category_id": "cat-1",
                    "position": 0,
                    "encrypted": false,
                    "is_private": false
                }],
                "roles": [],
                "permission_overwrites": []
            })),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(value["categories_created"].is_number());
    assert!(value["channels_created"].is_number());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn restore_server_non_member_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("restore2").await;
    let (token_outsider, _) = app.register_user("restore3").await;
    let server_id = app.create_server(&token_owner, "Restore Server2").await;

    let uri = format!("/api/v1/servers/{}/restore", server_id);
    let (status, _) = app
        .request(
            Method::POST,
            &uri,
            Some(&token_outsider),
            Some(json!({
                "server": { "id": server_id.to_string(), "name": "Hacked" },
                "categories": [],
                "channels": [],
                "roles": []
            })),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}
