mod common;

use axum::http::{Method, StatusCode};
use base64::Engine;
use haven_backend::db::Pool;
use serde_json::json;

use common::TestApp;

const B64: &base64::engine::GeneralPurpose = &base64::engine::general_purpose::STANDARD;

fn valid_backup_body() -> serde_json::Value {
    json!({
        "encrypted_data": B64.encode(b"test-encrypted-data-for-backup"),
        "nonce": B64.encode([0u8; 24]),
        "salt": B64.encode([0u8; 16]),
        "version": 1
    })
}

// ─── Upload Key Backup ────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn upload_key_backup(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("backup1").await;

    let (status, value) = app
        .request(
            Method::PUT,
            "/api/v1/keys/backup",
            Some(&token),
            Some(valid_backup_body()),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["ok"].as_bool(), Some(true));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn upload_key_backup_invalid_nonce_returns_400(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("backup2").await;

    let body = json!({
        "encrypted_data": B64.encode(b"data"),
        "nonce": B64.encode([0u8; 12]),  // Wrong size, should be 24
        "salt": B64.encode([0u8; 16]),
        "version": 1
    });

    let (status, _) = app
        .request(Method::PUT, "/api/v1/keys/backup", Some(&token), Some(body))
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn upload_key_backup_invalid_salt_returns_400(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("backup3").await;

    let body = json!({
        "encrypted_data": B64.encode(b"data"),
        "nonce": B64.encode([0u8; 24]),
        "salt": B64.encode([0u8; 8]),  // Wrong size, should be 16
        "version": 1
    });

    let (status, _) = app
        .request(Method::PUT, "/api/v1/keys/backup", Some(&token), Some(body))
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn upload_key_backup_too_large_returns_400(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("backup4").await;

    let huge_data = vec![0u8; 513 * 1024]; // > 512KB limit
    let body = json!({
        "encrypted_data": B64.encode(&huge_data),
        "nonce": B64.encode([0u8; 24]),
        "salt": B64.encode([0u8; 16]),
        "version": 1
    });

    let (status, _) = app
        .request(Method::PUT, "/api/v1/keys/backup", Some(&token), Some(body))
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn upload_key_backup_upsert_overwrites(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("backup5").await;

    // Upload first backup
    app.request(
        Method::PUT,
        "/api/v1/keys/backup",
        Some(&token),
        Some(valid_backup_body()),
    )
    .await;

    // Upload second backup (should overwrite)
    let body = json!({
        "encrypted_data": B64.encode(b"updated-data"),
        "nonce": B64.encode([1u8; 24]),
        "salt": B64.encode([1u8; 16]),
        "version": 2
    });

    let (status, _) = app
        .request(Method::PUT, "/api/v1/keys/backup", Some(&token), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);

    // Verify we get the updated data
    let (status, value) = app
        .request(Method::GET, "/api/v1/keys/backup", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["version"].as_i64(), Some(2));
}

// ─── Get Key Backup ───────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn get_key_backup(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("backup6").await;

    // Upload backup
    app.request(
        Method::PUT,
        "/api/v1/keys/backup",
        Some(&token),
        Some(valid_backup_body()),
    )
    .await;

    // Retrieve it
    let (status, value) = app
        .request(Method::GET, "/api/v1/keys/backup", Some(&token), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(value["encrypted_data"].is_string());
    assert!(value["nonce"].is_string());
    assert!(value["salt"].is_string());
    assert!(value["version"].is_number());
    assert!(value["updated_at"].is_string());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn get_key_backup_when_none_returns_404(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("backup7").await;

    let (status, _) = app
        .request(Method::GET, "/api/v1/keys/backup", Some(&token), None)
        .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ─── Delete Key Backup ────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn delete_key_backup(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("backup8").await;

    // Upload then delete
    app.request(
        Method::PUT,
        "/api/v1/keys/backup",
        Some(&token),
        Some(valid_backup_body()),
    )
    .await;

    let (status, value) = app
        .request(Method::DELETE, "/api/v1/keys/backup", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["ok"].as_bool(), Some(true));

    // Verify it's gone
    let (status, _) = app
        .request(Method::GET, "/api/v1/keys/backup", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ─── Key Backup Status ────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn key_backup_status_no_backup(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("backup9").await;

    let (status, value) = app
        .request(
            Method::GET,
            "/api/v1/keys/backup/status",
            Some(&token),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["has_backup"].as_bool(), Some(false));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn key_backup_status_with_backup(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("backup10").await;

    // Upload backup
    app.request(
        Method::PUT,
        "/api/v1/keys/backup",
        Some(&token),
        Some(valid_backup_body()),
    )
    .await;

    let (status, value) = app
        .request(
            Method::GET,
            "/api/v1/keys/backup/status",
            Some(&token),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["has_backup"].as_bool(), Some(true));
    assert!(value["version"].is_number());
    assert!(value["updated_at"].is_string());
}
