mod common;

use axum::http::{Method, StatusCode};
use haven_backend::db::Pool;
use serde_json::json;

use common::TestApp;

// ─── Link Preview ─────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn link_preview_no_auth_returns_401(pool: Pool) {
    let app = TestApp::new(pool).await;

    let (status, _) = app
        .request(
            Method::GET,
            "/api/v1/link-preview?url=https://example.com",
            None,
            None,
        )
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn link_preview_invalid_url_returns_400(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("lp1").await;

    let (status, _) = app
        .request(
            Method::GET,
            "/api/v1/link-preview?url=not-a-url",
            Some(&token),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn link_preview_private_ip_blocked(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("lp2").await;

    // Attempt SSRF with loopback
    let (status, _) = app
        .request(
            Method::GET,
            "/api/v1/link-preview?url=http://127.0.0.1/admin",
            Some(&token),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ─── GIF Search ───────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn gif_search_not_configured_returns_400(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("gif1").await;

    // GIPHY_API_KEY is empty in test config
    let (status, value) = app
        .request(
            Method::GET,
            "/api/v1/gifs/search?q=cats",
            Some(&token),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(value["error"]
        .as_str()
        .unwrap_or("")
        .to_lowercase()
        .contains("configured")
        || value["error"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("gif"));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn gif_trending_not_configured_returns_400(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("gif2").await;

    let (status, _) = app
        .request(
            Method::GET,
            "/api/v1/gifs/trending",
            Some(&token),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ─── Beta Code Request ────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn beta_request_code_smtp_not_configured_returns_400(pool: Pool) {
    let app = TestApp::new(pool).await;

    // SMTP is not configured in test env
    let (status, _) = app
        .request(
            Method::POST,
            "/api/v1/beta/request-code",
            None,
            Some(json!({ "email": "test@example.com" })),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}
