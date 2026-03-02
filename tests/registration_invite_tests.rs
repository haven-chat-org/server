mod common;

use axum::http::{Method, StatusCode};
use haven_backend::db::Pool;
use serde_json::json;

use common::TestApp;

// ─── Invite Required (Public) ─────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn invite_required_returns_config_value(pool: Pool) {
    let app = TestApp::new(pool).await;

    let (status, value) = app
        .request(
            Method::GET,
            "/api/v1/auth/invite-required",
            None,
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    // Default test config has registration_invite_only = false
    assert_eq!(value["invite_required"].as_bool(), Some(false));
}

// ─── List My Registration Invites ─────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn list_my_registration_invites_empty(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("ri1").await;

    let (status, value) = app
        .request(
            Method::GET,
            "/api/v1/registration-invites",
            Some(&token),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(value.as_array().is_some());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn list_my_registration_invites_no_auth_returns_401(pool: Pool) {
    let app = TestApp::new(pool).await;

    let (status, _) = app
        .request(
            Method::GET,
            "/api/v1/registration-invites",
            None,
            None,
        )
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ─── Admin Delete Nonexistent Invite ──────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_delete_nonexistent_registration_invite_returns_404(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("ri_admin1").await;
    app.make_admin(user_id).await;

    let fake_id = uuid::Uuid::new_v4();
    let uri = format!("/api/v1/admin/registration-invites/{}", fake_id);
    let (status, _) = app
        .request(Method::DELETE, &uri, Some(&token), None)
        .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ─── Admin Create and List Invites ────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_create_registration_invites_default_count(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("ri_admin2").await;
    app.make_admin(user_id).await;

    // Create with default count (should be 1)
    let (status, value) = app
        .request(
            Method::POST,
            "/api/v1/admin/registration-invites",
            Some(&token),
            Some(json!({})),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    let invites = value.as_array().unwrap();
    assert_eq!(invites.len(), 1);
    assert!(invites[0]["code"].is_string());
}
