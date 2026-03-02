mod common;

use axum::http::{Method, StatusCode};
use haven_backend::db::Pool;
use serde_json::json;
use uuid::Uuid;

use common::TestApp;

// ─── Admin Stats ──────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_stats_returns_counts(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("admin1").await;
    app.make_admin(user_id).await;

    let (status, value) = app
        .request(Method::GET, "/api/v1/admin/stats", Some(&token), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(value["total_users"].is_number());
    assert!(value["total_servers"].is_number());
    assert!(value["total_channels"].is_number());
    assert!(value["total_messages"].is_number());
    assert!(value["active_connections"].is_number());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_stats_non_admin_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("nonadmin").await;

    let (status, _) = app
        .request(Method::GET, "/api/v1/admin/stats", Some(&token), None)
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_stats_no_auth_returns_401(pool: Pool) {
    let app = TestApp::new(pool).await;

    let (status, _) = app
        .request(Method::GET, "/api/v1/admin/stats", None, None)
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ─── Admin Users ──────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_list_users(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("admin2").await;
    app.make_admin(user_id).await;
    app.register_user("user_a").await;
    app.register_user("user_b").await;

    let (status, value) = app
        .request(Method::GET, "/api/v1/admin/users", Some(&token), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    let users = value.as_array().unwrap();
    assert!(users.len() >= 3);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_list_users_non_admin_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("nonadmin2").await;

    let (status, _) = app
        .request(Method::GET, "/api/v1/admin/users", Some(&token), None)
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_list_users_search_filter(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("admin3").await;
    app.make_admin(user_id).await;
    app.register_user("searchable_xyz").await;
    app.register_user("other_user").await;

    let (status, value) = app
        .request(
            Method::GET,
            "/api/v1/admin/users?search=searchable",
            Some(&token),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    let users = value.as_array().unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["username"].as_str().unwrap(), "searchable_xyz");
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_list_users_pagination(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("admin4").await;
    app.make_admin(user_id).await;
    app.register_user("page_user1").await;
    app.register_user("page_user2").await;

    let (status, value) = app
        .request(
            Method::GET,
            "/api/v1/admin/users?limit=1&offset=0",
            Some(&token),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    let users = value.as_array().unwrap();
    assert_eq!(users.len(), 1);
}

// ─── Admin Set Admin ──────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_promote_user(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("admin5").await;
    app.make_admin(user_id).await;
    let (_, target_id) = app.register_user("promote_me").await;

    let uri = format!("/api/v1/admin/users/{}/admin", target_id);
    let (status, value) = app
        .request(Method::PUT, &uri, Some(&token), Some(json!({ "is_admin": true })))
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["is_instance_admin"].as_bool(), Some(true));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_promote_non_admin_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("nonadmin3").await;
    let (_, target_id) = app.register_user("target3").await;

    let uri = format!("/api/v1/admin/users/{}/admin", target_id);
    let (status, _) = app
        .request(Method::PUT, &uri, Some(&token), Some(json!({ "is_admin": true })))
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_cannot_self_demote(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("admin6").await;
    app.make_admin(user_id).await;

    let uri = format!("/api/v1/admin/users/{}/admin", user_id);
    let (status, _) = app
        .request(Method::PUT, &uri, Some(&token), Some(json!({ "is_admin": false })))
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_promote_nonexistent_returns_404(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("admin7").await;
    app.make_admin(user_id).await;

    let fake_id = Uuid::new_v4();
    let uri = format!("/api/v1/admin/users/{}/admin", fake_id);
    let (status, _) = app
        .request(Method::PUT, &uri, Some(&token), Some(json!({ "is_admin": true })))
        .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ─── Admin Delete User ────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_delete_user(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("admin8").await;
    app.make_admin(user_id).await;
    let (_, target_id) = app.register_user("deleteme").await;

    let uri = format!("/api/v1/admin/users/{}", target_id);
    let (status, value) = app
        .request(Method::DELETE, &uri, Some(&token), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["deleted"].as_bool(), Some(true));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_delete_user_non_admin_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("nonadmin4").await;
    let (_, target_id) = app.register_user("target4").await;

    let uri = format!("/api/v1/admin/users/{}", target_id);
    let (status, _) = app
        .request(Method::DELETE, &uri, Some(&token), None)
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_cannot_delete_self(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("admin9").await;
    app.make_admin(user_id).await;

    let uri = format!("/api/v1/admin/users/{}", user_id);
    let (status, _) = app
        .request(Method::DELETE, &uri, Some(&token), None)
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ─── Admin Reports ────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_list_reports(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("admin10").await;
    app.make_admin(user_id).await;

    let (status, value) = app
        .request(Method::GET, "/api/v1/admin/reports", Some(&token), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(value.as_array().is_some());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_list_reports_non_admin_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("nonadmin5").await;

    let (status, _) = app
        .request(Method::GET, "/api/v1/admin/reports", Some(&token), None)
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_report_counts(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("admin11").await;
    app.make_admin(user_id).await;

    let (status, value) = app
        .request(
            Method::GET,
            "/api/v1/admin/reports/counts",
            Some(&token),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(value["pending"].is_number());
    assert!(value["reviewed"].is_number());
    assert!(value["dismissed"].is_number());
    assert!(value["escalated"].is_number());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_get_report_nonexistent_returns_404(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("admin12").await;
    app.make_admin(user_id).await;

    let fake_id = Uuid::new_v4();
    let uri = format!("/api/v1/admin/reports/{}", fake_id);
    let (status, _) = app.request(Method::GET, &uri, Some(&token), None).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ─── Admin Instance Bans ──────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_list_instance_bans(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("admin13").await;
    app.make_admin(user_id).await;

    let (status, value) = app
        .request(Method::GET, "/api/v1/admin/bans", Some(&token), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(value.as_array().is_some());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_ban_and_revoke_user(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("admin14").await;
    app.make_admin(user_id).await;
    let (_, target_id) = app.register_user("banme").await;

    // Ban user
    let ban_uri = format!("/api/v1/admin/bans/{}", target_id);
    let (status, value) = app
        .request(
            Method::POST,
            &ban_uri,
            Some(&token),
            Some(json!({ "reason": "test ban" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["user_id"].as_str().unwrap(), target_id.to_string());

    // Revoke ban
    let (status, value) = app
        .request(Method::DELETE, &ban_uri, Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["unbanned"].as_bool(), Some(true));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_cannot_ban_self(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("admin15").await;
    app.make_admin(user_id).await;

    let uri = format!("/api/v1/admin/bans/{}", user_id);
    let (status, _) = app
        .request(Method::POST, &uri, Some(&token), Some(json!({})))
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ─── Admin Blocked Hashes ─────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_blocked_hash_crud(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("admin16").await;
    app.make_admin(user_id).await;

    // Create
    let valid_hash = "a".repeat(64);
    let (status, value) = app
        .request(
            Method::POST,
            "/api/v1/admin/blocked-hashes",
            Some(&token),
            Some(json!({ "hash": valid_hash, "description": "test hash" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let hash_id = value["id"].as_str().unwrap();

    // List
    let (status, value) = app
        .request(
            Method::GET,
            "/api/v1/admin/blocked-hashes",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!value.as_array().unwrap().is_empty());

    // Delete
    let uri = format!("/api/v1/admin/blocked-hashes/{}", hash_id);
    let (status, value) = app
        .request(Method::DELETE, &uri, Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["deleted"].as_bool(), Some(true));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_blocked_hash_invalid_format_returns_400(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("admin17").await;
    app.make_admin(user_id).await;

    // Too short
    let (status, _) = app
        .request(
            Method::POST,
            "/api/v1/admin/blocked-hashes",
            Some(&token),
            Some(json!({ "hash": "abc123" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Non-hex characters
    let (status, _) = app
        .request(
            Method::POST,
            "/api/v1/admin/blocked-hashes",
            Some(&token),
            Some(json!({ "hash": "g".repeat(64) })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ─── Admin Registration Invites ───────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn admin_registration_invite_crud(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("admin18").await;
    app.make_admin(user_id).await;

    // Create
    let (status, value) = app
        .request(
            Method::POST,
            "/api/v1/admin/registration-invites",
            Some(&token),
            Some(json!({ "count": 2 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let invites = value.as_array().unwrap();
    assert_eq!(invites.len(), 2);
    let invite_id = invites[0]["id"].as_str().unwrap();

    // List
    let (status, value) = app
        .request(
            Method::GET,
            "/api/v1/admin/registration-invites",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(value.as_array().unwrap().len() >= 2);

    // Delete
    let uri = format!("/api/v1/admin/registration-invites/{}", invite_id);
    let (status, value) = app
        .request(Method::DELETE, &uri, Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["deleted"].as_bool(), Some(true));
}
