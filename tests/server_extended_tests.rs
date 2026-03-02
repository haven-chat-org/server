mod common;

use axum::http::{Method, StatusCode};
use haven_backend::db::Pool;
use serde_json::json;

use common::TestApp;

// ─── Delete Server ────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn delete_server_as_owner(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("srv_del1").await;
    let server_id = app.create_server(&token, "Delete Me").await;

    let uri = format!("/api/v1/servers/{}", server_id);
    let (status, value) = app.request(Method::DELETE, &uri, Some(&token), None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["ok"].as_bool(), Some(true));

    // Verify server is gone
    let (status, _) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_ne!(status, StatusCode::OK);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn delete_server_non_owner_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("srv_del2").await;
    let (token_member, _) = app.register_user("srv_del3").await;
    let server_id = app.create_server(&token_owner, "No Delete").await;

    app.invite_and_join(&token_owner, &token_member, server_id)
        .await;

    let uri = format!("/api/v1/servers/{}", server_id);
    let (status, _) = app
        .request(Method::DELETE, &uri, Some(&token_member), None)
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── Leave Server ─────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn member_leaves_server(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("srv_leave1").await;
    let (token_member, _) = app.register_user("srv_leave2").await;
    let server_id = app.create_server(&token_owner, "Leave Test").await;

    app.invite_and_join(&token_owner, &token_member, server_id)
        .await;

    let uri = format!("/api/v1/servers/{}/members/@me", server_id);
    let (status, value) = app
        .request(Method::DELETE, &uri, Some(&token_member), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["ok"].as_bool(), Some(true));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn owner_cannot_leave_with_members(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("srv_leave3").await;
    let (token_member, _) = app.register_user("srv_leave4").await;
    let server_id = app.create_server(&token_owner, "Owner Leave").await;

    app.invite_and_join(&token_owner, &token_member, server_id)
        .await;

    let uri = format!("/api/v1/servers/{}/members/@me", server_id);
    let (status, _) = app
        .request(Method::DELETE, &uri, Some(&token_owner), None)
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn owner_leaves_as_sole_member_deletes_server(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("srv_leave5").await;
    let server_id = app.create_server(&token_owner, "Sole Owner").await;

    let uri = format!("/api/v1/servers/{}/members/@me", server_id);
    let (status, _) = app
        .request(Method::DELETE, &uri, Some(&token_owner), None)
        .await;

    assert_eq!(status, StatusCode::OK);

    // Server should be deleted
    let get_uri = format!("/api/v1/servers/{}", server_id);
    let (status, _) = app
        .request(Method::GET, &get_uri, Some(&token_owner), None)
        .await;
    assert_ne!(status, StatusCode::OK);
}

// ─── Timeout Member ───────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn timeout_member_as_owner(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("timeout1").await;
    let (token_member, member_id) = app.register_user("timeout2").await;
    let server_id = app.create_server(&token_owner, "Timeout Server").await;

    app.invite_and_join(&token_owner, &token_member, server_id)
        .await;

    let uri = format!("/api/v1/servers/{}/members/{}/timeout", server_id, member_id);
    let (status, value) = app
        .request(
            Method::PUT,
            &uri,
            Some(&token_owner),
            Some(json!({ "duration_seconds": 3600 })),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(value["timed_out_until"].is_string());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn timeout_member_no_permission_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, owner_id) = app.register_user("timeout3").await;
    let (token_member, _) = app.register_user("timeout4").await;
    let server_id = app.create_server(&token_owner, "Timeout Server2").await;

    app.invite_and_join(&token_owner, &token_member, server_id)
        .await;

    // Member tries to timeout the owner
    let uri = format!("/api/v1/servers/{}/members/{}/timeout", server_id, owner_id);
    let (status, _) = app
        .request(
            Method::PUT,
            &uri,
            Some(&token_member),
            Some(json!({ "duration_seconds": 3600 })),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── Set Member Nickname ──────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn set_member_nickname_as_owner(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("nick1").await;
    let (token_member, member_id) = app.register_user("nick2").await;
    let server_id = app.create_server(&token_owner, "Nick Server").await;

    app.invite_and_join(&token_owner, &token_member, server_id)
        .await;

    let uri = format!(
        "/api/v1/servers/{}/members/{}/nickname",
        server_id, member_id
    );
    let (status, value) = app
        .request(
            Method::PUT,
            &uri,
            Some(&token_owner),
            Some(json!({ "nickname": "NewNick" })),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["ok"].as_bool(), Some(true));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn set_member_nickname_no_permission_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, owner_id) = app.register_user("nick3").await;
    let (token_member, _) = app.register_user("nick4").await;
    let server_id = app.create_server(&token_owner, "Nick Server2").await;

    app.invite_and_join(&token_owner, &token_member, server_id)
        .await;

    let uri = format!(
        "/api/v1/servers/{}/members/{}/nickname",
        server_id, owner_id
    );
    let (status, _) = app
        .request(
            Method::PUT,
            &uri,
            Some(&token_member),
            Some(json!({ "nickname": "Hacker" })),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── Set Own Nickname ─────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn set_own_nickname(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("nick5").await;
    let server_id = app.create_server(&token, "Nick Server3").await;

    let uri = format!("/api/v1/servers/{}/nickname", server_id);
    let (status, value) = app
        .request(
            Method::PUT,
            &uri,
            Some(&token),
            Some(json!({ "nickname": "MyNick" })),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["ok"].as_bool(), Some(true));
}

// ─── Server Icon ──────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn upload_and_get_server_icon(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("icon1").await;
    let server_id = app.create_server(&token, "Icon Server").await;

    // Upload icon (minimal PNG header bytes)
    let png_bytes = vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG magic bytes
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
    ];
    let uri = format!("/api/v1/servers/{}/icon", server_id);
    let (status, value) = app
        .request_bytes(Method::POST, &uri, Some(&token), png_bytes)
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(value["icon_url"].is_string());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn get_icon_no_icon_returns_404(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("icon2").await;
    let server_id = app.create_server(&token, "No Icon Server").await;

    let uri = format!("/api/v1/servers/{}/icon", server_id);
    let (status, _) = app.request(Method::GET, &uri, None, None).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn delete_icon_no_permission_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("icon3").await;
    let (token_member, _) = app.register_user("icon4").await;
    let server_id = app.create_server(&token_owner, "Icon Server2").await;

    app.invite_and_join(&token_owner, &token_member, server_id)
        .await;

    let uri = format!("/api/v1/servers/{}/icon", server_id);
    let (status, _) = app
        .request(Method::DELETE, &uri, Some(&token_member), None)
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── Emojis ───────────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn list_emojis_empty(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("emoji1").await;
    let server_id = app.create_server(&token, "Emoji Server").await;

    let uri = format!("/api/v1/servers/{}/emojis", server_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;

    assert_eq!(status, StatusCode::OK);
    assert!(value.as_array().unwrap().is_empty());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn upload_emoji_name_too_short_returns_400(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("emoji2").await;
    let server_id = app.create_server(&token, "Emoji Server2").await;

    // Minimal valid PNG
    let png_bytes = vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    ];
    let uri = format!("/api/v1/servers/{}/emojis?name=a", server_id);
    let (status, _) = app
        .request_bytes(Method::POST, &uri, Some(&token), png_bytes)
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn upload_emoji_invalid_name_returns_400(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("emoji3").await;
    let server_id = app.create_server(&token, "Emoji Server3").await;

    let png_bytes = vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    ];
    let uri = format!("/api/v1/servers/{}/emojis?name=invalid%20name!!", server_id);
    let (status, _) = app
        .request_bytes(Method::POST, &uri, Some(&token), png_bytes)
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn upload_emoji_no_permission_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("emoji4").await;
    let (token_member, _) = app.register_user("emoji5").await;
    let server_id = app.create_server(&token_owner, "Emoji Server4").await;

    app.invite_and_join(&token_owner, &token_member, server_id)
        .await;

    let png_bytes = vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    ];
    let uri = format!("/api/v1/servers/{}/emojis?name=test_emoji", server_id);
    let (status, _) = app
        .request_bytes(Method::POST, &uri, Some(&token_member), png_bytes)
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── Content Filters ──────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn create_and_list_content_filters(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("cf1").await;
    let server_id = app.create_server(&token, "CF Server").await;

    let uri = format!("/api/v1/servers/{}/content-filters", server_id);

    // Create
    let (status, value) = app
        .request(
            Method::POST,
            &uri,
            Some(&token),
            Some(json!({ "pattern": "badword" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let filter_id = value["id"].as_str().unwrap();

    // List
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let filters = value.as_array().unwrap();
    assert_eq!(filters.len(), 1);
    assert_eq!(filters[0]["pattern"].as_str(), Some("badword"));

    // Delete
    let del_uri = format!("/api/v1/servers/{}/content-filters/{}", server_id, filter_id);
    let (status, value) = app
        .request(Method::DELETE, &del_uri, Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["deleted"].as_bool(), Some(true));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn create_content_filter_no_permission_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("cf2").await;
    let (token_member, _) = app.register_user("cf3").await;
    let server_id = app.create_server(&token_owner, "CF Server2").await;

    app.invite_and_join(&token_owner, &token_member, server_id)
        .await;

    let uri = format!("/api/v1/servers/{}/content-filters", server_id);
    let (status, _) = app
        .request(
            Method::POST,
            &uri,
            Some(&token_member),
            Some(json!({ "pattern": "test" })),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── Audit Log ────────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn get_audit_log_as_owner(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("audit1").await;
    let server_id = app.create_server(&token, "Audit Server").await;

    // Create a channel to generate an audit log entry
    app.create_channel(&token, server_id, "audit-test").await;

    let uri = format!("/api/v1/servers/{}/audit-log", server_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;

    assert_eq!(status, StatusCode::OK);
    assert!(value.as_array().is_some());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn get_audit_log_no_permission_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("audit2").await;
    let (token_member, _) = app.register_user("audit3").await;
    let server_id = app.create_server(&token_owner, "Audit Server2").await;

    app.invite_and_join(&token_owner, &token_member, server_id)
        .await;

    let uri = format!("/api/v1/servers/{}/audit-log", server_id);
    let (status, _) = app
        .request(Method::GET, &uri, Some(&token_member), None)
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── Export Server ────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn export_server_as_member(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("export1").await;
    let server_id = app.create_server(&token, "Export Server").await;

    let uri = format!("/api/v1/servers/{}/export", server_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        value["server_id"].as_str().unwrap(),
        server_id.to_string()
    );
    assert!(value["categories"].is_array());
    assert!(value["channels"].is_array());
    assert!(value["roles"].is_array());
    assert!(value["members"].is_array());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
async fn export_server_non_member_returns_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("export2").await;
    let (token_outsider, _) = app.register_user("export3").await;
    let server_id = app.create_server(&token_owner, "Export Server2").await;

    let uri = format!("/api/v1/servers/{}/export", server_id);
    let (status, _) = app
        .request(Method::GET, &uri, Some(&token_outsider), None)
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}
