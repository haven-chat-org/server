mod common;

use axum::http::{Method, StatusCode};
use base64::Engine;
use serde_json::json;
use haven_backend::db::Pool;
use uuid::Uuid;

use common::TestApp;

const B64: &base64::engine::GeneralPurpose = &base64::engine::general_purpose::STANDARD;

// ─── Auth ────────────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn register_returns_tokens_and_user(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("alice").await;

    assert!(!token.is_empty());
    assert!(!user_id.is_nil());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn login_with_correct_password(pool: Pool) {
    let app = TestApp::new(pool).await;
    app.register_user("bob").await;

    let (access, refresh, user_id) = app.login_user("bob").await;
    assert!(!access.is_empty());
    assert!(!refresh.is_empty());
    assert!(!user_id.is_nil());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn login_with_wrong_password_returns_401(pool: Pool) {
    let app = TestApp::new(pool).await;
    app.register_user("carol").await;

    let body = json!({ "username": "carol", "password": "wrongpassword" });
    let (status, _) = app
        .request(Method::POST, "/api/v1/auth/login", None, Some(body))
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn protected_route_without_token_returns_401(pool: Pool) {
    let app = TestApp::new(pool).await;

    let (status, _) = app
        .request(Method::GET, "/api/v1/servers", None, None)
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn protected_route_with_valid_token_returns_200(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("dave").await;

    let (status, _) = app
        .request(Method::GET, "/api/v1/servers", Some(&token), None)
        .await;

    assert_eq!(status, StatusCode::OK);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn duplicate_username_returns_error(pool: Pool) {
    let app = TestApp::new(pool).await;
    app.register_user("duplicate").await;

    // Try registering again with the same username
    let b64 = &base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let fake_key = b64.encode([0u8; 32]);
    let fake_sig = b64.encode([0u8; 64]);
    let body = json!({
        "username": "duplicate",
        "password": "testpassword123",
        "identity_key": fake_key,
        "signed_prekey": fake_key,
        "signed_prekey_signature": fake_sig,
        "one_time_prekeys": []
    });

    let (status, _) = app
        .request(Method::POST, "/api/v1/auth/register", None, Some(body))
        .await;

    // Should fail (conflict or bad request)
    assert_ne!(status, StatusCode::OK);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn refresh_token_returns_new_access_token(pool: Pool) {
    let app = TestApp::new(pool).await;
    app.register_user("refresh_user").await;

    let (_, refresh, _) = app.login_user("refresh_user").await;

    let body = json!({ "refresh_token": refresh });
    let (status, value) = app
        .request(Method::POST, "/api/v1/auth/refresh", None, Some(body))
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(value["access_token"].as_str().is_some());
}

// ─── Servers ─────────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn create_server_returns_server(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("server_owner").await;

    let server_id = app.create_server(&token, "Test Server").await;
    assert!(!server_id.is_nil());

    // Verify owner_id in get-server response
    let uri = format!("/api/v1/servers/{}", server_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["owner_id"].as_str().unwrap(), user_id.to_string());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn list_servers_includes_created_server(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("lister").await;

    app.create_server(&token, "My Server").await;

    let (status, value) = app
        .request(Method::GET, "/api/v1/servers", Some(&token), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    let servers = value.as_array().unwrap();
    assert_eq!(servers.len(), 1);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn non_member_cannot_access_server(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("owner_a").await;
    let (token_b, _) = app.register_user("outsider_b").await;

    let server_id = app.create_server(&token_a, "Private").await;

    // User B is not a member
    let uri = format!("/api/v1/servers/{}", server_id);
    let (status, _) = app.request(Method::GET, &uri, Some(&token_b), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── Channels ────────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn create_channel_and_list(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("chan_owner").await;
    let server_id = app.create_server(&token, "Channel Test").await;

    let channel_id = app.create_channel(&token, server_id, "dev-chat").await;
    assert!(!channel_id.is_nil());

    // List channels — should have "general" (auto-created) + "dev-chat"
    let uri = format!("/api/v1/servers/{}/channels", server_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);

    let channels = value.as_array().unwrap();
    assert_eq!(channels.len(), 2);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn delete_channel_removes_it(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("del_owner").await;
    let server_id = app.create_server(&token, "Del Test").await;

    let channel_id = app.create_channel(&token, server_id, "to-delete").await;

    // Delete the channel
    let uri = format!("/api/v1/channels/{}", channel_id);
    let (status, _) = app
        .request(Method::DELETE, &uri, Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // List channels — should only have "general"
    let uri = format!("/api/v1/servers/{}/channels", server_id);
    let (_, value) = app.request(Method::GET, &uri, Some(&token), None).await;
    let channels = value.as_array().unwrap();
    assert_eq!(channels.len(), 1);
}

// ─── Categories ──────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn create_and_list_categories(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("cat_owner").await;
    let server_id = app.create_server(&token, "Cat Test").await;

    // Create a category
    let uri = format!("/api/v1/servers/{}/categories", server_id);
    let body = json!({ "name": "Voice Channels", "position": 0 });
    let (status, value) = app
        .request(Method::POST, &uri, Some(&token), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    let cat_id = value["id"].as_str().unwrap();

    // List categories
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let categories = value.as_array().unwrap();
    assert!(categories.iter().any(|c| c["id"].as_str() == Some(cat_id)));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn assign_channel_to_category(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("assign_owner").await;
    let server_id = app.create_server(&token, "Assign Test").await;

    // Create category
    let cat_uri = format!("/api/v1/servers/{}/categories", server_id);
    let (_, cat_val) = app
        .request(
            Method::POST,
            &cat_uri,
            Some(&token),
            Some(json!({ "name": "Text", "position": 0 })),
        )
        .await;
    let cat_id = cat_val["id"].as_str().unwrap();

    // Create channel
    let channel_id = app.create_channel(&token, server_id, "my-channel").await;

    // Assign channel to category
    let uri = format!("/api/v1/channels/{}/category", channel_id);
    let (status, _) = app
        .request(
            Method::PUT,
            &uri,
            Some(&token),
            Some(json!({ "category_id": cat_id })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Verify via channel list
    let list_uri = format!("/api/v1/servers/{}/channels", server_id);
    let (_, value) = app
        .request(Method::GET, &list_uri, Some(&token), None)
        .await;
    let channels = value.as_array().unwrap();
    let ch = channels
        .iter()
        .find(|c| c["id"].as_str().unwrap() == channel_id.to_string())
        .unwrap();
    assert_eq!(ch["category_id"].as_str().unwrap(), cat_id);
}

// ─── Roles ───────────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn server_has_default_everyone_role(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("role_owner").await;
    let server_id = app.create_server(&token, "Role Test").await;

    let uri = format!("/api/v1/servers/{}/roles", server_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);

    let roles = value.as_array().unwrap();
    assert!(roles.iter().any(|r| r["is_default"].as_bool() == Some(true)));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn create_custom_role(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("role_creator").await;
    let server_id = app.create_server(&token, "Custom Role Test").await;

    let uri = format!("/api/v1/servers/{}/roles", server_id);
    let body = json!({
        "name": "Moderator",
        "color": "#00ff00",
        "permissions": "8", // MANAGE_CHANNELS
        "position": 1
    });

    let (status, value) = app
        .request(Method::POST, &uri, Some(&token), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["name"].as_str(), Some("Moderator"));
    assert_eq!(value["color"].as_str(), Some("#00ff00"));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn assign_role_to_member(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("role_assigner").await;
    let (token_member, member_id) = app.register_user("role_target").await;
    let server_id = app.create_server(&token_owner, "Assign Role Test").await;

    // Invite member to server
    let inv_uri = format!("/api/v1/servers/{}/invites", server_id);
    let (_, inv_val) = app
        .request(
            Method::POST,
            &inv_uri,
            Some(&token_owner),
            Some(json!({ "expires_in_hours": 24 })),
        )
        .await;
    let code = inv_val["code"].as_str().unwrap();

    // Member joins
    let join_uri = format!("/api/v1/invites/{}/join", code);
    let (status, _) = app
        .request(Method::POST, &join_uri, Some(&token_member), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Create a role
    let roles_uri = format!("/api/v1/servers/{}/roles", server_id);
    let (_, role_val) = app
        .request(
            Method::POST,
            &roles_uri,
            Some(&token_owner),
            Some(json!({ "name": "VIP", "position": 1 })),
        )
        .await;
    let role_id = role_val["id"].as_str().unwrap();

    // Assign role to member
    let assign_uri = format!(
        "/api/v1/servers/{}/members/{}/roles",
        server_id, member_id
    );
    let (status, _) = app
        .request(
            Method::PUT,
            &assign_uri,
            Some(&token_owner),
            Some(json!({ "role_id": role_id })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

// ─── Permissions ─────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn user_without_manage_channels_gets_403(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("perm_owner").await;
    let (token_member, _) = app.register_user("perm_member").await;
    let server_id = app.create_server(&token_owner, "Perm Test").await;

    // Invite member
    let inv_uri = format!("/api/v1/servers/{}/invites", server_id);
    let (_, inv_val) = app
        .request(
            Method::POST,
            &inv_uri,
            Some(&token_owner),
            Some(json!({ "expires_in_hours": 24 })),
        )
        .await;
    let code = inv_val["code"].as_str().unwrap();
    let join_uri = format!("/api/v1/invites/{}/join", code);
    app.request(Method::POST, &join_uri, Some(&token_member), None)
        .await;

    // Member tries to create a channel — should be 403 (no MANAGE_CHANNELS)
    use base64::Engine;
    let b64 = &base64::engine::general_purpose::STANDARD;
    let body = json!({ "encrypted_meta": b64.encode(b"test") });
    let uri = format!("/api/v1/servers/{}/channels", server_id);
    let (status, _) = app
        .request(Method::POST, &uri, Some(&token_member), Some(body))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── Invites ─────────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn create_and_use_invite(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("inv_owner").await;
    let (token_joiner, _) = app.register_user("inv_joiner").await;
    let server_id = app.create_server(&token_owner, "Invite Test").await;

    // Create invite
    let uri = format!("/api/v1/servers/{}/invites", server_id);
    let (status, value) = app
        .request(
            Method::POST,
            &uri,
            Some(&token_owner),
            Some(json!({ "expires_in_hours": 24 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let code = value["code"].as_str().unwrap();

    // Joiner uses the invite
    let join_uri = format!("/api/v1/invites/{}/join", code);
    let (status, _) = app
        .request(Method::POST, &join_uri, Some(&token_joiner), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Verify joiner can list channels
    let chan_uri = format!("/api/v1/servers/{}/channels", server_id);
    let (status, _) = app
        .request(Method::GET, &chan_uri, Some(&token_joiner), None)
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn invalid_invite_code_returns_error(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("bad_inv").await;

    let (status, _) = app
        .request(
            Method::POST,
            "/api/v1/invites/INVALIDCODE/join",
            Some(&token),
            None,
        )
        .await;

    assert_ne!(status, StatusCode::OK);
}

// ─── Friends ─────────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn send_and_accept_friend_request(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("friend_a").await;
    let (token_b, _) = app.register_user("friend_b").await;

    // A sends request to B
    let body = json!({ "username": "friend_b" });
    let (status, value) = app
        .request(
            Method::POST,
            "/api/v1/friends/request",
            Some(&token_a),
            Some(body),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["status"].as_str(), Some("pending"));
    let friendship_id = value["id"].as_str().unwrap();

    // B accepts the request
    let accept_uri = format!("/api/v1/friends/{}/accept", friendship_id);
    let (status, value) = app
        .request(Method::POST, &accept_uri, Some(&token_b), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["status"].as_str(), Some("accepted"));

    // Both should see each other in friends list
    let (_, val_a) = app
        .request(Method::GET, "/api/v1/friends", Some(&token_a), None)
        .await;
    let friends_a = val_a.as_array().unwrap();
    assert!(friends_a
        .iter()
        .any(|f| f["status"].as_str() == Some("accepted")));

    let (_, val_b) = app
        .request(Method::GET, "/api/v1/friends", Some(&token_b), None)
        .await;
    let friends_b = val_b.as_array().unwrap();
    assert!(friends_b
        .iter()
        .any(|f| f["status"].as_str() == Some("accepted")));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn decline_friend_request(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("decl_a").await;
    let (token_b, _) = app.register_user("decl_b").await;

    // A sends request to B
    let (_, value) = app
        .request(
            Method::POST,
            "/api/v1/friends/request",
            Some(&token_a),
            Some(json!({ "username": "decl_b" })),
        )
        .await;
    let friendship_id = value["id"].as_str().unwrap();

    // B declines
    let uri = format!("/api/v1/friends/{}/decline", friendship_id);
    let (status, _) = app
        .request(Method::POST, &uri, Some(&token_b), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // A's friends list should be empty (or no accepted friends)
    let (_, val) = app
        .request(Method::GET, "/api/v1/friends", Some(&token_a), None)
        .await;
    let friends = val.as_array().unwrap();
    assert!(friends
        .iter()
        .all(|f| f["status"].as_str() != Some("accepted")));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn mutual_friend_request_auto_accepts(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("mutual_a").await;
    let (token_b, _) = app.register_user("mutual_b").await;

    // A sends request to B
    app.request(
        Method::POST,
        "/api/v1/friends/request",
        Some(&token_a),
        Some(json!({ "username": "mutual_b" })),
    )
    .await;

    // B also sends request to A — should auto-accept
    let (status, value) = app
        .request(
            Method::POST,
            "/api/v1/friends/request",
            Some(&token_b),
            Some(json!({ "username": "mutual_a" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["status"].as_str(), Some("accepted"));
}

// ─── Health Check ────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn health_check_returns_ok(pool: Pool) {
    let app = TestApp::new(pool).await;

    let (status, value) = app.request(Method::GET, "/health", None, None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value.as_str(), Some("ok"));
}

// ─── Auth Extended ──────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn logout_revokes_tokens(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("logout_user").await;

    let (status, _) = app
        .request(Method::POST, "/api/v1/auth/logout", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn change_password_success(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("pw_change").await;

    let body = json!({
        "current_password": "testpassword123",
        "new_password": "newpassword456"
    });
    let (status, _) = app
        .request(Method::PUT, "/api/v1/auth/password", Some(&token), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);

    // Old password should fail
    let (status, _) = app
        .request(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "pw_change", "password": "testpassword123" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // New password should work
    let (status, _) = app
        .request(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "pw_change", "password": "newpassword456" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn change_password_wrong_current_fails(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("pw_wrong").await;

    let body = json!({
        "current_password": "wrongpassword",
        "new_password": "newpassword456"
    });
    let (status, _) = app
        .request(Method::PUT, "/api/v1/auth/password", Some(&token), Some(body))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ─── Messages ───────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn send_and_get_messages(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("msg_user").await;
    let server_id = app.create_server(&token, "Msg Server").await;
    let channel_id = app.create_channel(&token, server_id, "general").await;

    // Send a message
    let (msg_id, msg_val) = app.send_message(&token, channel_id).await;
    assert!(!msg_id.is_nil());
    assert_eq!(msg_val["channel_id"].as_str().unwrap(), channel_id.to_string());

    // Get messages
    let uri = format!("/api/v1/channels/{}/messages", channel_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let messages = value.as_array().unwrap();
    assert!(messages.iter().any(|m| m["id"].as_str().unwrap() == msg_id.to_string()));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn send_reply_includes_reply_to_id(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("reply_user").await;
    let server_id = app.create_server(&token, "Reply Server").await;
    let channel_id = app.create_channel(&token, server_id, "general").await;

    let (original_id, _) = app.send_message(&token, channel_id).await;
    let (reply_id, reply_val) = app.send_reply(&token, channel_id, original_id).await;

    assert!(!reply_id.is_nil());
    assert_eq!(
        reply_val["reply_to_id"].as_str().unwrap(),
        original_id.to_string()
    );
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn non_member_cannot_get_messages(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("msg_owner").await;
    let (token_b, _) = app.register_user("msg_outsider").await;
    let server_id = app.create_server(&token_a, "Private Msgs").await;
    let channel_id = app.create_channel(&token_a, server_id, "secret").await;

    let uri = format!("/api/v1/channels/{}/messages", channel_id);
    let (status, _) = app.request(Method::GET, &uri, Some(&token_b), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── Pins ───────────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn get_pins_empty_initially(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("pin_user").await;
    let server_id = app.create_server(&token, "Pin Server").await;
    let channel_id = app.create_channel(&token, server_id, "general").await;

    let uri = format!("/api/v1/channels/{}/pins", channel_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value.as_array().unwrap().len(), 0);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn get_pin_ids_empty_initially(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("pinid_user").await;
    let server_id = app.create_server(&token, "PinId Server").await;
    let channel_id = app.create_channel(&token, server_id, "general").await;

    let uri = format!("/api/v1/channels/{}/pin-ids", channel_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value.as_array().unwrap().len(), 0);
}

// ─── Reports ────────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn create_report_success(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("reporter").await;
    let server_id = app.create_server(&token, "Report Server").await;
    let channel_id = app.create_channel(&token, server_id, "general").await;

    let (msg_id, _) = app.send_message(&token, channel_id).await;

    let body = json!({
        "message_id": msg_id,
        "channel_id": channel_id,
        "reason": "This message violates the rules and is inappropriate."
    });
    let (status, value) = app
        .request(Method::POST, "/api/v1/reports", Some(&token), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["status"].as_str(), Some("pending"));
    assert!(value["id"].as_str().is_some());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn create_report_short_reason_fails(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("short_report").await;
    let server_id = app.create_server(&token, "Report2").await;
    let channel_id = app.create_channel(&token, server_id, "general").await;
    let (msg_id, _) = app.send_message(&token, channel_id).await;

    let body = json!({
        "message_id": msg_id,
        "channel_id": channel_id,
        "reason": "short"
    });
    let (status, _) = app
        .request(Method::POST, "/api/v1/reports", Some(&token), Some(body))
        .await;
    assert_ne!(status, StatusCode::OK);
}

// ─── Bans ───────────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn ban_and_list_bans(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("ban_owner").await;
    let (token_target, target_id) = app.register_user("ban_target").await;
    let server_id = app.create_server(&token_owner, "Ban Server").await;

    app.invite_and_join(&token_owner, &token_target, server_id).await;

    // Ban the target
    let ban_uri = format!("/api/v1/servers/{}/bans/{}", server_id, target_id);
    let (status, value) = app
        .request(
            Method::POST,
            &ban_uri,
            Some(&token_owner),
            Some(json!({ "reason": "Test ban" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["user_id"].as_str().unwrap(), target_id.to_string());

    // List bans
    let list_uri = format!("/api/v1/servers/{}/bans", server_id);
    let (status, value) = app
        .request(Method::GET, &list_uri, Some(&token_owner), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let bans = value.as_array().unwrap();
    assert_eq!(bans.len(), 1);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn revoke_ban(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("unban_owner").await;
    let (token_target, target_id) = app.register_user("unban_target").await;
    let server_id = app.create_server(&token_owner, "Unban Server").await;

    app.invite_and_join(&token_owner, &token_target, server_id).await;

    // Ban then unban
    let ban_uri = format!("/api/v1/servers/{}/bans/{}", server_id, target_id);
    app.request(
        Method::POST,
        &ban_uri,
        Some(&token_owner),
        Some(json!({ "reason": "Temp ban" })),
    )
    .await;

    let (status, value) = app
        .request(Method::DELETE, &ban_uri, Some(&token_owner), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["unbanned"].as_bool(), Some(true));

    // Bans list should be empty
    let list_uri = format!("/api/v1/servers/{}/bans", server_id);
    let (_, value) = app
        .request(Method::GET, &list_uri, Some(&token_owner), None)
        .await;
    assert_eq!(value.as_array().unwrap().len(), 0);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn banned_user_cannot_rejoin(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("banrej_owner").await;
    let (token_target, target_id) = app.register_user("banrej_target").await;
    let server_id = app.create_server(&token_owner, "BanReJoin").await;

    app.invite_and_join(&token_owner, &token_target, server_id).await;

    // Ban
    let ban_uri = format!("/api/v1/servers/{}/bans/{}", server_id, target_id);
    app.request(
        Method::POST,
        &ban_uri,
        Some(&token_owner),
        Some(json!({})),
    )
    .await;

    // Create new invite and try to rejoin
    let inv_uri = format!("/api/v1/servers/{}/invites", server_id);
    let (_, inv_val) = app
        .request(
            Method::POST,
            &inv_uri,
            Some(&token_owner),
            Some(json!({ "expires_in_hours": 24 })),
        )
        .await;
    let code = inv_val["code"].as_str().unwrap();
    let join_uri = format!("/api/v1/invites/{}/join", code);
    let (status, _) = app
        .request(Method::POST, &join_uri, Some(&token_target), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── User Profiles ──────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn get_user_profile(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("profile_a").await;
    let (_, user_b) = app.register_user("profile_b").await;

    let uri = format!("/api/v1/users/{}/profile", user_b);
    let (status, value) = app.request(Method::GET, &uri, Some(&token_a), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["username"].as_str(), Some("profile_b"));
    assert_eq!(value["is_friend"].as_bool(), Some(false));
    assert_eq!(value["is_blocked"].as_bool(), Some(false));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn update_profile(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("update_prof").await;

    let body = json!({
        "display_name": "Updated Name",
        "about_me": "Hello world",
        "custom_status": "Coding",
        "custom_status_emoji": "💻"
    });
    let (status, value) = app
        .request(Method::PUT, "/api/v1/users/profile", Some(&token), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["display_name"].as_str(), Some("Updated Name"));
    assert_eq!(value["about_me"].as_str(), Some("Hello world"));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn search_user_by_username(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("search_me").await;

    let (status, value) = app
        .request(
            Method::GET,
            "/api/v1/users/search?username=search_me",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["username"].as_str(), Some("search_me"));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn search_nonexistent_user_returns_404(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("searcher").await;

    let (status, _) = app
        .request(
            Method::GET,
            "/api/v1/users/search?username=doesnotexist",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ─── Blocked Users ──────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn block_and_unblock_user(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("blocker").await;
    let (_, user_b) = app.register_user("blockee").await;

    // Block
    let block_uri = format!("/api/v1/users/{}/block", user_b);
    let (status, _) = app
        .request(Method::POST, &block_uri, Some(&token_a), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Get blocked users
    let (status, value) = app
        .request(Method::GET, "/api/v1/users/blocked", Some(&token_a), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let blocked = value.as_array().unwrap();
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0]["user_id"].as_str().unwrap(), user_b.to_string());

    // Unblock
    let (status, _) = app
        .request(Method::DELETE, &block_uri, Some(&token_a), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Blocked list should be empty
    let (_, value) = app
        .request(Method::GET, "/api/v1/users/blocked", Some(&token_a), None)
        .await;
    assert_eq!(value.as_array().unwrap().len(), 0);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn cannot_block_self(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("self_blocker").await;

    let uri = format!("/api/v1/users/{}/block", user_id);
    let (status, _) = app.request(Method::POST, &uri, Some(&token), None).await;
    assert_ne!(status, StatusCode::OK);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn blocked_user_cannot_send_friend_request(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("block_fr_a").await;
    let (token_b, user_b) = app.register_user("block_fr_b").await;

    // A blocks B
    let block_uri = format!("/api/v1/users/{}/block", user_b);
    app.request(Method::POST, &block_uri, Some(&token_a), None).await;

    // B tries to friend A
    let (status, _) = app
        .request(
            Method::POST,
            "/api/v1/friends/request",
            Some(&token_b),
            Some(json!({ "username": "block_fr_a" })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── DMs ────────────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn create_and_list_dm(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("dm_a").await;
    let (token_b, user_b) = app.register_user("dm_b").await;

    let b64 = &base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let body = json!({
        "target_user_id": user_b,
        "encrypted_meta": b64.encode(b"dm-meta")
    });
    let (status, value) = app
        .request(Method::POST, "/api/v1/dm", Some(&token_a), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["channel_type"].as_str(), Some("dm"));

    // List DMs for user A
    let (status, value) = app
        .request(Method::GET, "/api/v1/dm", Some(&token_a), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value.as_array().unwrap().len(), 1);

    // User B should also see the DM
    let (status, value) = app
        .request(Method::GET, "/api/v1/dm", Some(&token_b), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value.as_array().unwrap().len(), 1);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn create_group_dm(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("gdm_a").await;
    let (token_b, user_b) = app.register_user("gdm_b").await;
    let (token_c, user_c) = app.register_user("gdm_c").await;

    // Make friends first
    app.make_friends(&token_a, &token_b, "gdm_b").await;
    app.make_friends(&token_a, &token_c, "gdm_c").await;

    let b64 = &base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let body = json!({
        "member_ids": [user_b, user_c],
        "encrypted_meta": b64.encode(b"group-dm-meta")
    });
    let (status, value) = app
        .request(Method::POST, "/api/v1/dm/group", Some(&token_a), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["channel_type"].as_str(), Some("group"));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn group_dm_requires_friends(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("gdm_nf_a").await;
    let (_, user_b) = app.register_user("gdm_nf_b").await;
    let (_, user_c) = app.register_user("gdm_nf_c").await;

    let b64 = &base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    // No friends — should fail
    let body = json!({
        "member_ids": [user_b, user_c],
        "encrypted_meta": b64.encode(b"meta")
    });
    let (status, _) = app
        .request(Method::POST, "/api/v1/dm/group", Some(&token_a), Some(body))
        .await;
    assert_ne!(status, StatusCode::OK);
}

// ─── Channel Members & Leave ────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn list_channel_members(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("ch_mem").await;
    let server_id = app.create_server(&token, "Member Test").await;
    let channel_id = app.create_channel(&token, server_id, "general").await;

    let uri = format!("/api/v1/channels/{}/members", channel_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let members = value.as_array().unwrap();
    assert!(members.len() >= 1);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn leave_group_dm(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("leave_a").await;
    let (token_b, user_b) = app.register_user("leave_b").await;
    let (token_c, user_c) = app.register_user("leave_c").await;

    app.make_friends(&token_a, &token_b, "leave_b").await;
    app.make_friends(&token_a, &token_c, "leave_c").await;

    let b64 = &base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let body = json!({
        "member_ids": [user_b, user_c],
        "encrypted_meta": b64.encode(b"leave-test")
    });
    let (status, value) = app
        .request(Method::POST, "/api/v1/dm/group", Some(&token_a), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    let channel_id = value["id"].as_str().unwrap();

    // User B leaves
    let leave_uri = format!("/api/v1/channels/{}/leave", channel_id);
    let (status, _) = app
        .request(Method::DELETE, &leave_uri, Some(&token_b), None)
        .await;
    assert_eq!(status, StatusCode::OK);
}

// ─── Roles Extended ─────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn update_role(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("role_updater").await;
    let server_id = app.create_server(&token, "Role Update Test").await;

    // Create a role
    let roles_uri = format!("/api/v1/servers/{}/roles", server_id);
    let (_, role_val) = app
        .request(
            Method::POST,
            &roles_uri,
            Some(&token),
            Some(json!({ "name": "Original", "position": 1 })),
        )
        .await;
    let role_id = role_val["id"].as_str().unwrap();

    // Update it
    let update_uri = format!("/api/v1/servers/{}/roles/{}", server_id, role_id);
    let (status, value) = app
        .request(
            Method::PUT,
            &update_uri,
            Some(&token),
            Some(json!({ "name": "Renamed", "color": "#ff0000" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["name"].as_str(), Some("Renamed"));
    assert_eq!(value["color"].as_str(), Some("#ff0000"));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn delete_role(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("role_deleter").await;
    let server_id = app.create_server(&token, "Role Delete Test").await;

    // Create and delete a role
    let roles_uri = format!("/api/v1/servers/{}/roles", server_id);
    let (_, role_val) = app
        .request(
            Method::POST,
            &roles_uri,
            Some(&token),
            Some(json!({ "name": "Deletable", "position": 1 })),
        )
        .await;
    let role_id = role_val["id"].as_str().unwrap();

    let del_uri = format!("/api/v1/servers/{}/roles/{}", server_id, role_id);
    let (status, _) = app
        .request(Method::DELETE, &del_uri, Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Verify it's gone — only @everyone should remain
    let (_, value) = app
        .request(Method::GET, &roles_uri, Some(&token), None)
        .await;
    let roles = value.as_array().unwrap();
    assert!(roles.iter().all(|r| r["name"].as_str() != Some("Deletable")));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn cannot_delete_default_role(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("no_del_default").await;
    let server_id = app.create_server(&token, "Default Role").await;

    // Find the default role
    let roles_uri = format!("/api/v1/servers/{}/roles", server_id);
    let (_, value) = app
        .request(Method::GET, &roles_uri, Some(&token), None)
        .await;
    let default_role = value
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["is_default"].as_bool() == Some(true))
        .unwrap();
    let role_id = default_role["id"].as_str().unwrap();

    let del_uri = format!("/api/v1/servers/{}/roles/{}", server_id, role_id);
    let (status, _) = app
        .request(Method::DELETE, &del_uri, Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn unassign_role_from_member(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("unassign_owner").await;
    let (token_member, member_id) = app.register_user("unassign_target").await;
    let server_id = app.create_server(&token_owner, "Unassign Test").await;

    app.invite_and_join(&token_owner, &token_member, server_id).await;

    // Create and assign a role
    let roles_uri = format!("/api/v1/servers/{}/roles", server_id);
    let (_, role_val) = app
        .request(
            Method::POST,
            &roles_uri,
            Some(&token_owner),
            Some(json!({ "name": "TempRole", "position": 1 })),
        )
        .await;
    let role_id = role_val["id"].as_str().unwrap();

    let assign_uri = format!("/api/v1/servers/{}/members/{}/roles", server_id, member_id);
    app.request(
        Method::PUT,
        &assign_uri,
        Some(&token_owner),
        Some(json!({ "role_id": role_id })),
    )
    .await;

    // Unassign
    let unassign_uri = format!(
        "/api/v1/servers/{}/members/{}/roles/{}",
        server_id, member_id, role_id
    );
    let (status, _) = app
        .request(Method::DELETE, &unassign_uri, Some(&token_owner), None)
        .await;
    assert_eq!(status, StatusCode::OK);
}

// ─── Categories Extended ────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn update_category(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("cat_updater").await;
    let server_id = app.create_server(&token, "Cat Update").await;

    let cat_uri = format!("/api/v1/servers/{}/categories", server_id);
    let (_, cat_val) = app
        .request(
            Method::POST,
            &cat_uri,
            Some(&token),
            Some(json!({ "name": "Original", "position": 0 })),
        )
        .await;
    let cat_id = cat_val["id"].as_str().unwrap();

    let update_uri = format!("/api/v1/servers/{}/categories/{}", server_id, cat_id);
    let (status, value) = app
        .request(
            Method::PUT,
            &update_uri,
            Some(&token),
            Some(json!({ "name": "Renamed Category" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["name"].as_str(), Some("Renamed Category"));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn delete_category(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("cat_deleter").await;
    let server_id = app.create_server(&token, "Cat Delete").await;

    let cat_uri = format!("/api/v1/servers/{}/categories", server_id);
    let (_, cat_val) = app
        .request(
            Method::POST,
            &cat_uri,
            Some(&token),
            Some(json!({ "name": "ToDelete", "position": 0 })),
        )
        .await;
    let cat_id = cat_val["id"].as_str().unwrap();

    let del_uri = format!("/api/v1/servers/{}/categories/{}", server_id, cat_id);
    let (status, _) = app
        .request(Method::DELETE, &del_uri, Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Verify it's gone
    let (_, value) = app
        .request(Method::GET, &cat_uri, Some(&token), None)
        .await;
    let cats = value.as_array().unwrap();
    assert!(cats.iter().all(|c| c["id"].as_str() != Some(cat_id)));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn reorder_categories(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("cat_reorder").await;
    let server_id = app.create_server(&token, "Reorder").await;

    let cat_uri = format!("/api/v1/servers/{}/categories", server_id);
    let (_, cat1) = app
        .request(
            Method::POST,
            &cat_uri,
            Some(&token),
            Some(json!({ "name": "First", "position": 0 })),
        )
        .await;
    let (_, cat2) = app
        .request(
            Method::POST,
            &cat_uri,
            Some(&token),
            Some(json!({ "name": "Second", "position": 1 })),
        )
        .await;

    let reorder_uri = format!("/api/v1/servers/{}/categories/reorder", server_id);
    let body = json!({
        "order": [
            { "id": cat1["id"], "position": 1 },
            { "id": cat2["id"], "position": 0 }
        ]
    });
    let (status, _) = app
        .request(Method::PUT, &reorder_uri, Some(&token), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
}

// ─── Invites Extended ───────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn list_invites(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("inv_lister").await;
    let server_id = app.create_server(&token, "Invite List").await;

    // Create two invites
    let uri = format!("/api/v1/servers/{}/invites", server_id);
    app.request(
        Method::POST,
        &uri,
        Some(&token),
        Some(json!({ "expires_in_hours": 24 })),
    )
    .await;
    app.request(
        Method::POST,
        &uri,
        Some(&token),
        Some(json!({ "expires_in_hours": 48 })),
    )
    .await;

    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value.as_array().unwrap().len(), 2);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn delete_invite(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("inv_deleter").await;
    let server_id = app.create_server(&token, "Invite Delete").await;

    let uri = format!("/api/v1/servers/{}/invites", server_id);
    let (_, inv_val) = app
        .request(
            Method::POST,
            &uri,
            Some(&token),
            Some(json!({ "expires_in_hours": 24 })),
        )
        .await;
    let invite_id = inv_val["id"].as_str().unwrap();

    let del_uri = format!("/api/v1/servers/{}/invites/{}", server_id, invite_id);
    let (status, value) = app
        .request(Method::DELETE, &del_uri, Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["deleted"].as_bool(), Some(true));
}

// ─── Server Members ─────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn list_server_members(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("mem_owner").await;
    let (token_member, _) = app.register_user("mem_member").await;
    let server_id = app.create_server(&token_owner, "Member List").await;

    app.invite_and_join(&token_owner, &token_member, server_id).await;

    let uri = format!("/api/v1/servers/{}/members", server_id);
    let (status, value) = app
        .request(Method::GET, &uri, Some(&token_owner), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let members = value.as_array().unwrap();
    assert_eq!(members.len(), 2);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn kick_member(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("kick_owner").await;
    let (token_member, member_id) = app.register_user("kick_target").await;
    let server_id = app.create_server(&token_owner, "Kick Test").await;

    app.invite_and_join(&token_owner, &token_member, server_id).await;

    let kick_uri = format!("/api/v1/servers/{}/members/{}", server_id, member_id);
    let (status, value) = app
        .request(Method::DELETE, &kick_uri, Some(&token_owner), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["kicked"].as_bool(), Some(true));

    // Verify member list reduced
    let list_uri = format!("/api/v1/servers/{}/members", server_id);
    let (_, value) = app
        .request(Method::GET, &list_uri, Some(&token_owner), None)
        .await;
    assert_eq!(value.as_array().unwrap().len(), 1);
}

// ─── Channel Update ─────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn update_channel_meta(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("ch_updater").await;
    let server_id = app.create_server(&token, "Ch Update").await;
    let channel_id = app.create_channel(&token, server_id, "old-name").await;

    use base64::Engine;
    let b64 = &base64::engine::general_purpose::STANDARD;
    let body = json!({ "encrypted_meta": b64.encode(b"new-name") });
    let uri = format!("/api/v1/channels/{}", channel_id);
    let (status, value) = app
        .request(Method::PUT, &uri, Some(&token), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(value["encrypted_meta"].as_str().is_some());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn join_channel(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("join_owner").await;
    let (token_member, _) = app.register_user("join_member").await;
    let server_id = app.create_server(&token_owner, "Join Test").await;

    app.invite_and_join(&token_owner, &token_member, server_id).await;

    let channel_id = app.create_channel(&token_owner, server_id, "new-channel").await;

    let join_uri = format!("/api/v1/channels/{}/join", channel_id);
    let (status, _) = app
        .request(Method::POST, &join_uri, Some(&token_member), None)
        .await;
    assert_eq!(status, StatusCode::OK);
}

// ─── Channel Overwrites ─────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn set_and_list_overwrites(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("ow_user").await;
    let server_id = app.create_server(&token, "Overwrite Test").await;
    let channel_id = app.create_channel(&token, server_id, "restricted").await;

    // Get the @everyone role to use as target
    let roles_uri = format!("/api/v1/servers/{}/roles", server_id);
    let (_, roles_val) = app
        .request(Method::GET, &roles_uri, Some(&token), None)
        .await;
    let everyone_role = roles_val
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["is_default"].as_bool() == Some(true))
        .unwrap();
    let role_id = everyone_role["id"].as_str().unwrap();

    // Set an overwrite
    let ow_uri = format!("/api/v1/channels/{}/overwrites", channel_id);
    let body = json!({
        "target_type": "role",
        "target_id": role_id,
        "allow_bits": "0",
        "deny_bits": "256"  // deny SEND_MESSAGES
    });
    let (status, value) = app
        .request(Method::PUT, &ow_uri, Some(&token), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["target_type"].as_str(), Some("role"));

    // List overwrites
    let (status, value) = app
        .request(Method::GET, &ow_uri, Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value.as_array().unwrap().len(), 1);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn delete_overwrite(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("ow_del").await;
    let server_id = app.create_server(&token, "OW Delete").await;
    let channel_id = app.create_channel(&token, server_id, "ch").await;

    let roles_uri = format!("/api/v1/servers/{}/roles", server_id);
    let (_, roles_val) = app
        .request(Method::GET, &roles_uri, Some(&token), None)
        .await;
    let role_id = roles_val
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["is_default"].as_bool() == Some(true))
        .unwrap()["id"]
        .as_str()
        .unwrap();

    // Create overwrite
    let ow_uri = format!("/api/v1/channels/{}/overwrites", channel_id);
    app.request(
        Method::PUT,
        &ow_uri,
        Some(&token),
        Some(json!({
            "target_type": "role",
            "target_id": role_id,
            "allow_bits": "0",
            "deny_bits": "256"
        })),
    )
    .await;

    // Delete it
    let del_uri = format!(
        "/api/v1/channels/{}/overwrites/role/{}",
        channel_id, role_id
    );
    let (status, _) = app
        .request(Method::DELETE, &del_uri, Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Verify empty
    let (_, value) = app
        .request(Method::GET, &ow_uri, Some(&token), None)
        .await;
    assert_eq!(value.as_array().unwrap().len(), 0);
}

// ─── Keys ───────────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn get_key_bundle(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("key_requester").await;
    let (_, user_b) = app.register_user("key_target").await;

    let uri = format!("/api/v1/users/{}/keys", user_b);
    let (status, value) = app.request(Method::GET, &uri, Some(&token_a), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(value["identity_key"].as_str().is_some());
    assert!(value["signed_prekey"].as_str().is_some());
    assert!(value["signed_prekey_sig"].as_str().is_some());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn upload_and_count_prekeys(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("prekey_user").await;

    use base64::Engine;
    let b64 = &base64::engine::general_purpose::STANDARD;
    let prekeys: Vec<String> = (0..5).map(|i| b64.encode([i as u8; 32])).collect();

    let body = json!({ "prekeys": prekeys });
    let (status, value) = app
        .request(
            Method::POST,
            "/api/v1/keys/prekeys",
            Some(&token),
            Some(body),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["total_available"].as_i64(), Some(5));

    // Check count
    let (status, value) = app
        .request(
            Method::GET,
            "/api/v1/keys/prekeys/count",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["count"].as_i64(), Some(5));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn update_identity_keys(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("key_updater").await;

    use base64::Engine;
    let b64 = &base64::engine::general_purpose::STANDARD;
    let body = json!({
        "identity_key": b64.encode([1u8; 32]),
        "signed_prekey": b64.encode([2u8; 32]),
        "signed_prekey_signature": b64.encode([3u8; 64])
    });

    let (status, _) = app
        .request(
            Method::PUT,
            "/api/v1/keys/identity",
            Some(&token),
            Some(body),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

// ─── Attachments ────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn upload_attachment(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("attach_user").await;

    let data = vec![0u8; 1024]; // 1KB of zeros
    let (status, value) = app
        .request_bytes(Method::POST, "/api/v1/attachments/upload", Some(&token), data)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(value["attachment_id"].as_str().is_some());
    assert!(value["storage_key"].as_str().is_some());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn upload_empty_attachment_fails(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("empty_attach").await;

    let (status, _) = app
        .request_bytes(Method::POST, "/api/v1/attachments/upload", Some(&token), vec![])
        .await;
    assert_ne!(status, StatusCode::OK);
}

// ─── DM Privacy ─────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn update_dm_privacy(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("dm_priv_user").await;

    let body = json!({ "dm_privacy": "friends_only" });
    let (status, value) = app
        .request(
            Method::PUT,
            "/api/v1/users/dm-privacy",
            Some(&token),
            Some(body),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["dm_privacy"].as_str(), Some("friends_only"));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn update_dm_privacy_invalid_value(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("dm_priv_bad").await;

    let body = json!({ "dm_privacy": "invalid_value" });
    let (status, _) = app
        .request(
            Method::PUT,
            "/api/v1/users/dm-privacy",
            Some(&token),
            Some(body),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn dm_friends_only_creates_pending_dm(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("dm_fo_a").await;
    let (token_b, user_b) = app.register_user("dm_fo_b").await;

    // B sets friends_only
    app.request(
        Method::PUT,
        "/api/v1/users/dm-privacy",
        Some(&token_b),
        Some(json!({ "dm_privacy": "friends_only" })),
    )
    .await;

    // A (not a friend) creates DM with B — should be pending
    use base64::Engine;
    let b64 = &base64::engine::general_purpose::STANDARD;
    let body = json!({
        "target_user_id": user_b,
        "encrypted_meta": b64.encode(b"dm-meta")
    });
    let (status, value) = app
        .request(Method::POST, "/api/v1/dm", Some(&token_a), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["dm_status"].as_str(), Some("pending"));
}

// ─── Friends Extended ───────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn remove_friend(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("remove_a").await;
    let (token_b, _) = app.register_user("remove_b").await;

    let friendship_id = app.make_friends(&token_a, &token_b, "remove_b").await;

    let uri = format!("/api/v1/friends/{}", friendship_id);
    let (status, _) = app
        .request(Method::DELETE, &uri, Some(&token_a), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Friends list should be empty
    let (_, value) = app
        .request(Method::GET, "/api/v1/friends", Some(&token_a), None)
        .await;
    let friends = value.as_array().unwrap();
    assert!(friends.is_empty());
}

// ─── Reactions ──────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn get_channel_reactions_empty(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("react_user").await;
    let server_id = app.create_server(&token, "React Server").await;
    let channel_id = app.create_channel(&token, server_id, "general").await;

    let uri = format!("/api/v1/channels/{}/reactions", channel_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value.as_array().unwrap().len(), 0);
}

// ─── Presence ───────────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn get_presence_returns_offline_for_unknown(pool: Pool) {
    let app = TestApp::new(pool).await;
    let random_id = Uuid::new_v4();
    let uri = format!("/api/v1/presence?user_ids={}", random_id);
    let (status, value) = app.request(Method::GET, &uri, None, None).await;
    assert_eq!(status, StatusCode::OK);
    let entries = value.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["status"].as_str(), Some("offline"));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn get_presence_empty_ids_returns_empty(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (status, value) = app
        .request(Method::GET, "/api/v1/presence?user_ids=", None, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value.as_array().unwrap().len(), 0);
}

// ─── TOTP (2FA) ──────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn totp_setup_returns_secret(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("totp_setup").await;

    let (status, value) = app
        .request(Method::POST, "/api/v1/auth/totp/setup", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(value["secret"].as_str().is_some());
    assert!(value["qr_code_uri"].as_str().is_some());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn totp_setup_twice_fails(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("totp_dup").await;

    // Setup TOTP
    let (_, value) = app
        .request(Method::POST, "/api/v1/auth/totp/setup", Some(&token), None)
        .await;
    let secret_b32 = value["secret"].as_str().unwrap().to_string();

    // Verify with a valid code to activate it
    let code = generate_totp_code(&secret_b32);
    let (status, _) = app
        .request(
            Method::POST,
            "/api/v1/auth/totp/verify",
            Some(&token),
            Some(json!({ "code": code })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Second setup should fail (TOTP already enabled)
    let (status, _) = app
        .request(Method::POST, "/api/v1/auth/totp/setup", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn totp_verify_activates_2fa(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("totp_verify").await;

    // Setup
    let (_, value) = app
        .request(Method::POST, "/api/v1/auth/totp/setup", Some(&token), None)
        .await;
    let secret_b32 = value["secret"].as_str().unwrap().to_string();

    // Verify with correct code
    let code = generate_totp_code(&secret_b32);
    let (status, value) = app
        .request(
            Method::POST,
            "/api/v1/auth/totp/verify",
            Some(&token),
            Some(json!({ "code": code })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(value["message"].as_str().unwrap().contains("enabled"));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn totp_verify_wrong_code_fails(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("totp_bad").await;

    // Setup
    app.request(Method::POST, "/api/v1/auth/totp/setup", Some(&token), None)
        .await;

    // Verify with wrong code
    let (status, _) = app
        .request(
            Method::POST,
            "/api/v1/auth/totp/verify",
            Some(&token),
            Some(json!({ "code": "000000" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn totp_disable_removes_2fa(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("totp_disable").await;

    // Setup and activate
    let (_, value) = app
        .request(Method::POST, "/api/v1/auth/totp/setup", Some(&token), None)
        .await;
    let secret_b32 = value["secret"].as_str().unwrap().to_string();
    let code = generate_totp_code(&secret_b32);
    app.request(
        Method::POST,
        "/api/v1/auth/totp/verify",
        Some(&token),
        Some(json!({ "code": code })),
    )
    .await;

    // Disable
    let (status, value) = app
        .request(Method::DELETE, "/api/v1/auth/totp", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(value["message"].as_str().unwrap().contains("disabled"));

    // Should be able to login without TOTP code now
    let (status, _) = app
        .request(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "totp_disable", "password": "testpassword123" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn login_requires_totp_when_enabled(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("totp_login").await;

    // Setup and activate TOTP
    let (_, value) = app
        .request(Method::POST, "/api/v1/auth/totp/setup", Some(&token), None)
        .await;
    let secret_b32 = value["secret"].as_str().unwrap().to_string();
    let code = generate_totp_code(&secret_b32);
    app.request(
        Method::POST,
        "/api/v1/auth/totp/verify",
        Some(&token),
        Some(json!({ "code": code })),
    )
    .await;

    // Login without TOTP code should return totp_required challenge
    let (status, value) = app
        .request(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "totp_login", "password": "testpassword123" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["totp_required"], json!(true));
    assert!(value.get("access_token").is_none());

    // Login with valid TOTP code should succeed
    let code = generate_totp_code(&secret_b32);
    let (status, _) = app
        .request(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({
                "username": "totp_login",
                "password": "testpassword123",
                "totp_code": code,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

/// Generate a valid TOTP code from a base32-encoded secret.
fn generate_totp_code(secret_b32: &str) -> String {
    use totp_rs::{Algorithm, Secret, TOTP};
    let secret = Secret::Encoded(secret_b32.into());
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().unwrap(),
        Some("Haven".into()),
        "test".into(),
    )
    .unwrap();
    totp.generate_current().unwrap()
}

// ─── Server Update & Nickname ────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn update_server_system_channel(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("srv_update").await;
    let server_id = app.create_server(&token, "Update Test").await;
    let channel_id = app.create_channel(&token, server_id, "announcements").await;

    // Update system channel
    let uri = format!("/api/v1/servers/{}", server_id);
    let body = json!({ "system_channel_id": channel_id });
    let (status, value) = app
        .request(Method::PATCH, &uri, Some(&token), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["ok"].as_bool(), Some(true));

    // Verify via get_server
    let (_, server) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(
        server["system_channel_id"].as_str().unwrap(),
        channel_id.to_string()
    );
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn update_server_invalid_channel_fails(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("srv_bad_ch").await;
    let server_id = app.create_server(&token, "Bad Channel").await;

    // Try setting system channel to a non-existent channel
    let uri = format!("/api/v1/servers/{}", server_id);
    let body = json!({ "system_channel_id": Uuid::new_v4() });
    let (status, _) = app
        .request(Method::PATCH, &uri, Some(&token), Some(body))
        .await;
    assert_ne!(status, StatusCode::OK);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn update_server_requires_permission(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("srv_perm_own").await;
    let (token_member, _) = app.register_user("srv_perm_mem").await;
    let server_id = app.create_server(&token_owner, "Perm Test").await;

    app.invite_and_join(&token_owner, &token_member, server_id).await;

    let channel_id = app.create_channel(&token_owner, server_id, "new-ch").await;
    let uri = format!("/api/v1/servers/{}", server_id);
    let body = json!({ "system_channel_id": channel_id });

    // Member without MANAGE_SERVER should be forbidden
    let (status, _) = app
        .request(Method::PATCH, &uri, Some(&token_member), Some(body))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn set_and_clear_nickname(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("nick_user").await;
    let server_id = app.create_server(&token, "Nick Test").await;

    let uri = format!("/api/v1/servers/{}/nickname", server_id);

    // Set nickname
    let (status, value) = app
        .request(
            Method::PUT,
            &uri,
            Some(&token),
            Some(json!({ "nickname": "CoolNick" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["ok"].as_bool(), Some(true));

    // Verify via member list
    let mem_uri = format!("/api/v1/servers/{}/members", server_id);
    let (_, value) = app.request(Method::GET, &mem_uri, Some(&token), None).await;
    let members = value.as_array().unwrap();
    assert!(members.iter().any(|m| m["nickname"].as_str() == Some("CoolNick")));

    // Clear nickname
    let (status, _) = app
        .request(
            Method::PUT,
            &uri,
            Some(&token),
            Some(json!({ "nickname": null })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn nickname_too_long_fails(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("nick_long").await;
    let server_id = app.create_server(&token, "Nick Long").await;

    let uri = format!("/api/v1/servers/{}/nickname", server_id);
    let long_nick = "a".repeat(33);
    let (status, _) = app
        .request(
            Method::PUT,
            &uri,
            Some(&token),
            Some(json!({ "nickname": long_nick })),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn get_my_permissions(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("perm_me").await;
    let server_id = app.create_server(&token, "Perm Check").await;

    let uri = format!("/api/v1/servers/{}/members/@me/permissions", server_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["is_owner"].as_bool(), Some(true));
    assert!(value["permissions"].as_str().is_some());
}

// ─── Channel Reorder ─────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn reorder_channels(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("ch_reorder").await;
    let server_id = app.create_server(&token, "Reorder Ch").await;

    let ch1 = app.create_channel(&token, server_id, "alpha").await;
    let ch2 = app.create_channel(&token, server_id, "beta").await;

    let uri = format!("/api/v1/servers/{}/channels/reorder", server_id);
    let body = json!({
        "order": [
            { "id": ch1, "position": 2, "category_id": null },
            { "id": ch2, "position": 1, "category_id": null },
        ]
    });
    let (status, _) = app
        .request(Method::PUT, &uri, Some(&token), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);

    // Verify positions changed
    let list_uri = format!("/api/v1/servers/{}/channels", server_id);
    let (_, value) = app.request(Method::GET, &list_uri, Some(&token), None).await;
    let channels = value.as_array().unwrap();
    let ch1_entry = channels.iter().find(|c| c["id"].as_str().unwrap() == ch1.to_string()).unwrap();
    assert_eq!(ch1_entry["position"].as_i64(), Some(2));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn reorder_channels_requires_permission(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("reord_own").await;
    let (token_member, _) = app.register_user("reord_mem").await;
    let server_id = app.create_server(&token_owner, "Reord Perm").await;

    app.invite_and_join(&token_owner, &token_member, server_id).await;

    let ch = app.create_channel(&token_owner, server_id, "ch").await;

    let uri = format!("/api/v1/servers/{}/channels/reorder", server_id);
    let body = json!({ "order": [{ "id": ch, "position": 5, "category_id": null }] });
    let (status, _) = app
        .request(Method::PUT, &uri, Some(&token_member), Some(body))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── Avatar Upload/Download ──────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn upload_and_download_avatar(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("avatar_user").await;

    // Upload a fake PNG (starts with PNG magic bytes)
    let mut png_data = vec![0x89, 0x50, 0x4E, 0x47]; // PNG magic
    png_data.extend_from_slice(&[0u8; 100]);
    let (status, value) = app
        .request_bytes(Method::POST, "/api/v1/users/avatar", Some(&token), png_data)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(value["avatar_url"].as_str().is_some());

    // Download avatar (no auth required)
    let download_uri = format!("/api/v1/users/{}/avatar", user_id);
    let (status, _) = app.request(Method::GET, &download_uri, None, None).await;
    assert_eq!(status, StatusCode::OK);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn upload_empty_avatar_fails(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("avatar_empty").await;

    let (status, _) = app
        .request_bytes(Method::POST, "/api/v1/users/avatar", Some(&token), vec![])
        .await;
    assert_ne!(status, StatusCode::OK);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn get_avatar_no_avatar_returns_404(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (_, user_id) = app.register_user("no_avatar").await;

    let uri = format!("/api/v1/users/{}/avatar", user_id);
    let (status, _) = app.request(Method::GET, &uri, None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ─── Profile Keys ────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn distribute_and_get_profile_keys(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, user_a) = app.register_user("pk_sender").await;
    let (token_b, user_b) = app.register_user("pk_receiver").await;

    // A distributes a profile key to B
    let body = json!({
        "distributions": [{
            "to_user_id": user_b,
            "encrypted_profile_key": B64.encode(b"fake-encrypted-profile-key-data")
        }]
    });
    let (status, value) = app
        .request(
            Method::PUT,
            "/api/v1/users/profile-keys",
            Some(&token_a),
            Some(body),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["distributed"].as_i64(), Some(1));

    // B fetches A's profile key
    let uri = format!("/api/v1/users/{}/profile-key", user_a);
    let (status, value) = app.request(Method::GET, &uri, Some(&token_b), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["from_user_id"].as_str().unwrap(), user_a.to_string());
    assert!(value["encrypted_profile_key"].as_str().is_some());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn get_profile_key_not_found(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("pk_miss").await;

    // No profile key distributed — should be 404
    let uri = format!("/api/v1/users/{}/profile-key", Uuid::new_v4());
    let (status, _) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ─── DM Requests ─────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn dm_request_accept_flow(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("dmr_a").await;
    let (token_b, user_b) = app.register_user("dmr_b").await;

    // B sets friends_only
    app.request(
        Method::PUT,
        "/api/v1/users/dm-privacy",
        Some(&token_b),
        Some(json!({ "dm_privacy": "friends_only" })),
    )
    .await;

    // A creates DM with B (not friends) → pending
    let body = json!({
        "target_user_id": user_b,
        "encrypted_meta": B64.encode(b"dm-meta")
    });
    let (status, value) = app
        .request(Method::POST, "/api/v1/dm", Some(&token_a), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["dm_status"].as_str(), Some("pending"));
    let channel_id = value["id"].as_str().unwrap();

    // B lists DM requests
    let (status, value) = app
        .request(Method::GET, "/api/v1/dm/requests", Some(&token_b), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let requests = value.as_array().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["id"].as_str().unwrap(), channel_id);

    // B accepts the DM request
    let uri = format!("/api/v1/dm/{}/request", channel_id);
    let (status, value) = app
        .request(
            Method::POST,
            &uri,
            Some(&token_b),
            Some(json!({ "action": "accept" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(value["message"].as_str().unwrap().contains("accepted"));

    // DM requests should be empty now
    let (_, value) = app
        .request(Method::GET, "/api/v1/dm/requests", Some(&token_b), None)
        .await;
    assert_eq!(value.as_array().unwrap().len(), 0);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn dm_request_decline_flow(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("dmrd_a").await;
    let (token_b, user_b) = app.register_user("dmrd_b").await;

    // B sets friends_only
    app.request(
        Method::PUT,
        "/api/v1/users/dm-privacy",
        Some(&token_b),
        Some(json!({ "dm_privacy": "friends_only" })),
    )
    .await;

    // A creates pending DM
    let body = json!({
        "target_user_id": user_b,
        "encrypted_meta": B64.encode(b"dm-meta")
    });
    let (_, value) = app
        .request(Method::POST, "/api/v1/dm", Some(&token_a), Some(body))
        .await;
    let channel_id = value["id"].as_str().unwrap();

    // B declines
    let uri = format!("/api/v1/dm/{}/request", channel_id);
    let (status, value) = app
        .request(
            Method::POST,
            &uri,
            Some(&token_b),
            Some(json!({ "action": "decline" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(value["message"].as_str().unwrap().contains("declined"));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn dm_request_invalid_action(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("dmri_a").await;
    let (token_b, user_b) = app.register_user("dmri_b").await;

    app.request(
        Method::PUT,
        "/api/v1/users/dm-privacy",
        Some(&token_b),
        Some(json!({ "dm_privacy": "friends_only" })),
    )
    .await;

    let body = json!({
        "target_user_id": user_b,
        "encrypted_meta": B64.encode(b"dm-meta")
    });
    let (_, value) = app
        .request(Method::POST, "/api/v1/dm", Some(&token_a), Some(body))
        .await;
    let channel_id = value["id"].as_str().unwrap();

    let uri = format!("/api/v1/dm/{}/request", channel_id);
    let (status, _) = app
        .request(
            Method::POST,
            &uri,
            Some(&token_b),
            Some(json!({ "action": "invalid" })),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
}

// ─── Sender Keys ─────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn distribute_and_get_sender_keys(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, user_a) = app.register_user("sk_sender").await;
    let (token_b, user_b) = app.register_user("sk_receiver").await;
    let server_id = app.create_server(&token_a, "SK Test").await;

    app.invite_and_join(&token_a, &token_b, server_id).await;

    let channel_id = app.create_channel(&token_a, server_id, "encrypted-ch").await;

    // B joins the channel
    let join_uri = format!("/api/v1/channels/{}/join", channel_id);
    app.request(Method::POST, &join_uri, Some(&token_b), None).await;

    let dist_id = Uuid::new_v4();

    // A distributes sender keys to B
    let uri = format!("/api/v1/channels/{}/sender-keys", channel_id);
    let body = json!({
        "distributions": [{
            "to_user_id": user_b,
            "distribution_id": dist_id,
            "encrypted_skdm": B64.encode(b"fake-sender-key-distribution-message")
        }]
    });
    let (status, value) = app
        .request(Method::POST, &uri, Some(&token_a), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["distributed"].as_i64(), Some(1));

    // B fetches sender keys for the channel
    let (status, value) = app.request(Method::GET, &uri, Some(&token_b), None).await;
    assert_eq!(status, StatusCode::OK);
    let keys = value.as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["from_user_id"].as_str().unwrap(), user_a.to_string());
    assert_eq!(keys[0]["distribution_id"].as_str().unwrap(), dist_id.to_string());
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn distribute_sender_keys_empty_fails(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("sk_empty").await;
    let server_id = app.create_server(&token, "SK Empty").await;
    let channel_id = app.create_channel(&token, server_id, "ch").await;

    let uri = format!("/api/v1/channels/{}/sender-keys", channel_id);
    let body = json!({ "distributions": [] });
    let (status, _) = app
        .request(Method::POST, &uri, Some(&token), Some(body))
        .await;
    assert_ne!(status, StatusCode::OK);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn get_channel_member_keys(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("mk_a").await;
    let (token_b, user_b) = app.register_user("mk_b").await;
    let server_id = app.create_server(&token_a, "MK Test").await;

    app.invite_and_join(&token_a, &token_b, server_id).await;

    let channel_id = app.create_channel(&token_a, server_id, "keys-ch").await;

    // B joins the channel
    let join_uri = format!("/api/v1/channels/{}/join", channel_id);
    app.request(Method::POST, &join_uri, Some(&token_b), None).await;

    // A fetches member keys (should exclude A, include B)
    let uri = format!("/api/v1/channels/{}/members/keys", channel_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token_a), None).await;
    assert_eq!(status, StatusCode::OK);
    let keys = value.as_array().unwrap();
    assert!(keys.iter().any(|k| k["user_id"].as_str().unwrap() == user_b.to_string()));
    assert!(keys.iter().all(|k| k["identity_key"].as_str().is_some()));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn sender_keys_non_member_forbidden(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("sk_own").await;
    let (token_b, _) = app.register_user("sk_outsider").await;
    let server_id = app.create_server(&token_a, "SK Forbid").await;
    let channel_id = app.create_channel(&token_a, server_id, "ch").await;

    // B is not a member — should be forbidden
    let uri = format!("/api/v1/channels/{}/sender-keys", channel_id);
    let (status, _) = app.request(Method::GET, &uri, Some(&token_b), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── User Profile Extended ───────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn profile_shows_friendship_status(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("prof_a").await;
    let (token_b, user_b) = app.register_user("prof_b").await;

    // Before friendship: not friends
    let uri = format!("/api/v1/users/{}/profile", user_b);
    let (_, value) = app.request(Method::GET, &uri, Some(&token_a), None).await;
    assert_eq!(value["is_friend"].as_bool(), Some(false));

    // Send friend request
    app.request(
        Method::POST,
        "/api/v1/friends/request",
        Some(&token_a),
        Some(json!({ "username": "prof_b" })),
    )
    .await;

    // Should show pending outgoing
    let (_, value) = app.request(Method::GET, &uri, Some(&token_a), None).await;
    assert_eq!(
        value["friend_request_status"].as_str(),
        Some("pending_outgoing")
    );

    // After accept: is_friend = true
    let friendship_id = value["friendship_id"].as_str().unwrap();
    let accept_uri = format!("/api/v1/friends/{}/accept", friendship_id);
    app.request(Method::POST, &accept_uri, Some(&token_b), None).await;

    let (_, value) = app.request(Method::GET, &uri, Some(&token_a), None).await;
    assert_eq!(value["is_friend"].as_bool(), Some(true));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn profile_shows_blocked_status(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("prof_blk_a").await;
    let (_, user_b) = app.register_user("prof_blk_b").await;

    // Block B
    let block_uri = format!("/api/v1/users/{}/block", user_b);
    app.request(Method::POST, &block_uri, Some(&token_a), None).await;

    // Profile should show blocked
    let uri = format!("/api/v1/users/{}/profile", user_b);
    let (_, value) = app.request(Method::GET, &uri, Some(&token_a), None).await;
    assert_eq!(value["is_blocked"].as_bool(), Some(true));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn profile_shows_mutual_friends(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("mut_a").await;
    let (token_b, user_b) = app.register_user("mut_b").await;
    let (token_c, _) = app.register_user("mut_c").await;

    // A and C are friends, B and C are friends
    app.make_friends(&token_a, &token_c, "mut_c").await;
    app.make_friends(&token_b, &token_c, "mut_c").await;

    // A views B's profile — mutual friend should be C
    let uri = format!("/api/v1/users/{}/profile", user_b);
    let (_, value) = app.request(Method::GET, &uri, Some(&token_a), None).await;
    assert_eq!(value["mutual_friend_count"].as_i64(), Some(1));
    let mutuals = value["mutual_friends"].as_array().unwrap();
    assert_eq!(mutuals.len(), 1);
    assert_eq!(mutuals[0]["username"].as_str(), Some("mut_c"));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn profile_with_server_roles(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("role_prof_own").await;
    let (token_member, member_id) = app.register_user("role_prof_mem").await;
    let server_id = app.create_server(&token_owner, "Role Prof").await;

    app.invite_and_join(&token_owner, &token_member, server_id).await;

    // Create and assign a role
    let roles_uri = format!("/api/v1/servers/{}/roles", server_id);
    let (_, role_val) = app
        .request(
            Method::POST,
            &roles_uri,
            Some(&token_owner),
            Some(json!({ "name": "Tester", "color": "#0000ff", "position": 1 })),
        )
        .await;
    let role_id = role_val["id"].as_str().unwrap();

    let assign_uri = format!("/api/v1/servers/{}/members/{}/roles", server_id, member_id);
    app.request(
        Method::PUT,
        &assign_uri,
        Some(&token_owner),
        Some(json!({ "role_id": role_id })),
    )
    .await;

    // Get profile with server_id — should include roles
    let uri = format!("/api/v1/users/{}/profile?server_id={}", member_id, server_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token_owner), None).await;
    assert_eq!(status, StatusCode::OK);
    let roles = value["roles"].as_array().unwrap();
    assert!(roles.iter().any(|r| r["name"].as_str() == Some("Tester")));
}

// ─── Auth Edge Cases ─────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn change_password_revokes_refresh_tokens(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("pw_revoke").await;

    // Get a refresh token
    let (_, refresh, _) = app.login_user("pw_revoke").await;

    // Change password
    app.request(
        Method::PUT,
        "/api/v1/auth/password",
        Some(&token),
        Some(json!({
            "current_password": "testpassword123",
            "new_password": "brandnewpass456"
        })),
    )
    .await;

    // Old refresh token should be invalid
    let (status, _) = app
        .request(
            Method::POST,
            "/api/v1/auth/refresh",
            None,
            Some(json!({ "refresh_token": refresh })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn change_password_too_short_fails(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("pw_short").await;

    let body = json!({
        "current_password": "testpassword123",
        "new_password": "short"
    });
    let (status, _) = app
        .request(Method::PUT, "/api/v1/auth/password", Some(&token), Some(body))
        .await;
    assert_ne!(status, StatusCode::OK);
}

// ─── Group DM Extended ───────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn add_member_to_group_dm(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("grp_add_a").await;
    let (token_b, user_b) = app.register_user("grp_add_b").await;
    let (token_c, user_c) = app.register_user("grp_add_c").await;
    let (token_d, user_d) = app.register_user("grp_add_d").await;

    app.make_friends(&token_a, &token_b, "grp_add_b").await;
    app.make_friends(&token_a, &token_c, "grp_add_c").await;
    app.make_friends(&token_a, &token_d, "grp_add_d").await;

    // Create group DM with B and C
    let body = json!({
        "member_ids": [user_b, user_c],
        "encrypted_meta": B64.encode(b"group-meta")
    });
    let (status, value) = app
        .request(Method::POST, "/api/v1/dm/group", Some(&token_a), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    let channel_id = value["id"].as_str().unwrap();

    // Add D to the group
    let uri = format!("/api/v1/channels/{}/members", channel_id);
    let (status, value) = app
        .request(
            Method::POST,
            &uri,
            Some(&token_a),
            Some(json!({ "user_id": user_d })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["added"].as_bool(), Some(true));

    // Verify 4 members
    let mem_uri = format!("/api/v1/channels/{}/members", channel_id);
    let (_, value) = app.request(Method::GET, &mem_uri, Some(&token_a), None).await;
    assert_eq!(value.as_array().unwrap().len(), 4);
}

// ─── Message Search ──────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn search_messages(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("search_user").await;
    let server_id = app.create_server(&token, "Search Server").await;
    let channel_id = app.create_channel(&token, server_id, "general").await;

    // Send a few messages
    app.send_message(&token, channel_id).await;
    app.send_message(&token, channel_id).await;

    // Get messages with limit
    let uri = format!("/api/v1/channels/{}/messages?limit=1", channel_id);
    let (status, value) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let messages = value.as_array().unwrap();
    assert_eq!(messages.len(), 1);
}

// ─── DM with Server Members Privacy ─────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn dm_server_members_privacy(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("sm_a").await;
    let (token_b, user_b) = app.register_user("sm_b").await;

    // B sets server_members privacy
    app.request(
        Method::PUT,
        "/api/v1/users/dm-privacy",
        Some(&token_b),
        Some(json!({ "dm_privacy": "server_members" })),
    )
    .await;

    // A and B are not in a shared server and not friends → pending
    let body = json!({
        "target_user_id": user_b,
        "encrypted_meta": B64.encode(b"dm-meta")
    });
    let (status, value) = app
        .request(Method::POST, "/api/v1/dm", Some(&token_a), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["dm_status"].as_str(), Some("pending"));
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn dm_server_members_shared_server_is_active(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("sms_a").await;
    let (token_b, user_b) = app.register_user("sms_b").await;

    // B sets server_members privacy
    app.request(
        Method::PUT,
        "/api/v1/users/dm-privacy",
        Some(&token_b),
        Some(json!({ "dm_privacy": "server_members" })),
    )
    .await;

    // Put both in a server
    let server_id = app.create_server(&token_a, "Shared").await;
    app.invite_and_join(&token_a, &token_b, server_id).await;

    // Now DM should be active (shared server)
    let body = json!({
        "target_user_id": user_b,
        "encrypted_meta": B64.encode(b"dm-meta")
    });
    let (status, value) = app
        .request(Method::POST, "/api/v1/dm", Some(&token_a), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["dm_status"].as_str(), Some("active"));
}

// ─── Attachment Download ─────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn download_attachment_not_found(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("att_404").await;

    let uri = format!("/api/v1/attachments/{}", Uuid::new_v4());
    let (status, _) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ─── Prekey Count ────────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn prekey_count_zero_initially(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("pk_zero").await;

    let (status, value) = app
        .request(Method::GET, "/api/v1/keys/prekeys/count", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["count"].as_i64(), Some(0));
}

// ─── Friend Request Edge Cases ───────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn friend_request_to_self_fails(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("self_friend").await;

    let (status, _) = app
        .request(
            Method::POST,
            "/api/v1/friends/request",
            Some(&token),
            Some(json!({ "username": "self_friend" })),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn friend_request_when_already_friends_fails(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("alr_a").await;
    let (token_b, _) = app.register_user("alr_b").await;

    app.make_friends(&token_a, &token_b, "alr_b").await;

    let (status, _) = app
        .request(
            Method::POST,
            "/api/v1/friends/request",
            Some(&token_a),
            Some(json!({ "username": "alr_b" })),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn friend_request_unknown_user_fails(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("fr_unknown").await;

    let (status, _) = app
        .request(
            Method::POST,
            "/api/v1/friends/request",
            Some(&token),
            Some(json!({ "username": "nobody_exists_here" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ─── Invite Edge Cases ───────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn join_invite_already_member(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("inv_alr_own").await;
    let (token_member, _) = app.register_user("inv_alr_mem").await;
    let server_id = app.create_server(&token_owner, "Already Member").await;

    let code = app.invite_and_join(&token_owner, &token_member, server_id).await;

    // Try to join again
    let join_uri = format!("/api/v1/invites/{}/join", code);
    let (status, _) = app
        .request(Method::POST, &join_uri, Some(&token_member), None)
        .await;
    assert_ne!(status, StatusCode::OK);
}

// ─── Kick / Ban Edge Cases ───────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn kick_member_by_non_owner_fails(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("kick_p_own").await;
    let (token_member, _) = app.register_user("kick_p_mem").await;
    let (_, target_id) = app.register_user("kick_p_tgt").await;
    let server_id = app.create_server(&token_owner, "Kick Perm").await;

    app.invite_and_join(&token_owner, &token_member, server_id).await;

    // Member (without KICK_MEMBERS) tries to kick — should be forbidden
    let kick_uri = format!("/api/v1/servers/{}/members/{}", server_id, target_id);
    let (status, _) = app
        .request(Method::DELETE, &kick_uri, Some(&token_member), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn cannot_ban_self(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("ban_self").await;
    let server_id = app.create_server(&token, "Ban Self").await;

    let ban_uri = format!("/api/v1/servers/{}/bans/{}", server_id, user_id);
    let (status, _) = app
        .request(Method::POST, &ban_uri, Some(&token), Some(json!({})))
        .await;
    assert_ne!(status, StatusCode::OK);
}

// ─── DM Edge Cases ───────────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn create_dm_returns_existing_if_exists(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_a, _) = app.register_user("dup_dm_a").await;
    let (_, user_b) = app.register_user("dup_dm_b").await;

    let body = json!({
        "target_user_id": user_b,
        "encrypted_meta": B64.encode(b"dm-meta")
    });

    let (status, value1) = app
        .request(Method::POST, "/api/v1/dm", Some(&token_a), Some(body.clone()))
        .await;
    assert_eq!(status, StatusCode::OK);
    let dm_id_1 = value1["id"].as_str().unwrap().to_string();

    let (status, value2) = app
        .request(Method::POST, "/api/v1/dm", Some(&token_a), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value2["id"].as_str().unwrap(), dm_id_1);
}

// ─── Message Pagination ──────────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn get_messages_with_limit_and_pagination(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token, _) = app.register_user("msg_page").await;
    let server_id = app.create_server(&token, "Page Test").await;
    let channel_id = app.create_channel(&token, server_id, "ch").await;

    // Send 5 messages
    for _ in 0..5 {
        app.send_message(&token, channel_id).await;
    }

    // Default: all 5
    let uri = format!("/api/v1/channels/{}/messages", channel_id);
    let (_, value) = app.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(value.as_array().unwrap().len(), 5);

    // Limit to 2
    let uri2 = format!("/api/v1/channels/{}/messages?limit=2", channel_id);
    let (status, value) = app.request(Method::GET, &uri2, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value.as_array().unwrap().len(), 2);

    // Limit capped at 100 — requesting 200 should still work
    let uri3 = format!("/api/v1/channels/{}/messages?limit=200", channel_id);
    let (status, value) = app.request(Method::GET, &uri3, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value.as_array().unwrap().len(), 5); // only 5 messages exist
}

// ─── Registration Validation ─────────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn register_short_password_fails(pool: Pool) {
    let app = TestApp::new(pool).await;
    let fake_key = B64.encode([0u8; 32]);
    let fake_sig = B64.encode([0u8; 64]);

    let body = json!({
        "username": "shortpw",
        "password": "short",
        "identity_key": fake_key,
        "signed_prekey": fake_key,
        "signed_prekey_signature": fake_sig,
        "one_time_prekeys": []
    });
    let (status, _) = app
        .request(Method::POST, "/api/v1/auth/register", None, Some(body))
        .await;
    assert_ne!(status, StatusCode::OK);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn register_short_username_fails(pool: Pool) {
    let app = TestApp::new(pool).await;
    let fake_key = B64.encode([0u8; 32]);
    let fake_sig = B64.encode([0u8; 64]);

    let body = json!({
        "username": "ab",
        "password": "testpassword123",
        "identity_key": fake_key,
        "signed_prekey": fake_key,
        "signed_prekey_signature": fake_sig,
        "one_time_prekeys": []
    });
    let (status, _) = app
        .request(Method::POST, "/api/v1/auth/register", None, Some(body))
        .await;
    assert_ne!(status, StatusCode::OK);
}

// ─── Channel Permission Checks ───────────────────────

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn delete_channel_requires_permission(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("del_ch_own").await;
    let (token_member, _) = app.register_user("del_ch_mem").await;
    let server_id = app.create_server(&token_owner, "Del Ch Perm").await;

    app.invite_and_join(&token_owner, &token_member, server_id).await;

    let channel_id = app.create_channel(&token_owner, server_id, "protected").await;

    let uri = format!("/api/v1/channels/{}", channel_id);
    let (status, _) = app
        .request(Method::DELETE, &uri, Some(&token_member), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[cfg_attr(feature = "postgres", sqlx::test(migrations = "./migrations"))]
#[cfg_attr(feature = "sqlite", sqlx::test(migrations = "./migrations_sqlite"))]
async fn update_channel_requires_permission(pool: Pool) {
    let app = TestApp::new(pool).await;
    let (token_owner, _) = app.register_user("upd_ch_own").await;
    let (token_member, _) = app.register_user("upd_ch_mem").await;
    let server_id = app.create_server(&token_owner, "Upd Ch Perm").await;

    app.invite_and_join(&token_owner, &token_member, server_id).await;

    let channel_id = app.create_channel(&token_owner, server_id, "protected").await;

    let uri = format!("/api/v1/channels/{}", channel_id);
    let body = json!({ "encrypted_meta": B64.encode(b"new-meta") });
    let (status, _) = app
        .request(Method::PUT, &uri, Some(&token_member), Some(body))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
