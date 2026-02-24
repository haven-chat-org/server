use axum::{
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts},
};
use uuid::Uuid;

use crate::auth::{user_id_from_claims, validate_access_token};
use crate::db::queries;
use crate::errors::AppError;
use crate::AppState;

/// Extractor that validates JWT and provides the authenticated user ID.
/// Use in handler signatures: `AuthUser(user_id): AuthUser`
#[derive(Debug, Clone)]
pub struct AuthUser(pub Uuid);

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::AuthError("Missing authorization header".into()))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AppError::AuthError("Invalid authorization format".into()))?;

        let claims = validate_access_token(token, &state.config)?;
        let user_id = user_id_from_claims(&claims)?;

        Ok(AuthUser(user_id))
    }
}

/// Extractor that validates JWT and verifies the user is an instance admin.
/// Use in handler signatures: `AdminUser(user_id): AdminUser`
#[derive(Debug, Clone)]
pub struct AdminUser(pub Uuid);

#[axum::async_trait]
impl FromRequestParts<AppState> for AdminUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::AuthError("Missing authorization header".into()))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AppError::AuthError("Invalid authorization format".into()))?;

        let claims = validate_access_token(token, &state.config)?;
        let user_id = user_id_from_claims(&claims)?;

        // Verify user is an instance admin
        let user = queries::find_user_by_id(state.db.read(), user_id)
            .await?
            .ok_or(AppError::AuthError("User not found".into()))?;

        if !user.is_instance_admin {
            return Err(AppError::Forbidden("Instance admin access required".into()));
        }

        Ok(AdminUser(user_id))
    }
}

/// Optional auth extractor — returns None if no valid token present.
/// Useful for endpoints that behave differently for authenticated users.
#[derive(Debug, Clone)]
pub struct OptionalAuthUser(pub Option<Uuid>);

#[axum::async_trait]
impl FromRequestParts<AppState> for OptionalAuthUser {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let user_id = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .and_then(|token| validate_access_token(token, &state.config).ok())
            .and_then(|claims| user_id_from_claims(&claims).ok());

        Ok(OptionalAuthUser(user_id))
    }
}
