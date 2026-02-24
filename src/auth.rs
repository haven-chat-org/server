use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::AppConfig;
use crate::errors::{AppError, AppResult};

// ─── JWT Claims ────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // user ID
    pub exp: usize,  // expiry timestamp
    pub iat: usize,  // issued at
    pub jti: String, // unique token ID
}

// ─── Password Hashing (Argon2id) ───────────────────────

/// Hash a password using Argon2id with a random salt.
pub fn hash_password(password: &str) -> AppResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Password hashing failed: {}", e)))?;
    Ok(hash.to_string())
}

/// Verify a password against a stored Argon2id hash.
pub fn verify_password(password: &str, hash: &str) -> AppResult<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid password hash: {}", e)))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Hash an email for storage (one-way, for account recovery matching).
/// Uses HMAC-SHA256 with the server's JWT secret as key to prevent rainbow table attacks.
pub fn hash_email(email: &str, secret: &str) -> String {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let normalized = email.trim().to_lowercase();
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC can accept key of any size");
    mac.update(normalized.as_bytes());
    format!("{:x}", mac.finalize().into_bytes())
}

// ─── JWT Token Generation ──────────────────────────────

/// Generate a JWT access token for a user.
pub fn generate_access_token(user_id: Uuid, config: &AppConfig) -> AppResult<String> {
    let now = Utc::now();
    let expiry = now + Duration::hours(config.jwt_expiry_hours);

    let claims = Claims {
        sub: user_id.to_string(),
        exp: expiry.timestamp() as usize,
        iat: now.timestamp() as usize,
        jti: Uuid::new_v4().to_string(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(anyhow::anyhow!("JWT encoding failed: {}", e)))?;

    Ok(token)
}

/// Validate a JWT access token and extract claims.
pub fn validate_access_token(token: &str, config: &AppConfig) -> AppResult<Claims> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::TokenExpired,
        _ => AppError::InvalidToken,
    })?;

    Ok(token_data.claims)
}

/// Extract the user ID from validated claims.
pub fn user_id_from_claims(claims: &Claims) -> AppResult<Uuid> {
    Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::InvalidToken)
}

// ─── Refresh Tokens ────────────────────────────────────

/// Generate a cryptographically random refresh token.
pub fn generate_refresh_token() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..48).map(|_| rng.gen()).collect();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes)
}

/// Hash a refresh token for storage (we never store the raw token).
pub fn hash_refresh_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ─── TOTP (2FA) ────────────────────────────────────────

/// Generate a new TOTP secret and return it with the provisioning URI.
pub fn generate_totp_secret(username: &str) -> AppResult<(String, String)> {
    use totp_rs::{Algorithm, Secret, TOTP};

    let secret = Secret::generate_secret();
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().unwrap(),
        Some("Haven".into()),
        username.into(),
    )
    .map_err(|e| AppError::Internal(anyhow::anyhow!("TOTP generation failed: {}", e)))?;

    let uri = totp.get_url();
    let secret_b32 = secret.to_encoded().to_string();

    Ok((secret_b32, uri))
}

/// Verify a TOTP code against a stored secret.
pub fn verify_totp(secret_b32: &str, code: &str) -> AppResult<bool> {
    use totp_rs::{Algorithm, Secret, TOTP};

    let secret = Secret::Encoded(secret_b32.into());
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().map_err(|e| {
            AppError::Internal(anyhow::anyhow!("Invalid TOTP secret: {}", e))
        })?,
        Some("Haven".into()),
        String::new(),
    )
    .map_err(|e| AppError::Internal(anyhow::anyhow!("TOTP creation failed: {}", e)))?;

    Ok(totp.check_current(code).unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;

    fn test_config() -> AppConfig {
        AppConfig::test_default()
    }

    // ─── Password Hashing ───────────────────────────────

    #[test]
    fn hash_password_produces_argon2_hash() {
        let hash = hash_password("mypassword").unwrap();
        assert!(hash.starts_with("$argon2"));
    }

    #[test]
    fn hash_password_different_salts() {
        let h1 = hash_password("same").unwrap();
        let h2 = hash_password("same").unwrap();
        assert_ne!(h1, h2); // different salts
    }

    #[test]
    fn verify_password_correct() {
        let hash = hash_password("correcthorse").unwrap();
        assert!(verify_password("correcthorse", &hash).unwrap());
    }

    #[test]
    fn verify_password_incorrect() {
        let hash = hash_password("correcthorse").unwrap();
        assert!(!verify_password("wronghorse", &hash).unwrap());
    }

    // ─── Email Hashing ──────────────────────────────────

    #[test]
    fn hash_email_deterministic() {
        let h1 = hash_email("test@example.com", "secret");
        let h2 = hash_email("test@example.com", "secret");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_email_case_insensitive() {
        let h1 = hash_email("Test@Example.COM", "secret");
        let h2 = hash_email("test@example.com", "secret");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_email_trims_whitespace() {
        let h1 = hash_email("  test@example.com  ", "secret");
        let h2 = hash_email("test@example.com", "secret");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_email_different_secrets() {
        let h1 = hash_email("test@example.com", "secret1");
        let h2 = hash_email("test@example.com", "secret2");
        assert_ne!(h1, h2);
    }

    // ─── JWT Tokens ─────────────────────────────────────

    #[test]
    fn generate_and_validate_access_token() {
        let config = test_config();
        let user_id = Uuid::new_v4();
        let token = generate_access_token(user_id, &config).unwrap();
        let claims = validate_access_token(&token, &config).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
    }

    #[test]
    fn validate_token_wrong_secret_fails() {
        let config = test_config();
        let user_id = Uuid::new_v4();
        let token = generate_access_token(user_id, &config).unwrap();

        let mut bad_config = test_config();
        bad_config.jwt_secret = "completely-different-secret-key-for-testing".into();
        assert!(validate_access_token(&token, &bad_config).is_err());
    }

    #[test]
    fn validate_token_garbage_fails() {
        let config = test_config();
        assert!(validate_access_token("not.a.jwt", &config).is_err());
    }

    #[test]
    fn user_id_from_claims_valid() {
        let user_id = Uuid::new_v4();
        let claims = Claims {
            sub: user_id.to_string(),
            exp: 99999999999,
            iat: 0,
            jti: Uuid::new_v4().to_string(),
        };
        assert_eq!(user_id_from_claims(&claims).unwrap(), user_id);
    }

    #[test]
    fn user_id_from_claims_invalid_uuid() {
        let claims = Claims {
            sub: "not-a-uuid".into(),
            exp: 99999999999,
            iat: 0,
            jti: Uuid::new_v4().to_string(),
        };
        assert!(user_id_from_claims(&claims).is_err());
    }

    // ─── Refresh Tokens ─────────────────────────────────

    #[test]
    fn refresh_token_is_unique() {
        let t1 = generate_refresh_token();
        let t2 = generate_refresh_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn refresh_token_not_empty() {
        let t = generate_refresh_token();
        assert!(!t.is_empty());
        assert!(t.len() > 20); // 48 bytes base64 = 64 chars
    }

    #[test]
    fn hash_refresh_token_deterministic() {
        let t = generate_refresh_token();
        let h1 = hash_refresh_token(&t);
        let h2 = hash_refresh_token(&t);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_refresh_token_different_inputs() {
        let h1 = hash_refresh_token("token_a");
        let h2 = hash_refresh_token("token_b");
        assert_ne!(h1, h2);
    }

    // ─── TOTP ───────────────────────────────────────────

    #[test]
    fn generate_totp_secret_returns_secret_and_uri() {
        let (secret, uri) = generate_totp_secret("testuser").unwrap();
        assert!(!secret.is_empty());
        assert!(uri.contains("otpauth://"));
        assert!(uri.contains("Haven"));
        assert!(uri.contains("testuser"));
    }

    #[test]
    fn verify_totp_correct_code() {
        let (secret, _) = generate_totp_secret("testuser").unwrap();
        // Generate a valid code from the same secret
        use totp_rs::{Algorithm, Secret, TOTP};
        let s = Secret::Encoded(secret.clone());
        let totp = TOTP::new(
            Algorithm::SHA1, 6, 1, 30,
            s.to_bytes().unwrap(),
            Some("Haven".into()), "testuser".into(),
        ).unwrap();
        let code = totp.generate_current().unwrap();
        assert!(verify_totp(&secret, &code).unwrap());
    }

    #[test]
    fn verify_totp_wrong_code() {
        let (secret, _) = generate_totp_secret("testuser").unwrap();
        assert!(!verify_totp(&secret, "000000").unwrap());
    }
}
