use axum::{extract::State, Json};
use lettre::{
    message::header::ContentType,
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use sha2::{Digest, Sha256};

use crate::db::queries;
use crate::errors::{AppError, AppResult};
use crate::models::{BetaCodeRequest, BetaCodeResponse};
use crate::AppState;

/// Hash an email address with SHA-256 for duplicate detection.
/// Only the hash is stored — the email itself is never persisted.
fn hash_email(email: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(email.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// POST /api/v1/beta/request-code
///
/// Public endpoint (no auth required). Rate-limited to 3 req/min per IP.
///
/// Privacy guarantee: the email address exists ONLY in the request body
/// and the SMTP send buffer. Only a SHA-256 hash is stored for dedup.
pub async fn request_beta_code(
    State(state): State<AppState>,
    Json(req): Json<BetaCodeRequest>,
) -> AppResult<Json<BetaCodeResponse>> {
    // 1. Validate SMTP is configured
    if !state.config.smtp_enabled() {
        return Err(AppError::BadRequest(
            "Beta signups are not currently available".into(),
        ));
    }

    // 2. Basic email validation (not exhaustive — just reject garbage)
    let email = req.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') || email.len() > 254 {
        return Err(AppError::Validation("Invalid email address".into()));
    }

    // 3. Check if this email already received a beta code
    let email_hash = hash_email(&email);
    let already_issued = queries::beta_code_exists_for_email(state.db.read(), &email_hash).await?;
    if already_issued {
        // Same generic response — don't reveal whether we recognized the email
        return Ok(Json(BetaCodeResponse {
            success: true,
            message: "If slots are available, you'll receive a code shortly.".into(),
        }));
    }

    // 4. Check global cap
    let issued = queries::count_beta_codes(state.db.read()).await?;
    if issued >= state.config.beta_code_limit as i64 {
        return Ok(Json(BetaCodeResponse {
            success: true,
            message: "If slots are available, you'll receive a code shortly.".into(),
        }));
    }

    // 5. Create a registration invite (email hash stored, not the email)
    let invite = queries::create_beta_invite(
        state.db.write(),
        state.config.beta_code_expiry_days,
        &email_hash,
    )
    .await?;

    // 6. Send the email (fire-and-forget: spawn so we don't block the response)
    let smtp_host = state.config.smtp_host.clone();
    let smtp_port = state.config.smtp_port;
    let smtp_username = state.config.smtp_username.clone();
    let smtp_password = state.config.smtp_password.clone();
    let smtp_from = state.config.smtp_from.clone();
    let code = invite.code.clone();
    let expiry_days = state.config.beta_code_expiry_days;

    tokio::spawn(async move {
        match send_beta_email(
            &smtp_host,
            smtp_port,
            &smtp_username,
            &smtp_password,
            &smtp_from,
            &email,
            &code,
            expiry_days,
        )
        .await
        {
            Ok(()) => {
                tracing::info!("Beta code email sent successfully via {}", smtp_host);
            }
            Err(e) => {
                tracing::error!("Failed to send beta code email via {}: {:?}", smtp_host, e);
                // Note: the invite code was already created in the DB.
                // We intentionally do NOT delete it on send failure — the code
                // is still valid and the user could retry or contact support.
            }
        }
        // After this block, `email` is dropped and gone forever.
    });

    // 7. Always return success (don't leak whether email was valid/duplicate)
    Ok(Json(BetaCodeResponse {
        success: true,
        message: "If slots are available, you'll receive a code shortly.".into(),
    }))
}

#[allow(clippy::too_many_arguments)]
async fn send_beta_email(
    smtp_host: &str,
    smtp_port: u16,
    smtp_username: &str,
    smtp_password: &str,
    smtp_from: &str,
    to_email: &str,
    code: &str,
    expiry_days: i64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let from_trimmed = smtp_from.trim().trim_matches('"');
    let to_trimmed = to_email.trim();

    let from_mailbox = from_trimmed.parse().map_err(|e| {
        format!("Failed to parse From address '{}': {}", from_trimmed, e)
    })?;
    let to_mailbox = to_trimmed.parse().map_err(|e| {
        format!("Failed to parse To address: {}", e)
    })?;

    let email = Message::builder()
        .from(from_mailbox)
        .to(to_mailbox)
        .subject("Your Haven Beta Code")
        .header(ContentType::TEXT_HTML)
        .body(format!(
            r#"<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #F5F0E8; padding: 40px 20px;">
  <div style="max-width: 480px; margin: 0 auto; background: #fff; border-radius: 12px; padding: 40px; box-shadow: 0 2px 8px rgba(0,0,0,0.06);">
    <h1 style="color: #1A1310; font-size: 24px; margin: 0 0 8px;">Welcome to Haven</h1>
    <p style="color: #6F6358; margin: 0 0 24px;">Your beta access code is below. Use it when registering at Haven.</p>
    <div style="background: #F5F0E8; border: 1px solid #D1C8BA; border-radius: 8px; padding: 16px; text-align: center; margin: 0 0 24px;">
      <code style="font-size: 28px; font-weight: 700; color: #C2410C; letter-spacing: 2px;">{code}</code>
    </div>
    <p style="color: #8A7E73; font-size: 14px; margin: 0;">This code expires in {expiry_days} days and can only be used once.</p>
    <hr style="border: none; border-top: 1px solid #D1C8BA; margin: 24px 0;" />
    <p style="color: #8A7E73; font-size: 12px; margin: 0;">Haven &mdash; Privacy-first communication.<br/>This email was sent because someone requested a beta code. Your email is not stored.</p>
  </div>
</body>
</html>"#,
        ))?;

    let creds = Credentials::new(smtp_username.to_owned(), smtp_password.to_owned());

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(smtp_host)?
        .port(smtp_port)
        .credentials(creds)
        .build();

    mailer.send(email).await?;
    Ok(())
}
