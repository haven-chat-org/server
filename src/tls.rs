use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use std::path::Path;

/// Ensure TLS certificate and key files exist, generating them if needed.
/// Returns a `RustlsConfig` ready for use with `axum-server`.
///
/// CRITICAL: ALPN is locked to http/1.1 ONLY. WebSocket upgrades require
/// HTTP/1.1, and HTTP/2 WebSocket (RFC 8441 extended CONNECT) is not
/// supported by axum-server/hyper. If we offer h2, browsers negotiate it
/// and WebSocket connections silently fail.
pub async fn ensure_certs(
    cert_path: &str,
    key_path: &str,
    auto_generate: bool,
) -> Result<RustlsConfig> {
    let cert_path = Path::new(cert_path);
    let key_path = Path::new(key_path);

    if !cert_path.exists() || !key_path.exists() {
        if !auto_generate {
            anyhow::bail!(
                "TLS cert/key not found at {:?} / {:?} and auto_generate is disabled",
                cert_path,
                key_path
            );
        }
        generate_self_signed(cert_path, key_path)?;
    } else {
        tracing::info!("Using existing TLS certificate: {:?}", cert_path);
    }

    // Build a custom rustls ServerConfig so we can set ALPN protocols
    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("Failed to read cert from {:?}", cert_path))?;
    let key_pem = std::fs::read(key_path)
        .with_context(|| format!("Failed to read key from {:?}", key_path))?;

    let certs = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse PEM certificates")?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .context("Failed to parse PEM private key")?
        .context("No private key found in PEM file")?;

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build rustls ServerConfig")?;

    // Lock ALPN to http/1.1 only — no h2 (breaks WebSockets)
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let rustls_config = RustlsConfig::from_config(std::sync::Arc::new(server_config));
    Ok(rustls_config)
}

/// Generate a self-signed certificate with SANs for localhost, 127.0.0.1, ::1.
fn generate_self_signed(cert_path: &Path, key_path: &Path) -> Result<()> {
    tracing::info!("Generating self-signed TLS certificate...");

    let san_strings = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];

    let certified_key = rcgen::generate_simple_self_signed(san_strings)
        .context("Failed to generate self-signed certificate")?;

    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create certs directory: {:?}", parent))?;
    }

    std::fs::write(cert_path, certified_key.cert.pem())
        .with_context(|| format!("Failed to write cert to {:?}", cert_path))?;
    std::fs::write(key_path, certified_key.key_pair.serialize_pem())
        .with_context(|| format!("Failed to write key to {:?}", key_path))?;

    tracing::info!("Self-signed TLS certificate written to {:?}", cert_path);
    tracing::info!("TLS private key written to {:?}", key_path);

    Ok(())
}
