use std::net::IpAddr;

use axum::extract::Query;
use axum::Json;
use regex::Regex;

use crate::errors::AppError;
use crate::middleware::auth::AuthUser;
use crate::models::{LinkPreviewQuery, LinkPreviewResponse};

/// Fetch Open Graph metadata from a URL for client-side link previews.
/// The client calls this before encrypting the message, so the preview
/// data is included in the E2EE payload. The server does NOT log URLs.
///
/// Requires authentication to prevent abuse by unauthenticated scrapers.
pub async fn fetch_link_preview(
    _user: AuthUser,
    Query(query): Query<LinkPreviewQuery>,
) -> Result<Json<LinkPreviewResponse>, AppError> {
    let url = query.url.trim().to_string();

    // Basic URL validation
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(AppError::BadRequest("URL must start with http:// or https://".into()));
    }

    // ── SSRF protection: resolve hostname and block private/reserved IPs ──
    let parsed = reqwest::Url::parse(&url)
        .map_err(|_| AppError::BadRequest("Invalid URL".into()))?;

    let host = parsed.host_str()
        .ok_or_else(|| AppError::BadRequest("URL must have a host".into()))?;

    // Block well-known metadata hostnames
    let host_lower = host.to_lowercase();
    if host_lower == "metadata.google.internal"
        || host_lower == "metadata.google"
        || host_lower.ends_with(".internal")
    {
        return Err(AppError::BadRequest("Blocked: internal hostname".into()));
    }

    let port = parsed.port_or_known_default().unwrap_or(80);
    let addr_str = format!("{host}:{port}");

    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&addr_str)
        .await
        .map_err(|_| AppError::BadRequest("Could not resolve hostname".into()))?
        .collect();

    if addrs.is_empty() {
        return Err(AppError::BadRequest("Could not resolve hostname".into()));
    }

    for addr in &addrs {
        if is_private_ip(addr.ip()) {
            return Err(AppError::BadRequest(
                "Blocked: URL resolves to a private/reserved IP address".into(),
            ));
        }
    }

    // Try oEmbed for known providers (YouTube, etc.) before scraping
    if let Some(preview) = try_oembed(&url).await {
        return Ok(Json(preview));
    }

    // Fetch with timeout and size limit
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("HTTP client error: {e}")))?;

    let response = client
        .get(&url)
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await
        .map_err(|_| AppError::BadRequest("Failed to fetch URL".into()))?;

    // Only process HTML responses
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if !content_type.contains("text/html") {
        return Ok(Json(LinkPreviewResponse {
            url,
            ..Default::default()
        }));
    }

    // Read body with size limit (512KB max)
    let body = response
        .text()
        .await
        .map_err(|_| AppError::BadRequest("Failed to read response body".into()))?;

    let html = if body.len() > 512 * 1024 {
        &body[..512 * 1024]
    } else {
        &body
    };

    let preview = extract_og_metadata(html, &url);
    Ok(Json(preview))
}

/// Returns true if the IP address belongs to a private, loopback, link-local,
/// or otherwise reserved range that should not be accessed via SSRF.
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()              // 127.0.0.0/8
                || v4.is_private()         // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()      // 169.254/16
                || v4.is_broadcast()       // 255.255.255.255
                || v4.is_unspecified()     // 0.0.0.0
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64  // 100.64/10 (CGNAT)
                || v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0  // 192.0.0/24
                || v4.octets()[0] == 198 && (v4.octets()[1] & 0xFE) == 18  // 198.18/15 (benchmarking)
                || v4.is_documentation()   // 192.0.2/24, 198.51.100/24, 203.0.113/24
                || v4.octets()[0] >= 240   // 240/4 (reserved/future)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()              // ::1
                || v6.is_unspecified()     // ::
                || v6.segments()[0] == 0xfe80  // link-local fe80::/10
                || v6.segments()[0] == 0xfc00 || v6.segments()[0] == 0xfd00  // ULA fc00::/7
                // IPv4-mapped IPv6 (::ffff:0:0/96) — check inner v4
                || matches!(v6.to_ipv4_mapped(), Some(v4) if is_private_ip(IpAddr::V4(v4)))
        }
    }
}

/// Try to fetch preview via oEmbed for known providers.
/// Returns None if the URL isn't from a supported provider or the request fails.
async fn try_oembed(url: &str) -> Option<LinkPreviewResponse> {
    let oembed_url = if is_youtube_url(url) {
        format!("https://www.youtube.com/oembed?url={}&format=json", urlencoding::encode(url))
    } else {
        return None;
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;

    let resp = client
        .get(&oembed_url)
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let json: serde_json::Value = resp.json().await.ok()?;

    Some(LinkPreviewResponse {
        url: url.to_string(),
        title: json["title"].as_str().map(String::from),
        description: json["author_name"].as_str().map(String::from),
        image: json["thumbnail_url"].as_str().map(String::from),
        site_name: json["provider_name"].as_str().map(String::from),
    })
}

fn is_youtube_url(url: &str) -> bool {
    let re = Regex::new(r"(?i)^https?://(www\.)?(youtube\.com|youtu\.be)/").unwrap();
    re.is_match(url)
}

/// Extract Open Graph metadata from HTML using regex.
fn extract_og_metadata(html: &str, url: &str) -> LinkPreviewResponse {
    let mut resp = LinkPreviewResponse {
        url: url.to_string(),
        ..Default::default()
    };

    // Match <meta property="og:..." content="..."> (handles both " and ' quotes)
    // Handles both property="og:X" content="Y" and content="Y" property="og:X" orderings
    let og_re = Regex::new(
        r#"(?i)<meta\s+(?:[^>]*?\s)?property\s*=\s*["']og:([^"']+)["'][^>]*?\scontent\s*=\s*["']([^"']*)["'][^>]*/?\s*>"#,
    )
    .unwrap();

    let og_re_rev = Regex::new(
        r#"(?i)<meta\s+(?:[^>]*?\s)?content\s*=\s*["']([^"']*)["'][^>]*?\sproperty\s*=\s*["']og:([^"']+)["'][^>]*/?\s*>"#,
    )
    .unwrap();

    for cap in og_re.captures_iter(html) {
        let key = cap[1].to_lowercase();
        let value = cap[2].to_string();
        match key.as_str() {
            "title" => resp.title = Some(value),
            "description" => resp.description = Some(value),
            "image" => resp.image = Some(value),
            "site_name" => resp.site_name = Some(value),
            _ => {}
        }
    }

    // Also check reversed attribute order
    for cap in og_re_rev.captures_iter(html) {
        let value = cap[1].to_string();
        let key = cap[2].to_lowercase();
        match key.as_str() {
            "title" if resp.title.is_none() => resp.title = Some(value),
            "description" if resp.description.is_none() => resp.description = Some(value),
            "image" if resp.image.is_none() => resp.image = Some(value),
            "site_name" if resp.site_name.is_none() => resp.site_name = Some(value),
            _ => {}
        }
    }

    // Fallback: <title> tag
    if resp.title.is_none() {
        let title_re = Regex::new(r"(?i)<title[^>]*>([^<]+)</title>").unwrap();
        if let Some(cap) = title_re.captures(html) {
            resp.title = Some(cap[1].trim().to_string());
        }
    }

    // Fallback: <meta name="description" content="...">
    if resp.description.is_none() {
        let desc_re = Regex::new(
            r#"(?i)<meta\s+(?:[^>]*?\s)?name\s*=\s*"description"[^>]*?\scontent\s*=\s*"([^"]*)"[^>]*/?\s*>"#,
        )
        .unwrap();
        if let Some(cap) = desc_re.captures(html) {
            resp.description = Some(cap[1].to_string());
        }
    }

    resp
}
