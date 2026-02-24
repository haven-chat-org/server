use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

#[derive(rust_embed::Embed)]
#[folder = "packages/web/dist/"]
struct WebAssets;

pub fn router() -> axum::Router {
    axum::Router::new().fallback(serve_embedded)
}

async fn serve_embedded(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Try the exact path first
    if let Some(content) = WebAssets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, mime.as_ref().to_string()),
                (header::CACHE_CONTROL, cache_control(path).to_string()),
            ],
            content.data.into_owned(),
        )
            .into_response();
    }

    // SPA fallback: serve index.html for all non-file routes
    match WebAssets::get("index.html") {
        Some(content) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/html".to_string()),
                (header::CACHE_CONTROL, "no-cache".to_string()),
            ],
            content.data.into_owned(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "Web UI not found").into_response(),
    }
}

/// Assets with hashes in filenames (Vite output) can be cached aggressively.
fn cache_control(path: &str) -> &'static str {
    if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}
