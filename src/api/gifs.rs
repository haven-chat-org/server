use axum::extract::{Query, State};
use axum::Json;

use crate::errors::AppError;
use crate::middleware::auth::AuthUser;
use crate::models::{GifResult, GifSearchQuery, GifSearchResponse};
use crate::AppState;

/// Search GIFs via the Giphy API (proxied to avoid exposing API key to clients).
pub async fn search_gifs(
    _user: AuthUser,
    State(state): State<AppState>,
    Query(query): Query<GifSearchQuery>,
) -> Result<Json<GifSearchResponse>, AppError> {
    let api_key = &state.config.giphy_api_key;
    if api_key.is_empty() {
        return Err(AppError::BadRequest(
            "GIF search not configured".into(),
        ));
    }

    let offset = query.offset.unwrap_or(0);
    let url = format!(
        "https://api.giphy.com/v1/gifs/search?api_key={}&q={}&limit=25&offset={}&rating=g",
        api_key,
        urlencoding::encode(&query.q),
        offset,
    );

    let resp = fetch_giphy(&url).await?;
    Ok(Json(resp))
}

/// Get trending GIFs via the Giphy API.
pub async fn trending_gifs(
    _user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<GifSearchResponse>, AppError> {
    let api_key = &state.config.giphy_api_key;
    if api_key.is_empty() {
        return Err(AppError::BadRequest(
            "GIF search not configured".into(),
        ));
    }

    let url = format!(
        "https://api.giphy.com/v1/gifs/trending?api_key={}&limit=25&rating=g",
        api_key,
    );

    let resp = fetch_giphy(&url).await?;
    Ok(Json(resp))
}

/// Fetch from Giphy API and parse into our simplified response.
async fn fetch_giphy(url: &str) -> Result<GifSearchResponse, AppError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("HTTP client error: {e}")))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Giphy API request failed: {e}")))?;

    if !response.status().is_success() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "Giphy API returned status {}",
            response.status()
        )));
    }

    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to parse Giphy response: {e}")))?;

    let total_count = json["pagination"]["total_count"]
        .as_u64()
        .unwrap_or(0) as u32;

    let data = json["data"].as_array();
    let results = data
        .map(|arr| {
            arr.iter()
                .filter_map(|gif| {
                    let id = gif["id"].as_str()?;
                    let title = gif["title"].as_str().unwrap_or("");
                    let fixed = &gif["images"]["fixed_height"];
                    let url = fixed["url"].as_str()?;
                    let preview_url = gif["images"]["fixed_height_still"]["url"]
                        .as_str()
                        .unwrap_or(url);
                    let width = fixed["width"]
                        .as_str()
                        .and_then(|w| w.parse().ok())
                        .unwrap_or(200);
                    let height = fixed["height"]
                        .as_str()
                        .and_then(|h| h.parse().ok())
                        .unwrap_or(200);

                    Some(GifResult {
                        id: id.to_string(),
                        title: title.to_string(),
                        url: url.to_string(),
                        preview_url: preview_url.to_string(),
                        width,
                        height,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(GifSearchResponse {
        results,
        total_count,
    })
}
