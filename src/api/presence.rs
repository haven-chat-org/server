use axum::{extract::{Query, State}, Json};
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{PresenceEntry, PresenceQuery};
use crate::AppState;

/// Bulk presence check: returns online/offline status for a list of user IDs.
/// GET /api/v1/presence?user_ids=uuid1,uuid2,...
pub async fn get_presence(
    State(state): State<AppState>,
    Query(query): Query<PresenceQuery>,
) -> Result<Json<Vec<PresenceEntry>>, AppError> {
    let user_ids: Vec<Uuid> = query
        .user_ids
        .split(',')
        .filter_map(|s| s.trim().parse::<Uuid>().ok())
        .collect();

    if user_ids.is_empty() {
        return Ok(Json(vec![]));
    }

    let entries = if let Some(mut redis) = state.redis.clone() {
        // Bulk-fetch presence from Redis hash
        let mut cmd = redis::cmd("HMGET");
        cmd.arg("haven:presence");
        for uid in &user_ids {
            cmd.arg(uid.to_string());
        }
        let statuses: Vec<Option<String>> = cmd
            .query_async(&mut redis)
            .await
            .unwrap_or_else(|_| vec![None; user_ids.len()]);

        user_ids
            .iter()
            .zip(statuses.iter())
            .map(|(uid, status)| {
                let s = match status.as_deref() {
                    // Never leak "invisible" to other users
                    Some("invisible") | None => "offline",
                    Some(s) => s,
                };
                PresenceEntry {
                    user_id: *uid,
                    status: s.to_string(),
                }
            })
            .collect()
    } else {
        // In-memory presence fallback
        user_ids
            .iter()
            .map(|uid| {
                let status = state.memory.presence
                    .get(uid)
                    .map(|v| v.value().clone())
                    .unwrap_or_else(|| "offline".to_string());
                let s = if status == "invisible" { "offline" } else { &status };
                PresenceEntry {
                    user_id: *uid,
                    status: s.to_string(),
                }
            })
            .collect()
    };

    Ok(Json(entries))
}
