use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use uuid::Uuid;

/// Active DM/group call state (ephemeral, not persisted).
pub struct ActiveCall {
    pub caller_id: Uuid,
    pub started_at: Instant,
}

/// A connected (accepted) call with its start time for duration tracking.
pub struct ConnectedCall {
    pub started_at: Instant,
}

/// In-memory state stores for single-instance mode (no Redis).
///
/// When Redis is configured, these still serve as a local cache layer.
/// When Redis is absent, these are the sole source of truth for ephemeral state.
#[derive(Clone)]
pub struct MemoryStore {
    /// User presence: user_id → status string (online, idle, dnd, invisible)
    pub presence: Arc<DashMap<Uuid, String>>,
    /// Generic cache: key → (JSON string, expiry instant)
    pub cache: Arc<DashMap<String, (String, Instant)>>,
    /// PoW challenges: challenge string → expiry instant
    pub pow_challenges: Arc<DashMap<String, Instant>>,
    /// Voice channel participants: channel_id → set of user_ids
    pub voice_participants: Arc<DashMap<Uuid, HashSet<Uuid>>>,
    /// Server-muted users per voice channel
    pub voice_muted: Arc<DashMap<Uuid, HashSet<Uuid>>>,
    /// Server-deafened users per voice channel
    pub voice_deafened: Arc<DashMap<Uuid, HashSet<Uuid>>>,
    /// Active DM/group calls: channel_id → call state
    pub active_calls: Arc<DashMap<Uuid, ActiveCall>>,
    /// Connected (accepted) calls: channel_id → connected call state
    pub connected_calls: Arc<DashMap<Uuid, ConnectedCall>>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self {
            presence: Arc::new(DashMap::new()),
            cache: Arc::new(DashMap::new()),
            pow_challenges: Arc::new(DashMap::new()),
            voice_participants: Arc::new(DashMap::new()),
            voice_muted: Arc::new(DashMap::new()),
            voice_deafened: Arc::new(DashMap::new()),
            active_calls: Arc::new(DashMap::new()),
            connected_calls: Arc::new(DashMap::new()),
        }
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawn a background task that prunes expired cache and PoW entries every 60 seconds.
    pub fn spawn_cleanup_task(&self) {
        let cache = self.cache.clone();
        let pow = self.pow_challenges.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = Instant::now();

                // Prune expired cache entries
                cache.retain(|_, (_, expiry)| *expiry > now);

                // Prune expired PoW challenges
                pow.retain(|_, expiry| *expiry > now);
            }
        });
    }
}
