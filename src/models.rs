use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

// ─── Pagination ────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl PaginationQuery {
    /// Returns clamped limit (default 50, max 100) and offset (default 0).
    pub fn resolve(&self) -> (i64, i64) {
        let limit = self.limit.unwrap_or(50).clamp(1, 100);
        let offset = self.offset.unwrap_or(0).max(0);
        (limit, offset)
    }
}

// ─── User ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub email_hash: Option<String>,
    pub password_hash: String,
    pub identity_key: Vec<u8>,     // X25519 public identity key
    pub signed_prekey: Vec<u8>,    // Signed pre-key (public)
    pub signed_prekey_sig: Vec<u8>, // Signature over the signed pre-key
    pub totp_secret: Option<String>,
    pub pending_totp_secret: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub about_me: Option<String>,
    pub custom_status: Option<String>,
    pub custom_status_emoji: Option<String>,
    pub avatar_url: Option<String>,
    pub banner_url: Option<String>,
    pub dm_privacy: String, // "everyone", "friends_only", "server_members"
    pub encrypted_profile: Option<Vec<u8>>,
    pub is_instance_admin: bool,
    pub is_system: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserPublic {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub about_me: Option<String>,
    pub avatar_url: Option<String>,
    pub banner_url: Option<String>,
    pub custom_status: Option<String>,
    pub custom_status_emoji: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_profile: Option<String>, // base64
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_instance_admin: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_system: Option<bool>,
    pub totp_enabled: bool,
}

impl From<User> for UserPublic {
    fn from(u: User) -> Self {
        let admin = if u.is_instance_admin { Some(true) } else { None };
        let system = if u.is_system { Some(true) } else { None };
        let totp = u.totp_secret.is_some();
        Self {
            id: u.id,
            username: u.username,
            display_name: u.display_name,
            about_me: u.about_me,
            avatar_url: u.avatar_url,
            banner_url: u.banner_url,
            custom_status: u.custom_status,
            custom_status_emoji: u.custom_status_emoji,
            created_at: u.created_at,
            encrypted_profile: u.encrypted_profile.map(|v| {
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &v)
            }),
            is_instance_admin: admin,
            is_system: system,
            totp_enabled: totp,
        }
    }
}

// ─── Auth Requests / Responses ─────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 3, max = 32, message = "Username must be 3-32 characters"))]
    #[validate(custom(function = "validate_username"))]
    pub username: String,

    #[validate(length(min = 8, max = 128, message = "Password must be 8-128 characters"))]
    pub password: String,

    pub display_name: Option<String>,
    pub email: Option<String>, // optional, hashed before storage

    // Crypto keys (base64-encoded)
    pub identity_key: String,
    pub signed_prekey: String,
    pub signed_prekey_signature: String,
    pub one_time_prekeys: Vec<String>, // batch upload of OTPs

    // Proof-of-Work anti-bot challenge
    pub pow_challenge: String,
    pub pow_nonce: String,

    /// Registration invite code (required when REGISTRATION_INVITE_ONLY=true)
    pub invite_code: Option<String>,

    /// Cloudflare Turnstile token (required when TURNSTILE_SECRET_KEY is set)
    pub turnstile_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub totp_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user: UserPublic,
}

/// Login endpoint returns either full auth tokens or a TOTP challenge.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    Success(Box<AuthResponse>),
    TotpRequired { totp_required: bool },
}

impl axum::response::IntoResponse for LoginResponse {
    fn into_response(self) -> axum::response::Response {
        axum::Json(self).into_response()
    }
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

// ─── Proof-of-Work Challenge ──────────────────────────

#[derive(Debug, Serialize)]
pub struct PowChallengeResponse {
    pub challenge: String,
    /// Number of leading zero bits required in SHA-256(challenge + nonce)
    pub difficulty: u32,
    /// Cloudflare Turnstile site key (present when Turnstile is enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turnstile_site_key: Option<String>,
}

// ─── TOTP ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub qr_code_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct TotpVerifyRequest {
    pub code: String,
}

// ─── Pre-Keys (X3DH) ──────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PreKey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub key_id: i32,
    pub public_key: Vec<u8>,
    pub used: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct KeyBundle {
    pub identity_key: String,       // base64
    pub signed_prekey: String,      // base64
    pub signed_prekey_sig: String,  // base64
    pub one_time_prekey: Option<String>, // base64, consumed on fetch
}

#[derive(Debug, Deserialize)]
pub struct UploadPreKeysRequest {
    pub prekeys: Vec<String>, // base64-encoded public keys
}

#[derive(Debug, Deserialize)]
pub struct UpdateKeysRequest {
    pub identity_key: String,          // base64
    pub signed_prekey: String,         // base64
    pub signed_prekey_signature: String, // base64
}

// ─── Servers ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Server {
    pub id: Uuid,
    pub encrypted_meta: Vec<u8>, // name, description, icon — encrypted with server key
    pub owner_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub system_channel_id: Option<Uuid>,
    pub icon_url: Option<String>,
    pub is_system: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateServerRequest {
    pub encrypted_meta: String, // base64
}

#[derive(Debug, Serialize)]
pub struct ServerResponse {
    pub id: Uuid,
    pub encrypted_meta: String, // base64
    pub owner_id: Uuid,
    pub created_at: DateTime<Utc>,
    /// Effective permissions for the requesting user (i64 as string for JS safety).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub my_permissions: Option<String>,
    /// Channel where system messages (joins, etc.) are posted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_channel_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_system: Option<bool>,
}

// ─── Channels ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Channel {
    pub id: Uuid,
    pub server_id: Option<Uuid>, // null for DM channels
    pub encrypted_meta: Vec<u8>,
    pub channel_type: String,    // "text", "dm"
    pub position: i32,
    pub created_at: DateTime<Utc>,
    pub category_id: Option<Uuid>,
    pub dm_status: Option<String>, // "active", "pending", "declined" — only for DM channels
    pub is_private: bool,
    pub encrypted: bool,
    pub export_allowed: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateChannelRequest {
    pub encrypted_meta: String, // base64
    pub channel_type: Option<String>,
    pub position: Option<i32>,
    pub category_id: Option<Uuid>,
    pub is_private: Option<bool>,
    pub encrypted: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ChannelResponse {
    pub id: Uuid,
    pub server_id: Option<Uuid>,
    pub encrypted_meta: String, // base64
    pub channel_type: String,
    pub position: i32,
    pub created_at: DateTime<Utc>,
    pub category_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dm_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_message_id: Option<Uuid>,
    pub is_private: bool,
    pub encrypted: bool,
    pub export_allowed: bool,
}

// ─── Channel Categories ──────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ChannelCategory {
    pub id: Uuid,
    pub server_id: Uuid,
    pub name: String,
    pub position: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateCategoryRequest {
    pub name: String,
    pub position: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCategoryRequest {
    pub name: Option<String>,
    pub position: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct ReorderCategoriesRequest {
    pub order: Vec<CategoryPosition>,
}

#[derive(Debug, Deserialize)]
pub struct CategoryPosition {
    pub id: Uuid,
    pub position: i32,
}

#[derive(Debug, Deserialize)]
pub struct ReorderChannelsRequest {
    pub order: Vec<ChannelPosition>,
}

#[derive(Debug, Deserialize)]
pub struct ChannelPosition {
    pub id: Uuid,
    pub position: i32,
    pub category_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct CategoryResponse {
    pub id: Uuid,
    pub server_id: Uuid,
    pub name: String,
    pub position: i32,
    pub created_at: DateTime<Utc>,
}

impl From<ChannelCategory> for CategoryResponse {
    fn from(c: ChannelCategory) -> Self {
        Self {
            id: c.id,
            server_id: c.server_id,
            name: c.name,
            position: c.position,
            created_at: c.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SetChannelCategoryRequest {
    pub category_id: Option<Uuid>,
}

// ─── Members ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ServerMember {
    pub id: Uuid,
    pub server_id: Uuid,
    pub user_id: Uuid,
    pub encrypted_role: Vec<u8>, // role encrypted with server key
    pub joined_at: DateTime<Utc>,
    pub nickname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ChannelMember {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub user_id: Uuid,
    pub joined_at: DateTime<Utc>,
}

// ─── Messages ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Message {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub sender_token: Vec<u8>,    // sealed sender: ephemeral token
    pub encrypted_body: Vec<u8>,  // E2EE payload
    pub timestamp: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub has_attachments: bool,
    pub sender_id: Option<Uuid>,  // for edit authorization; null for legacy messages
    pub edited_at: Option<DateTime<Utc>>,
    pub reply_to_id: Option<Uuid>,
    pub message_type: String,     // "user" or "system"
}

#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    pub channel_id: Uuid,
    pub sender_token: String,    // base64
    pub encrypted_body: String,  // base64
    pub expires_at: Option<DateTime<Utc>>,
    pub has_attachments: bool,
    pub reply_to_id: Option<Uuid>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MessageResponse {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub sender_token: String,    // base64
    pub encrypted_body: String,  // base64
    pub timestamp: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub has_attachments: bool,
    pub edited: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_type: Option<String>,
}

impl From<Message> for MessageResponse {
    fn from(m: Message) -> Self {
        let message_type = if m.message_type != "user" {
            Some(m.message_type.clone())
        } else {
            None
        };
        Self {
            id: m.id,
            channel_id: m.channel_id,
            sender_token: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &m.sender_token,
            ),
            encrypted_body: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &m.encrypted_body,
            ),
            timestamp: m.timestamp,
            expires_at: m.expires_at,
            has_attachments: m.has_attachments,
            edited: m.edited_at.is_some(),
            reply_to_id: m.reply_to_id,
            message_type,
        }
    }
}

// ─── Attachments ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Attachment {
    pub id: Uuid,
    pub message_id: Uuid,
    pub storage_key: String,
    pub encrypted_meta: Vec<u8>,
    pub size_bucket: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct UploadResponse {
    pub attachment_id: Uuid,
    pub storage_key: String,
}

// ─── Sender Key Distributions ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SenderKeyDistribution {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub from_user_id: Uuid,
    pub to_user_id: Uuid,
    pub distribution_id: Uuid,
    pub encrypted_skdm: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct DistributeSenderKeyRequest {
    pub distributions: Vec<SenderKeyDistributionEntry>,
}

#[derive(Debug, Deserialize)]
pub struct SenderKeyDistributionEntry {
    pub to_user_id: Uuid,
    pub distribution_id: Uuid,
    pub encrypted_skdm: String, // base64
}

#[derive(Debug, Serialize)]
pub struct SenderKeyDistributionResponse {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub from_user_id: Uuid,
    pub distribution_id: Uuid,
    pub encrypted_skdm: String, // base64
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ChannelMemberKeyInfo {
    pub user_id: Uuid,
    pub identity_key: String, // base64
}

// ─── Key Backups ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct KeyBackup {
    pub id: Uuid,
    pub user_id: Uuid,
    pub encrypted_data: Vec<u8>,
    pub nonce: Vec<u8>,
    pub salt: Vec<u8>,
    pub version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct UploadKeyBackupRequest {
    pub encrypted_data: String, // base64
    pub nonce: String,          // base64
    pub salt: String,           // base64
    pub version: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct KeyBackupResponse {
    pub encrypted_data: String, // base64
    pub nonce: String,          // base64
    pub salt: String,           // base64
    pub version: i32,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct KeyBackupStatusResponse {
    pub has_backup: bool,
    pub version: Option<i32>,
    pub updated_at: Option<DateTime<Utc>>,
}

// ─── Reactions ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Reaction {
    pub id: Uuid,
    pub message_id: Uuid,
    pub user_id: Uuid,
    pub emoji: String,
    pub created_at: DateTime<Utc>,
    pub sender_token: Option<String>,
}

/// Aggregated reaction info for a single emoji on a message.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReactionGroup {
    pub message_id: Uuid,
    pub emoji: String,
    pub count: i64,
    pub user_ids: Vec<Uuid>,
}

// ─── Link Previews ────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LinkPreviewQuery {
    pub url: String,
}

#[derive(Debug, Serialize, Default)]
pub struct LinkPreviewResponse {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_name: Option<String>,
}

// ─── Voice ────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct VoiceTokenResponse {
    pub token: String,
    pub url: String,
    pub channel_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct VoiceParticipantResponse {
    pub user_id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub server_muted: bool,
    pub server_deafened: bool,
}

#[derive(Debug, Deserialize)]
pub struct VoiceMuteRequest {
    pub muted: bool,
}

#[derive(Debug, Deserialize)]
pub struct VoiceDeafenRequest {
    pub deafened: bool,
}

// ─── WebSocket Messages ────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", content = "payload")]
pub enum WsClientMessage {
    /// Send an encrypted message to a channel
    SendMessage {
        channel_id: Uuid,
        sender_token: String,
        encrypted_body: String,
        expires_at: Option<DateTime<Utc>>,
        attachment_ids: Option<Vec<Uuid>>,
        reply_to_id: Option<Uuid>,
    },
    /// Edit a previously sent message
    EditMessage {
        message_id: Uuid,
        encrypted_body: String,
    },
    /// Subscribe to channel events
    Subscribe { channel_id: Uuid },
    /// Unsubscribe from channel events
    Unsubscribe { channel_id: Uuid },
    /// Delete a previously sent message
    DeleteMessage { message_id: Uuid },
    /// Add a reaction to a message
    AddReaction { message_id: Uuid, emoji: String },
    /// Remove a reaction from a message
    RemoveReaction { message_id: Uuid, emoji: String },
    /// Typing indicator
    Typing { channel_id: Uuid },
    /// Set user presence status (online, idle, dnd, invisible)
    SetStatus { status: String },
    /// Pin a message in a channel
    PinMessage { channel_id: Uuid, message_id: Uuid },
    /// Unpin a message from a channel
    UnpinMessage { channel_id: Uuid, message_id: Uuid },
    /// Initiate a call in a DM/group channel
    CallInvite { channel_id: Uuid },
    /// Accept an incoming call
    CallAccept { channel_id: Uuid },
    /// Reject an incoming call
    CallReject { channel_id: Uuid },
    /// End an active call
    CallEnd { channel_id: Uuid },
    /// Ping (keepalive)
    Ping,
    /// Mark a channel as read (up to latest message)
    MarkRead { channel_id: Uuid },
    /// Resume a previous session after reconnect
    Resume { session_id: Uuid },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", content = "payload")]
pub enum WsServerMessage {
    /// New message in a subscribed channel
    NewMessage(MessageResponse),
    /// A message was edited
    MessageEdited {
        message_id: Uuid,
        channel_id: Uuid,
        encrypted_body: String,
    },
    /// Typing indicator from another user
    UserTyping {
        channel_id: Uuid,
        user_id: Uuid,
        username: String,
    },
    /// Acknowledgment of a sent message
    MessageAck { message_id: Uuid },
    /// Error
    Error { message: String },
    /// Pong (keepalive response)
    Pong,
    /// Subscribed confirmation
    Subscribed { channel_id: Uuid },
    /// New sender key distributions are available for a channel
    SenderKeysUpdated { channel_id: Uuid },
    /// A message was deleted
    MessageDeleted {
        message_id: Uuid,
        channel_id: Uuid,
    },
    /// A reaction was added to a message
    ReactionAdded {
        message_id: Uuid,
        channel_id: Uuid,
        user_id: Uuid,
        sender_token: String,
        emoji: String,
    },
    /// A reaction was removed from a message
    ReactionRemoved {
        message_id: Uuid,
        channel_id: Uuid,
        user_id: Uuid,
        sender_token: String,
        emoji: String,
    },
    /// User presence change (online/offline)
    PresenceUpdate { user_id: Uuid, status: String },
    /// A friend request was received
    FriendRequestReceived { from_user_id: Uuid, from_username: String, friendship_id: Uuid },
    /// A friend request was accepted
    FriendRequestAccepted { user_id: Uuid, username: String, friendship_id: Uuid },
    /// A friend was removed
    FriendRemoved { user_id: Uuid },
    /// A DM message request was received (pending channel)
    DmRequestReceived { channel_id: Uuid, from_user_id: Uuid },
    /// A message was pinned
    MessagePinned { channel_id: Uuid, message_id: Uuid, pinned_by: Uuid },
    /// A message was unpinned
    MessageUnpinned { channel_id: Uuid, message_id: Uuid },
    /// Voice state change (user joined/left a voice channel)
    VoiceStateUpdate {
        channel_id: Uuid,
        user_id: Uuid,
        username: String,
        joined: bool,
    },
    /// Server mute/deafen state change for a voice participant
    VoiceMuteUpdate {
        channel_id: Uuid,
        user_id: Uuid,
        server_muted: bool,
        server_deafened: bool,
    },
    /// Incoming call ring event (sent to callee(s))
    CallRinging {
        channel_id: Uuid,
        caller_id: Uuid,
        caller_name: String,
    },
    /// Call was accepted
    CallAccepted {
        channel_id: Uuid,
        user_id: Uuid,
    },
    /// Call was rejected
    CallRejected {
        channel_id: Uuid,
        user_id: Uuid,
    },
    /// Call ended
    CallEnded {
        channel_id: Uuid,
        ended_by: Uuid,
    },
    /// A custom emoji was created in a server
    EmojiCreated {
        server_id: Uuid,
        emoji: CustomEmojiResponse,
    },
    /// A custom emoji was deleted from a server
    EmojiDeleted {
        server_id: Uuid,
        emoji_id: Uuid,
    },
    /// Multiple messages were bulk-deleted from a channel
    BulkMessagesDeleted {
        channel_id: Uuid,
        message_ids: Vec<Uuid>,
    },
    /// A member was timed out (or timeout removed)
    MemberTimedOut {
        server_id: Uuid,
        user_id: Uuid,
        timed_out_until: Option<DateTime<Utc>>,
    },
    /// Read state synced across devices
    ReadStateUpdated {
        channel_id: Uuid,
        last_read_at: DateTime<Utc>,
    },
    /// Sent on initial connection with session info
    Hello {
        session_id: Uuid,
        heartbeat_interval_ms: u64,
    },
    /// Resume succeeded — missed events were replayed
    Resumed {
        replayed_count: u32,
    },
    /// Server structure changed (channels/categories created/updated/deleted)
    ServerUpdated { server_id: Uuid },
    /// Session expired or invalid — do a full reconnect
    InvalidSession,
}

// ─── Presence ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PresenceQuery {
    pub user_ids: String, // comma-separated UUIDs
}

#[derive(Debug, Serialize)]
pub struct PresenceEntry {
    pub user_id: Uuid,
    pub status: String,
}

// ─── Refresh Tokens ────────────────────────────────────

#[derive(Debug, Clone, FromRow)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    /// Groups tokens from the same login session for theft detection.
    pub family_id: Option<Uuid>,
    /// When true, this token has been rotated. If a revoked token is replayed,
    /// the entire family is invalidated (potential theft).
    pub revoked: bool,
    /// Device/browser info from User-Agent header at login time.
    pub device_name: Option<String>,
    /// Client IP address at login time.
    pub ip_address: Option<String>,
    /// Last activity timestamp (updated on each token refresh).
    pub last_activity: Option<DateTime<Utc>>,
}

/// Response for the session list endpoint.
#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub id: Uuid,
    pub family_id: Option<Uuid>,
    pub device_name: Option<String>,
    pub ip_address: Option<String>,
    pub last_activity: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub is_current: bool,
}

// ─── Invites ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Invite {
    pub id: Uuid,
    pub server_id: Uuid,
    pub created_by: Uuid,
    pub code: String,
    pub max_uses: Option<i32>,
    pub use_count: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateInviteRequest {
    pub max_uses: Option<i32>,
    pub expires_in_hours: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct InviteResponse {
    pub id: Uuid,
    pub code: String,
    pub server_id: Uuid,
    pub max_uses: Option<i32>,
    pub use_count: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<Invite> for InviteResponse {
    fn from(i: Invite) -> Self {
        Self {
            id: i.id,
            code: i.code,
            server_id: i.server_id,
            max_uses: i.max_uses,
            use_count: i.use_count,
            expires_at: i.expires_at,
            created_at: i.created_at,
        }
    }
}

// ─── Registration Invites (instance-level) ────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RegistrationInvite {
    pub id: Uuid,
    pub code: String,
    pub created_by: Option<Uuid>,
    pub used_by: Option<Uuid>,
    pub used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub email_hash: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistrationInviteResponse {
    pub id: Uuid,
    pub code: String,
    pub created_by: Option<Uuid>,
    pub used: bool,
    pub used_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<RegistrationInvite> for RegistrationInviteResponse {
    fn from(i: RegistrationInvite) -> Self {
        Self {
            id: i.id,
            code: i.code,
            created_by: i.created_by,
            used: i.used_by.is_some(),
            used_by: i.used_by,
            expires_at: i.expires_at,
            created_at: i.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AdminCreateInvitesRequest {
    pub count: Option<u32>,
}

// ─── Beta Code Request ──────────────────────────────

#[derive(Debug, Deserialize)]
pub struct BetaCodeRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct BetaCodeResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct ServerMemberResponse {
    pub user_id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub joined_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    pub role_ids: Vec<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timed_out_until: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_system: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateNicknameRequest {
    pub nickname: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateServerRequest {
    pub system_channel_id: Option<Uuid>,
    pub encrypted_meta: Option<String>,
}

// ─── Channel Member Info ─────────────────────────────

#[derive(Debug, Serialize, FromRow)]
pub struct ChannelMemberInfo {
    pub user_id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub joined_at: DateTime<Utc>,
}

// ─── Group DM ────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateGroupDmRequest {
    pub member_ids: Vec<Uuid>,
    pub encrypted_meta: String, // base64
}

// ─── Change Password ─────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

// ─── User Profiles ───────────────────────────────────

#[derive(Debug, Serialize)]
pub struct UserProfileResponse {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub about_me: Option<String>,
    pub avatar_url: Option<String>,
    pub banner_url: Option<String>,
    pub custom_status: Option<String>,
    pub custom_status_emoji: Option<String>,
    pub created_at: DateTime<Utc>,
    pub is_blocked: bool,
    pub is_friend: bool,
    pub friend_request_status: Option<String>, // null, "pending_incoming", "pending_outgoing"
    pub friendship_id: Option<Uuid>,
    pub mutual_friend_count: i64,
    pub mutual_friends: Vec<MutualFriendInfo>,
    pub mutual_server_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<RoleResponse>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_profile: Option<String>, // base64
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_system: Option<bool>,
}

#[derive(Debug, Serialize, FromRow)]
pub struct MutualFriendInfo {
    pub user_id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub display_name: Option<String>,
    pub about_me: Option<String>,
    pub custom_status: Option<String>,
    pub custom_status_emoji: Option<String>,
    pub encrypted_profile: Option<String>, // base64-encoded encrypted blob
}

// ─── Profile Key Distribution ───────────────────────

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct ProfileKeyDistribution {
    pub id: Uuid,
    pub from_user_id: Uuid,
    pub to_user_id: Uuid,
    pub encrypted_profile_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ProfileKeyDistributionEntry {
    pub to_user_id: Uuid,
    pub encrypted_profile_key: String, // base64
}

#[derive(Debug, Deserialize)]
pub struct DistributeProfileKeysRequest {
    pub distributions: Vec<ProfileKeyDistributionEntry>,
}

#[derive(Debug, Serialize)]
pub struct ProfileKeyResponse {
    pub from_user_id: Uuid,
    pub encrypted_profile_key: String, // base64
}

// ─── Blocked Users ───────────────────────────────────

#[derive(Debug, Serialize, FromRow)]
pub struct BlockedUserResponse {
    pub user_id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub blocked_at: DateTime<Utc>,
}

// ─── Roles & Permissions ─────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Role {
    pub id: Uuid,
    pub server_id: Uuid,
    pub name: String,
    pub color: Option<String>,
    pub permissions: i64,
    pub position: i32,
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub color: Option<String>,
    /// Permissions as string to avoid JS precision loss with i64
    pub permissions: Option<String>,
    pub position: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub color: Option<String>,
    pub permissions: Option<String>,
    pub position: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct RoleResponse {
    pub id: Uuid,
    pub server_id: Uuid,
    pub name: String,
    pub color: Option<String>,
    /// Permissions as string to avoid JS precision loss
    pub permissions: String,
    pub position: i32,
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
}

impl From<Role> for RoleResponse {
    fn from(r: Role) -> Self {
        Self {
            id: r.id,
            server_id: r.server_id,
            name: r.name,
            color: r.color,
            permissions: r.permissions.to_string(),
            position: r.position,
            is_default: r.is_default,
            created_at: r.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AssignRoleRequest {
    pub role_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ChannelPermissionOverwrite {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub target_type: String,
    pub target_id: Uuid,
    pub allow_bits: i64,
    pub deny_bits: i64,
}

#[derive(Debug, Deserialize)]
pub struct SetOverwriteRequest {
    pub target_type: String,   // "role" or "member"
    pub target_id: Uuid,
    pub allow_bits: String,    // string to avoid JS precision loss
    pub deny_bits: String,
}

#[derive(Debug, Serialize)]
pub struct OverwriteResponse {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub target_type: String,
    pub target_id: Uuid,
    pub allow_bits: String,
    pub deny_bits: String,
}

impl From<ChannelPermissionOverwrite> for OverwriteResponse {
    fn from(o: ChannelPermissionOverwrite) -> Self {
        Self {
            id: o.id,
            channel_id: o.channel_id,
            target_type: o.target_type,
            target_id: o.target_id,
            allow_bits: o.allow_bits.to_string(),
            deny_bits: o.deny_bits.to_string(),
        }
    }
}

// ─── Friends ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Friendship {
    pub id: Uuid,
    pub requester_id: Uuid,
    pub addressee_id: Uuid,
    pub status: String, // "pending", "accepted"
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, FromRow)]
pub struct FriendResponse {
    pub id: Uuid,            // friendship ID
    pub user_id: Uuid,       // the other user
    pub username: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub status: String,      // "pending", "accepted"
    pub is_incoming: bool,   // true if the other user sent the request
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_system: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct FriendRequestBody {
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub struct DmRequestAction {
    pub action: String, // "accept" or "decline"
}

#[derive(Debug, Deserialize)]
pub struct UpdateDmPrivacyRequest {
    pub dm_privacy: String, // "everyone", "friends_only", "server_members"
}

// ─── Pinned Messages ────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PinnedMessage {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub message_id: Uuid,
    pub pinned_by: Uuid,
    pub pinned_at: DateTime<Utc>,
}

// ─── Reports ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Report {
    pub id: Uuid,
    pub reporter_id: Uuid,
    pub message_id: Uuid,
    pub channel_id: Uuid,
    pub reason: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateReportRequest {
    pub message_id: Uuid,
    pub channel_id: Uuid,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct ReportResponse {
    pub id: Uuid,
    pub message_id: Uuid,
    pub reason: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

// ─── Bans ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Ban {
    pub id: Uuid,
    pub server_id: Uuid,
    pub user_id: Uuid,
    pub reason: Option<String>,
    pub banned_by: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct BanResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub reason: Option<String>,
    pub banned_by: Uuid,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateBanRequest {
    pub reason: Option<String>,
}

// ─── Custom Emojis ───────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CustomEmoji {
    pub id: Uuid,
    pub server_id: Uuid,
    pub name: String,
    pub uploaded_by: Option<Uuid>,
    pub animated: bool,
    pub storage_key: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomEmojiResponse {
    pub id: Uuid,
    pub server_id: Uuid,
    pub name: String,
    pub uploaded_by: Option<Uuid>,
    pub animated: bool,
    pub image_url: String,
    pub created_at: DateTime<Utc>,
}

impl CustomEmoji {
    pub fn to_response(&self) -> CustomEmojiResponse {
        CustomEmojiResponse {
            id: self.id,
            server_id: self.server_id,
            name: self.name.clone(),
            uploaded_by: self.uploaded_by,
            animated: self.animated,
            image_url: format!("/api/v1/servers/{}/emojis/{}/image", self.server_id, self.id),
            created_at: self.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateEmojiQuery {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct RenameEmojiRequest {
    pub name: String,
}

// ─── Delete Account ──────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct DeleteAccountRequest {
    pub password: String,
}

// ─── Audit Log ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub server_id: Uuid,
    pub actor_id: Uuid,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub changes: Option<serde_json::Value>,
    pub reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub id: Uuid,
    pub actor_id: Uuid,
    pub actor_username: String,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub changes: Option<serde_json::Value>,
    pub reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ─── Moderation ──────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TimeoutMemberRequest {
    pub duration_seconds: i64,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BulkDeleteRequest {
    pub message_ids: Vec<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    pub limit: Option<i64>,
    pub before: Option<DateTime<Utc>>,
}

// ─── Read States ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ReadState {
    pub user_id: Uuid,
    pub channel_id: Uuid,
    pub last_read_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ChannelUnreadInfo {
    pub channel_id: Uuid,
    pub last_message_id: Option<Uuid>,
    pub last_message_at: Option<DateTime<Utc>>,
    pub unread_count: i64,
}

// ─── Admin Dashboard ─────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AdminStats {
    pub total_users: i64,
    pub total_servers: i64,
    pub total_channels: i64,
    pub total_messages: i64,
    pub active_connections: usize,
}

#[derive(Debug, Deserialize)]
pub struct AdminSearchQuery {
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize, FromRow)]
pub struct AdminUserResponse {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub is_instance_admin: bool,
    pub server_count: i64,
}

#[derive(Debug, Deserialize)]
pub struct SetAdminRequest {
    pub is_admin: bool,
}

// ─── GIF Search (Giphy Proxy) ────────────────────────

#[derive(Debug, Deserialize)]
pub struct GifSearchQuery {
    pub q: String,
    pub offset: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct GifSearchResponse {
    pub results: Vec<GifResult>,
    pub total_count: u32,
}

#[derive(Debug, Serialize)]
pub struct GifResult {
    pub id: String,
    pub title: String,
    pub url: String,
    pub preview_url: String,
    pub width: u32,
    pub height: u32,
}

// ─── Server Restore ─────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RestoreServerRequest {
    pub server: RestoreServerMeta,
    pub categories: Vec<RestoreCategory>,
    pub channels: Vec<RestoreChannel>,
    pub roles: Vec<RestoreRole>,
    #[serde(default)]
    pub permission_overwrites: Vec<RestoreOverwrite>,
}

#[derive(Debug, Deserialize)]
pub struct RestoreServerMeta {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RestoreCategory {
    pub id: String,
    pub name: String,
    pub position: i32,
}

#[derive(Debug, Deserialize)]
pub struct RestoreChannel {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub channel_type: String,
    pub category_id: Option<String>,
    pub position: i32,
    pub encrypted: bool,
    pub is_private: bool,
}

#[derive(Debug, Deserialize)]
pub struct RestoreRole {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
    pub permissions: i64,
    pub position: i32,
    pub is_default: bool,
}

#[derive(Debug, Deserialize)]
pub struct RestoreOverwrite {
    pub channel_id: String,
    pub target_type: String,
    pub target_id: String,
    pub allow: i64,
    pub deny: i64,
}

#[derive(Debug, Serialize)]
pub struct RestoreServerResponse {
    pub categories_created: usize,
    pub channels_created: usize,
    pub roles_created: usize,
    pub roles_updated: usize,
    pub overwrites_applied: usize,
    pub channel_id_map: std::collections::HashMap<String, String>,
}

// ─── Message Import ─────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ImportMessagesRequest {
    pub messages: Vec<ImportMessage>,
}

#[derive(Debug, Deserialize)]
pub struct ImportMessage {
    pub sender_token: String,
    pub encrypted_body: String,
    pub timestamp: String,
    pub sender_id: Option<String>,
    pub message_type: String,
    pub reply_to_id: Option<String>,
    pub has_attachments: bool,
}

#[derive(Debug, Serialize)]
pub struct ImportMessagesResponse {
    pub imported: usize,
}

// ─── Validation helpers ───────────────────────────────

use std::sync::LazyLock;

static USERNAME_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap()
});

fn validate_username(username: &str) -> Result<(), validator::ValidationError> {
    if !USERNAME_REGEX.is_match(username) {
        return Err(validator::ValidationError::new("invalid_username"));
    }
    Ok(())
}
