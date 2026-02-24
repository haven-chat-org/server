# Haven Backend

Rust backend built with axum 0.7, sqlx 0.7, PostgreSQL, and Redis.

## Architecture

The backend is a single async Rust binary that serves the REST API, WebSocket connections, and (in production) the embedded frontend static files.

```
src/
├── main.rs                 # Server entrypoint — loads config, runs migrations, starts listening
├── lib.rs                  # Router builder — assembles all routes, CORS, middleware, AppState
├── config.rs               # AppConfig — all env vars with defaults and TOML file support
├── models.rs               # Every request/response struct and WebSocket message type
├── errors.rs               # AppError enum → HTTP status codes, AppResult type alias
├── permissions.rs          # Bitfield permission constants + computation (Discord-style)
├── crypto.rs               # Server-side crypto utilities (invite codes, file encryption keys)
├── auth.rs                 # JWT generation/validation, Argon2id hashing, TOTP, refresh tokens
├── ws.rs                   # WebSocket handler — message dispatch, subscriptions, presence, session resume
├── pubsub.rs               # Redis pub/sub for multi-instance message fanout
├── cache.rs                # Redis cache helpers
├── memory_store.rs         # In-memory ephemeral state (typing indicators, etc.)
├── storage.rs              # Attachment storage (local filesystem or S3) with AES-256-GCM
├── tls.rs                  # Optional TLS termination (auto-generate self-signed or use provided certs)
├── livekit_proc.rs         # Optional bundled LiveKit process management
├── embedded_ui.rs          # Serves frontend from rust-embed (feature-gated: embed-ui)
│
├── api/                    # REST endpoint handlers (one file per domain)
│   ├── auth_routes.rs      # register, login, refresh, logout, password, TOTP
│   ├── servers.rs          # CRUD servers, leave, permissions, icons, nicknames, audit log
│   ├── channels.rs         # CRUD channels, DMs, group DMs, join/leave, read states
│   ├── messages.rs         # send, list, edit, delete, bulk-delete, pins, reactions, search
│   ├── sender_keys.rs      # Sender Key Distribution Messages for group E2EE
│   ├── keys.rs             # Key bundles, prekeys, identity key updates
│   ├── key_backup.rs       # Encrypted key backup (upload, download, status, delete)
│   ├── roles.rs            # CRUD roles, assign/unassign, permission overwrites
│   ├── categories.rs       # CRUD categories, reorder, assign channel to category
│   ├── invites.rs          # Server invite codes — create, list, delete, join, members, kick
│   ├── registration_invites.rs  # Instance-level invite-only registration system
│   ├── friends.rs          # Friend requests, DM requests, DM privacy settings
│   ├── users.rs            # Profiles, search, avatar/banner upload, block/unblock
│   ├── admin.rs            # Instance admin — stats, user management
│   ├── bans.rs             # Server bans — ban, revoke, list
│   ├── reports.rs          # Content reporting
│   ├── presence.rs         # Bulk presence via Redis
│   ├── attachments.rs      # Encrypted file upload/download
│   ├── emojis.rs           # Custom emoji upload/list/rename/delete
│   ├── link_preview.rs     # OpenGraph link previews
│   └── voice.rs            # LiveKit voice channel tokens, join/leave, mute/deafen
│
├── db/
│   └── queries.rs          # All SQL queries — runtime sqlx (no compile-time macros)
│
└── middleware/
    └── mod.rs              # AuthUser JWT extractor, AdminUser extractor, rate limiting
```

## Key Design Decisions

**Single query file**: All SQL lives in `db/queries.rs` rather than spread across handler files. This makes it easy to audit every database interaction in one place.

**Runtime queries**: We use `sqlx::query` / `sqlx::query_as` at runtime (not `sqlx::query!` compile-time macros). This means no `.sqlx/` directory is needed and `cargo check` works without a running database.

**Flat handler modules**: Each `api/*.rs` file owns a single domain. Handlers receive `State<AppState>` + extractors and return `AppResult<Json<T>>`. No service layer abstraction — handlers call query functions directly.

**Permission computation**: Permissions are a single `i64` bitfield. `permissions.rs` computes effective permissions from server role + channel overwrites, matching Discord's model.

**WebSocket sessions**: `ws.rs` supports session resume — if a client disconnects and reconnects with the same `session_id`, buffered messages are replayed. This makes deploys transparent to connected users.

## Route Parameter Syntax

axum 0.7.9 uses matchit 0.7.3 which **only supports `:param` syntax**. Do NOT use `{param}` — it silently registers as a literal string and returns 404 with 0ms latency.

```rust
// Correct
.route("/:server_id/channels", get(list_channels))

// WRONG — will silently 404
.route("/{server_id}/channels", get(list_channels))
```

## Running Tests

```bash
# Ensure Docker infrastructure is running
docker compose up -d

# Run all tests (81 unit + 126 integration + 10 WebSocket)
cargo test
```

Integration tests use `#[sqlx::test(migrations = "./migrations")]` — each test gets a fresh database.
