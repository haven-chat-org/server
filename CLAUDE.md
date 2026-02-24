# Haven Server — Project Guide

## What Is This?

Haven is an end-to-end encrypted (E2EE) chat platform — a privacy-focused gaming chat alternative. All message content is encrypted client-side; the server stores only encrypted blobs and never sees plaintext.

This repo contains the **Rust backend server**. The web frontend lives at https://github.com/haven-chat-org/web and the shared crypto/networking library at https://github.com/haven-chat-org/core.

## Golden Rules

- **Route params use `:param`** syntax (NOT `{param}`). axum 0.7.9 uses matchit 0.7.3 which only supports colon syntax. `{param}` silently registers as a literal string and returns 404.
- **Never commit secrets** — `.env.*` files (except `.env.example`), private keys, API tokens.
- **Migrations are append-only** — NEVER edit, delete, rename, or reorder an existing migration file. sqlx checksums every migration; a mismatch causes the server to panic on startup. Schema changes always go in a new file.

## Architecture

```
haven-server/
├── src/                        # Rust backend (axum 0.7.9, sqlx 0.7, PostgreSQL, Redis)
│   ├── main.rs                 # Server entrypoint
│   ├── lib.rs                  # Router builder, AppState, re-exports
│   ├── config.rs               # AppConfig (env vars)
│   ├── models.rs               # All request/response structs, WS message types
│   ├── errors.rs               # AppError enum, AppResult type alias
│   ├── permissions.rs          # Bitfield permission constants + computation
│   ├── middleware.rs            # AuthUser JWT extractor
│   ├── ws.rs                   # WebSocket handler + message dispatch
│   ├── db/queries.rs           # All SQL queries (sqlx)
│   └── api/                    # REST endpoint handlers
│       ├── auth_routes.rs      # register, login, refresh, logout, password, totp
│       ├── servers.rs          # CRUD servers
│       ├── channels.rs         # CRUD channels, DMs, group DMs, join/leave
│       ├── messages.rs         # send, get, pins, pin-ids, reactions
│       ├── sender_keys.rs      # Sender key distribution (group E2EE)
│       ├── invites.rs          # create/list/delete invites, join, members, kick
│       ├── roles.rs            # CRUD roles, assign/unassign, overwrites
│       ├── categories.rs       # CRUD categories, reorder, assign channel
│       ├── friends.rs          # friend requests, DM requests, DM privacy
│       ├── users.rs            # profiles, search, avatar, block/unblock
│       ├── keys.rs             # key bundles, prekeys, identity key updates
│       ├── bans.rs             # ban/revoke/list
│       ├── reports.rs          # content reporting
│       ├── presence.rs         # bulk presence via Redis
│       ├── attachments.rs      # encrypted file upload/download
│       └── link_preview.rs     # OpenGraph link previews
├── migrations/                 # PostgreSQL migrations (sequential timestamps)
├── tests/
│   ├── common/mod.rs           # TestApp helper — builds router, provides request helpers
│   └── api_tests.rs            # Integration tests (#[sqlx::test])
├── Dockerfile                  # Downloads pre-built web frontend, builds Rust binary
├── docker-compose.yml          # PostgreSQL + Redis (dev)
└── docker-compose.prod.yml     # Caddy + Haven + PostgreSQL + Redis + LiveKit
```

## E2EE Model

- **DMs**: X3DH key agreement → Double Ratchet session (type bytes 0x01 initial, 0x02 follow-up)
- **Server channels**: Sender Keys protocol (type byte 0x03)
  - Each user generates a sender key per channel
  - SKDM (Sender Key Distribution Message) encrypted to each member's identity key via `crypto_box_seal`
  - SKDMs are stored in DB and re-fetchable (NOT consumed on read)
  - Wire format: `[0x03][distId:16][chainIdx:4 LE][nonce:24][ciphertext+tag]`
- **Files**: XChaCha20-Poly1305 client-side encryption, key/nonce embedded in message payload
- The server never decrypts content — it only stores and relays encrypted blobs

## Database

- PostgreSQL via sqlx 0.7 with compile-time query checking
- Migrations in `migrations/` — named `YYYYMMDD000001_description.sql`
- Redis for presence, rate limiting, refresh tokens
- Integration tests use `#[sqlx::test(migrations = "./migrations")]` — each test gets a fresh DB
- **Production data persists across deploys** — Docker named volumes (`postgres_data`, `redis_data`, `haven_data`) survive container recreation. `deploy.sh` only recreates the Haven container; PostgreSQL/Redis stay running.

### Migration Safety (production data preservation)

Migrations run automatically on server startup via `sqlx::migrate!()`. sqlx tracks applied migrations by checksum in a `_sqlx_migrations` table and only runs new ones.

**NEVER do in a migration:**
- `DROP TABLE` / `TRUNCATE` — destroys production data
- `DROP COLUMN` without first deploying code that stops using it (two-phase approach)
- `ALTER COLUMN ... TYPE` that narrows a type (e.g. `TEXT` → `VARCHAR(50)`)

**NEVER do to existing migration files:**
- Edit content — checksum mismatch → server panics on startup
- Delete the file — same panic
- Rename or reorder — breaks the sequential application order

**Safe operations (do freely):**
- `CREATE TABLE`, `ADD COLUMN`, `CREATE INDEX`, `ADD CONSTRAINT` (with defaults)
- Always in a **new** migration file following the `YYYYMMDD000001_description.sql` naming convention

**To remove a column safely (two-phase):**
1. Deploy code that stops reading/writing the column
2. Next deploy: add a new migration with `ALTER TABLE ... DROP COLUMN`

## Testing

Run these to verify changes:

- **Compile check**: `cargo check --features postgres,embed-ui` (requires web dist in `packages/web/dist/`)
- **Lint**: `cargo clippy --workspace -- -D warnings`
- **Integration tests**: `cargo test` (requires Docker: PostgreSQL + Redis via `docker-compose up -d`)

## Key Conventions

- Permissions are a bitfield system (Discord-style). Constants in `src/permissions.rs`.
- WebSocket messages: `WsClientMessage` / `WsServerMessage` enums in `src/models.rs`.
- All API routes are under `/api/v1/`. Router defined in `src/lib.rs`.

## Deployment

- Docker image: `ghcr.io/haven-chat-org/haven:latest`
- Production stack: `docker-compose.prod.yml` (Caddy + Haven + PostgreSQL + Redis + LiveKit)
- Merges to `main` auto-tag, build, push to GHCR, and deploy to production via SSH
- Rust binary is built with `--features postgres,embed-ui` (web frontend embedded into binary)
- Web frontend is downloaded as a pre-built artifact from https://github.com/haven-chat-org/web/releases
- `SQLX_OFFLINE=true` for CI builds (no live DB needed for compile-time checks)

## Related Repos

- **Web frontend**: https://github.com/haven-chat-org/web
- **Shared library**: https://github.com/haven-chat-org/core (`@haven-chat-org/core` on npm)
- **Archive viewer**: https://github.com/haven-chat-org/archive-viewer

## Common Gotchas

- If new DB columns/tables are added but tests fail with 500: check that a migration file was created (not just applied via psql).
- If routes return 404 with 0ms latency: check for `{param}` instead of `:param` in route definitions.
- If the server panics on startup with a migration checksum error: an existing migration file was modified. Revert it to the original content — never edit applied migrations.
- `cargo test` requires Docker (PostgreSQL + Redis) running via `docker-compose up -d`.
- The `embed-ui` feature requires `packages/web/dist/` to exist at build time. CI downloads this from the web repo's releases.
