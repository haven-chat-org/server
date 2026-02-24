# Contributing & Development Workflow

How to make changes to Haven and push them to your production Hetzner deployment.

## Local Development Setup

### Prerequisites
- Rust 1.77+
- Node.js 20+
- Docker & Docker Compose

### Start the dev environment

```bash
# 1. Start PostgreSQL + Redis
docker compose up -d

# 2. Copy env (only needed once)
cp .env.example .env

# 3. Run the backend (auto-runs migrations on startup)
cargo run

# 4. In a second terminal — build the shared library and start the frontend
cd packages/haven-core && npm install && npm run build
cd ../web && npm install && npm run dev
```

Backend: http://localhost:8080 | Frontend: http://localhost:5173

## Making Changes

### Backend (Rust)

All backend code lives in `src/`. The typical flow for a new feature:

1. **Models** — Add request/response structs to `src/models.rs`
2. **Queries** — Add SQL queries to `src/db/queries.rs`
3. **Handler** — Add endpoint handler to the appropriate `src/api/*.rs` file (or create a new one)
4. **Routes** — Wire the handler in `src/lib.rs`
5. **Migration** — If you added new tables/columns, create a migration in `migrations/`

Migration naming convention: `YYYYMMDD000001_description.sql`

Verify your changes:
```bash
cargo check     # Fast compile check
cargo test      # Full test suite (needs Docker running)
```

### Frontend (TypeScript/React)

The frontend has two packages that work together:

- **haven-core** (`packages/haven-core/`) — Shared types, API client, crypto
- **web** (`packages/web/`) — React app

If you change `haven-core`, you **must rebuild** it before the web frontend picks up changes:

```bash
cd packages/haven-core && npm run build
```

If you only change files in `packages/web/`, Vite hot-reloads automatically.

Verify your changes:
```bash
cd packages/web && npx tsc --noEmit    # Type check
cd packages/web && npx vitest run      # Tests
```

### Both

If your change touches both backend and frontend (e.g., adding a new API endpoint):

1. Add the Rust handler + route + migration
2. Add TypeScript types to `packages/haven-core/src/types.ts`
3. Add the API method to `packages/haven-core/src/net/api.ts`
4. Rebuild haven-core: `cd packages/haven-core && npm run build`
5. Use the new API in the React frontend
6. Run verification:
   ```bash
   cargo check && cargo test
   cd packages/web && npx tsc --noEmit
   ```

## Pushing to Production

### Quick deploy (most common)

After committing your changes locally:

```bash
# On your local machine
git push origin main

# SSH into your Hetzner VPS
ssh haven@YOUR_SERVER_IP

# Pull and deploy
cd /opt/haven
git pull
./deploy.sh
```

The deploy script builds a new Docker image, swaps the container (2-5s downtime), and verifies the health check passes.

### What `deploy.sh` does

1. Builds the Haven Docker image (3-stage: Node frontend → Rust backend → slim runtime)
2. Recreates only the Haven container (PostgreSQL, Redis, LiveKit, Caddy stay running)
3. Polls `/health` for up to 60 seconds
4. On success: prunes old images and prints status
5. On failure: prints the last 50 lines of Haven logs

### Database migrations

Migrations run automatically on server startup via `sqlx::migrate!()`. If you add a new migration file in `migrations/`, it will be applied the next time the Haven container starts. Production data (users, messages, channels, etc.) persists across deploys — only the Haven container is recreated.

**Critical rules — violating these will cause production outages or data loss:**

- **Never edit, delete, rename, or reorder an existing migration file.** sqlx checksums every migration. A mismatch causes the server to **panic on startup** and refuse to boot.
- **Never use `DROP TABLE`, `TRUNCATE`, or `DROP COLUMN`** in a migration unless you've already deployed code that stops using that table/column (two-phase approach).
- **Always create a new file** for schema changes: `YYYYMMDD000001_description.sql`
- **Safe operations:** `CREATE TABLE`, `ADD COLUMN`, `CREATE INDEX`, `ADD CONSTRAINT` (with defaults)

**To safely remove a column in production:**
1. First deploy: ship code that no longer reads/writes the column
2. Second deploy: add a new migration with `ALTER TABLE ... DROP COLUMN`

### When things go wrong

Check logs:
```bash
ssh haven@YOUR_SERVER_IP
cd /opt/haven
docker compose -f docker-compose.prod.yml --env-file .env.production logs --tail=100 haven
```

Restart everything:
```bash
docker compose -f docker-compose.prod.yml --env-file .env.production restart
```

Roll back to a previous commit:
```bash
git log --oneline -5           # Find the commit to roll back to
git checkout <commit-hash>     # Switch to that commit
./deploy.sh                    # Rebuild and deploy
```

### Environment changes

If you add new environment variables:

1. Add them to `.env.production.example` (with documentation)
2. Add them to `docker-compose.prod.yml` under the `haven` service
3. Add them to your server's `.env.production` file
4. Redeploy: `./deploy.sh`

## Testing Checklist

Before pushing to production, verify:

```bash
# Backend compiles and all tests pass
cargo check && cargo test

# Frontend compiles
cd packages/web && npx tsc --noEmit

# haven-core compiles (if you changed it)
cd packages/haven-core && npm run build
```

## Common Gotchas

- **Route params**: Use `:param` syntax, NOT `{param}`. axum 0.7 uses matchit 0.7.3 which only supports colon syntax. `{param}` silently 404s.
- **haven-core rebuild**: If the frontend shows stale types or missing methods, rebuild haven-core (`cd packages/haven-core && npm run build`).
- **Test database**: `cargo test` requires Docker running with PostgreSQL + Redis (`docker compose up -d`).
- **Migration files are immutable**: Never edit, delete, or reorder an existing migration. sqlx checksums each one — a mismatch causes the server to panic on startup. Always create a new file.
- **Migration order**: Migration filenames must sort chronologically. Use the `YYYYMMDD000001_description.sql` pattern.
- **Migration checksum panic**: If the server won't start due to a checksum error, an existing migration was modified. Revert it to the original content.
- **CORS in production**: The `CORS_ORIGINS` env var is set to `https://{HAVEN_DOMAIN}` in `docker-compose.prod.yml`. If you're testing from a different origin, update it.
