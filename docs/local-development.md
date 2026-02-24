# Haven — Local Development Guide

## Prerequisites

- **Rust** (stable, 1.77+): `rustup update stable`
- **Node.js** (18+) and **npm**
- **Docker Desktop** (for PostgreSQL + Redis)
- **Xcode Command Line Tools** (macOS): `xcode-select --install`

---

## Architecture Overview

```
┌─────────────────┐     ┌──────────────┐     ┌───────────────┐
│  Desktop Client  │────▶│ Haven Backend │────▶│ PostgreSQL    │
│  (Tauri + React) │     │ (Rust/axum)  │     │ + Redis       │
│  localhost:5173   │     │ localhost:8080│     │ (Docker)      │
└─────────────────┘     └──────────────┘     └───────────────┘
```

You need **three things running**:
1. **Docker** — PostgreSQL and Redis
2. **Backend** — the Rust server (`cargo run`)
3. **Frontend** — either the web app or the desktop client

---

## Quick Start

### 1. Start Docker (PostgreSQL + Redis)

```bash
docker compose up -d
```

This starts:
- **PostgreSQL** on port 5432 (user: `haven`, password: `haven_secret`, db: `haven`)
- **Redis** on port 6379

Check they're running:
```bash
docker compose ps
```

### 2. Start the Backend

In a **separate terminal**:
```bash
cargo run
```

This will:
- Load config from `.env`
- Run database migrations automatically
- Start the API server on `http://localhost:8080`

You should see output like:
```
haven_backend: listening on 0.0.0.0:8080
```

### 3. Start a Frontend

**Option A: Web browser (fastest for iteration)**
```bash
cd packages/web
npm run dev
```
Opens at `http://localhost:5173` in your browser.

**Option B: Desktop app (Tauri)**
```bash
cd client
npm run tauri:dev
```
Opens a native window. On first launch, enter `http://localhost:8080` in the server connect screen.

---

## Resetting the Database

### Full reset (drop everything, start fresh)

```bash
# Stop the backend first (Ctrl+C), then:
docker compose down -v
docker compose up -d
```

The `-v` flag deletes the PostgreSQL and Redis data volumes. When you run `cargo run` again, migrations will recreate all tables from scratch.

### Reset just the data (keep tables)

```bash
# Connect to PostgreSQL and truncate:
docker compose exec postgres psql -U haven -d haven -c "
  DO \$\$ DECLARE r RECORD;
  BEGIN
    FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename != '_sqlx_migrations')
    LOOP EXECUTE 'TRUNCATE TABLE ' || r.tablename || ' CASCADE'; END LOOP;
  END \$\$;"
```

### Reset Redis only (presence, rate limits, sessions)

```bash
docker compose exec redis redis-cli FLUSHALL
```

---

## Common Tasks

### Rebuild haven-core (shared TypeScript library)

Required when you change files in `packages/haven-core/src/`:
```bash
cd packages/haven-core && npm run build
```
The web frontend imports from `dist/`, not `src/`.

### Run tests

```bash
# Backend (requires Docker running)
cargo test

# haven-core
cd packages/haven-core && npx vitest run

# Web frontend
cd packages/web && npx vitest run
```

### Build a release desktop app

```bash
cd client
npm run tauri:build
# Output: client/src-tauri/target/release/bundle/dmg/Haven_0.1.0_aarch64.dmg
```

---

## FAQ

**Do I always need Docker running?**
Yes. The backend requires PostgreSQL and Redis. Docker provides both.

**Do I need `cargo run` in a separate terminal?**
Yes. The Tauri desktop app and the web frontend are just UI shells — they both talk to the backend over HTTP/WebSocket at `localhost:8080`. The backend is a separate process.

**What's the "Connect to a server" screen in the desktop app?**
The desktop app doesn't assume which server to talk to (since Haven is self-hosted). Enter `http://localhost:8080` for local development. It saves this in localStorage so you only do it once.

**How do I see logs?**
- Backend: logs print to the terminal running `cargo run`
- Frontend: open browser DevTools (or Tauri DevTools with Cmd+Shift+I in the desktop app)
- Set `RUST_LOG=debug` for verbose backend logging

**Port conflicts?**
- Backend: change `HAVEN_PORT` in `.env` (default 8080)
- Web dev server: Vite auto-picks next available port if 5173 is taken
- PostgreSQL: change port mapping in `docker-compose.yml` if 5432 is taken
