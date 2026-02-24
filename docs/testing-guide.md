# Haven — Testing & Coverage

## Quick Start

```bash
# Backend: run all tests (requires docker compose up -d)
cargo test

# Backend: run with coverage summary
cargo llvm-cov report --summary-only

# Backend: generate HTML coverage report
cargo llvm-cov --html --output-dir target/llvm-cov-html
open target/llvm-cov-html/html/index.html

# Frontend: run all tests
cd packages/web && npx vitest run

# Frontend: run with coverage report
cd packages/web && npx vitest run --coverage
open packages/web/coverage/index.html
```

## Tools

| Layer | Tool | Install | Output formats |
|-------|------|---------|---------------|
| Backend (Rust) | `cargo-llvm-cov` | `cargo install cargo-llvm-cov` | text, HTML, lcov |
| Frontend (TS/React) | `@vitest/coverage-v8` | Already in devDependencies | text, HTML, lcov |

---

## Test Architecture

### Backend — Rust

**213 tests total** (77 unit + 126 integration + 10 WebSocket)

| Tool | Purpose |
|------|---------|
| `#[test]` / `#[tokio::test]` | Built-in Rust test runner, async support |
| `#[sqlx::test]` | Auto-creates a temporary Postgres database per test, runs migrations, tears down after |
| `tower::ServiceExt::oneshot` | Sends HTTP requests through the full axum middleware stack without starting a server |

No external mocking libraries. Permission functions are pure, and integration tests use real Postgres + Redis.

**Prerequisites:**
```bash
docker compose up -d  # Starts Postgres + Redis
```

#### Unit Tests — 77 tests across 5 modules

| Module | Tests | Coverage | What's tested |
|--------|:-----:|:--------:|---------------|
| `permissions.rs` | 22 | 100% | `has_permission`, `compute_server_permissions`, `apply_channel_overwrites` — single/missing/ADMINISTRATOR bits, owner override, role OR, channel overwrites |
| `auth.rs` | 17 | 95% | Argon2id hashing (format, different salts, correct/incorrect verify), HMAC email hashing (deterministic, case-insensitive, whitespace trim, different secrets), JWT (roundtrip, wrong secret, garbage, user_id extraction), refresh tokens (unique, length, hash deterministic), TOTP (generate, verify correct/wrong) |
| `storage.rs` | 15 | 64% | `obfuscated_key` (format, deterministic, different inputs), AES-256-GCM encrypt/decrypt (roundtrip, different ciphertext, wrong key, too short, corrupted, empty data), local storage (store+load roundtrip, raw access, presign returns None) |
| `crypto.rs` | 13 | 100% | X25519 key validation (correct/short/long/empty), `random_bytes` (length, non-zero), invite codes (length, URL-safe, unique), size buckets (all 4 ranges) |
| `config.rs` | 10 | 50% | `test_default()` values, `livekit_enabled()` (all permutations of empty/set fields) |

```bash
cargo test --lib  # Runs all unit tests
```

#### Integration Tests — `tests/api_tests.rs` (126 tests)

Each test gets a completely fresh database via `#[sqlx::test]`. The `TestApp` helper in `tests/common/mod.rs` builds a real `AppState` with the test pool, connects to Redis, and constructs the full production router.

**Auth (17):** register, login, wrong password, protected routes, duplicate username, refresh tokens, logout, password change (success + wrong current + too short + revokes tokens), TOTP setup, TOTP setup twice fails, TOTP verify, TOTP wrong code, TOTP disable, login requires TOTP, register short password fails, register short username fails
**Servers (7):** create, list, non-member 403, update system channel (success + invalid channel + requires permission), nickname (set/clear + too long), get my permissions
**Channels (7):** create + list, delete, update meta, join, reorder (success + requires permission), delete requires permission, update requires permission
**Categories (6):** create, list, update, delete, reorder, assign channel to category
**Roles (6):** default @everyone, create, update, delete (+ cannot delete default), assign, unassign
**Permissions (2):** 403 without MANAGE_CHANNELS, channel overwrites (set + list + delete)
**Invites (5):** create + join, invalid code, list, revoke, join when already member
**Friends (8):** send + accept, decline, remove, mutual auto-accept, blocked user cannot friend, request to self fails, request when already friends fails, request to unknown user fails
**Messages (6):** send + get, reply, non-member 403, search with limit, pin/unpin IDs, get with limit and pagination
**Users (13):** profile (basic + friendship status + blocked status + mutual friends + server roles), update profile, search (success + nonexistent), block/unblock, self-block fails, avatar upload/download/empty/no-avatar, profile keys distribute + get + not found
**DMs (10):** create + list, group DM (create + requires friends + add member + leave), friends-only creates pending, server_members privacy (pending + shared server active), DM requests (accept + decline + invalid action), create DM returns existing
**Sender Keys (4):** distribute + get, empty distribution fails, member keys, non-member 403
**Attachments (3):** upload, empty fails, download not found
**Bans (4):** ban + list, revoke, banned user cannot rejoin, cannot ban self
**Reports (2):** submit, short reason fails
**Presence (2):** bulk presence, empty IDs
**Prekeys (1):** count zero initially
**Health (1):** `/health` returns 200

#### WebSocket Tests — `tests/ws_tests.rs` (10 tests)

Uses `tokio-tungstenite` to connect a real WebSocket client to the full axum server (bound to a random port via `TcpListener::bind("127.0.0.1:0")`).

**Tests:** ping/pong, subscribe (success + unauthorized channel), send message (ACK + unauthorized + invalid base64), invalid JSON error, set status (invalid value), typing broadcast, message broadcast to subscriber

#### Test Helpers — `tests/common/mod.rs`

`TestApp` struct with high-level helpers:
- `new(pool)` — builds AppState from `#[sqlx::test]` pool, connects to Redis
- `request(method, uri, token, body)` → `(StatusCode, Value)`
- `register_user(username)` → `(access_token, user_id)`
- `login_user(username)` → `(access_token, refresh_token, user_id)`
- `create_server(token, name)` → `server_id`
- `create_channel(token, server_id, name)` → `channel_id`
- `invite_and_join(owner_token, joiner_token, server_id)` → `invite_code`
- `send_message(token, channel_id)` → `(message_id, Value)`
- `send_reply(token, channel_id, reply_to_id)` → `(message_id, Value)`
- `make_friends(token_a, token_b, username_b)` → `friendship_id`
- `request_bytes(method, uri, token, body_bytes)` → `(StatusCode, Value)` (for file uploads)
- `router_clone()` → `Router` (for WS tests that need `axum::serve`)

### Frontend — TypeScript/React

**46 tests total** across 3 test files

| Tool | Purpose |
|------|---------|
| vitest 4.x | Test runner |
| jsdom | Lightweight browser environment |
| `@vitest/coverage-v8` | V8 native code coverage |

#### UI Store — `src/store/__tests__/ui.test.ts` (27 tests)

Tests `useUiStore`: server selection, member sidebar toggle, friends panel, user settings, pinned/search panels.

#### Friends Store — `src/store/__tests__/friends.test.ts` (11 tests)

Tests `useFriendsStore` with mock API: loadFriends, send/accept/decline requests, DM request handling.

#### Draft Store — `src/lib/__tests__/draft-store.test.ts` (8 tests)

Tests localStorage-backed message draft persistence: save, load, clear, channel isolation.

### haven-core — `packages/haven-core/src/net/api.test.ts` (21 tests)

Tests the `HavenApi` client: token management, auth endpoints, auth headers, error handling, server/channel/friend/role endpoints, URL construction. Uses `vi.stubGlobal("fetch", ...)` mock.

---

## Coverage Report (as of 2025-02-11)

### Backend — 74.8% line coverage

| File | Lines | Functions | Notes |
|------|:-----:|:---------:|-------|
| `permissions.rs` | **100%** | 100% | Fully tested |
| `crypto.rs` | **100%** | 100% | +100pp — unit tests added |
| `api/bans.rs` | **100%** | 100% | |
| `api/categories.rs` | **96.5%** | 100% | |
| `api/servers.rs` | **96.7%** | 94% | |
| `api/reports.rs` | **96.4%** | 100% | |
| `models.rs` | **95.7%** | 90% | |
| `auth.rs` | **95.4%** | 85% | +17.0pp — unit tests for JWT, TOTP, refresh tokens |
| `api/presence.rs` | **95.1%** | 80% | |
| `api/friends.rs` | **93.8%** | 100% | |
| `api/sender_keys.rs` | **93.5%** | 90% | |
| `api/invites.rs` | **93.4%** | 100% | |
| `api/channels.rs` | **93.0%** | 84% | +3.5pp — permission edge cases |
| `lib.rs` (router) | **92.6%** | 75% | |
| `api/auth_routes.rs` | **89.3%** | 71% | +0.5pp — short password/username |
| `rate_limit.rs` | **88.3%** | 69% | |
| `api/keys.rs` | **87.3%** | 67% | |
| `cache.rs` | **86.8%** | 100% | |
| `db/queries.rs` | **82.2%** | 83% | |
| `api/messages.rs` | **82.1%** | 73% | |
| `api/users.rs` | **79.1%** | 75% | |
| `api/roles.rs` | **79.4%** | 87% | |
| `storage.rs` | **63.6%** | 80% | +41.8pp — unit tests for encrypt/decrypt, local backend |
| `config.rs` | **49.7%** | 32% | +49.7pp — unit tests for test_default, livekit_enabled |
| `errors.rs` | **48.4%** | 100% | |
| `pubsub.rs` | **44.8%** | 69% | +18.1pp — exercised by WS tests |
| `ws.rs` | **42.4%** | 59% | +39.4pp — 10 WebSocket integration tests |
| `api/attachments.rs` | **40.7%** | 50% | |
| `middleware/auth.rs` | **33.3%** | 29% | Tested indirectly |
| `db/mod.rs` | **23.1%** | 38% | Pool setup |
| `api/voice.rs` | **6.3%** | 17% | LiveKit integration (requires config) |
| `api/link_preview.rs` | **0%** | 0% | External HTTP calls |
| `main.rs` | **0%** | 0% | Entry point |

### Frontend — 2.1% line coverage

| File | Lines | Notes |
|------|:-----:|-------|
| `store/ui.ts` | **100%** | Fully tested |
| `store/friends.ts` | **100%** | Fully tested |
| `lib/draft-store.ts` | **88.2%** | Well tested |
| `store/auth.ts` | 5.7% | Import-time only |
| `lib/crypto.ts` | 5.7% | Import-time only |
| `store/chat.ts` | 0% | Complex, needs WS mock |
| All 40+ components | 0% | No component tests |

---

## Biggest Coverage Gaps

### Backend — remaining high-value targets

1. **WebSocket handlers** (`ws.rs` — 42%): Core flows (ping, subscribe, send, typing, broadcast) are tested. Remaining: EditMessage, DeleteMessage, Pin/Unpin, Reactions, SetStatus with valid values, message edit/delete broadcasts, reconnection.
2. **Storage** (`storage.rs` — 64%): Encrypt/decrypt and local backend tested via unit tests. Remaining: S3 backend, presigned URLs, CDN paths.
3. **Config** (`config.rs` — 50%): `test_default()` and `livekit_enabled()` tested. Remaining: `from_env()` parsing (requires env var manipulation).
4. **Pub/Sub** (`pubsub.rs` — 45%): Partially exercised by WS tests. Remaining: Redis reconnection, error paths.
5. **Voice** (`api/voice.rs` — 6%): Requires LiveKit configuration.
6. **Link preview** (`api/link_preview.rs` — 0%): Makes external HTTP calls; would need request mocking or test URL.

### Frontend — high-value targets

1. **chat.ts store** (0%): Most critical store — messages, channels, edits, deletes. Needs WS mocking.
2. **crypto.ts** (6%): E2EE encrypt/decrypt. Needs libsodium test fixtures.
3. **Components** (0%): No component tests. Priority candidates:
   - `MessageInput.tsx` — send, edit, reply flows
   - `ChannelSidebar.tsx` — server/channel navigation
   - `ServerBar.tsx` — create/join server

---

## CI Integration

Both tools output lcov for integration with Codecov, Coveralls, etc.:

```bash
# Backend lcov
cargo llvm-cov --lcov --output-path target/lcov.info

# Frontend lcov (already configured in vitest.config.ts)
cd packages/web && npx vitest run --coverage
# Output: packages/web/coverage/lcov.info
```

---

## Adding New Tests

### Rust integration test

Add to `tests/api_tests.rs`:

```rust
#[sqlx::test(migrator = "haven_backend::MIGRATOR")]
async fn my_new_test(pool: PgPool) {
    let app = TestApp::new(pool).await;
    let (token, user_id) = app.register_user("testuser").await;

    let (status, body) = app.request(
        Method::GET, "/api/v1/some/endpoint", Some(&token), None
    ).await;
    assert_eq!(status, StatusCode::OK);
}
```

### Rust unit test

Add to the `#[cfg(test)] mod tests` block in the source file.

### Frontend store test

Create `packages/web/src/store/__tests__/mystore.test.ts`:

```typescript
import { describe, it, expect, beforeEach } from "vitest";
import { useMyStore } from "../mystore.js";

beforeEach(() => {
  useMyStore.setState(useMyStore.getInitialState());
});

describe("myStore", () => {
  it("does something", () => {
    useMyStore.getState().doSomething();
    expect(useMyStore.getState().value).toBe(expected);
  });
});
```

### haven-core test

Create `*.test.ts` files alongside source in `packages/haven-core/src/`. Vitest auto-discovers them.
