<p align="center">
  <img src="assets/havenlogocircle.png" alt="Haven" width="128" />
</p>

<h1 align="center">Haven</h1>

<p align="center">
  <img src="assets/haven.jpg" alt="Haven" width="800" />
</p>

<p align="center">A privacy-first, end-to-end encrypted chat platform.</p>

## What is Haven?

Haven is a full-featured chat application servers, channels, DMs, friends, roles, voice, screen and file sharing with one fundamental difference: **all message content are encrypted client-side before it ever touches the server**. The backend is an intentional "dumb relay" for encrypted blobs. It handles routing, auth, and access control, and has zero knowledge of what you're saying or sending. Current beta build is hosted in EU/Germany.

### What the server can see
- Encrypted blobs (messages, metadata, attachments)
- Public cryptographic keys (for key exchange)
- Routing data (channel IDs, ephemeral sender tokens, timestamps)

### What the server cannot see
- Message content (Double Ratchet / Sender Keys encryption)
- Sender identity within channels (sealed sender tokens)
- Server/channel names (encrypted metadata)
- File contents or types (client-side encryption with padded sizes)
- Email addresses (hashed before storage)

## Why Use Haven?

Most chat platforms choose between features and privacy. Haven doesn't.

| | Haven | Discord | Matrix/Element | Signal |
|---|:---:|:---:|:---:|:---:|
| End-to-end encryption | All messages | None | Opt-in per room | All messages |
| Servers & channels | Yes | Yes | Yes (spaces) | No |
| Voice & screen share | Yes | Yes | Yes | 1-on-1 only |
| Roles & permissions | Yes | Yes | Limited | No |
| Self-hostable | Yes | No | Yes | Partial |
| Open source | Yes | No | Yes | Yes |
| Rich text & embeds | Yes | Yes | Limited | No |
| Encrypted file sharing | Yes | No encryption | Opt-in | Yes |
| Internationalization (i18n) | Yes | Partial | Yes | Yes |
| Accessibility (a11y) | Yes | Partial | Limited | Limited |
| No tracking / telemetry | Yes | No | Varies | Yes |

**Haven gives you Discord-level features with Signal-level privacy.** Your server, your data, your keys. The backend never sees plaintext not messages, not filenames, not even channel names. Features that are normally paywalled like animated emojis, higher quality video and voice calls, are uncompromised.

### How Haven compares to other open-source alternatives

| | Haven | [Stoat](https://stoat.chat/) (formerly Revolt) | [Spacebar](https://spacebar.chat/) (formerly Fosscord) |
|---|:---:|:---:|:---:|
| End-to-end encryption | Yes (all messages) | Planned, not yet implemented | Not implemented |
| Backend language | Rust | Rust | TypeScript (Node.js) |
| Database | PostgreSQL | MongoDB | PostgreSQL |
| Discord API compatible | No (own API) | No (own API) | Yes (reimplements Discord's API) |
| Voice & video | Yes (LiveKit) | Yes (LiveKit), maturing | Partial (WebRTC WIP) |
| Self-hostable | Yes | Yes | Yes |
| Mobile apps | Planned | Android, iOS | None |
| License | AGPL-3.0 | AGPL-3.0 | AGPL-3.0 |

**[Stoat](https://stoat.chat/)** is a polished, feature-rich Discord alternative with native mobile apps and a growing community. It does not yet offer end-to-end encryption, though it's on their roadmap. If you want a mature, general-purpose chat platform and don't need E2EE, Stoat is a solid choice.

**[Spacebar](https://spacebar.chat/)** takes a unique approach: it reimplements Discord's backend API, so existing Discord bots and client libraries work out of the box. It's still in active development and not yet production-ready. Like Stoat, it does not offer end-to-end encryption.

**Haven** is purpose-built for privacy. Every message is encrypted client-side before reaching the server — the backend is an intentional "dumb relay" for encrypted blobs. If E2EE is a requirement, Haven is the only option in this space that delivers it today.

## Features

**Communication** — Servers with text and voice channels, 1-on-1 and group DMs, friend requests, typing indicators, online presence, link previews, @mentions, message pinning, emoji reactions, animated emojis, and supports gifs

**Media** — Encrypted file attachments with inline image/video/audio previews, image lightbox viewer, embedded audio player with seek and volume controls, video playback with MIME normalization, spoiler overlays for sensitive content, drag-and-drop uploads with progress tracking, thumbnail previews during loading

**Organization** — Channel categories with drag-and-drop, server folders for grouping servers, Discord-style roles and permissions (bitfield with channel overwrites), shareable invite codes, server management, audit logs

**Security** — X3DH + Double Ratchet for DMs (Signal Protocol), Sender Keys for group channels, per-channel encryption toggle (on by default, can be disabled for public info/help channels), encrypted file attachments, encrypted key backup (Argon2id KDF), Argon2id password hashing, JWT + rotating refresh tokens, optional TOTP 2FA with two-step login, proof-of-work registration gate, Cloudflare Turnstile CAPTCHA

**Voice** — self hosted LiveKit-powered voice channels with screen sharing (360p–4K quality presets), per-user volume control (0–200%), server mute/deafen, right-click context menu on participants

**Internationalization** — Full i18n support via react-i18next with externalized string keys, ready for community translations

**Accessibility** — ARIA labels and roles throughout, keyboard navigation, focus traps in modals and dialogs, screen reader support, configurable reduced motion, high-contrast mode, dyslexia-friendly font option

**Customization** - 7 themes to start with plenty more options on the way, customize your profile card, avatar, bio, status, add custom emojis and more.

| | | |
|:---:|:---:|:---:|
| ![Bluebird](assets/bluebird.png) | ![Cosmos](assets/cosmos.png) | ![Forest](assets/forest.png) |
| ![Light Mode](assets/lightmode.png) | ![Night Mode](assets/night-mode.png) | ![Sage](assets/sage.png) |

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Rust, axum 0.7, Tokio |
| Database | PostgreSQL 16 (sqlx 0.7) |
| Cache / Pub-Sub | Redis 7 |
| Frontend | React 19, Vite 6, Zustand 5 |
| Shared Library | TypeScript (crypto, API client, types) |
| Crypto | libsodium (X25519, Ed25519, XChaCha20-Poly1305) |
| Voice | LiveKit (self-hosted) |
| Storage | Local filesystem with AES-256-GCM at rest |

## Project Structure

```
Haven/
├── src/                        # Rust backend — see src/README.md
│   ├── api/                    # REST endpoint handlers
│   ├── db/                     # Database queries
│   └── middleware/              # Auth extractors, rate limiting
├── packages/
│   ├── haven-core/             # Shared TS library — see packages/haven-core/README.md
│   └── web/                    # React frontend — see packages/web/README.md
├── assets/                     # Logo and icon files
├── migrations/                 # PostgreSQL schema migrations
├── tests/                      # Rust integration tests (136 tests)
├── docs/                       # Guides and research
└── docker-compose.yml          # Local dev infrastructure
```

## Quick Start

### Prerequisites
- Rust 1.77+
- Node.js 20+
- Docker & Docker Compose

### 1. Start infrastructure
```bash
docker compose up -d    # PostgreSQL + Redis
```

### 2. Configure environment
```bash
cp .env.example .env
# Defaults work for local development
```

### 3. Run the backend
```bash
cargo run
# Server starts on http://localhost:8080
```

### 4. Run the frontend
```bash
cd packages/haven-core && npm install && npm run build
cd ../web && npm install && npm run dev
# Frontend starts on http://localhost:5173
```

### 5. Verify
```bash
curl http://localhost:8080/health   # → "ok"
```

The first user to register is automatically promoted to instance admin.

## Testing

```bash
# Rust backend
cargo test

# haven-core — 78 tests
cd packages/haven-core && npx vitest run

# Web frontend — 61 tests
cd packages/web && npx vitest run
```

Docker must be running for Rust integration tests (they need PostgreSQL + Redis).

## Deployment

See [docs/deployment.md](docs/deployment.md) for the full production deployment guide, covering:
- Hetzner Cloud VPS setup (Debian 12, ~8/mo)
- Docker Compose production stack (Caddy + Haven + PostgreSQL + Redis + LiveKit)
- Auto-TLS via Let's Encrypt
- Invite-only registration for beta
- Backup strategies

See [docs/contributing.md](docs/contributing.md) for the development workflow and how to push updates.

## API Overview

All routes are under `/api/v1/`. The WebSocket endpoint is at `/api/v1/ws?token=<JWT>`.

| Area | Endpoints | Description |
|------|-----------|-------------|
| Auth | `/auth/register`, `/auth/login`, `/auth/refresh` | Registration with PoW + Turnstile, JWT auth, session management |
| 2FA | `/auth/totp/setup`, `/auth/totp/verify`, `/auth/totp` | TOTP setup, verification, and disable |
| Users | `/users/:id/profile`, `/users/search`, `/users/:id/block` | Profiles, avatars, banners, search, blocking |
| Keys | `/users/:id/keys`, `/keys/prekeys`, `/keys/backup` | X3DH key bundles, prekey management, encrypted backup |
| Servers | `/servers`, `/servers/:id/channels` | CRUD servers, channels, icons |
| Categories | `/servers/:id/categories` | Channel categories with ordering |
| Messages | `/channels/:id/messages`, `/channels/:id/pins` | Send/receive encrypted messages, pinning |
| Sender Keys | `/channels/:id/sender-keys` | Group E2EE key distribution |
| Roles | `/servers/:id/roles`, `/channels/:id/overwrites` | Permission management with channel overwrites |
| Friends | `/friends`, `/dm` | Friend requests, DMs, privacy settings |
| Invites | `/servers/:id/invites`, `/invites/:code/join` | Server invite codes |
| Voice | `/voice/:id/join`, `/voice/:id/participants` | LiveKit voice tokens, server mute/deafen |
| Attachments | `/attachments/upload`, `/attachments/:id` | Encrypted file upload/download |
| Emojis | `/servers/:id/emojis` | Custom server emoji management |
| GIFs | `/gifs/search`, `/gifs/trending` | GIF search and trending via Giphy |
| Reports | `/reports` | Content reporting |
| Audit Log | `/servers/:id/audit-log` | Server audit trail |
| Admin | `/admin/stats`, `/admin/users` | Instance administration |
| Registration Invites | `/registration-invites`, `/auth/invite-required` | Beta invite system |

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-or-later).
