# Haven Deployment Guide

This guide covers deploying Haven to a Hetzner Cloud VPS for beta testing.

## Why Hetzner?

- **German/EU jurisdiction** — outside Five Eyes, GDPR-aligned, strong privacy protections
- **Only responds to German court orders** — no US CLOUD Act reach
- **Datacenters in Falkenstein (FSN1) and Nuremberg (NBG1)**, Germany
- **Affordable** — ~8/mo for a capable VPS

## Server Selection

| Plan | vCPU | RAM | Storage | Cost | Notes |
|------|------|-----|---------|------|-------|
| **CPX21** (recommended) | 3 | 4 GB | 80 GB NVMe | ~8/mo | x86_64, good Docker compat |
| CAX21 (alternative) | 4 | 8 GB | 80 GB NVMe | ~7/mo | ARM64, more RAM but verify image compat |

**OS:** Debian 12 (Bookworm)

## Getting Started

### 1. Create a Hetzner Account

1. Go to https://console.hetzner.cloud
2. Sign up and verify your account
3. Add an SSH key (Settings > SSH Keys) — you'll need this to access your server

### 2. Provision the Server

1. Click **Add Server**
2. Location: **Falkenstein** or **Nuremberg**
3. Image: **Debian 12**
4. Type: **CPX21** (Shared vCPU, x86)
5. SSH Key: Select the key you added
6. Name: `haven` (or whatever you prefer)
7. Click **Create & Buy Now**

Note the server's IPv4 address once it's created.

### 3. Initial Server Setup

SSH into the server:

```bash
ssh root@YOUR_SERVER_IP
```

Install Docker and Docker Compose:

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh

# Create an unprivileged user
adduser --disabled-password --gecos "" haven
usermod -aG docker haven

# Switch to haven user for the rest of setup
su - haven
```

### 4. Harden the Server

```bash
# Back as root:
exit

# Firewall
apt install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp       # SSH
ufw allow 80/tcp       # HTTP (Caddy redirect)
ufw allow 443/tcp      # HTTPS
ufw allow 443/udp      # HTTP/3
ufw allow 7881/tcp     # LiveKit WebRTC TCP
ufw allow 7882/udp     # LiveKit WebRTC UDP
ufw enable

# Harden SSH
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd

# Auto-update security patches
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
```

After this, SSH in as the `haven` user:

```bash
ssh haven@YOUR_SERVER_IP
```

### 5. Clone and Configure Haven

```bash
sudo mkdir -p /opt/haven
sudo chown haven:haven /opt/haven
git clone https://github.com/markjsapp/haven.git /opt/haven
cd /opt/haven

# Create production environment file
cp .env.production.example .env.production
```

Edit `.env.production` and fill in all values:

```bash
nano /opt/haven/.env.production
```

**Required values to generate:**

```bash
# Run these to generate secrets:
openssl rand -hex 24    # POSTGRES_PASSWORD
openssl rand -hex 24    # REDIS_PASSWORD
openssl rand -hex 32    # JWT_SECRET
openssl rand -hex 32    # STORAGE_ENCRYPTION_KEY
openssl rand -hex 12    # LIVEKIT_API_KEY
openssl rand -base64 32 # LIVEKIT_API_SECRET
```

**Important settings:**
- `HAVEN_DOMAIN` — your domain (e.g., `chat.yourdomain.com`)
- `ACME_EMAIL` — email for Let's Encrypt notifications
- `REGISTRATION_INVITE_ONLY=true` — beta invite-only mode

### 6. Point DNS

Create an **A record** pointing your domain to the server IP:

```
chat.yourdomain.com  →  A  →  YOUR_SERVER_IP
```

DNS propagation can take a few minutes. Verify with:

```bash
dig +short chat.yourdomain.com
```

### 7. Deploy

```bash
# Start the full stack (first run builds everything — takes 5-10 minutes)
cd /opt/haven
docker compose -f docker-compose.prod.yml --env-file .env.production up -d
```

Watch the logs:

```bash
docker compose -f /opt/haven/docker-compose.prod.yml --env-file /opt/haven/.env.production logs -f haven
```

Caddy will automatically obtain a Let's Encrypt TLS certificate once DNS resolves.

### 8. Register the First User (Admin)

1. Open `https://chat.yourdomain.com` in your browser
2. Register an account — the first user is automatically promoted to **instance admin**
3. The first user does **not** need an invite code (even with `REGISTRATION_INVITE_ONLY=true`)
4. After registration, you'll automatically receive **3 invite codes**

### 9. Share Invite Codes

Your invite codes are visible in the app (Settings > Invite Codes). Share them with beta testers.

Each new user who registers with an invite code also receives 3 invite codes of their own.

## Updating Haven

After pushing code changes:

```bash
cd /opt/haven
git pull
./deploy.sh
```

The deploy script:
1. Builds a new Docker image
2. Recreates the Haven container (2-5 second downtime)
3. Waits for the health check to pass
4. Cleans up old images

WebSocket clients auto-reconnect via the `Resume { session_id }` protocol.

## Backups

### Database Backup (automated)

Create a cron job for daily pg_dump:

```bash
# Create backup directory
mkdir -p ~/backups

# Add to crontab (as haven user)
crontab -e
```

Add this line:

```
0 3 * * * docker compose -f /opt/haven/docker-compose.prod.yml --env-file /opt/haven/.env.production exec -T postgres pg_dump -U haven haven | gzip > ~/backups/haven-$(date +\%Y\%m\%d).sql.gz && find ~/backups -name "*.sql.gz" -mtime +14 -delete
```

This runs daily at 3 AM and keeps 14 days of backups.

### Hetzner Snapshots

For full-server snapshots:
1. Go to Hetzner Console > Your Server > Snapshots
2. Click **Create Snapshot** (or automate via Hetzner API)
3. Recommended: weekly snapshots, keep 4

## Architecture Overview

```
Internet
    │
    ▼
┌──────────┐
│   Caddy   │ :443 (HTTPS + auto TLS)
│           │ :80  (redirect → HTTPS)
└─────┬─────┘
      │
      ├── /api/v1/*    → Haven :8080
      ├── /api/v1/ws   → Haven :8080 (WebSocket)
      └── /livekit/*   → LiveKit :7880 (signaling)

┌──────────┐
│  Haven    │ :8080 (API + embedded frontend)
│           │ → PostgreSQL :5432 (Docker internal)
│           │ → Redis :6379 (Docker internal)
└───────────┘

┌──────────┐
│ LiveKit   │ :7881/tcp, :7882/udp (WebRTC media)
│           │ :7880 internal (signaling, via Caddy)
└───────────┘
```

PostgreSQL and Redis have **no external port mappings** — they're only accessible within the Docker network.

## Troubleshooting

### Haven won't start

```bash
docker compose -f docker-compose.prod.yml --env-file .env.production logs haven
```

Common issues:
- Missing env vars in `.env.production`
- Database connection failure (check PostgreSQL is healthy)
- Port already in use

### TLS certificate not issued

- Verify DNS A record resolves to your server IP
- Check Caddy logs: `docker compose -f docker-compose.prod.yml --env-file .env.production logs caddy`
- Ensure ports 80 and 443 are open in UFW

### WebSocket disconnections

- Check `MAX_WS_CONNECTIONS_PER_USER` isn't too low
- Clients auto-reconnect via session resume

### Invite codes not working

- Verify `REGISTRATION_INVITE_ONLY=true` is set
- Check the code hasn't been used already (single-use)
- Check the code hasn't expired
