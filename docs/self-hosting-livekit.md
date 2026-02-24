# Self-Hosting LiveKit for Haven

## Why Self-Host?

Haven currently uses **LiveKit Cloud** (`wss://haven-ssrnfsnd.livekit.cloud`) for voice and video. This means all media traffic routes through LiveKit's infrastructure, and their [privacy policy](https://livekit.io/privacy) applies — they may collect IP addresses, device information, and usage data.

For a privacy-focused platform, this is a contradiction. The fix is straightforward: **self-host LiveKit Server**.

## What Changes

| | LiveKit Cloud | Self-Hosted |
|---|---|---|
| Media traffic | Routes through LiveKit Inc. servers | Stays on your infrastructure |
| Privacy policy | LiveKit's policy applies | Only your policy applies |
| IP addresses | Visible to LiveKit | Visible only to you |
| Cost | Free tier, then paid | Your server costs only |
| Maintenance | Managed by LiveKit | Managed by you |

## What Doesn't Change

- Haven's backend code — zero modifications needed
- Haven's frontend code — zero modifications needed
- Client SDKs — they connect to whatever URL you configure, no telemetry
- Token generation — Haven already creates properly scoped tokens in `src/api/voice.rs`

## How to Self-Host

### Option 1: Docker (simplest)

Add to `docker-compose.yml`:

```yaml
livekit:
  image: livekit/livekit-server:latest
  ports:
    - "7880:7880"   # HTTP/WebSocket
    - "7881:7881"   # RTC (TCP)
    - "7882:7882/udp" # RTC (UDP — required for media)
  environment:
    LIVEKIT_KEYS: "your-api-key: your-api-secret"
  command: --dev  # remove --dev for production
```

Generate API credentials:
```bash
# Generate a random key/secret pair
API_KEY=$(openssl rand -hex 12)
API_SECRET=$(openssl rand -base64 32)
echo "LIVEKIT_API_KEY=$API_KEY"
echo "LIVEKIT_API_SECRET=$API_SECRET"
```

### Option 2: Binary

Download from [LiveKit releases](https://github.com/livekit/livekit/releases) and run:

```bash
./livekit-server --keys "your-api-key: your-api-secret" --dev
```

### Option 3: Kubernetes / Cloud VM

LiveKit provides Helm charts and deployment guides at [docs.livekit.io/deploy](https://docs.livekit.io/home/self-hosting/deployment/).

## Haven Configuration

Update `.env` to point to your self-hosted instance:

```env
# Before (LiveKit Cloud):
LIVEKIT_URL=wss://haven-ssrnfsnd.livekit.cloud
LIVEKIT_API_KEY=APIJ5hZxhSUBhzy
LIVEKIT_API_SECRET=<cloud-secret>

# After (self-hosted, local dev):
LIVEKIT_URL=ws://localhost:7880
LIVEKIT_API_KEY=<your-generated-key>
LIVEKIT_API_SECRET=<your-generated-secret>

# After (self-hosted, production with TLS):
LIVEKIT_URL=wss://livekit.yourdomain.com
LIVEKIT_API_KEY=<your-generated-key>
LIVEKIT_API_SECRET=<your-generated-secret>
```

Restart the Haven backend and everything works identically — just with all media traffic staying on your servers.

## Production Considerations

- **TLS is required** for WebRTC in production browsers (`wss://`, not `ws://`)
- **UDP port 7882** must be open for media traffic — TCP fallback exists but adds latency
- **TURN server**: If users are behind restrictive NATs/firewalls, you may need a TURN relay. LiveKit has a built-in TURN server, or you can use [coturn](https://github.com/coturn/coturn)
- **Bandwidth**: Voice is ~50 kbps/user, video is ~1-2.5 Mbps/user. Plan server bandwidth accordingly
- **CPU**: LiveKit's SFU (Selective Forwarding Unit) architecture is lightweight — it forwards media packets rather than mixing them. A modest VPS handles dozens of concurrent users

## SDK Telemetry

The LiveKit client SDKs (`livekit-client-sdk-js`, etc.) are open-source and do not include telemetry. They establish WebRTC connections to whatever server URL you provide and nothing else. The data collection described in LiveKit's privacy policy applies exclusively to their cloud service's dashboard, billing, and analytics — none of which exist when self-hosting.
