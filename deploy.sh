#!/usr/bin/env bash
set -euo pipefail

# Haven deployment script
# Usage: ./deploy.sh              Pull latest image from GHCR and deploy
#        ./deploy.sh --build      Build the Docker image locally and deploy

COMPOSE_FILE="docker-compose.prod.yml"
ENV_FILE=".env.production"
HEALTH_URL="http://localhost:8080/health"
HEALTH_TIMEOUT=60
BUILD_LOCAL=false

for arg in "$@"; do
  case "$arg" in
    --build) BUILD_LOCAL=true ;;
    *) echo "Unknown option: $arg"; exit 1 ;;
  esac
done

# ─── Pre-flight checks ─────────────────────────────────

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: $ENV_FILE not found."
  echo "Copy .env.production.example to .env.production and fill in values."
  exit 1
fi

if ! command -v docker &>/dev/null; then
  echo "ERROR: docker not found. Install Docker first."
  exit 1
fi

if [ "$BUILD_LOCAL" = true ]; then
  echo "==> Building Haven locally..."
  docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" build haven
else
  echo "==> Pulling latest Haven image from GHCR..."
  docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" pull haven
fi

echo "==> Recreating Haven container..."
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --no-deps --force-recreate haven

# ─── Health check ───────────────────────────────────────

echo "==> Waiting for Haven to become healthy..."
elapsed=0
while [ $elapsed -lt $HEALTH_TIMEOUT ]; do
  if curl -sf "$HEALTH_URL" >/dev/null 2>&1; then
    echo "==> Haven is healthy!"
    # Clean up old images
    docker image prune -f >/dev/null 2>&1 || true
    echo "==> Deployment complete."
    docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" ps
    exit 0
  fi
  sleep 2
  elapsed=$((elapsed + 2))
  echo "    ...waiting ($elapsed/${HEALTH_TIMEOUT}s)"
done

echo "ERROR: Haven did not become healthy within ${HEALTH_TIMEOUT}s."
echo "==> Recent logs:"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" logs --tail=50 haven
exit 1
