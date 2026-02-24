# ─── Stage 1: Download Web Frontend ──────────────────────
FROM debian:bookworm-slim AS web
ARG WEB_DIST_URL=https://github.com/haven-chat-org/web/releases/latest/download/web-dist.tar.gz
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /web-dist && curl -fSL "$WEB_DIST_URL" -o /tmp/web-dist.tar.gz \
    && tar -xzf /tmp/web-dist.tar.gz -C /web-dist \
    && rm /tmp/web-dist.tar.gz

# ─── Stage 2: Rust Build ───────────────────────────────
FROM rust:slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies by building them first
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

# Copy pre-built frontend from stage 1
COPY --from=web /web-dist packages/web/dist

# Build the actual application with embedded UI
COPY src src
COPY migrations migrations
ENV SQLX_OFFLINE=true
RUN cargo build --release --features postgres,embed-ui

# ─── Stage 3: Runtime ──────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /bin/false haven

WORKDIR /app

COPY --from=builder /app/target/release/haven-backend /app/haven-backend
COPY --from=builder /app/migrations /app/migrations

RUN mkdir -p /data/attachments && chown -R haven:haven /data

USER haven

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["/app/haven-backend"]
