FROM rust:1.92-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy workspace crates
COPY crates ./crates

# Build all workspace crates
RUN cargo build --release --workspace

# Runtime image
FROM alpine:3.23

RUN apk add --no-cache ca-certificates curl

WORKDIR /app

COPY --from=builder /app/target/release/miniapm /usr/local/bin/
COPY --from=builder /app/target/release/miniapm-admin /usr/local/bin/
COPY --from=builder /app/target/release/miniapm-cli /usr/local/bin/

# Admin UI assets (for miniapm-admin)
COPY --from=builder /app/crates/mini-apm-admin/static ./static

ENV SQLITE_PATH=/data/miniapm.db
VOLUME /data

EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
  CMD curl -sf http://localhost:3000/health || exit 1

CMD ["miniapm"]
