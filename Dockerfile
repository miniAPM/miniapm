FROM rust:1.85-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app

# Copy manifests (without lock file to avoid version issues)
COPY Cargo.toml ./

# Copy source
COPY src ./src

# Build
RUN cargo build --release

# Runtime image
FROM alpine:3.19

RUN apk add --no-cache ca-certificates curl

WORKDIR /app

COPY --from=builder /app/target/release/miniapm /usr/local/bin/

ENV SQLITE_PATH=/data/miniapm.db
VOLUME /data

EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
  CMD curl -sf http://localhost:3000/health || exit 1

CMD ["miniapm", "server"]
