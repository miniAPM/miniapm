FROM rust:1.92-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app

COPY Cargo.toml ./
COPY Cargo.lock ./

# Copy crate sources
COPY crates ./crates

# Build
RUN cargo build --release -p miniapm

# Runtime image
FROM alpine:3.19

RUN apk add --no-cache ca-certificates curl

WORKDIR /app

COPY --from=builder /app/target/release/miniapm /usr/local/bin/
COPY --from=builder /app/crates/miniapm/templates ./templates
COPY --from=builder /app/crates/miniapm/static ./static

ENV SQLITE_PATH=/data/miniapm.db
VOLUME /data

EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
  CMD curl -sf http://localhost:3000/health || exit 1

CMD ["miniapm"]
