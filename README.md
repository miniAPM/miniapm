# MiniAPM

The smallest useful APM. A single-binary, self-hosted application performance monitor and error tracker built on OpenTelemetry.

![MiniAPM Dashboard](screenshot.png)

## Features

- **Distributed Tracing** - Full request-to-response visibility with waterfall visualization
- **Error Tracking** - Exceptions with stack traces and source context, auto-grouped by fingerprint
- **Route Performance** - P50, P95, P99 latencies with request counts and error rates
- **N+1 Query Detection** - Automatically identifies repeated query patterns
- **Deploy Tracking** - Correlate releases with performance changes

## Quick Start

### Docker (recommended)

```bash
# Run ingestion server
docker run -d -p 3000:3000 -v miniapm_data:/data ghcr.io/miniapm/miniapm

# Optional: Run admin dashboard
docker run -d -p 3001:3001 -v miniapm_data:/data ghcr.io/miniapm/miniapm-admin
```

On first run, you'll see your API key in the logs:
```
INFO miniapm: Single-project mode - API key: proj_abc123...
```

### From Source

```bash
git clone https://github.com/miniapm/miniapm
cd miniapm

# Run ingestion server (port 3000)
cargo run -p miniapm

# Run admin dashboard (port 3001)
cargo run -p miniapm-admin

# Run CLI tools
cargo run -p miniapm-cli -- create-key myapp
cargo run -p miniapm-cli -- list-keys
```

## Sending Data

### Rails with miniapm gem (recommended)

Add to your Gemfile:
```ruby
gem 'miniapm'
```

Configure in `config/initializers/miniapm.rb`:
```ruby
MiniAPM.configure do |config|
  config.endpoint = "http://localhost:3000"
  config.api_key = "proj_abc123..."
  config.service_name = "my-app"
end
```

### Any OpenTelemetry SDK

Configure your OTLP exporter:
```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:3000/ingest
OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer proj_abc123...
```

### Error Tracking API

```bash
curl -X POST http://localhost:3000/ingest/errors \
  -H "Authorization: Bearer proj_abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "error_type": "RuntimeError",
    "message": "Something went wrong",
    "backtrace": "app/models/user.rb:42:in `validate'\n...",
    "context": {"user_id": 123}
  }'
```

### Deploy Tracking API

```bash
curl -X POST http://localhost:3000/ingest/deploys \
  -H "Authorization: Bearer proj_abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "version": "v1.2.3",
    "git_sha": "abc123",
    "deployer": "ci"
  }'
```

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SQLITE_PATH` | `./data/miniapm.db` | Database file location |
| `APM_PORT` | `3000` | Port for ingestion server |
| `ADMIN_PORT` | `3001` | Port for admin dashboard |
| `RUST_LOG` | `miniapm=info` | Log level |
| `RETENTION_DAYS_REQUESTS` | `7` | Days to keep request data |
| `RETENTION_DAYS_ERRORS` | `30` | Days to keep error data |
| `RETENTION_DAYS_SPANS` | `7` | Days to keep trace spans |
| `RETENTION_DAYS_HOURLY_ROLLUPS` | `90` | Days to keep hourly aggregates |
| `SLOW_REQUEST_THRESHOLD_MS` | `500` | Threshold for slow request alerts |
| `ENABLE_USER_ACCOUNTS` | `false` | Enable multi-user authentication |
| `ENABLE_PROJECTS` | `false` | Enable multi-project mode |
| `SESSION_SECRET` | (generated) | Required when user accounts enabled |

See `.env.example` for a complete template.

## Multi-User Mode

To enable login and user management:

```bash
# Generate a session secret
export SESSION_SECRET=$(openssl rand -hex 32)
export ENABLE_USER_ACCOUNTS=true
```

Default admin credentials on first run:
- Username: `admin`
- Password: `admin` (you'll be prompted to change it)

## CLI Commands

```bash
# Ingestion server
miniapm                      # Start server (default port 3000)
miniapm -p 8080              # Start on custom port

# Admin dashboard
miniapm-admin                # Start dashboard (default port 3001)
miniapm-admin -p 8081        # Start on custom port

# CLI tools
miniapm-cli create-key <name>   # Create a new API key
miniapm-cli list-keys           # List all API keys
```

## Docker Compose

```yaml
services:
  miniapm:
    image: ghcr.io/miniapm/miniapm
    ports:
      - "3000:3000"
    volumes:
      - miniapm_data:/data
    environment:
      - RUST_LOG=miniapm=info
    restart: unless-stopped

  miniapm-admin:
    image: ghcr.io/miniapm/miniapm-admin
    ports:
      - "3001:3001"
    volumes:
      - miniapm_data:/data
    environment:
      - RUST_LOG=miniapm-admin=info
    restart: unless-stopped

volumes:
  miniapm_data:
```

## Architecture

- **miniapm** - Ingestion server (port 3000), receives traces, errors, and deploys
- **miniapm-admin** - Web dashboard (port 3001), UI for viewing data
- **miniapm-cli** - CLI tools for key management
- **SQLite storage** - Zero-config, automatic migrations, shared between services
- **Rust/Axum** - Fast, memory-efficient
- **OTLP/HTTP** - Standard OpenTelemetry protocol

## Development

```bash
# Run ingestion server
cargo run -p miniapm

# Run admin dashboard
cargo run -p miniapm-admin

# Run CLI tools
cargo run -p miniapm-cli -- create-key mykey
cargo run -p miniapm-cli -- list-keys

# Run tests
cargo test
```

## License

MIT License - see [LICENSE](LICENSE) for details.
