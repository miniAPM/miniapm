# miniapm / miniapm-pg

The [MiniAPM](https://github.com/miniapm/miniapm) server as precompiled binaries, packaged as gems.
No Rust toolchain needed.

| Gem          | Storage           |
|--------------|-------------------|
| `miniapm`    | SQLite            |
| `miniapm-pg` | PostgreSQL 18+    |

Both install the same three executables, so install one or the other:

```
miniapm         # collector, port 3000
miniapm-admin   # dashboard (port 3001) and project creation
miniapm-cli     # project and API key management
```

```sh
gem install miniapm        # or: gem install miniapm-pg
miniapm-admin create-project my-app
miniapm
```

Prebuilt for x86_64/aarch64 Linux (glibc and musl), arm64/x86_64 macOS and FreeBSD.

## Upgrading from miniapm 1.x

miniapm 1.x was the Rails client. 2.x is the server and instruments nothing.
To report from a Rails app, replace `gem "miniapm"` with `gem "lapsoss"`:

```ruby
Lapsoss.configure do |config|
  config.use_otlp(
    endpoint: "http://localhost:3000/ingest",
    api_key: ENV["MINIAPM_API_KEY"],
    service_name: "my-app"
  )
end
```

## Building

```sh
cd ruby
rake gem:native             # this machine's miniapm and miniapm-pg gems
rake "gem:native[,miniapm-pg]"
```

Releases: the release workflow builds every platform gem on a `v*` tag and attaches them to the
GitHub release. Then `rake gem:download gem:push_all`.
