# Persistent MiniAPM on macOS

Use Docker Compose with OrbStack or Docker Desktop. The collector and dashboard
run in the background and share a SQLite database in a named Docker volume.
No separate database service is needed.

## Start

Start your Docker engine, then run these commands from the repository root:

```bash
# Once only; keep the same secret across restarts.
# If .env already exists, add SESSION_SECRET instead of overwriting it.
if [ ! -e .env ]; then
  (umask 077; printf 'SESSION_SECRET=%s\n' "$(openssl rand -hex 32)" > .env)
fi

# Build this checkout and wait for both services to become healthy.
docker compose up -d --build --wait
```

- Collector: <http://localhost:3000>
- Dashboard: <http://localhost:3001>
- Initial dashboard username: `admin`. A random password is printed in the
  dashboard's first-start logs; change it when prompted.

Both ports are bound to `127.0.0.1`, not exposed to your local network.
The session secret is stored in the git-ignored `.env` file.

Find the collector's API key and initial dashboard password in their startup
logs:

```bash
docker compose logs miniapm
docker compose logs miniapm-admin
```

Save the initial password before recreating containers (which removes their
logs). If you lose it, set a new password with
`docker compose exec miniapm miniapm-cli reset-password admin <new-password>`.

## Persistence and automatic restarts

Both services mount the `miniapm_data` Compose volume at `/data` and use
`SQLITE_PATH=/data/miniapm.db`. With this repository's default project name, the
Docker volume is `miniapm_miniapm_data`.

Data survives container restarts, recreation, image rebuilds, and
`docker compose down`. Keep the same Compose project name (`miniapm`) to reuse
the same volume.

`restart: unless-stopped` restarts the containers after failures and when the
Docker engine restarts, unless you explicitly stopped them. On macOS, enable
**start at login** in OrbStack or Docker Desktop so the engine starts after you
log in. Containers do not run while the Mac is asleep or the engine is stopped.

## Manage

Run from the repository root:

```bash
docker compose ps                       # Status / health
docker compose logs -f                  # Follow logs
docker compose restart                 # Restart both services
docker compose stop                    # Stop without deleting containers/data
docker compose up -d --wait             # Start again
docker compose up -d --build --wait     # Rebuild after source changes
docker compose down                    # Remove containers; retain data
```

**Do not use `docker compose down -v` or remove the volume unless you intend to
delete the database.** A persistent volume is not a backup.

## Backup

Stop both services briefly for a consistent copy of SQLite and its journal
files, copy `/data` to your Mac, then start the services again:

```bash
backup="./backups/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup"
docker compose stop
docker compose cp miniapm:/data/. "$backup/"
docker compose up -d --wait
```

Keep backups somewhere safe, separate from the Docker engine's storage.
