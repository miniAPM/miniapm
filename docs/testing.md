# Testing

Run the workspace suite with:

```sh
cargo test --workspace
cargo fmt --all -- --check
```

PostgreSQL tests require PostgreSQL 18+ and an **isolated disposable database**:

```sh
MINIAPM_TEST_DATABASE_URL=postgres://user:password@localhost/miniapm_test \
  cargo test --workspace --no-default-features --features postgres -- --test-threads=4
```

Tests create migrated schemas and may sweep old test schemas. Never point this
variable at an application database. Admission tests cover authenticated shared
HTTP/gRPC budgets, tenant isolation, retry responses, batch accounting, and
persisted data. Do not retest the crates' rate-limiting or backoff algorithms here.

PostgreSQL job-lock tests also keep the original pool alive while cancelling a
running job, then acquire its advisory lock through an independent collector
session. Normal success/failure paths must release the lock and reuse healthy
connections. Cancellation discards the possibly locked session; it does **not**
undo committed job work or make an arbitrary job safe to retry.

Session-cleanup integration tests use real SQLite write contention and PostgreSQL
statement triggers with explicit SQLSTATEs. Tests cover error classification,
persisted cleanup results, the fixed cutoff, and job-lock ownership during backoff
and cancellation—not the crate's delay calculations or attempt arithmetic.
Backoff sleepers are injected to avoid timing-dependent tests; production uses Tokio timers and
the published `chrono-machines` async retry driver.

Maintenance shutdown tests cover stopping before the first scheduled run,
allowing a running job to commit during grace, and cancelling uncommitted work
even when HTTP draining times out. PostgreSQL tests also acquire the cancelled
job's lock from an independent pool while its original pool remains alive.
These exercise MiniAPM's lifecycle wiring, not Tokio's scheduling algorithms.
An occupied-port regression test covers listener-error propagation both with
collector maintenance jobs and without them (the admin server path), including
connection cleanup without sending an OS signal.
Injected shutdown notifications cover successful shutdown and signal-source
errors, preserving the underlying error after listener and maintenance cleanup.
Self-monitor tests explicitly drain the writer while sender clones remain alive,
verify buffered spans and errors in the database without polling sleeps, and
cover multiple queued batches, late records, and a writer blocked on pool capacity.
Stored self-monitor SQL spans must also identify the selected database backend.
Admin-port tests inject environment lookup results without mutating process-wide
variables: only an absent `ADMIN_PORT` defaults to 3001; invalid values must fail.

## Ingestion load experiment

Run the ignored, release-mode in-process experiment against a temporary on-disk
SQLite database:

```sh
cargo test -p mini-apm --release --lib ingestion_load -- --ignored --nocapture
MINIAPM_LOAD_MAX_IN_FLIGHT=4 \
  cargo test -p mini-apm --release --lib ingestion_load -- --ignored --nocapture
```

For PostgreSQL, supply the isolated `MINIAPM_TEST_DATABASE_URL` and add
`--no-default-features --features postgres` before `--`. The harness uses a fresh
schema and a production-sized ten-connection pool. Compare unset, 1, 4, and 8.

Each run uses 32 concurrent clients, 16 exports per client, and a mix of 16/128
spans per export. It measures accepted/rejected counts and p95 durations plus
concurrent database-backed health queries, and checks persisted span counts.
It exercises authentication and handlers, not sockets or production background
jobs. Refusals are **not retried**; capped runs process less work, so lower
latencies are not evidence of higher throughput or of a need for adaptation.
Repeat runs before drawing conclusions; do not assert timing thresholds in CI.

### Local observations (2026-11-03)

Two sequential release-mode runs on macOS/aarch64, Rust 1.99.1, using fresh
databases/schemas and the workload above. PostgreSQL 18.6 ran in the local
`postgis-with-extensions:18` container:

| Backend | In-flight cap | Accepted exports (of 512) | Accepted p95 (ms) |
|---------|--------------:|-------------------------:|------------------:|
| SQLite WAL | unlimited | 512 | 64.96–65.14 |
| SQLite WAL | 1 | 11–12 | 15.57–17.39 |
| SQLite WAL | 4 | 55–56 | 19.32–19.83 |
| SQLite WAL | 8 | 109–110 | 27.35–43.99 |
| PostgreSQL 18.6 | unlimited | 512 | 61.31–75.85 |
| PostgreSQL 18.6 | 1 | 7–8 | 19.06–19.37 |
| PostgreSQL 18.6 | 4 | 44–45 | 23.50–28.39 |
| PostgreSQL 18.6 | 8 | 91–106 | 31.63–33.51 |

All other exports received retryable refusals, and stored span counts matched
accepted exports. Low caps shed most of this unpaced burst; that is protection,
not increased throughput. Very short capped runs have few health samples (only
three with SQLite cap 1), so their health p95 is not a reliable capacity estimate.

**Decision:** keep the fixed bound opt-in; do not add adaptive control yet.
A sustained, retry-aware workload with changing database pressure is needed to
justify `shed-machines`. Adaptive feedback would also require typed storage
failure classification rather than treating every handler error as overload.

## Conventions

- Keep tests in `<module>/tests.rs`, wired with `#[cfg(test)] mod tests;`.
  Production files should not contain inline test bodies.
- Prefer observable behavior: HTTP responses **and persisted data**, account and
  project lifecycles, retention, aggregation, and tenant isolation.
- Do not add standalone tests for simple formatting, getters, enum mappings,
  token generators, or thin wrappers. Exercise them through their callers.
- Keep focused unit tests for complex logic such as SQL normalization, span
  classification, error-location selection, similarity, timestamp precision,
  validation boundaries, and state-machine transitions. Use tables of cases.
- Use real migrated, isolated in-memory SQLite pools for persistence tests.
  Avoid global environment mutations or external services.
- Assert identities and values rather than only success status or row counts.
  Cover failure paths and repeatable operations where relevant.
- Async tests use `#[tokio::test]`. Returning `anyhow::Result<()>` allows setup
  errors to propagate; use descriptive `expect` messages for required values.
