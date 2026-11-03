//! Repeatable in-process overload experiment, never part of the default suite.

use super::*;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Barrier;
use tokio::task::JoinSet;

const CLIENTS: usize = 32;
const EXPORTS_PER_CLIENT: usize = 16;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "load experiment; use --release --ignored --nocapture and an isolated database"]
async fn ingestion_load() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let pool = load_pool(&directory).await?;
    let project = models::project::ensure_default_project(&pool).await?;
    let limit = match std::env::var("MINIAPM_LOAD_MAX_IN_FLIGHT") {
        Ok(value) => Some(api::admission::InFlightLimit::new(value.parse()?)?),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error.into()),
    };
    let app = make_app(AppState {
        pool: pool.clone(),
        config: Config {
            ingest_max_in_flight: limit,
            ..Config::default()
        },
    });
    let (done, mut stopped) = tokio::sync::watch::channel(());
    let health_app = app.clone();
    let health = tokio::spawn(async move {
        let mut latencies = Vec::new();
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = stopped.changed() => break,
                _ = interval.tick() => {
                    let start = Instant::now();
                    assert_eq!(health_app.serve(get("/health")).await.unwrap().status(), StatusCode::OK);
                    latencies.push(start.elapsed());
                }
            }
        }
        latencies
    });
    let gate = Arc::new(Barrier::new(CLIENTS + 1));
    let mut workers = JoinSet::new();
    for client in 0..CLIENTS {
        let app = app.clone();
        let auth = format!("Bearer {}", project.api_key);
        let gate = gate.clone();
        workers.spawn(async move {
            let mut samples = Vec::new();
            gate.wait().await;
            for export in 0..EXPORTS_PER_CLIENT {
                let count = if export % 8 == 0 { 128 } else { 16 };
                let payload = export_payload(client * EXPORTS_PER_CLIENT + export, count);
                let request = post_json("/ingest/v1/traces", Some(&auth), &payload);
                let start = Instant::now();
                let status = app.serve(request).await.unwrap().status();
                samples.push((status, start.elapsed(), count));
            }
            samples
        });
    }
    let start = Instant::now();
    gate.wait().await;
    let mut samples = Vec::new();
    while let Some(worker) = workers.join_next().await {
        samples.extend(worker?);
    }
    let elapsed = start.elapsed();
    drop(done);
    let mut health = health.await?;
    let mut accepted = Vec::new();
    let mut refused = Vec::new();
    let mut expected = 0;
    for (status, duration, count) in samples {
        match status {
            StatusCode::ACCEPTED => {
                accepted.push(duration);
                expected += i64::try_from(count)?;
            }
            StatusCode::SERVICE_UNAVAILABLE => refused.push(duration),
            _ => anyhow::bail!("unexpected ingestion response: {status}"),
        }
    }
    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM spans WHERE project_id = $1")
        .bind(project.id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(stored, expected, "only accepted exports must be stored");
    println!(
        "limit={limit:?} exports={} accepted={} refused={} spans={} elapsed_ms={} accepted_p95_us={} refused_p95_us={} health_samples={} health_p95_us={}",
        CLIENTS * EXPORTS_PER_CLIENT,
        accepted.len(),
        refused.len(),
        stored,
        elapsed.as_millis(),
        p95(&mut accepted),
        p95(&mut refused),
        health.len(),
        p95(&mut health),
    );
    pool.close().await;
    Ok(())
}

fn p95(values: &mut [Duration]) -> u128 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    values[(values.len() * 95).div_ceil(100) - 1].as_micros()
}

fn export_payload(export: usize, count: usize) -> serde_json::Value {
    let now = jiff::Timestamp::now().as_nanosecond();
    let spans: Vec<_> = (0..count)
        .map(|span| {
            serde_json::json!({
                "traceId": format!("{export:032x}"),
                "spanId": format!("{:016x}", span + 1),
                "name": "GET /load",
                "kind": 2,
                "startTimeUnixNano": now.to_string(),
                "endTimeUnixNano": (now + 1_000_000).to_string(),
            })
        })
        .collect();
    serde_json::json!({"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]})
}

#[cfg(feature = "sqlite")]
async fn load_pool(directory: &tempfile::TempDir) -> anyhow::Result<DbPool> {
    db::init(&Config {
        sqlite_path: directory
            .path()
            .join("load.sqlite3")
            .to_string_lossy()
            .into_owned(),
        ..Config::default()
    })
    .await
}

#[cfg(feature = "postgres")]
async fn load_pool(_directory: &tempfile::TempDir) -> anyhow::Result<DbPool> {
    // Reuse the schema isolation helper but match the production ten-connection pool.
    let seed = db::test_pool().await;
    let options = (*seed.connect_options()).clone();
    seed.close().await;
    Ok(sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await?)
}
