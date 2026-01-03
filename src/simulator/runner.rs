use super::{patterns, routes, traces};
use crate::config::Config;
use chrono::{Datelike, Duration, Timelike, Utc};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::time::Duration as StdDuration;

pub async fn run(
    config: &Config,
    requests_per_minute: u32,
    error_rate: f64,
    continuous: bool,
) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{}/ingest", config.mini_apm_url);
    let api_key = config.api_key.as_deref().unwrap_or("");

    tracing::info!(
        "Simulator starting: {} req/min, {}% error rate (with OTLP traces)",
        requests_per_minute,
        error_rate * 100.0
    );

    loop {
        let multiplier = patterns::traffic_multiplier();
        let adjusted_rpm = (requests_per_minute as f64 * multiplier) as u32;
        let delay_ms = if adjusted_rpm > 0 {
            60_000 / adjusted_rpm
        } else {
            1000
        };

        // Generate request
        let route = routes::pick_random();
        let mut rng = rand::thread_rng();

        let total_ms = patterns::simulate_latency(route.base_ms);
        let db_ms = patterns::simulate_db_time(total_ms);
        let view_ms = patterns::simulate_view_time(total_ms, db_ms);
        let status = if rng.gen::<f64>() < error_rate { 500 } else { 200 };

        let request_id = format!("{:032x}", rng.gen::<u128>());
        let timestamp = Utc::now().to_rfc3339();

        // Send request
        let payload = serde_json::json!({
            "metadata": {
                "host": "simulator",
                "env": "development",
                "rails_version": "7.1.2",
                "ruby_version": "3.2.2",
                "git_sha": "abc123"
            },
            "requests": [{
                "request_id": request_id,
                "method": route.method,
                "path": route.path,
                "controller": route.controller,
                "action": route.action,
                "status": status,
                "total_ms": total_ms,
                "db_ms": db_ms,
                "db_count": route.db_queries,
                "view_ms": view_ms,
                "timestamp": timestamp
            }]
        });

        let resp = client
            .post(format!("{}/requests", url))
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&payload)
            .send()
            .await;

        match resp {
            Ok(_) => {
                tracing::debug!(
                    "{} {} {} {}ms",
                    route.method,
                    route.path,
                    status,
                    total_ms.round()
                );
            }
            Err(e) => {
                tracing::warn!("Failed to send request: {}", e);
            }
        }

        // Send OTLP trace for this request
        let trace_payload = traces::generate_web_trace(route, total_ms, db_ms, view_ms);
        let _ = client
            .post(format!("{}/v1/traces", url))
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&trace_payload)
            .send()
            .await;

        // Occasionally send background job traces (10% chance)
        if rng.gen::<f64>() < 0.10 {
            let job_trace = traces::generate_job_trace();
            let _ = client
                .post(format!("{}/v1/traces", url))
                .header("Authorization", format!("Bearer {}", api_key))
                .json(&job_trace)
                .send()
                .await;
            tracing::debug!("Sent background job trace");
        }

        // Rarely send rake task traces (1% chance)
        if rng.gen::<f64>() < 0.01 {
            let rake_trace = traces::generate_rake_trace();
            let _ = client
                .post(format!("{}/v1/traces", url))
                .header("Authorization", format!("Bearer {}", api_key))
                .json(&rake_trace)
                .send()
                .await;
            tracing::debug!("Sent rake task trace");
        }

        // Maybe send an error
        if rng.gen::<f64>() < error_rate {
            let error = routes::pick_random_error();
            let message = error.message.replace("{}", &rng.gen::<u32>().to_string());

            // Generate fingerprint
            let mut hasher = Sha256::new();
            hasher.update(error.class);
            hasher.update(&message);
            let fingerprint = hex::encode(&hasher.finalize()[..8]);

            // Generate realistic source context
            let controller_file = format!("app/controllers/{}.rb", route.controller.to_lowercase().replace("::", "/"));
            let error_line = 42;

            let error_payload = serde_json::json!({
                "exception_class": error.class,
                "message": message,
                "backtrace": [
                    format!("{}:{}:in `{}'", controller_file, error_line, route.action),
                    "app/controllers/application_controller.rb:15:in `process_action'",
                    "actionpack/lib/action_controller/metal.rb:227:in `dispatch'"
                ],
                "fingerprint": fingerprint,
                "request_id": request_id,
                "timestamp": timestamp,
                "source_context": {
                    "file": controller_file,
                    "lineno": error_line,
                    "pre_context": [
                        format!("  def {}", route.action),
                        "    @user = current_user",
                        "    @items = @user.items.order(created_at: :desc)"
                    ],
                    "context_line": format!("    raise {} if @items.empty?", error.class),
                    "post_context": [
                        "    respond_to do |format|",
                        "      format.html { render :index }",
                        "    end"
                    ]
                }
            });

            let _ = client
                .post(format!("{}/errors", url))
                .header("Authorization", format!("Bearer {}", api_key))
                .json(&error_payload)
                .send()
                .await;

            tracing::debug!("Error: {} {}", error.class, message);
        }

        if !continuous {
            break;
        }

        tokio::time::sleep(StdDuration::from_millis(delay_ms as u64)).await;
    }

    Ok(())
}

pub async fn backfill(config: &Config, days: u32, requests_per_day: u32) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{}/ingest", config.mini_apm_url);
    let api_key = config.api_key.as_deref().unwrap_or("");

    tracing::info!("Backfilling {} days with ~{} requests/day", days, requests_per_day);

    let mut rng = rand::thread_rng();

    for day_offset in (0..days).rev() {
        let base_date = Utc::now() - Duration::days(day_offset as i64);
        tracing::info!("Generating data for {}", base_date.format("%Y-%m-%d"));

        // Distribute requests across hours
        for hour in 0..24 {
            let multiplier = patterns::traffic_multiplier_for(hour, base_date.weekday().num_days_from_monday());
            let requests_this_hour = ((requests_per_day as f64 / 24.0) * multiplier) as u32;

            let mut batch = Vec::new();

            for _ in 0..requests_this_hour {
                let route = routes::pick_random();
                let minute = rng.gen_range(0..60);
                let second = rng.gen_range(0..60);

                let timestamp = base_date
                    .with_hour(hour)
                    .unwrap()
                    .with_minute(minute)
                    .unwrap()
                    .with_second(second)
                    .unwrap();

                let total_ms = patterns::simulate_latency(route.base_ms);
                let db_ms = patterns::simulate_db_time(total_ms);
                let view_ms = patterns::simulate_view_time(total_ms, db_ms);

                batch.push(serde_json::json!({
                    "request_id": format!("{:032x}", rng.gen::<u128>()),
                    "method": route.method,
                    "path": route.path,
                    "controller": route.controller,
                    "action": route.action,
                    "status": 200,
                    "total_ms": total_ms,
                    "db_ms": db_ms,
                    "db_count": route.db_queries,
                    "view_ms": view_ms,
                    "timestamp": timestamp.to_rfc3339()
                }));

                // Send in batches of 100
                if batch.len() >= 100 {
                    let payload = serde_json::json!({
                        "metadata": {
                            "host": "simulator",
                            "env": "development"
                        },
                        "requests": batch
                    });

                    let _ = client
                        .post(format!("{}/requests", url))
                        .header("Authorization", format!("Bearer {}", api_key))
                        .json(&payload)
                        .send()
                        .await;

                    batch.clear();
                }
            }

            // Send remaining
            if !batch.is_empty() {
                let payload = serde_json::json!({
                    "metadata": {
                        "host": "simulator",
                        "env": "development"
                    },
                    "requests": batch
                });

                let _ = client
                    .post(format!("{}/requests", url))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .json(&payload)
                    .send()
                    .await;
            }
        }
    }

    tracing::info!("Backfill complete");
    Ok(())
}
