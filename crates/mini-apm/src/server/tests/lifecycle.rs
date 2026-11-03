use super::*;

#[tokio::test]
async fn signal_source_result_is_preserved_after_cleanup() -> anyhow::Result<()> {
    for maintenance in [false, true] {
        for failed in [false, true] {
            let pool = db::test_pool().await;
            let config = Config::default();
            let jobs = maintenance.then(|| jobs::start(pool.clone(), config.clone()));
            let app = make_app(AppState {
                pool: pool.clone(),
                config,
            });
            let signal = if failed {
                Err(std::io::Error::other("signal source unavailable").into())
            } else {
                Ok(())
            };
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                serve_until("127.0.0.1:0".into(), app, jobs, std::future::ready(signal)),
            )
            .await?;
            if failed {
                let error = result.unwrap_err();
                assert_eq!(error.to_string(), "Shutdown signal failed");
                assert_eq!(
                    error.downcast_ref::<std::io::Error>().unwrap().to_string(),
                    "signal source unavailable"
                );
            } else {
                result?;
            }
            tokio::time::timeout(Duration::from_secs(5), pool.close()).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn occupied_port_returns_an_error_without_waiting_for_a_signal() -> anyhow::Result<()> {
    // Keep the socket open throughout: there is no bind/release/rebind race.
    let occupied = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = occupied.local_addr()?.to_string();
    for maintenance in [false, true] {
        let pool = db::test_pool().await;
        let config = Config::default();
        let jobs = maintenance.then(|| jobs::start(pool.clone(), config.clone()));
        let app = make_app(AppState {
            pool: pool.clone(),
            config,
        });
        let error = tokio::time::timeout(
            Duration::from_secs(5),
            serve_with_jobs(addr.clone(), app, jobs),
        )
        .await
        .expect("listener failure must return without an OS signal")
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("HTTP listener"), "{message}");
        assert!(message.contains(&addr), "{message}");
        // Both the admin-style path and collector maintenance path must release
        // their connections before returning, so closing the pool cannot hang.
        tokio::time::timeout(Duration::from_secs(5), pool.close()).await?;
    }
    Ok(())
}
