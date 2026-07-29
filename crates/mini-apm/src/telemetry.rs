use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize the global tracing subscriber, honoring `RUST_LOG` if set and
/// falling back to `default_filter` otherwise.
pub fn init_tracing(default_filter: &str) {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| default_filter.into()),
        )
        .init();
}
