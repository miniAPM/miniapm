use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt, util::SubscriberInitExt};

use crate::self_monitor::CaptureLayer;

/// Initialize the global tracing subscriber, honoring `RUST_LOG` if set and
/// falling back to `default_filter` otherwise. Logged errors and queries also
/// go to the `self` project once a self monitor is installed.
pub fn init_tracing(default_filter: &str) {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| default_filter.into());
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(env_filter))
        .with(CaptureLayer::global().with_filter(CaptureLayer::filter()))
        .init();
}
