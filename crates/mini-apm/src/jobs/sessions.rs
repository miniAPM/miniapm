//! Retry only the atomic, idempotent session deletion, inside the existing job lock.

use chrono_machines::{AsyncRetryable, ExponentialBackoff, RetryError, RetryOutcome};
use std::future::Future;
use std::time::Duration;

use crate::{DbPool, models, time::Stamp};

const ATTEMPTS: u8 = 3;
const BASE_DELAY_MS: u64 = 100;

pub(super) async fn cleanup(pool: &DbPool) -> anyhow::Result<()> {
    let outcome = delete_with_retry(pool, Stamp::now(), |ms| {
        tokio::time::sleep(Duration::from_millis(ms))
    })
    .await?;
    if *outcome.value() > 0 {
        tracing::info!(
            count = outcome.value(),
            attempts = outcome.attempts(),
            "Cleaned up expired sessions"
        );
    }
    Ok(())
}

async fn delete_with_retry<S, Fut>(
    pool: &DbPool,
    cutoff: Stamp,
    sleeper: S,
) -> Result<RetryOutcome<u64>, RetryError<sqlx::Error>>
where
    S: Fn(u64) -> Fut + Send + Sync,
    Fut: Future<Output = ()> + Send,
{
    (|| models::user::delete_expired_sessions_before(pool, cutoff))
        .retry_async(
            ExponentialBackoff::new()
                .max_attempts(ATTEMPTS)
                .base_delay_ms(BASE_DELAY_MS)
                .max_delay_ms(1_000)
                .jitter_factor(1.0),
        )
        .when(retryable)
        .notify(|context| {
            if let Some(delay_ms) = context.next_delay_ms {
                tracing::warn!(
                    attempt = context.attempt,
                    delay_ms,
                    "Transient session cleanup failure; retrying"
                );
            }
        })
        .call_async(sleeper)
        .await
}

fn retryable(error: &sqlx::Error) -> bool {
    let sqlx::Error::Database(error) = error else {
        // In particular, never replay ambiguous I/O failures or query cancellations.
        return false;
    };
    error.code().is_some_and(|code| retryable_code(&code))
}

#[cfg(feature = "postgres")]
fn retryable_code(code: &str) -> bool {
    // PostgreSQL has rejected/rolled back this autocommit statement.
    matches!(code, "40001" | "40P01" | "55P03")
}

#[cfg(feature = "sqlite")]
fn retryable_code(code: &str) -> bool {
    // SQLITE_BUSY and its extended variants; not SQLITE_LOCKED or constraints.
    code.parse::<u32>().is_ok_and(|code| code & 0xff == 5)
}

#[cfg(test)]
mod tests;
