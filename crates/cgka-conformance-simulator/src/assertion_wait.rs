//! Real app assertion rounds have a stable wall-clock allowance, independent
//! of participant catch-up parallelism. Engine rounds remain deterministic.
use std::future::Future;
use std::time::Duration;
use tokio::time::Instant;

const APP_ASSERTION_ROUND: Duration = Duration::from_secs(1);

pub(crate) struct AssertionWait {
    started: Instant,
    timeout: Option<Duration>,
}

impl AssertionWait {
    pub(crate) fn new(max_iterations: usize, wall_clock: bool) -> Self {
        Self {
            started: Instant::now(),
            timeout: wall_clock.then(|| {
                // Include one round for the initial sample, so the last
                // allowed tick can still be observed before the deadline.
                APP_ASSERTION_ROUND.saturating_mul(
                    u32::try_from(max_iterations)
                        .unwrap_or(u32::MAX)
                        .saturating_add(1),
                )
            }),
        }
    }

    pub(crate) fn expired(&self) -> bool {
        self.timeout
            .is_some_and(|timeout| self.started.elapsed() >= timeout)
    }

    pub(crate) fn timeout_ms(&self) -> Option<u64> {
        self.timeout.map(|timeout| timeout.as_millis() as u64)
    }

    pub(crate) fn elapsed_ms(&self) -> Option<u64> {
        self.timeout
            .map(|_| self.started.elapsed().as_millis() as u64)
    }

    /// Bound a remote operation by the remaining assertion allowance.
    pub(crate) async fn run<T, E>(
        &self,
        operation: impl Future<Output = Result<T, E>>,
    ) -> Result<Option<T>, E> {
        let Some(timeout) = self.timeout else {
            return operation.await.map(Some);
        };
        let remaining = timeout.saturating_sub(self.started.elapsed());
        if remaining.is_zero() {
            return Ok(None);
        }
        match tokio::time::timeout(remaining, operation).await {
            Ok(result) => result.map(Some),
            Err(_) => Ok(None),
        }
    }

    /// Finish a catch-up round before sampling again. Fast rounds are paced;
    /// slow or stalled rounds cannot extend the assertion's total allowance.
    /// Only the coordinator wait is cancelled; no participant state is reset.
    pub(crate) async fn tick<E>(
        &self,
        tick: impl Future<Output = Result<(), E>>,
    ) -> Result<bool, E> {
        if self.timeout.is_none() {
            return tick.await.map(|()| true);
        }
        let next_sample = Instant::now() + APP_ASSERTION_ROUND;
        self.run(async {
            tick.await?;
            tokio::time::sleep_until(next_sample).await;
            Ok(())
        })
        .await
        .map(|result| result.is_some() && !self.expired())
    }
}
