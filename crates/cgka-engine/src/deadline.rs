use std::{future::Future, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DeadlineElapsed;

#[cfg(any(target_arch = "wasm32", test))]
fn browser_timeout_milliseconds(duration: Duration) -> u32 {
    // Browser timers accept integer milliseconds. Round a fractional
    // millisecond up so conversion never expires a nonzero budget early, then
    // stay within the signed delay range used by browser timer implementations.
    let fractional_millisecond = !duration.subsec_nanos().is_multiple_of(1_000_000);
    duration
        .as_millis()
        .saturating_add(u128::from(fractional_millisecond))
        .min(i32::MAX as u128) as u32
}

#[cfg(any(target_arch = "wasm32", test))]
async fn browser_timeout_with_timer<F, T>(
    operation: F,
    timer: T,
) -> Result<F::Output, DeadlineElapsed>
where
    F: Future,
    T: Future<Output = ()>,
{
    use futures::{FutureExt, pin_mut, select_biased};

    let operation = operation.fuse();
    let timer = timer.fuse();
    pin_mut!(operation, timer);

    // Match Tokio's timeout contract: if both branches are ready on the same
    // poll, the operation completes instead of being reported as elapsed.
    select_biased! {
        output = operation => Ok(output),
        _ = timer => Err(DeadlineElapsed),
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn timeout<F>(duration: Duration, future: F) -> Result<F::Output, DeadlineElapsed>
where
    F: Future,
{
    tokio::time::timeout(duration, future)
        .await
        .map_err(|_| DeadlineElapsed)
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn timeout<F>(duration: Duration, future: F) -> Result<F::Output, DeadlineElapsed>
where
    F: Future,
{
    let milliseconds = browser_timeout_milliseconds(duration);
    let timer = gloo_timers::future::TimeoutFuture::new(milliseconds);
    browser_timeout_with_timer(future, timer).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn cancels_a_pending_future() {
        let result = timeout(Duration::from_millis(1), std::future::pending::<()>()).await;
        assert_eq!(result, Err(DeadlineElapsed));
    }

    #[tokio::test]
    async fn returns_a_ready_value() {
        assert_eq!(timeout(Duration::from_secs(1), async { 7 }).await, Ok(7));
    }

    #[tokio::test]
    async fn browser_selection_always_prefers_the_operation_when_both_are_ready() {
        for _ in 0..64 {
            assert_eq!(
                browser_timeout_with_timer(async { 7 }, std::future::ready(())).await,
                Ok(7)
            );
        }
    }

    #[tokio::test]
    async fn browser_selection_drops_the_pending_operation_when_the_timer_wins() {
        let operation_dropped = Arc::new(AtomicBool::new(false));
        let dropped = Arc::clone(&operation_dropped);
        let operation = async move {
            let _drop_flag = DropFlag(dropped);
            std::future::pending::<()>().await;
        };

        assert_eq!(
            browser_timeout_with_timer(operation, std::future::ready(())).await,
            Err(DeadlineElapsed)
        );
        assert!(
            operation_dropped.load(Ordering::SeqCst),
            "the losing operation must be cancelled before timeout returns"
        );
    }

    #[test]
    fn browser_timeout_zero_stays_zero() {
        assert_eq!(browser_timeout_milliseconds(Duration::ZERO), 0);
    }

    #[test]
    fn browser_timeout_nonzero_submillisecond_rounds_up() {
        assert_eq!(browser_timeout_milliseconds(Duration::from_nanos(1)), 1);
    }

    #[test]
    fn browser_timeout_exact_millisecond_stays_exact() {
        assert_eq!(browser_timeout_milliseconds(Duration::from_millis(1)), 1);
    }

    #[test]
    fn browser_timeout_fractional_millisecond_rounds_up() {
        assert_eq!(
            browser_timeout_milliseconds(Duration::from_millis(1) + Duration::from_nanos(1)),
            2
        );
    }

    #[test]
    fn browser_timeout_milliseconds_caps_at_signed_timer_maximum() {
        let maximum = Duration::from_millis(i32::MAX as u64);
        let first_out_of_range = maximum + Duration::from_millis(1);
        assert_eq!(browser_timeout_milliseconds(maximum), i32::MAX as u32);
        assert_eq!(
            browser_timeout_milliseconds(first_out_of_range),
            i32::MAX as u32
        );
    }
}
