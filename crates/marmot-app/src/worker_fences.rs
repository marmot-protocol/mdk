//! Named account-worker fences for tests (mdk#3273).
//!
//! A read answered from the published read state answers on the caller's
//! task and waits for no worker unit, so it fences nothing. Tests that need
//! the worker to reach a point call one of these instead of picking a read
//! themselves. Each names its contract and picks, in this one place, a call
//! that still provides it; a change that moves that call to the read state or
//! retires startup's snapshot reads updates the helper here, and this
//! module's test fails until it does. No host surface signals the end of
//! startup, so the fences are calls the worker still queues.

use crate::{AppError, MarmotAppRuntime};

/// Wait until the account's worker has finished startup.
///
/// Every startup phase defers this read until startup ends: today the pending
/// Welcome deliveries.
pub async fn worker_startup_finished(
    runtime: &MarmotAppRuntime,
    account_ref: &str,
) -> Result<(), AppError> {
    runtime
        .pending_welcome_deliveries(account_ref)
        .await
        .map(drop)
}

/// While the worker's startup sync is held (by a test barrier or a blocked
/// dependency), wait until the worker has taken every command queued before
/// this call.
///
/// Startup sync answers this read from its snapshot, in the worker's FIFO
/// order, without waiting for startup to end: today an empty membership page.
/// Use it only while startup sync is held; it says nothing about later units.
pub async fn startup_sync_took_queued_commands(
    runtime: &MarmotAppRuntime,
    account_ref: &str,
) -> Result<(), AppError> {
    runtime
        .group_member_ids_page(account_ref, &[])
        .await
        .map(drop)
}

/// Send one command through the worker after startup and wait for its reply.
///
/// The worker has then taken every command queued before it, and it publishes
/// the read state before it replies. Not a startup fence by name: use
/// [`worker_startup_finished`] for that. Today the pending Welcome deliveries.
pub async fn worker_round_trip(
    runtime: &MarmotAppRuntime,
    account_ref: &str,
) -> Result<(), AppError> {
    runtime
        .pending_welcome_deliveries(account_ref)
        .await
        .map(drop)
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::Poll;
    use std::time::Duration;

    use cgka_traits::GroupId;

    use super::*;
    use crate::tests::ScriptedPushRelayClient;
    use crate::{AccountHome, MarmotApp};

    /// Poll once without cooperative budget yields, so a call that reaches
    /// the worker's queue enqueues its command on this poll.
    async fn still_waiting(
        fence: &mut Pin<Box<impl Future<Output = Result<(), AppError>>>>,
    ) -> bool {
        std::future::poll_fn(|cx| Poll::Ready(fence.as_mut().poll(cx).is_pending())).await
    }

    // One thread: nothing else runs between a fence's first poll and the
    // worker taking its command.
    #[tokio::test(flavor = "current_thread")]
    async fn each_fence_waits_for_what_it_names() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let runtime = MarmotAppRuntime::new(app);
        let startup = Arc::new(tokio::sync::Barrier::new(2));
        runtime
            .shared_services()
            .set_next_startup_sync_barrier(startup.clone());
        runtime.reconcile_accounts().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), startup.wait())
            .await
            .expect("the worker reaches startup sync");

        // Held startup sync answers invite acceptance busy at once: an earlier
        // command whose answer shows when the worker took it.
        let unknown = GroupId::new(vec![7; 16]);
        let mut busy = Box::pin(tokio::task::unconstrained(
            runtime.accept_group_invite("alice", &unknown),
        ));
        assert!(std::future::poll_fn(|cx| Poll::Ready(busy.as_mut().poll(cx).is_pending())).await);
        let mut finished = Box::pin(tokio::task::unconstrained(worker_startup_finished(
            &runtime, "alice",
        )));
        let mut round_trip = Box::pin(tokio::task::unconstrained(worker_round_trip(
            &runtime, "alice",
        )));
        assert!(still_waiting(&mut finished).await);
        assert!(still_waiting(&mut round_trip).await);
        // The worker has not run since these polls: an answer here would come
        // from the read state, not from startup sync behind those commands.
        let mut took = Box::pin(tokio::task::unconstrained(
            startup_sync_took_queued_commands(&runtime, "alice"),
        ));
        assert!(
            still_waiting(&mut took).await,
            "the queued-commands fence must go through the worker"
        );
        tokio::time::timeout(Duration::from_secs(5), took)
            .await
            .expect("held startup sync answers the queued-commands fence")
            .unwrap();
        // The worker took every earlier command before that answer: it
        // answered the acceptance and deferred the other two.
        assert!(matches!(
            std::future::poll_fn(|cx| Poll::Ready(busy.as_mut().poll(cx))).await,
            Poll::Ready(Err(AppError::AccountWorkerBusy))
        ));
        assert!(
            still_waiting(&mut finished).await,
            "the startup fence must wait for startup to end"
        );
        assert!(
            still_waiting(&mut round_trip).await,
            "the round trip must go through the worker, not the read state"
        );

        startup.wait().await;
        tokio::time::timeout(Duration::from_secs(10), finished)
            .await
            .expect("the startup fence answers once startup ends")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), round_trip)
            .await
            .expect("the round trip answers once startup ends")
            .unwrap();
        runtime.shutdown().await;
    }
}
