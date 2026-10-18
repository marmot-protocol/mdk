//! The Tokio runtime MarmotKit runs MDK on.
//!
//! UniFFI hosts poll exported futures from their own threads (Swift's
//! cooperative pool, a Kotlin dispatcher, sometimes the main thread), with no
//! Tokio runtime entered. UniFFI's `async_runtime = "tokio"` support handles
//! that by entering `async_compat`'s fallback: one current-thread runtime on a
//! single `async-compat/tokio-1` thread. Every task `marmot-app` spawns then
//! shares that thread: account workers, the relay plane, subscription
//! forwarders and timers.
//!
//! Instead, exports annotated with `#[marmot_uniffi_macros::on_tokio_runtime]`
//! spawn their bodies with [`spawn_export`], and the constructors enter
//! [`handle`] so construction-time spawns land on the same runtime.
//! Subscription receives marked `#[marmot_uniffi_macros::receive]` stay on the
//! caller's thread through [`poll_on_caller`], so a cancelled wait never
//! consumes an update, and terminal shutdown marked
//! `#[marmot_uniffi_macros::survives_cancellation]` uses
//! [`spawn_detached_export`] so a cancelled call cannot stop it. When the
//! caller is already inside a runtime (the `marmot-c` client runtime, Rust
//! tests), that runtime is used; otherwise MarmotKit's own multi-thread runtime
//! is. If that runtime cannot be built, construction fails with
//! [`MarmotKitError::Runtime`]; nothing falls back to another executor. Each
//! account worker still processes its own commands in order; the
//! extra threads let independent workers, the relay plane and host reads run
//! at the same time.

use std::future::Future;
use std::sync::{Mutex, OnceLock, PoisonError};

use tokio::runtime::{Handle, Runtime};
use tokio::task::{JoinError, JoinHandle};

use crate::MarmotKitError;

/// Name of MarmotKit's runtime threads, visible in crash reports and
/// profilers. Short enough for Linux's 15-byte thread names.
pub(crate) const THREAD_NAME: &str = "marmotkit-rt";

/// Worker threads for MarmotKit's runtime: half the CPUs, between 2 and 4.
///
/// Phones have 6–8 cores split into performance and efficiency clusters, and
/// the host's UI thread must keep one to itself. Two workers already let a
/// slow account worker or relay burst run beside a host read; more than four
/// adds contention with the host without shortening any single account's
/// queue, which stays serial. Blocking work (`spawn_blocking`) uses Tokio's
/// separate on-demand blocking pool and does not count against this.
pub(crate) fn worker_threads() -> usize {
    let cpus = std::thread::available_parallelism().map_or(2, |cpus| cpus.get());
    (cpus / 2).clamp(2, 4)
}

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static BUILDING: Mutex<()> = Mutex::new(());

/// MarmotKit's own runtime, built on first use. A failed build is reported,
/// not cached, so a later constructor tries again.
fn owned_runtime() -> Result<&'static Runtime, MarmotKitError> {
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }
    let _building = BUILDING.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads())
        .thread_name(THREAD_NAME)
        .enable_all()
        .build()
        .map_err(|error| MarmotKitError::Runtime {
            details: format!("cannot start the MarmotKit Tokio runtime: {error}"),
        })?;
    Ok(RUNTIME.get_or_init(|| runtime))
}

/// The runtime MarmotKit work runs on: the caller's runtime when one is
/// entered, otherwise MarmotKit's process-wide multi-thread runtime. Fails
/// only when there is no caller runtime and MarmotKit's cannot be built; there
/// is no fallback to another executor.
pub(crate) fn handle() -> Result<Handle, MarmotKitError> {
    match Handle::try_current() {
        Ok(handle) => Ok(handle),
        Err(_) => owned_runtime().map(|runtime| runtime.handle().clone()),
    }
}

/// Run an export's body as a task on [`handle`] and wait for it.
///
/// Dropping the returned future aborts the task, so a host that cancels its
/// call (a Kotlin coroutine) still cancels the work, as when the body ran
/// inside the host's poll. A panic in the body resumes here, where UniFFI
/// reports it to the host as before.
pub(crate) async fn spawn_export<F>(future: F) -> F::Output
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let mut task = AbortOnDrop(spawn(future));
    join(&mut task.0).await
}

/// Like [`spawn_export`], but dropping the returned future leaves the task
/// running. The task exists once the host first polls the call, so work that
/// must outlive cancellation starts even if the host gives up before a runtime
/// worker reaches it.
pub(crate) async fn spawn_detached_export<F>(future: F) -> F::Output
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    join(spawn(future)).await
}

/// Poll `future` on the caller's thread with [`handle`] entered, so anything
/// it spawns or times runs on MarmotKit's runtime.
///
/// A subscription receive must not advance between host polls: a spawned
/// receive could consume an update that the host, having cancelled, never
/// collects.
pub(crate) fn poll_on_caller<F: Future>(future: F) -> impl Future<Output = F::Output> {
    let runtime = expect_handle();
    let mut future = Box::pin(future);
    std::future::poll_fn(move |cx| {
        let _entered = runtime.enter();
        future.as_mut().poll(cx)
    })
}

fn spawn<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    expect_handle().spawn(future)
}

/// Exports are methods on objects a constructor made, and construction fails
/// unless [`handle`] succeeds, so this cannot fail in practice.
fn expect_handle() -> Handle {
    handle().unwrap_or_else(|error| panic!("{error}"))
}

async fn join<T>(task: impl Future<Output = Result<T, JoinError>>) -> T {
    match task.await {
        Ok(output) => output,
        Err(error) => match error.try_into_panic() {
            Ok(panic) => std::panic::resume_unwind(panic),
            Err(error) => panic!("MarmotKit export task stopped: {error}"),
        },
    }
}

struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::*;

    #[test]
    fn worker_threads_stay_small() {
        let workers = worker_threads();
        assert!((2..=4).contains(&workers), "{workers} workers");
    }

    #[test]
    fn exports_without_a_caller_runtime_run_on_marmotkit_threads() {
        let thread = futures::executor::block_on(spawn_export(async {
            std::thread::current().name().map(str::to_owned)
        }));
        assert_eq!(thread.as_deref(), Some(THREAD_NAME));
    }

    #[tokio::test]
    async fn exports_inside_a_caller_runtime_stay_on_it() {
        let caller = tokio::runtime::Handle::current().id();
        let runtime = spawn_export(async { tokio::runtime::Handle::current().id() }).await;
        assert_eq!(runtime, caller);
    }

    #[test]
    fn dropping_an_export_future_aborts_its_task() {
        struct SetOnDrop(Arc<AtomicBool>);
        impl Drop for SetOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let guard = SetOnDrop(dropped.clone());
        let mut export = Box::pin(spawn_export(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        }));
        let waker = futures::task::noop_waker();
        assert!(
            export
                .as_mut()
                .poll(&mut std::task::Context::from_waker(&waker))
                .is_pending()
        );
        drop(export);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !dropped.load(Ordering::SeqCst) {
            assert!(std::time::Instant::now() < deadline, "task was not aborted");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_dropped_receive_leaves_its_item_queued() {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        {
            let mut call = Box::pin(poll_on_caller(receiver.recv()));
            let waker = futures::task::noop_waker();
            assert!(
                call.as_mut()
                    .poll(&mut std::task::Context::from_waker(&waker))
                    .is_pending()
            );
            sender.send(1).unwrap();
            // Nothing polls the receive between host polls, so the item stays
            // queued when the host drops the call.
            std::thread::sleep(Duration::from_millis(20));
        }
        let next = futures::executor::block_on(poll_on_caller(receiver.recv()));
        assert_eq!(next, Some(1));
    }

    #[tokio::test]
    async fn a_detached_export_runs_after_its_call_is_dropped() {
        let (done, finished) = tokio::sync::oneshot::channel();
        let mut call = Box::pin(spawn_detached_export(async move {
            let _ = done.send(());
        }));
        // On this current-thread runtime the task cannot start before the drop.
        assert!(futures::poll!(&mut call).is_pending());
        drop(call);
        tokio::time::timeout(Duration::from_secs(5), finished)
            .await
            .expect("the dropped call's task still runs")
            .unwrap();
    }

    #[test]
    fn export_panics_reach_the_caller() {
        let result = std::panic::catch_unwind(|| {
            futures::executor::block_on(spawn_export(async { panic!("export body panicked") }))
        });
        let payload = result.expect_err("panic propagates");
        assert_eq!(
            payload.downcast_ref::<&str>().copied(),
            Some("export body panicked")
        );
    }

    /// A spawned receive could consume an update its cancelled caller never
    /// collects, and a spawned export could drop a lease its cancelled caller
    /// never learns of, so both stay on the caller's thread.
    #[test]
    fn subscription_receives_poll_on_the_caller() {
        fn visit(dir: &Path, unmarked: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    visit(&path, unmarked);
                    continue;
                }
                if path.extension().is_none_or(|ext| ext != "rs") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).unwrap();
                let lines: Vec<&str> = source.lines().collect();
                for (index, line) in lines.iter().enumerate() {
                    let line = line.trim();
                    // Subscription receives, and exports whose result owns
                    // something the host must release (a handoff lease).
                    let receive = line.starts_with("pub async fn next(")
                        || line.starts_with("pub async fn next_update(")
                        || line.starts_with("pub async fn open_attachment_handoff(");
                    if receive
                        && (index == 0
                            || lines[index - 1].trim() != "#[marmot_uniffi_macros::receive]")
                    {
                        unmarked.push(format!("{}:{}", path.display(), index + 1));
                    }
                }
            }
        }

        let mut unmarked = Vec::new();
        visit(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut unmarked,
        );
        assert!(
            unmarked.is_empty(),
            "receives and lease-returning exports without #[receive]: {unmarked:#?}"
        );
    }

    /// Async exports must go through `on_tokio_runtime`; `async_runtime =
    /// "tokio"` would bring back `async_compat`'s single fallback thread.
    #[test]
    fn every_async_export_block_runs_on_the_tokio_runtime() {
        fn visit(dir: &Path, missing: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    visit(&path, missing);
                    continue;
                }
                if path.extension().is_none_or(|ext| ext != "rs") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).unwrap();
                let lines: Vec<&str> = source.lines().collect();
                for (index, line) in lines.iter().enumerate() {
                    let line = line.trim();
                    if line.starts_with("#[uniffi::export(async_runtime") {
                        missing.push(format!("{}:{}: async_runtime", path.display(), index + 1));
                    }
                    if !line.starts_with("#[uniffi::export") || line.contains("with_foreign") {
                        continue;
                    }
                    let annotated = index > 0
                        && lines[index - 1].trim() == "#[marmot_uniffi_macros::on_tokio_runtime]";
                    let block_end = lines[index..]
                        .iter()
                        .position(|line| *line == "}")
                        .map_or(lines.len(), |end| index + end);
                    let has_async = lines[index..block_end]
                        .iter()
                        .any(|line| line.trim_start().starts_with("pub async fn "));
                    if has_async && !annotated {
                        missing.push(format!("{}:{}", path.display(), index + 1));
                    }
                }
            }
        }

        let mut missing = Vec::new();
        visit(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut missing,
        );
        assert!(
            missing.is_empty(),
            "async exports outside on_tokio_runtime: {missing:#?}"
        );
    }
}
