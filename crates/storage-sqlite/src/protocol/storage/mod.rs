mod account_device_history_key;
mod account_device_signer;
mod announced_key_packages;
mod capabilities;
mod convergence_passes;
mod convergence_policy;
mod deferred_peel_generations;
mod device_group_welcome;
/// `pub(crate)` because the chat-list projection reads the durable disband gate
/// at read time instead of denormalizing it into `chat_list_rows`.
pub(crate) mod disband_requests;
pub(crate) mod groups;
/// `pub(crate)` because the chat-list projection reads durable leave requests at
/// read time instead of denormalizing them into `chat_list_rows`.
pub(crate) mod leave_requests;
mod maintenance;
mod member_validation_cache;
pub(crate) mod messages;
mod outbound;
mod private_key_packages;
mod roster_tag_keys;
mod sibling_adds;
pub(crate) mod snapshots;
mod transport_routes;
mod welcomes;

/// A database file that a test opens twice, so one connection can hold the
/// write lock while the store under test works on the other.
///
/// The holder commits only once the store under test has contended for the
/// lock, as reported by a busy handler on that store, so no sleep decides
/// whether a test passes: under load the holder just waits longer.
#[cfg(test)]
pub(crate) mod write_contention {
    use crate::{SqlCipherKey, SqliteAccountStorage, SqliteStorageOptions};
    use cgka_traits::storage::{StorageError, StorageProvider};
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::{self, RecvTimeoutError, Sender};
    use std::thread::JoinHandle;
    use std::time::Duration;

    const KEY: &str = "write contention test key";

    /// Busy-handler calls, each after a 1 ms sleep, before the first attempt
    /// under [`Release::AfterAFailedAttempt`] gives up with `SQLITE_BUSY`.
    const FIRST_ATTEMPT_CALLS: i32 = 50;

    /// Bounds every other wait, so a broken test fails instead of hanging.
    const WAIT_CALLS: i32 = 30_000;
    const WAIT_BOUND: Duration = Duration::from_secs(30);

    /// When the holder of the write lock commits.
    #[derive(Clone, Copy)]
    pub(crate) enum Release {
        /// Once the store under test waits for the lock.
        WhenTheStoreWaits,
        /// Once the store's first attempt has failed with `SQLITE_BUSY`, so
        /// its operation can succeed only by retrying.
        AfterAFailedAttempt,
    }

    struct Awaited {
        release: Release,
        observed: Sender<()>,
    }

    thread_local! {
        /// The hold that the store under test, called from this thread, is
        /// expected to contend with.
        static AWAITED: RefCell<Option<Awaited>> = const { RefCell::new(None) };
    }

    /// Busy handler of a store under test. SQLite runs it on the thread making
    /// the store call, which is the thread that took the hold.
    fn on_busy(calls: i32) -> bool {
        std::thread::sleep(Duration::from_millis(1));
        AWAITED.with_borrow_mut(|awaited| match awaited.as_ref().map(|a| a.release) {
            Some(Release::AfterAFailedAttempt) if calls < FIRST_ATTEMPT_CALLS => true,
            Some(release) => {
                if let Some(awaited) = awaited.take() {
                    let _ = awaited.observed.send(());
                }
                matches!(release, Release::WhenTheStoreWaits)
            }
            None => calls < WAIT_CALLS,
        })
    }

    pub(crate) struct SharedDatabase {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl SharedDatabase {
        pub(crate) fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("contention.sqlite");
            Self { _dir: dir, path }
        }

        /// Opens a store under test; its busy waits report contention.
        pub(crate) fn open(&self) -> SqliteAccountStorage {
            let store = open(&self.path);
            store.lock().unwrap().busy_handler(Some(on_busy)).unwrap();
            store
        }

        /// Takes the write lock on another connection with `BEGIN IMMEDIATE`
        /// and runs `uncommitted` inside that transaction. The holder commits
        /// when the store under test, called from this thread, contends as
        /// `release` says; [`HeldWriteLock::join`] asserts that it did.
        pub(crate) fn hold_write_lock(
            &self,
            release: Release,
            uncommitted: impl FnOnce(&SqliteAccountStorage) + Send + 'static,
        ) -> HeldWriteLock {
            let (observed, contended) = mpsc::channel();
            AWAITED.set(Some(Awaited { release, observed }));
            let path = self.path.clone();
            let (held_tx, held_rx) = mpsc::channel();
            let handle = std::thread::spawn(move || {
                open(&path)
                    .with_transaction(|storage| {
                        uncommitted(storage);
                        held_tx.send(()).unwrap();
                        match contended.recv_timeout(WAIT_BOUND) {
                            // Disconnected: the test joined without contending.
                            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                                Ok::<_, StorageError>(())
                            }
                            Err(RecvTimeoutError::Timeout) => {
                                panic!("the store under test never contended for the write lock")
                            }
                        }
                    })
                    .unwrap();
            });
            held_rx
                .recv()
                .expect("the second connection takes the write lock");
            HeldWriteLock { handle }
        }
    }

    fn open(path: &Path) -> SqliteAccountStorage {
        let key = SqlCipherKey::new(KEY).unwrap();
        SqliteAccountStorage::open_encrypted_with_options(
            path,
            &key,
            SqliteStorageOptions::default(),
        )
        .unwrap()
    }

    pub(crate) struct HeldWriteLock {
        handle: JoinHandle<()>,
    }

    impl HeldWriteLock {
        /// Waits for the holder to commit and asserts that the store under
        /// test contended for the lock first. Call it from the thread that
        /// took the hold.
        pub(crate) fn join(self) {
            // Dropping an unobserved expectation releases a holder still waiting.
            let unobserved = AWAITED.take().is_some();
            self.handle
                .join()
                .expect("the holder of the write lock failed");
            assert!(
                !unobserved,
                "the store under test never contended for the write lock"
            );
        }
    }
}
