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
mod sibling_adds;
pub(crate) mod snapshots;
mod transport_routes;
mod welcomes;

/// A database file that a test opens twice, so one connection can hold the
/// write lock while the store under test works on the other.
#[cfg(test)]
pub(crate) mod write_contention {
    use crate::{SqlCipherKey, SqliteAccountStorage, SqliteStorageOptions};
    use cgka_traits::storage::{StorageError, StorageProvider};
    use std::path::PathBuf;
    use std::thread::JoinHandle;
    use std::time::Duration;

    const KEY: &str = "write contention test key";

    /// How long the second connection keeps the write lock: longer than the
    /// 50 ms busy timeout the retry tests use, so their first attempt fails
    /// busy, and well inside their retry budget.
    const HOLD: Duration = Duration::from_millis(200);

    pub(crate) struct SharedDatabase {
        _dir: tempfile::TempDir,
        path: PathBuf,
        options: SqliteStorageOptions,
    }

    impl SharedDatabase {
        pub(crate) fn new(busy_timeout_ms: u64) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("contention.sqlite");
            Self {
                _dir: dir,
                path,
                options: SqliteStorageOptions {
                    busy_timeout_ms,
                    ..SqliteStorageOptions::default()
                },
            }
        }

        pub(crate) fn open(&self) -> SqliteAccountStorage {
            let key = SqlCipherKey::new(KEY).unwrap();
            SqliteAccountStorage::open_encrypted_with_options(
                &self.path,
                &key,
                self.options.clone(),
            )
            .unwrap()
        }

        /// Takes the write lock on a second connection with `BEGIN IMMEDIATE`,
        /// runs `uncommitted` inside that transaction and returns once the lock
        /// is held. The connection commits after [`HOLD`]; join the handle to
        /// wait for it.
        pub(crate) fn hold_write_lock(
            &self,
            uncommitted: impl FnOnce(&SqliteAccountStorage) + Send + 'static,
        ) -> JoinHandle<()> {
            let (path, options) = (self.path.clone(), self.options.clone());
            let (held_tx, held_rx) = std::sync::mpsc::channel();
            let handle = std::thread::spawn(move || {
                let key = SqlCipherKey::new(KEY).unwrap();
                let blocker =
                    SqliteAccountStorage::open_encrypted_with_options(&path, &key, options)
                        .unwrap();
                blocker
                    .with_transaction(|storage| {
                        uncommitted(storage);
                        held_tx.send(()).unwrap();
                        std::thread::sleep(HOLD);
                        Ok::<_, StorageError>(())
                    })
                    .unwrap();
            });
            held_rx
                .recv()
                .expect("the second connection takes the write lock");
            handle
        }
    }
}
