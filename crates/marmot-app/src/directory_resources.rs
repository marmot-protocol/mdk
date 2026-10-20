//! The directory's per-account cache lifecycle and account resolution.
//!
//! Opening, keying, evicting and closing the per-account directory caches stays
//! in `marmot-app`, beside its other per-account resources, when the directory
//! moves to its own crate (step 3 of
//! `docs/marmot-architecture/review/brief-directory.md`). So do the legacy
//! cache import, the future-dated cleanup, and the label-based wrappers that
//! resolve an account before calling the directory.

use std::fs;
use std::path::PathBuf;

use marmot_account::AccountSummary;

use crate::directory::DirectoryCache;
use crate::directory::records::public_directory_user_record;
use crate::{
    APP_CACHE_DB_FILE, AccountRelayListStatus, AppError,
    DIRECTORY_FUTURE_CREATED_AT_CLEANUP_MARKER, MarmotApp, SqlcipherDatabaseKind,
    remove_sqlite_file_set,
};

impl MarmotApp {
    pub fn warm_directory_storage(&self) -> Result<(), AppError> {
        let _span = tracing::debug_span!(
            target: "marmot_app::directory",
            "directory_storage_warm",
            method = "warm_directory_storage"
        )
        .entered();
        let _shared = self.shared_storage()?;
        let _caches = self.directory_caches()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn directory_cache_open_count_for_test(&self) -> usize {
        self.directory_cache_open_count
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn directory_handle_acquire_count_for_test(&self) -> usize {
        self.directory_handle_acquire_count
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn directory_cache_cached_for_test(&self, label: &str) -> bool {
        self.directory_caches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(label)
    }

    pub fn account_relay_list_status(
        &self,
        label: &str,
    ) -> Result<AccountRelayListStatus, AppError> {
        let account = self.account_home().account(label)?;
        self.account_relay_list_status_for_account_id(&account.account_id_hex)
    }

    pub(crate) fn directory_cache_path(&self, label: &str) -> PathBuf {
        self.account_dir(label).join(APP_CACHE_DB_FILE)
    }

    fn legacy_directory_cache_path(&self) -> PathBuf {
        self.root.join(APP_CACHE_DB_FILE)
    }

    pub(crate) fn directory_cache_for_account(
        &self,
        account: &AccountSummary,
    ) -> Result<DirectoryCache, AppError> {
        self.ensure_storage_open("directory cache")?;
        self.clean_future_dated_directory_caches_for_all_accounts_once()?;
        if let Some(cache) = self
            .directory_caches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&account.label)
            .cloned()
        {
            return Ok(cache);
        }
        let lifecycle = self.begin_storage_open("directory cache")?;
        let _span = tracing::debug_span!(
            target: "marmot_app::directory",
            "directory_cache_handle_open",
            method = "directory_cache_for_account"
        )
        .entered();
        let path = self.directory_cache_path(&account.label);
        let lock = crate::sqlcipher::database_open_lock(&path);
        let database = lock.lock();
        if let Some(cache) = self
            .directory_caches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&account.label)
            .cloned()
        {
            return Ok(cache);
        }
        let key = if account.local_signing {
            let keys = self.account_home().load_signing_keys(&account.label)?;
            self.sqlcipher_key_locked(
                &account.label,
                &keys,
                &database,
                SqlcipherDatabaseKind::DirectoryCache,
            )?
        } else {
            self.external_sqlcipher_key(
                &account.label,
                &account.account_id_hex,
                &database,
                SqlcipherDatabaseKind::DirectoryCache,
            )?
        };
        let cache = DirectoryCache::open(path, &key)?;
        #[cfg(test)]
        self.directory_cache_open_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // Registering under `lifecycle` is what keeps this cache reachable by
        // a later `close_storage`; see `MarmotApp::begin_storage_open`.
        self.root_closers.register(&lifecycle, cache.closer());
        let mut caches = self
            .directory_caches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(caches
            .entry(account.label.clone())
            .or_insert_with(|| cache.clone())
            .clone())
    }

    pub(crate) fn directory_caches(&self) -> Result<Vec<DirectoryCache>, AppError> {
        #[cfg(test)]
        self.directory_handle_acquire_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let accounts = self
            .account_home()
            .accounts()?
            .into_iter()
            .filter(|account| account.is_active_signing())
            .collect::<Vec<_>>();
        self.clean_future_dated_directory_caches_once(&accounts)?;

        let mut caches = Vec::with_capacity(accounts.len());
        for account in accounts {
            caches.push(self.directory_cache_for_account(&account)?);
        }

        self.migrate_legacy_directory_cache_once(&caches)?;
        Ok(caches)
    }

    pub(crate) fn migrate_legacy_directory_cache_once(
        &self,
        caches: &[DirectoryCache],
    ) -> Result<(), AppError> {
        let mut checked = self
            .legacy_directory_cache_checked
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *checked {
            return Ok(());
        }
        let legacy_path = self.legacy_directory_cache_path();
        let legacy_entries = DirectoryCache::open_legacy_plaintext(legacy_path.clone())?
            .map(|cache| cache.entries())
            .transpose()?;

        let Some(entries) = legacy_entries else {
            *checked = true;
            return Ok(());
        };

        let local_accounts = self.local_accounts_by_id()?;
        let entries = entries
            .into_iter()
            .map(|entry| Self::hydrate_directory_record(entry, &local_accounts))
            .collect::<Result<Vec<_>, _>>()?;
        let shared_storage = self.shared_storage()?;
        for entry in &entries {
            shared_storage.put_public_directory_user(&public_directory_user_record(entry)?)?;
            // Each row commits independently; a later import error must not hide this work.
            let _ = self
                .presentation_signals
                .profile_updates
                .send(entry.account_id_hex.clone());
            self.presentation_signals.wake();
        }
        for cache in caches {
            for entry in &entries {
                cache.put(entry)?;
            }
        }
        for entry in &entries {
            if shared_storage
                .public_directory_user(&entry.account_id_hex)?
                .is_none()
            {
                return Err(AppError::MissingDirectoryEntry(
                    entry.account_id_hex.clone(),
                ));
            }
            for cache in caches {
                if cache.entry(&entry.account_id_hex)?.is_none() {
                    return Err(AppError::MissingDirectoryEntry(
                        entry.account_id_hex.clone(),
                    ));
                }
            }
        }
        remove_sqlite_file_set(&legacy_path)?;
        *checked = true;
        Ok(())
    }

    fn clean_future_dated_directory_caches_once(
        &self,
        accounts: &[AccountSummary],
    ) -> Result<(), AppError> {
        let marker_path = self.root.join(DIRECTORY_FUTURE_CREATED_AT_CLEANUP_MARKER);
        if marker_path.exists() {
            return Ok(());
        }
        fs::create_dir_all(&self.root)?;
        remove_sqlite_file_set(&self.legacy_directory_cache_path())?;
        for account in accounts {
            remove_sqlite_file_set(&self.directory_cache_path(&account.label))?;
        }
        fs_private::write_private(&marker_path, b"done\n")?;
        Ok(())
    }

    fn clean_future_dated_directory_caches_for_all_accounts_once(&self) -> Result<(), AppError> {
        let accounts = self
            .account_home()
            .accounts()?
            .into_iter()
            .filter(|account| account.is_active_signing())
            .collect::<Vec<_>>();
        self.clean_future_dated_directory_caches_once(&accounts)
    }
}
