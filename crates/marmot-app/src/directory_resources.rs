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

use cgka_traits::TransportEndpoint;
use storage_sqlite::SqliteSharedStorage;

use crate::{
    APP_CACHE_DB_FILE, AccountRelayListStatus, AppError,
    DIRECTORY_FUTURE_CREATED_AT_CLEANUP_MARKER, MarmotApp, SqlcipherDatabaseKind,
    remove_sqlite_file_set,
};
use crate::{ProductFamily, ProductObservation, ProductUnit};
use nostr_directory::error::DirectoryError;
use nostr_directory::hydrate_directory_record;
use nostr_directory::public_directory_user_record;
use nostr_directory::{
    Directory, DirectoryAccount, DirectoryCache, DirectoryConfig, DirectoryObservation,
    DirectoryObserver, DirectoryResources, ObservedFamily, ObservedUnit,
};

/// The directory service over this app's resources.
impl MarmotApp {
    /// The user directory: lookups, refreshes, search and KeyPackage
    /// resolution over other people's public Nostr data. Its methods return
    /// [`DirectoryError`], which converts into [`AppError`] with the same
    /// variant, message and `privacy_safe_kind`.
    ///
    /// Builds the service on each call. What the directory keeps between
    /// calls lives in `directory_state` and is shared into every service, so
    /// nothing it needs later is owned by the value returned here.
    pub fn directory(&self) -> Directory<MarmotApp> {
        Directory::new(
            self.clone(),
            self.directory_config(),
            self.relay_plane.clone(),
            self.directory_state.clone(),
        )
    }

    /// Read from the app's configuration on each call, so a test that edits
    /// `config` after construction sees its change.
    fn directory_config(&self) -> DirectoryConfig {
        DirectoryConfig {
            directory_relays: self
                .config
                .directory_relay_urls
                .iter()
                .cloned()
                .map(TransportEndpoint)
                .collect(),
            default_relays: self.relay_endpoints(),
            max_future_skew: self.config.directory_max_future_skew,
            key_package_client_preference: self.deployment().key_package_client_preference.clone(),
            open_ranking: self.deployment().open_ranking.clone(),
            fallback_seeds: self.config.directory_search_fallback_seeds.clone(),
            http_builder: crate::network_proxy::http_builder,
            #[cfg(test)]
            test_clock: self.directory_test_clock.clone(),
            #[cfg(not(test))]
            test_clock: None,
        }
    }
}

/// The directory's handles come from the lifecycle below, so it never opens,
/// keys or evicts a cache itself.
impl DirectoryResources for MarmotApp {
    fn local_accounts(&self) -> Result<Vec<DirectoryAccount>, DirectoryError> {
        Ok(self
            .account_home()
            .accounts()
            .map_err(AppError::from)?
            .iter()
            .map(directory_account)
            .collect())
    }

    fn account_id_for_label(&self, label: &str) -> Result<String, DirectoryError> {
        Ok(self
            .account_home()
            .account(label)
            .map_err(AppError::from)?
            .account_id_hex)
    }

    fn current_caches(&self) -> Result<Vec<DirectoryCache>, DirectoryError> {
        Ok(self.directory_caches()?)
    }

    fn cache_for_account(
        &self,
        account: &DirectoryAccount,
    ) -> Result<DirectoryCache, DirectoryError> {
        Ok(self.open_directory_cache(
            &account.label,
            &account.account_id_hex,
            account.local_signing,
        )?)
    }

    fn shared_storage(&self) -> Result<SqliteSharedStorage, DirectoryError> {
        Ok(MarmotApp::shared_storage(self)?)
    }

    fn directory_entry_changed(&self, account_id_hex: &str) {
        let _ = self
            .presentation_signals
            .profile_updates
            .send(account_id_hex.to_owned());
        self.presentation_signals.wake();
    }
}

/// Directory analytics go to the app's usage-diagnostics collector, under the
/// families and units they always used.
impl DirectoryObserver for MarmotApp {
    type Observation = ProductObservation;

    fn begin(
        &self,
        family: ObservedFamily,
        operation: &'static str,
        unit: ObservedUnit,
    ) -> Option<ProductObservation> {
        self.product_analytics
            .begin(product_family(family), operation, product_unit(unit))
    }
}

impl DirectoryObservation for ProductObservation {
    fn counts_only(self) -> Self {
        ProductObservation::counts_only(self)
    }

    fn count(&self, outcome: &str, unit: ObservedUnit, count: u64) {
        ProductObservation::count(self, outcome, product_unit(unit), count);
    }

    fn directory_sample(&self, outcome: &str, source: &str, count: u64) {
        ProductObservation::directory_sample(self, outcome, source, count);
    }

    fn finish(self, outcome: &str) {
        ProductObservation::finish(self, outcome);
    }

    fn discard(self) {
        ProductObservation::discard(self);
    }
}

fn product_family(family: ObservedFamily) -> ProductFamily {
    match family {
        ObservedFamily::Directory => ProductFamily::Directory,
        ObservedFamily::KeyPackage => ProductFamily::KeyPackage,
    }
}

fn product_unit(unit: ObservedUnit) -> ProductUnit {
    match unit {
        ObservedUnit::Action => ProductUnit::Action,
        ObservedUnit::Attempt => ProductUnit::Attempt,
    }
}

/// The directory's view of a local account.
pub(crate) fn directory_account(account: &AccountSummary) -> DirectoryAccount {
    DirectoryAccount {
        account_id_hex: account.account_id_hex.clone(),
        label: account.label.clone(),
        local_signing: account.local_signing,
        active_signing: account.is_active_signing(),
    }
}

impl MarmotApp {
    pub fn warm_directory_storage(&self) -> Result<(), AppError> {
        let _span = tracing::debug_span!(
            target: "marmot_app::directory_resources",
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
        self.directory()
            .account_relay_list_status_for_account_id(&account.account_id_hex)
            .map_err(AppError::from)
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
        self.open_directory_cache(
            &account.label,
            &account.account_id_hex,
            account.local_signing,
        )
    }

    /// The account's cache, from the handle map or opened under the storage
    /// gate.
    fn open_directory_cache(
        &self,
        label: &str,
        account_id_hex: &str,
        local_signing: bool,
    ) -> Result<DirectoryCache, AppError> {
        self.ensure_storage_open("directory cache")?;
        self.clean_future_dated_directory_caches_for_all_accounts_once()?;
        if let Some(cache) = self
            .directory_caches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(label)
            .cloned()
        {
            return Ok(cache);
        }
        let lifecycle = self.begin_storage_open("directory cache")?;
        let _span = tracing::debug_span!(
            target: "marmot_app::directory_resources",
            "directory_cache_handle_open",
            method = "directory_cache_for_account"
        )
        .entered();
        let path = self.directory_cache_path(label);
        let lock = crate::sqlcipher::database_open_lock(&path);
        let database = lock.lock();
        if let Some(cache) = self
            .directory_caches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(label)
            .cloned()
        {
            return Ok(cache);
        }
        let key = if local_signing {
            let keys = self.account_home().load_signing_keys(label)?;
            self.sqlcipher_key_locked(
                label,
                &keys,
                &database,
                SqlcipherDatabaseKind::DirectoryCache,
            )?
        } else {
            self.external_sqlcipher_key(
                label,
                account_id_hex,
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
            .entry(label.to_owned())
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

        let local_accounts = self.directory().local_accounts_by_id()?;
        let entries = entries
            .into_iter()
            .map(|entry| hydrate_directory_record(entry, &local_accounts))
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

#[cfg(all(test, feature = "product-analytics-export"))]
mod observer_tests {
    use super::*;

    fn summaries(app: &MarmotApp, event: &str, operation: &str) -> Vec<serde_json::Value> {
        app.product_analytics
            .test_payloads()
            .into_iter()
            .filter(|payload| {
                payload["eventName"] == event && payload["props"]["operation"] == operation
            })
            .map(|payload| payload["props"].clone())
            .collect()
    }

    /// Directory analytics reach the collector under the families,
    /// operations and units they used before the observer, and keep the
    /// collector's rule that an unfinished observation records a cancellation
    /// unless it is counts-only.
    #[test]
    fn directory_observations_keep_their_events_and_drop_rule() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = MarmotApp::with_relays(dir.path(), vec![]);
        app.product_analytics = crate::product_analytics::test_product_collector();
        app.set_usage_diagnostics_consent(true).unwrap();

        let counts = DirectoryObserver::begin(
            &app,
            ObservedFamily::Directory,
            "key_package",
            ObservedUnit::Attempt,
        )
        .map(DirectoryObservation::counts_only)
        .unwrap();
        DirectoryObservation::count(&counts, "success", ObservedUnit::Attempt, 2);
        DirectoryObservation::directory_sample(&counts, "success", "cache", 3);
        drop(counts);
        DirectoryObservation::finish(
            DirectoryObserver::begin(
                &app,
                ObservedFamily::KeyPackage,
                "lookup",
                ObservedUnit::Action,
            )
            .unwrap(),
            "usable",
        );
        DirectoryObservation::discard(
            DirectoryObserver::begin(
                &app,
                ObservedFamily::KeyPackage,
                "lookup",
                ObservedUnit::Attempt,
            )
            .unwrap(),
        );
        drop(
            DirectoryObserver::begin(
                &app,
                ObservedFamily::Directory,
                "relay_list",
                ObservedUnit::Attempt,
            )
            .unwrap(),
        );

        let key_package = summaries(&app, "mdk_directory_summary", "key_package");
        assert!(
            key_package
                .iter()
                .all(|props| props["outcome"] != "cancelled"),
            "a counts-only observation records no cancellation: {key_package:?}"
        );
        assert!(key_package.iter().any(|props| {
            props["outcome"] == "success" && props["unit"] == "attempt" && props["source"].is_null()
        }));
        assert!(key_package.iter().any(|props| props["source"] == "cache"));

        let lookups = summaries(&app, "mdk_key_package_summary", "lookup");
        assert_eq!(lookups.len(), 1, "a discarded observation records nothing");
        assert_eq!(lookups[0]["outcome"], "usable");
        assert_eq!(lookups[0]["unit"], "action");

        let relay_lists = summaries(&app, "mdk_directory_summary", "relay_list");
        assert!(
            relay_lists
                .iter()
                .any(|props| props["outcome"] == "cancelled"),
            "an unfinished observation still records a cancellation: {relay_lists:?}"
        );
    }
}
