use super::*;
use crate::public_event_preview::{PublicEventCache, RefreshAdmission};
use crate::{
    PublicEventCacheKey, PublicEventCacheRead, PublicEventCacheResult, PublicEventReference,
};

/// Upper bound for a coalesced caller waiting on another refresh of the same key.
const COALESCED_REFRESH_WAIT: Duration = Duration::from_secs(12);

impl MarmotAppRuntime {
    /// Synchronous, network-free cached reads for first-frame host state.
    ///
    /// Returns exactly one result per input, duplicates included, in input
    /// order. The whole request (at most 16 references) is validated before
    /// storage is touched; invalid input is an error. If account lifecycle work
    /// currently owns the account transaction, every row is `Busy` (retryable)
    /// rather than waiting or reporting `Missing`. Never sleeps, blocks on an
    /// async lock, or enters the async runtime.
    pub fn cached_public_event_previews(
        &self,
        account_ref: &str,
        references: &[String],
    ) -> Result<Vec<PublicEventCacheRead>, AppError> {
        let references = PublicEventReference::parse_batch(references)?;
        let Ok(account_transaction) = self.accounts.worker_transactions.clone().try_lock_owned()
        else {
            return references
                .iter()
                .map(|reference| {
                    Ok(PublicEventCacheRead {
                        key: reference.cache_key()?,
                        result: PublicEventCacheResult::Busy,
                    })
                })
                .collect();
        };
        self.accounts.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let reads = self
            .accounts
            .app
            .cached_public_events_for_account(&account, &references);
        drop(account_transaction);
        reads
    }

    /// Admit a bounded batch of signed candidates: target events, NIP-09
    /// deletions and the selected author's kind-0. No relay I/O. Candidate
    /// admission is not a network refresh.
    pub async fn cache_public_event_preview(
        &self,
        account_ref: &str,
        reference: &str,
        candidates: Vec<String>,
    ) -> Result<PublicEventCacheRead, AppError> {
        let reference = PublicEventReference::parse(reference)?;
        PublicEventCache::validate_candidates(&candidates)?;
        // Serialize cache handle publication against removal, wipe and setup rollback.
        let account_transaction = self.accounts.worker_transactions.clone().lock_owned().await;
        self.accounts.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let app = self.accounts.app.clone();
        blocking_app_task(move || {
            // Owned by the blocking closure: dropping the caller's future cannot
            // release removal protection while this I/O is still running.
            let _account_transaction = account_transaction;
            app.admit_public_events_for_account(&account, &reference, &candidates)
        })
        .await
    }

    /// Bounded native refresh for one reference, returning the resulting local
    /// state. Local state is read under the account transaction, which is then
    /// released before any relay await; persistence reacquires it and writes
    /// only if the same account-cache incarnation is still published. Requests
    /// for one key coalesce, and an attempted refresh starts a 30-second
    /// in-memory cooldown. Failed or empty refreshes keep prior content. If the
    /// account was removed, wiped, reimported or closed meanwhile, the leader
    /// and every coalesced waiter return a retryable `Busy` row without
    /// opening any storage for the replaced incarnation.
    /// A coalesced wait that expires also returns `Busy`: cached state is
    /// not a completed refresh while its leader still owns persistence.
    pub async fn resolve_public_event_preview(
        &self,
        account_ref: &str,
        reference: &str,
    ) -> Result<PublicEventCacheRead, AppError> {
        let (reference, hints) = PublicEventReference::parse_with_hints(reference)?;
        let key = reference.cache_key()?;

        let account_transaction = self.accounts.worker_transactions.clone().lock_owned().await;
        self.accounts.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let (cache, local, known) = {
            let app = self.accounts.app.clone();
            let account = account.clone();
            let reference = reference.clone();
            blocking_app_task(move || {
                let _account_transaction = account_transaction;
                let cache = app.public_event_cache_for_account(&account)?;
                let local = single_read(app.cached_public_events_with_cache(
                    &account,
                    &cache,
                    std::slice::from_ref(&reference),
                )?)?;
                let known = cache.selected_event(&reference, unix_now_seconds())?;
                Ok((cache, local, known))
            })
            .await?
        };
        // A deleted immutable ID cannot come back; skip the network entirely.
        if matches!(key, PublicEventCacheKey::EventId { .. })
            && matches!(
                local.result,
                PublicEventCacheResult::AuthoritativeDeleted(_)
            )
        {
            return Ok(local);
        }
        let mut lease = match cache.begin_refresh(&key.storage_key()) {
            RefreshAdmission::Lead(lease) => lease,
            RefreshAdmission::Coalesced(mut done) => {
                // Expiry is not completion: the leader may still own the
                // persistence transaction. Report retryable Busy even when
                // older cached content exists, rather than a finished refresh.
                if timeout(COALESCED_REFRESH_WAIT, done.changed())
                    .await
                    .is_err()
                {
                    return stale_incarnation(&reference);
                }
                return self
                    .fenced_public_event_read(account_ref, account, cache, reference)
                    .await;
            }
            RefreshAdmission::CoolingDown => return Ok(local),
            RefreshAdmission::Saturated => {
                return Ok(match local.result {
                    PublicEventCacheResult::Missing => PublicEventCacheRead {
                        key: local.key,
                        result: PublicEventCacheResult::Busy,
                    },
                    _ => local,
                });
            }
        };

        // Network: no account transaction or database guard is held here.
        lease.mark_attempted();
        let candidates = self
            .accounts
            .app
            .fetch_public_event_candidates(&reference, &hints, known.as_ref())
            .await;

        let account_transaction = self.accounts.worker_transactions.clone().lock_owned().await;
        let Some(current) = self.public_event_account_after_wait(account_ref) else {
            return stale_incarnation(&reference);
        };
        let app = self.accounts.app.clone();
        blocking_app_task(move || {
            let _account_transaction = account_transaction;
            // Keep the refresh lease until persistence finishes so coalesced
            // callers observe the written state.
            let _lease = lease;
            persist_refresh_if_current(&app, &account, &current, &cache, &reference, &candidates)
        })
        .await
    }

    /// A coalesced caller's read after another refresh of the same key. It
    /// reuses the handle captured with the original account, under the account
    /// transaction, and never opens storage for a replaced incarnation.
    async fn fenced_public_event_read(
        &self,
        account_ref: &str,
        account: AccountSummary,
        cache: PublicEventCache,
        reference: PublicEventReference,
    ) -> Result<PublicEventCacheRead, AppError> {
        let account_transaction = self.accounts.worker_transactions.clone().lock_owned().await;
        let Some(current) = self.public_event_account_after_wait(account_ref) else {
            return stale_incarnation(&reference);
        };
        let app = self.accounts.app.clone();
        blocking_app_task(move || {
            let _account_transaction = account_transaction;
            read_if_current(&app, &account, &current, &cache, &reference)
        })
        .await
    }

    /// Called under the account transaction after a refresh or coalesced wait.
    /// Initial admission already resolved this account. A late lifecycle failure
    /// is retryable stale work, not a new fatal error or permission to open storage.
    fn public_event_account_after_wait(&self, account_ref: &str) -> Option<AccountSummary> {
        self.accounts.shared.lifecycle().ensure_running().ok()?;
        self.accounts.resolve(account_ref).ok()
    }
}

/// Whether `cache` is still the published handle of the same account the
/// request started with. Removal, wipe, same-label reimport, setup rollback
/// and terminal close all fail this check.
fn same_incarnation(
    app: &MarmotApp,
    original: &AccountSummary,
    current: &AccountSummary,
    cache: &PublicEventCache,
) -> bool {
    current.account_id_hex == original.account_id_hex
        && current.label == original.label
        && app.public_event_cache_is_current(&current.label, cache)
}

/// Retryable result for a request whose account incarnation was replaced.
/// It is neither `Missing` nor an opened cache: the caller retries against
/// the current incarnation.
fn stale_incarnation(reference: &PublicEventReference) -> Result<PublicEventCacheRead, AppError> {
    Ok(PublicEventCacheRead {
        key: reference.cache_key()?,
        result: PublicEventCacheResult::Busy,
    })
}

/// Persist late network evidence only into the same incarnation. On a
/// mismatch the evidence is discarded and no cache, directory or account
/// storage is opened.
fn persist_refresh_if_current(
    app: &MarmotApp,
    original: &AccountSummary,
    current: &AccountSummary,
    cache: &PublicEventCache,
    reference: &PublicEventReference,
    candidates: &[String],
) -> Result<PublicEventCacheRead, AppError> {
    if !same_incarnation(app, original, current, cache) {
        return stale_incarnation(reference);
    }
    app.admit_public_events_with_cache(current, cache, reference, candidates)
}

/// Read through the captured handle only while it is the current incarnation.
fn read_if_current(
    app: &MarmotApp,
    original: &AccountSummary,
    current: &AccountSummary,
    cache: &PublicEventCache,
    reference: &PublicEventReference,
) -> Result<PublicEventCacheRead, AppError> {
    if !same_incarnation(app, original, current, cache) {
        return stale_incarnation(reference);
    }
    single_read(app.cached_public_events_with_cache(
        current,
        cache,
        std::slice::from_ref(reference),
    )?)
}

fn single_read(mut reads: Vec<PublicEventCacheRead>) -> Result<PublicEventCacheRead, AppError> {
    match (reads.pop(), reads.is_empty()) {
        (Some(read), true) => Ok(read),
        _ => Err(AppError::from(cgka_traits::StorageError::Backend(
            "public event cache returned an unexpected batch".into(),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MarmotApp;
    use marmot_account::AccountHome;
    use nostr::nips::nip19::{Nip19Coordinate, ToBech32};
    use nostr::prelude::{
        Coordinate, Event, EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp,
    };

    fn signed(keys: &Keys, kind: u16, at: u64, body: &str, tags: Vec<Tag>) -> Event {
        EventBuilder::new(Kind::from(kind), body)
            .custom_created_at(Timestamp::from_secs(at))
            .tags(tags)
            .finalize(keys)
            .unwrap()
    }

    fn d(value: &str) -> Tag {
        Tag::parse(["d", value]).unwrap()
    }

    fn e(event: &Event) -> Tag {
        Tag::parse(["e", event.id.to_hex().as_str()]).unwrap()
    }

    fn state(read: &PublicEventCacheRead) -> &'static str {
        match read.result {
            PublicEventCacheResult::Present(_) => "present",
            PublicEventCacheResult::AuthoritativeDeleted(_) => "deleted",
            PublicEventCacheResult::Missing => "missing",
            PublicEventCacheResult::Busy => "busy",
        }
    }

    fn present_id(read: &PublicEventCacheRead) -> String {
        match &read.result {
            PublicEventCacheResult::Present(preview) => {
                assert_eq!(
                    preview.projection_version,
                    crate::PUBLIC_EVENT_PROJECTION_VERSION
                );
                Event::from_json(&preview.event_json).unwrap().id.to_hex()
            }
            other => panic!("expected a present preview, got {other:?}"),
        }
    }

    fn profile_name(read: &PublicEventCacheRead) -> Option<String> {
        match &read.result {
            PublicEventCacheResult::Present(preview) => preview
                .author_profile
                .as_ref()
                .and_then(|profile| profile.name.clone()),
            _ => None,
        }
    }

    #[tokio::test]
    async fn public_event_preview_cache_round_trips_across_runtime_restart() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        home.create_account("bob").unwrap();
        let keys = Keys::generate();
        let base = Timestamp::now().as_secs() - 1_000;
        let note = signed(&keys, 1, base, "immutable note", Vec::new());
        let older = signed(&keys, 30023, base + 1, "first", vec![d("entry")]);
        let newer = signed(&keys, 30023, base + 2, "second", vec![d("entry")]);
        let profile = signed(
            &keys,
            0,
            base + 3,
            "{\"name\":\"Alice\\u0007\",\"about\":\"one\\ntwo\"}",
            Vec::new(),
        );
        let deleted = signed(&keys, 1, base + 4, "regretted", Vec::new());
        let deletion = signed(&keys, 5, base + 5, "", vec![e(&deleted)]);
        let forged = signed(&Keys::generate(), 5, base + 6, "", vec![e(&note)]);
        let mut tampered = serde_json::to_value(&note).unwrap();
        tampered["content"] = serde_json::json!("tampered");
        let naddr = Nip19Coordinate::new(
            Coordinate::new(Kind::from(30023), keys.public_key()).identifier("entry"),
            std::iter::empty(),
        )
        .to_bech32()
        .unwrap();
        let note_ref = note.id.to_hex();
        let deleted_ref = deleted.id.to_hex();
        let missing_ref = "ab".repeat(32);

        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let runtime = app.runtime();
        let admitted = runtime
            .cache_public_event_preview(
                "alice",
                &note_ref,
                vec![
                    tampered.to_string(),
                    forged.as_json(),
                    older.as_json(),
                    note.as_json(),
                    profile.as_json(),
                ],
            )
            .await
            .unwrap();
        assert_eq!(present_id(&admitted), note.id.to_hex());
        assert_eq!(profile_name(&admitted).as_deref(), Some("Alice"));
        let selected = runtime
            .cache_public_event_preview("alice", &naddr, vec![older.as_json(), newer.as_json()])
            .await
            .unwrap();
        assert_eq!(present_id(&selected), newer.id.to_hex());
        let removed = runtime
            .cache_public_event_preview(
                "alice",
                &deleted_ref,
                vec![deleted.as_json(), deletion.as_json()],
            )
            .await
            .unwrap();
        assert_eq!(state(&removed), "deleted");
        let isolated = runtime
            .cached_public_event_previews("bob", std::slice::from_ref(&note_ref))
            .unwrap();
        assert_eq!(state(&isolated[0]), "missing");

        let batch = vec![
            note_ref.clone(),
            naddr.clone(),
            deleted_ref.clone(),
            note_ref.clone(),
            missing_ref.clone(),
        ];
        let before = runtime
            .cached_public_event_previews("alice", &batch)
            .unwrap();
        assert_eq!(
            before.iter().map(state).collect::<Vec<_>>(),
            ["present", "present", "deleted", "present", "missing"]
        );
        runtime.shutdown_and_close().await.unwrap();

        // Restart offline: the relay is never contacted by cached reads or admission.
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let runtime = app.runtime();
        let after = runtime
            .cached_public_event_previews("alice", &batch)
            .unwrap();
        assert_eq!(after.len(), batch.len());
        assert_eq!(
            after.iter().map(state).collect::<Vec<_>>(),
            ["present", "present", "deleted", "present", "missing"]
        );
        assert_eq!(present_id(&after[0]), note.id.to_hex());
        assert_eq!(present_id(&after[1]), newer.id.to_hex());
        assert_eq!(profile_name(&after[0]).as_deref(), Some("Alice"));
        assert_eq!(after[0].key, after[3].key);
        assert_eq!(
            after[2].result, before[2].result,
            "signed deletion evidence survives the restart unchanged"
        );
        // Stale or replayed evidence cannot regress the restored state.
        let kept = runtime
            .cache_public_event_preview("alice", &naddr, vec![older.as_json()])
            .await
            .unwrap();
        assert_eq!(present_id(&kept), newer.id.to_hex());
        let still_deleted = runtime
            .cache_public_event_preview("alice", &deleted_ref, vec![deleted.as_json()])
            .await
            .unwrap();
        assert_eq!(state(&still_deleted), "deleted");
        runtime.shutdown_and_close().await.unwrap();
    }

    #[tokio::test]
    async fn cached_public_event_reads_report_busy_and_validate_before_storage() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let runtime = app.runtime();
        let id = "cd".repeat(32);
        let held = runtime
            .accounts
            .worker_transactions
            .clone()
            .lock_owned()
            .await;
        let reads = runtime
            .cached_public_event_previews("alice", &[id.clone(), id.clone()])
            .unwrap();
        assert_eq!(
            reads.iter().map(state).collect::<Vec<_>>(),
            ["busy", "busy"]
        );
        assert!(
            !app.public_event_cache_path("alice").exists(),
            "contention must not open storage"
        );
        assert!(
            runtime
                .cached_public_event_previews("alice", &vec![id.clone(); 17])
                .is_err()
        );
        assert!(
            runtime
                .cached_public_event_previews("alice", &[id.clone(), "npub1invalid".into()])
                .is_err()
        );
        drop(held);
        let reads = runtime
            .cached_public_event_previews("alice", std::slice::from_ref(&id))
            .unwrap();
        assert_eq!(state(&reads[0]), "missing");
        assert!(
            runtime
                .cached_public_event_previews("alice", &[])
                .unwrap()
                .is_empty()
        );
        runtime.shutdown_and_close().await.unwrap();
        assert!(
            runtime
                .cached_public_event_previews("alice", std::slice::from_ref(&id))
                .is_err()
        );
    }

    #[tokio::test]
    async fn cancelled_admission_cannot_outlive_account_removal() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let runtime = app.runtime();
        let note = signed(&Keys::generate(), 1, 1_000, "late", Vec::new());
        let admission = {
            let runtime = runtime.clone();
            let reference = note.id.to_hex();
            let candidates = vec![note.as_json()];
            tokio::spawn(async move {
                runtime
                    .cache_public_event_preview("alice", &reference, candidates)
                    .await
            })
        };
        tokio::task::yield_now().await;
        admission.abort();
        let _ = admission.await;
        runtime.accounts.remove_account("alice").await.unwrap();
        assert!(!app.public_event_cache_path("alice").exists());
        assert!(
            !app.public_event_caches
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains_key("alice")
        );
        assert!(
            runtime
                .cached_public_event_previews("alice", &[note.id.to_hex()])
                .is_err()
        );
        runtime.shutdown_and_close().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn public_event_preview_regression_coalesced_timeout_is_busy_until_commit() {
        let dir = tempfile::tempdir().unwrap();
        let alice = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let cache = app.public_event_cache_for_account(&alice).unwrap();
        let runtime = app.runtime();
        for retained in [false, true] {
            let note = signed(
                &Keys::generate(),
                1,
                Timestamp::now().as_secs() - 20,
                "note",
                vec![],
            );
            let reference_text = note.id.to_hex();
            let reference = PublicEventReference::parse(&reference_text).unwrap();
            if retained {
                runtime
                    .cache_public_event_preview("alice", &reference_text, vec![note.as_json()])
                    .await
                    .unwrap();
            }
            let key = reference.cache_key().unwrap().storage_key();
            let RefreshAdmission::Lead(mut lease) = cache.begin_refresh(&key) else {
                panic!("a fresh key must admit the leader");
            };
            lease.mark_attempted();
            let read = runtime
                .resolve_public_event_preview("alice", &reference_text)
                .await
                .unwrap();
            assert_eq!(
                state(&read),
                "busy",
                "timeout does not certify cached state"
            );
            assert!(matches!(
                cache.begin_refresh(&key),
                RefreshAdmission::Coalesced(_)
            ));
            // Model the leader committing before releasing its shared lease.
            runtime
                .cache_public_event_preview("alice", &reference_text, vec![note.as_json()])
                .await
                .unwrap();
            drop(lease);
            let completed = runtime
                .resolve_public_event_preview("alice", &reference_text)
                .await
                .unwrap();
            assert_eq!(present_id(&completed), note.id.to_hex());
        }
        runtime.shutdown_and_close().await.unwrap();
    }

    #[tokio::test]
    async fn late_public_event_lifecycle_failures_are_busy_without_reopening_storage() {
        for close in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let account = AccountHome::open(dir.path())
                .create_account("alice")
                .unwrap();
            let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
            let runtime = app.runtime();
            let reference = PublicEventReference::parse(&"ab".repeat(32)).unwrap();
            let cache = app.public_event_cache_for_account(&account).unwrap();
            if close {
                runtime.shutdown_and_close().await.unwrap();
            } else {
                runtime.accounts.remove_account("alice").await.unwrap();
            }
            // Leader persistence and coalesced readers share this late fence.
            assert!(runtime.public_event_account_after_wait("alice").is_none());
            let read = runtime
                .fenced_public_event_read("alice", account, cache, reference)
                .await
                .unwrap();
            assert_eq!(state(&read), "busy");
            assert!(
                !app.public_event_caches
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .contains_key("alice"),
                "late work must not publish another cache handle"
            );
            if !close {
                assert!(!app.public_event_cache_path("alice").exists());
                runtime.shutdown_and_close().await.unwrap();
            }
        }
    }

    #[test]
    fn stale_refresh_and_coalesced_reads_never_reopen_a_replaced_cache() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let alice = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let note = signed(
            &Keys::generate(),
            1,
            Timestamp::now().as_secs() - 10,
            "late network evidence",
            Vec::new(),
        );
        let reference = PublicEventReference::parse(&note.id.to_hex()).unwrap();
        let candidates = vec![note.as_json()];
        let published = |app: &MarmotApp| {
            app.public_event_caches
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains_key("alice")
        };

        // The same incarnation accepts the late refresh and serves waiters.
        let cache = app.public_event_cache_for_account(&alice).unwrap();
        let stored =
            persist_refresh_if_current(&app, &alice, &alice, &cache, &reference, &candidates)
                .unwrap();
        assert_eq!(present_id(&stored), note.id.to_hex());
        assert_eq!(
            state(&read_if_current(&app, &alice, &alice, &cache, &reference).unwrap()),
            "present"
        );

        // Removal or wipe replaced the incarnation while the network ran.
        app.drop_account_caches("alice");
        let path = app.public_event_cache_path("alice");
        let _ = std::fs::remove_file(&path);
        let late =
            persist_refresh_if_current(&app, &alice, &alice, &cache, &reference, &candidates)
                .unwrap();
        let waiter = read_if_current(&app, &alice, &alice, &cache, &reference).unwrap();
        assert_eq!(
            state(&late),
            "busy",
            "stale refreshes are retryable, not misses"
        );
        assert_eq!(state(&waiter), "busy");
        assert!(
            !path.exists(),
            "a stale request never recreates erased files"
        );
        assert!(!published(&app), "a stale request never publishes a handle");

        // Same-label reimport: a fresh incarnation belongs to another account.
        let fresh = app.public_event_cache_for_account(&alice).unwrap();
        let mut reimported = alice.clone();
        reimported.account_id_hex = "ee".repeat(32);
        assert_eq!(
            state(
                &persist_refresh_if_current(
                    &app,
                    &alice,
                    &reimported,
                    &fresh,
                    &reference,
                    &candidates
                )
                .unwrap()
            ),
            "busy"
        );
        assert_eq!(
            state(
                &persist_refresh_if_current(&app, &alice, &alice, &cache, &reference, &candidates)
                    .unwrap()
            ),
            "busy",
            "the replaced handle stays stale after a new one is published"
        );
        assert_eq!(
            state(&read_if_current(&app, &alice, &alice, &fresh, &reference).unwrap()),
            "missing",
            "no late evidence reached the new incarnation"
        );

        // Terminal close fences every handle.
        app.close_storage().unwrap();
        assert_eq!(
            state(
                &persist_refresh_if_current(&app, &alice, &alice, &fresh, &reference, &candidates)
                    .unwrap()
            ),
            "busy"
        );
        assert_eq!(
            state(&read_if_current(&app, &alice, &alice, &fresh, &reference).unwrap()),
            "busy"
        );
    }

    #[tokio::test]
    async fn future_versions_cannot_redirect_deletion_discovery_from_the_admitted_selection() {
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let deletion_relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let deletion_url = deletion_relay.url().await;
        let future_relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let future_url = future_relay.url().await;
        let keys = Keys::generate();
        let now = Timestamp::now().as_secs();
        let target = signed(
            &keys,
            30023,
            now - 20,
            "admissible",
            vec![Tag::parse(["d", "entry"]).unwrap()],
        );
        let future = signed(
            &keys,
            30023,
            now + 86_400,
            "future",
            vec![Tag::parse(["d", "entry"]).unwrap()],
        );
        let deletion = signed(
            &keys,
            5,
            now - 10,
            "deleted",
            vec![Tag::parse(["e", &target.id.to_hex()]).unwrap()],
        );
        let publisher = nostr_sdk::prelude::Client::default();
        publisher.add_relay(url.as_str()).await.unwrap();
        publisher.connect_relay(url.as_str()).await.unwrap();
        publisher.send_event(&target).await.unwrap();
        publisher.shutdown().await;
        let deletion_publisher = nostr_sdk::prelude::Client::default();
        deletion_publisher
            .add_relay(deletion_url.as_str())
            .await
            .unwrap();
        deletion_publisher
            .connect_relay(deletion_url.as_str())
            .await
            .unwrap();
        deletion_publisher.send_event(&deletion).await.unwrap();
        deletion_publisher.shutdown().await;
        let future_publisher = nostr_sdk::prelude::Client::default();
        future_publisher
            .add_relay(future_url.as_str())
            .await
            .unwrap();
        future_publisher
            .connect_relay(future_url.as_str())
            .await
            .unwrap();
        future_publisher.send_event(&future).await.unwrap();
        future_publisher.shutdown().await;
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relays(
            dir.path(),
            vec![
                url.to_string(),
                future_url.to_string(),
                deletion_url.to_string(),
            ],
        );
        let runtime = app.runtime();
        // Use the shared NIP-19 encoder, preserving an ordinary complete coordinate.
        let coordinate = nostr::prelude::Coordinate::new(Kind::from(30023), keys.public_key())
            .identifier("entry");
        use nostr::nips::nip19::ToBech32;
        let reference = nostr::nips::nip19::Nip19Coordinate::new(coordinate, std::iter::empty())
            .to_bech32()
            .unwrap();
        let read = runtime
            .resolve_public_event_preview("alice", &reference)
            .await
            .unwrap();
        assert!(
            matches!(read.result, PublicEventCacheResult::AuthoritativeDeleted(_)),
            "the admissible version must determine deletion discovery: {:?}",
            read.result
        );
        runtime.shutdown_and_close().await.unwrap();
    }

    #[tokio::test]
    async fn resolve_admits_exact_target_and_selected_author_metadata_from_relays() {
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let now = Timestamp::now().as_secs();
        let note = signed(&keys, 1, now - 20, "resolved", Vec::new());
        let profile = signed(&keys, 0, now - 30, "{\"name\":\"Relay Alice\"}", Vec::new());
        let stranger = signed(
            &Keys::generate(),
            0,
            now - 10,
            "{\"name\":\"Stranger\"}",
            Vec::new(),
        );
        let publisher = nostr_sdk::prelude::Client::default();
        publisher.add_relay(url.as_str()).await.unwrap();
        publisher.connect_relay(url.as_str()).await.unwrap();
        for event in [&note, &profile, &stranger] {
            publisher.send_event(event).await.unwrap();
        }
        publisher.shutdown().await;

        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relays(dir.path(), vec![url.to_string()]);
        let runtime = app.runtime();
        let reference = note.id.to_hex();
        let resolved = runtime
            .resolve_public_event_preview("alice", &reference)
            .await
            .unwrap();
        assert_eq!(present_id(&resolved), note.id.to_hex());
        assert_eq!(profile_name(&resolved).as_deref(), Some("Relay Alice"));
        let cached = runtime
            .cached_public_event_previews("alice", std::slice::from_ref(&reference))
            .unwrap();
        assert_eq!(present_id(&cached[0]), note.id.to_hex());
        assert_eq!(profile_name(&cached[0]).as_deref(), Some("Relay Alice"));
        // A second call inside the cooldown is served locally.
        let again = runtime
            .resolve_public_event_preview("alice", &reference)
            .await
            .unwrap();
        assert_eq!(again.result, cached[0].result);
        runtime.shutdown_and_close().await.unwrap();
    }
}
