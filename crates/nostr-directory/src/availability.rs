//! Bounded, account-local Marmot availability for direct follows.
//!
//! The cache belongs to the selected local account, so follow rows never enter
//! the shared public directory tier. That tier stores only per-slot replacement
//! metadata; KeyPackage bytes stay in the existing directory record.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cgka_engine::key_package::key_package_metadata;
use cgka_traits::TransportEndpoint;
use futures::StreamExt;
use rusqlite::params;
use storage_sqlite::{
    PublicKeyPackageBarrierRecord, PublicKeyPackageEvidenceSnapshot,
    PublicKeyPackageReplacementRecord, SqliteSharedStorage,
};

use tokio::sync::watch;

use super::cache::DirectoryCache;
use super::error::{DirectoryError, MissingKeyPackageReason, blocking_directory_task};
use super::key_package_recovery::KeyPackageRecoveryRequest;
use super::observer::DirectoryObserver;
use super::published_records::{
    KEY_PACKAGE_FRESHNESS, barrier_allows, key_package_queries, key_package_read_page_full,
    replacement_allows, select_key_packages_from_records, watermark_allows,
};
use super::resources::{DirectoryAccount, DirectoryResources};
use super::{Directory, DirectoryKeyPackage, FetchedKeyPackage};

pub const MAX_FOLLOW_AVAILABILITY_TARGETS: usize = 100;
pub const MAX_FOLLOW_AVAILABILITY_PAGE_SIZE: usize = 100;
pub const FOLLOW_AVAILABILITY_CONCURRENCY: usize = 4;
pub const FOLLOW_AVAILABILITY_TARGET_TIMEOUT: Duration = Duration::from_secs(10);
pub const FOLLOW_AVAILABILITY_REFRESH_TIMEOUT: Duration = Duration::from_secs(300);
pub const FOLLOW_AVAILABILITY_REFRESH_CADENCE: Duration = Duration::from_secs(60);
pub const FOLLOW_AVAILABILITY_NEGATIVE_TTL: Duration = Duration::from_secs(15 * 60);
pub const MAX_FOLLOW_AVAILABILITY_RELAY_FETCHES: usize = 2 * MAX_FOLLOW_AVAILABILITY_TARGETS;
pub const MAX_FOLLOW_AVAILABILITY_RELAYS_PER_TARGET: usize = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FollowAvailabilityState {
    Ready,
    #[default]
    Unknown,
    NotFound,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FollowAvailabilitySource {
    #[default]
    None,
    Network,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FollowAvailability {
    pub account_id_hex: String,
    pub state: FollowAvailabilityState,
    pub checked_at: Option<u64>,
    pub fresh_until: Option<u64>,
    pub key_package_event_id: Option<String>,
    pub source: FollowAvailabilitySource,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FollowAvailabilityPage {
    pub rows: Vec<FollowAvailability>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FollowAvailabilityRefreshPhase {
    #[default]
    Idle,
    Running,
    Complete,
    Partial,
    Cancelled,
    Throttled,
    Failed,
}

impl FollowAvailabilityRefreshPhase {
    fn is_terminal(self) -> bool {
        !matches!(self, Self::Idle | Self::Running)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FollowAvailabilityRefreshStatus {
    pub operation_id: Option<u64>,
    pub phase: FollowAvailabilityRefreshPhase,
    pub total: u32,
    pub completed: u32,
    pub ready: u32,
    pub unknown: u32,
    pub not_found: u32,
    pub failed: u32,
    pub truncated: bool,
}

#[derive(Clone)]
pub(crate) struct FollowAvailabilityRefresh {
    status: watch::Sender<FollowAvailabilityRefreshStatus>,
    cancel: watch::Sender<bool>,
    finished_at: Option<Instant>,
}

#[derive(Default)]
pub(crate) struct FollowAvailabilityRefreshes {
    next_operation_id: u64,
    by_account: HashMap<String, FollowAvailabilityRefresh>,
}

type SharedRefreshes = Arc<Mutex<FollowAvailabilityRefreshes>>;

#[derive(Clone, Default)]
struct AvailabilityWrite {
    state: FollowAvailabilityState,
    checked_at: u64,
    fresh_until: Option<u64>,
    key_package_event_id: Option<String>,
    key_package_id: Option<String>,
    key_package_created_at: Option<u64>,
    source: FollowAvailabilitySource,
    failed: bool,
    observed_event_ids: HashSet<String>,
    evidence_revision: i64,
    alternatives: Vec<FetchedKeyPackage>,
}

impl AvailabilityWrite {
    fn unknown(checked_at: u64) -> Self {
        Self {
            state: FollowAvailabilityState::Unknown,
            checked_at,
            fresh_until: None,
            key_package_event_id: None,
            key_package_id: None,
            key_package_created_at: None,
            source: FollowAvailabilitySource::None,
            failed: true,
            observed_event_ids: HashSet::new(),
            evidence_revision: 0,
            alternatives: Vec::new(),
        }
    }
}

impl DirectoryCache {
    fn direct_follows(&self, account_id_hex: &str) -> Result<Vec<String>, DirectoryError> {
        let conn = self.lock()?;
        let mut statement = conn.prepare(
            "SELECT follows.follow_account_id_hex FROM directory_user_follows AS follows
             LEFT JOIN follow_availability AS availability
               ON availability.follow_account_id_hex = follows.follow_account_id_hex
             WHERE follows.account_id_hex = ?1
             ORDER BY availability.checked_at IS NOT NULL,
                      availability.checked_at,
                      follows.follow_account_id_hex",
        )?;
        let rows = statement.query_map([account_id_hex], |row| row.get(0))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    fn prune_follow_availability(&self, account_id_hex: &str) -> Result<(), DirectoryError> {
        self.lock()?.execute(
            "DELETE FROM follow_availability
             WHERE NOT EXISTS (
                 SELECT 1 FROM directory_user_follows AS follows
                 WHERE follows.account_id_hex = ?1
                   AND follows.follow_account_id_hex = follow_availability.follow_account_id_hex
             )",
            [account_id_hex],
        )?;
        Ok(())
    }

    fn record_follow_availability(
        &self,
        account_id_hex: &str,
        follow_account_id_hex: &str,
        value: &AvailabilityWrite,
    ) -> Result<bool, DirectoryError> {
        let changed = self.lock()?.execute(
            "INSERT INTO follow_availability (
                 follow_account_id_hex, state, checked_at, fresh_until,
                 key_package_event_id, key_package_id, key_package_created_at,
                 source, evidence_revision, updated_at
             )
             SELECT ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?4
             WHERE EXISTS (
                 SELECT 1 FROM directory_user_follows
                 WHERE account_id_hex = ?1 AND follow_account_id_hex = ?2
             )
             ON CONFLICT(follow_account_id_hex) DO UPDATE SET
                 state = excluded.state,
                 checked_at = excluded.checked_at,
                 fresh_until = excluded.fresh_until,
                 key_package_event_id = excluded.key_package_event_id,
                 key_package_id = excluded.key_package_id,
                 key_package_created_at = excluded.key_package_created_at,
                 source = excluded.source,
                 evidence_revision = excluded.evidence_revision,
                 updated_at = excluded.updated_at",
            params![
                account_id_hex,
                follow_account_id_hex,
                availability_state_token(value.state),
                value.checked_at as i64,
                value.fresh_until.map(|timestamp| timestamp as i64),
                value.key_package_event_id,
                value.key_package_id,
                value
                    .key_package_created_at
                    .map(|timestamp| timestamp as i64),
                availability_source_token(value.source),
                value.evidence_revision,
            ],
        )?;
        Ok(changed != 0)
    }
    #[cfg(test)]
    fn follow_availability_page(
        &self,
        account_id_hex: &str,
        after: Option<&str>,
        limit: usize,
        now: u64,
    ) -> Result<FollowAvailabilityPage, DirectoryError> {
        self.follow_availability_page_with_shared(account_id_hex, after, limit, now, 0, None)
    }

    fn follow_availability_page_with_shared(
        &self,
        account_id_hex: &str,
        after: Option<&str>,
        limit: usize,
        now: u64,
        future_skew_secs: u64,
        shared: Option<&SqliteSharedStorage>,
    ) -> Result<FollowAvailabilityPage, DirectoryError> {
        let limit = limit.clamp(1, MAX_FOLLOW_AVAILABILITY_PAGE_SIZE);
        let conn = self.lock()?;
        let mut statement = conn.prepare(
            "SELECT follows.follow_account_id_hex,
                    availability.state, availability.checked_at,
                    availability.fresh_until, availability.key_package_event_id,
                    availability.key_package_id, availability.key_package_created_at,
                    availability.source, availability.evidence_revision,
                    json_extract(users.key_package_json, '$.key_package_id'),
                    json_extract(users.key_package_json, '$.key_package_event_id'),
                    json_extract(users.key_package_json, '$.created_at')
             FROM directory_user_follows AS follows
             LEFT JOIN follow_availability AS availability
               ON availability.follow_account_id_hex = follows.follow_account_id_hex
             LEFT JOIN directory_users AS users
               ON users.account_id_hex = follows.follow_account_id_hex
             WHERE follows.account_id_hex = ?1
               AND (?2 = '' OR follows.follow_account_id_hex > ?2)
             ORDER BY follows.follow_account_id_hex
             LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![
                account_id_hex,
                after.unwrap_or_default(),
                (limit + 1) as i64,
            ],
            |row| {
                Ok(StoredAvailability {
                    account_id_hex: row.get(0)?,
                    state: row.get(1)?,
                    checked_at: row.get(2)?,
                    fresh_until: row.get(3)?,
                    key_package_event_id: row.get(4)?,
                    key_package_id: row.get(5)?,
                    key_package_created_at: row.get(6)?,
                    evidence_revision: row.get::<_, Option<i64>>(8)?.unwrap_or(0),
                    source: row.get(7)?,
                    current: Publication {
                        key_package_id: row.get(9)?,
                        event_id: row.get(10)?,
                        created_at: row.get(11)?,
                    },
                    shared: None,
                    replacements: Vec::new(),
                    replacement_evicted_at: None,
                    global_eviction: None,
                    shared_evidence_revision: None,
                    barriers: Vec::new(),
                    eviction_watermark: None,
                })
            },
        )?;
        let mut stored = rows.collect::<Result<Vec<_>, _>>()?;
        let has_more = stored.len() > limit;
        stored.truncate(limit);
        let next_cursor = has_more
            .then(|| stored.last().map(|row| row.account_id_hex.clone()))
            .flatten();
        if let Some(shared) = shared {
            for row in &mut stored {
                if !matches!(row.state.as_deref(), Some("ready" | "not_found")) {
                    continue;
                }
                let snapshot = shared.key_package_evidence_snapshot(&row.account_id_hex)?;
                row.replacement_evicted_at = snapshot
                    .barriers
                    .iter()
                    .map(|barrier| barrier.observed_at)
                    .max()
                    .or_else(|| {
                        snapshot
                            .watermark
                            .as_ref()
                            .map(|barrier| barrier.observed_at)
                    })
                    .or_else(|| {
                        snapshot
                            .global_eviction
                            .as_ref()
                            .map(|barrier| barrier.observed_at)
                    });
                row.global_eviction = snapshot.global_eviction;
                row.shared_evidence_revision = Some(snapshot.revision);
                row.barriers = snapshot.barriers;
                row.eviction_watermark = snapshot.watermark;
                row.replacements = snapshot.replacements;
                if let Some(record) = shared.public_directory_user(&row.account_id_hex)?
                    && let Some(json) = record.key_package_json
                {
                    let package: DirectoryKeyPackage = serde_json::from_str(&json)?;
                    if !package.key_package_event_id.is_empty() {
                        row.shared = Some(Publication {
                            event_id: Some(package.key_package_event_id),
                            key_package_id: Some(package.key_package_id),
                            created_at: Some(package.created_at as i64),
                        });
                    }
                }
            }
        }
        let rows = stored
            .into_iter()
            .map(|row| row.project(now, future_skew_secs))
            .collect();
        Ok(FollowAvailabilityPage { rows, next_cursor })
    }
}

#[derive(Default)]
struct Publication {
    event_id: Option<String>,
    key_package_id: Option<String>,
    created_at: Option<i64>,
}

struct StoredAvailability {
    account_id_hex: String,
    state: Option<String>,
    checked_at: Option<i64>,
    fresh_until: Option<i64>,
    key_package_event_id: Option<String>,
    key_package_id: Option<String>,
    key_package_created_at: Option<i64>,
    source: Option<i64>,
    evidence_revision: i64,
    shared_evidence_revision: Option<i64>,
    current: Publication,
    shared: Option<Publication>,
    replacements: Vec<PublicKeyPackageReplacementRecord>,
    replacement_evicted_at: Option<u64>,
    // Device-wide loss is conservative: every account needs a newer publication.
    global_eviction: Option<PublicKeyPackageBarrierRecord>,
    barriers: Vec<PublicKeyPackageBarrierRecord>,
    eviction_watermark: Option<PublicKeyPackageBarrierRecord>,
}

impl StoredAvailability {
    fn project(self, now: u64, future_skew_secs: u64) -> FollowAvailability {
        let checked_at = self.checked_at.and_then(|value| u64::try_from(value).ok());
        let fresh_until = self.fresh_until.and_then(|value| u64::try_from(value).ok());
        let source = match self.source {
            Some(1) => FollowAvailabilitySource::Network,
            _ => FollowAvailabilitySource::None,
        };
        let publication_allows = |current: &Publication| {
            let other_slot = self.key_package_id.is_some()
                && current.key_package_id.is_some()
                && self.key_package_id != current.key_package_id;
            let current_is_not_newer = match (current.created_at, self.key_package_created_at) {
                (Some(current), Some(selected)) => current <= selected,
                _ => true,
            };
            current.event_id.is_some()
                && (other_slot
                    || (current.event_id == self.key_package_event_id && current_is_not_newer))
        };
        let current_publication_allows = publication_allows(&self.current)
            && self.shared.as_ref().is_none_or(publication_allows);
        let replacement_allows = self
            .replacements
            .iter()
            .filter(|replacement| Some(&replacement.key_package_id) == self.key_package_id.as_ref())
            .all(|replacement| {
                let Some(event_id) = self.key_package_event_id.as_ref() else {
                    return false;
                };
                let Some(created_at) = self
                    .key_package_created_at
                    .and_then(|value| u64::try_from(value).ok())
                else {
                    return false;
                };
                replacement_allows(event_id, created_at, replacement)
            });
        let barrier_allows_for_selected = self
            .barriers
            .iter()
            .filter(|barrier| {
                barrier.deleted_event_id.is_some()
                    || Some(&barrier.key_package_id) == self.key_package_id.as_ref()
            })
            .all(|barrier| {
                let Some(event_id) = self.key_package_event_id.as_ref() else {
                    return false;
                };
                let Some(created_at) = self
                    .key_package_created_at
                    .and_then(|value| u64::try_from(value).ok())
                else {
                    return false;
                };
                barrier_allows(event_id, created_at, barrier)
            });
        let selected_allows = |barrier: &PublicKeyPackageBarrierRecord| {
            self.key_package_event_id
                .as_ref()
                .zip(
                    self.key_package_created_at
                        .and_then(|value| u64::try_from(value).ok()),
                )
                .is_some_and(|(event_id, created_at)| {
                    watermark_allows(event_id, created_at, now, future_skew_secs, barrier)
                })
        };
        let watermark_allows = self.eviction_watermark.as_ref().is_none_or(selected_allows)
            && self.global_eviction.as_ref().is_none_or(selected_allows);
        let shared_before_check = self.shared.as_ref().is_none_or(|current| {
            current
                .created_at
                .and_then(|value| u64::try_from(value).ok())
                <= checked_at
        });
        let replacements_before_check = self
            .replacements
            .iter()
            .all(|replacement| Some(replacement.observed_at) <= checked_at)
            && self
                .barriers
                .iter()
                .all(|barrier| Some(barrier.observed_at) <= checked_at)
            && self
                .replacement_evicted_at
                .is_none_or(|evicted_at| Some(evicted_at) <= checked_at)
            && self
                .eviction_watermark
                .as_ref()
                .is_none_or(|barrier| Some(barrier.observed_at) <= checked_at);
        let negative_is_current = self
            .current
            .created_at
            .and_then(|value| u64::try_from(value).ok())
            <= checked_at
            && shared_before_check
            && replacements_before_check
            && self.evidence_revision == self.shared_evidence_revision.unwrap_or(0);
        let publication_fresh = self
            .key_package_created_at
            .and_then(|value| u64::try_from(value).ok())
            .is_some_and(|created_at| {
                created_at.saturating_add(KEY_PACKAGE_FRESHNESS.as_secs()) > now
            });
        let state = match self.state.as_deref() {
            Some("ready")
                if fresh_until.is_some_and(|expiry| expiry > now)
                    && publication_fresh
                    && self.key_package_event_id.is_some()
                    && current_publication_allows
                    && replacement_allows
                    && barrier_allows_for_selected
                    && watermark_allows =>
            {
                FollowAvailabilityState::Ready
            }
            Some("not_found") if negative_is_current => {
                if fresh_until.is_some_and(|expiry| expiry > now) {
                    FollowAvailabilityState::NotFound
                } else {
                    FollowAvailabilityState::Unknown
                }
            }
            _ => FollowAvailabilityState::Unknown,
        };
        FollowAvailability {
            account_id_hex: self.account_id_hex,
            state,
            checked_at,
            fresh_until,
            key_package_event_id: self.key_package_event_id,
            source,
        }
    }
}

fn availability_state_token(state: FollowAvailabilityState) -> &'static str {
    match state {
        FollowAvailabilityState::Ready => "ready",
        FollowAvailabilityState::Unknown => "unknown",
        FollowAvailabilityState::NotFound => "not_found",
    }
}

fn availability_source_token(source: FollowAvailabilitySource) -> i64 {
    match source {
        FollowAvailabilitySource::None => 0,
        FollowAvailabilitySource::Network => 1,
    }
}

enum RefreshAdmission {
    Leader(Arc<RefreshLeader>),
    Follower(watch::Receiver<FollowAvailabilityRefreshStatus>),
    Throttled(FollowAvailabilityRefreshStatus),
}

struct RefreshLeader {
    account_id_hex: String,
    operation_id: u64,
    operations: SharedRefreshes,
    status: watch::Sender<FollowAvailabilityRefreshStatus>,
    cancel: watch::Sender<bool>,
    finished: std::sync::atomic::AtomicBool,
}

impl RefreshLeader {
    fn is_cancelled(&self) -> bool {
        *self.cancel.subscribe().borrow()
    }

    async fn cancelled(&self) {
        let mut receiver = self.cancel.subscribe();
        if *receiver.borrow() {
            return;
        }
        while receiver.changed().await.is_ok() {
            if *receiver.borrow() {
                return;
            }
        }
    }

    fn finish(&self, phase: FollowAvailabilityRefreshPhase) {
        if self
            .finished
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return;
        }
        let mut operations = self.operations.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = operations.by_account.get_mut(&self.account_id_hex)
            && entry.status.borrow().operation_id == Some(self.operation_id)
            && matches!(
                phase,
                FollowAvailabilityRefreshPhase::Complete | FollowAvailabilityRefreshPhase::Partial
            )
        {
            entry.finished_at = Some(Instant::now());
        }
        drop(operations);
        self.status.send_if_modified(|status| {
            status.phase = phase;
            true
        });
    }
}

impl Drop for RefreshLeader {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
        self.finish(FollowAvailabilityRefreshPhase::Cancelled);
    }
}

impl<R: DirectoryResources> Directory<R> {
    pub fn follow_availability_page(
        &self,
        account: &DirectoryAccount,
        after: Option<&str>,
        limit: usize,
    ) -> Result<FollowAvailabilityPage, DirectoryError> {
        let now = self.directory_freshness().now;
        let cache = self.resources.cache_for_account(account)?;
        let shared = self.resources.shared_storage()?;
        cache.follow_availability_page_with_shared(
            &account.account_id_hex,
            after,
            limit,
            now,
            self.config.max_future_skew.as_secs(),
            Some(&shared),
        )
    }

    pub fn follow_availability_status(
        &self,
        account_id_hex: &str,
    ) -> FollowAvailabilityRefreshStatus {
        self.state
            .follow_availability_refreshes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .by_account
            .get(account_id_hex)
            .map(|entry| entry.status.borrow().clone())
            .unwrap_or_default()
    }

    pub fn cancel_follow_availability(&self, account_id_hex: &str, operation_id: u64) -> bool {
        let operations = self
            .state
            .follow_availability_refreshes
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let Some(entry) = operations.by_account.get(account_id_hex) else {
            return false;
        };
        if entry.status.borrow().operation_id != Some(operation_id)
            || entry.status.borrow().phase != FollowAvailabilityRefreshPhase::Running
        {
            return false;
        }
        entry.cancel.send_replace(true);
        true
    }
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn reset_availability_cadence(&self, account_id_hex: &str) {
        if let Some(entry) = self
            .state
            .follow_availability_refreshes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .by_account
            .get_mut(account_id_hex)
        {
            entry.finished_at = None;
        }
    }

    fn begin_availability_refresh(&self, account_id_hex: &str) -> RefreshAdmission {
        let mut operations = self
            .state
            .follow_availability_refreshes
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = operations.by_account.get(account_id_hex) {
            let status = entry.status.borrow().clone();
            if status.phase == FollowAvailabilityRefreshPhase::Running {
                let updates = entry.status.subscribe();
                #[cfg(any(test, feature = "test-support"))]
                if let Some(notify) = self
                    .state
                    .availability_admission
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .as_ref()
                {
                    notify.notify_one();
                }
                return RefreshAdmission::Follower(updates);
            }
            if entry
                .finished_at
                .is_some_and(|finished| finished.elapsed() < FOLLOW_AVAILABILITY_REFRESH_CADENCE)
            {
                return RefreshAdmission::Throttled(FollowAvailabilityRefreshStatus {
                    phase: FollowAvailabilityRefreshPhase::Throttled,
                    ..status
                });
            }
        }

        operations.next_operation_id = operations.next_operation_id.wrapping_add(1).max(1);
        let operation_id = operations.next_operation_id;
        let (status, _) = watch::channel(FollowAvailabilityRefreshStatus {
            operation_id: Some(operation_id),
            phase: FollowAvailabilityRefreshPhase::Running,
            ..FollowAvailabilityRefreshStatus::default()
        });
        let (cancel, _) = watch::channel(false);
        operations.by_account.insert(
            account_id_hex.to_owned(),
            FollowAvailabilityRefresh {
                status: status.clone(),
                cancel: cancel.clone(),
                finished_at: None,
            },
        );
        RefreshAdmission::Leader(Arc::new(RefreshLeader {
            account_id_hex: account_id_hex.to_owned(),
            operation_id,
            operations: self.state.follow_availability_refreshes.clone(),
            status,
            cancel,
            finished: std::sync::atomic::AtomicBool::new(false),
        }))
    }
}

impl<R: DirectoryResources + DirectoryObserver> Directory<R> {
    pub async fn refresh_follow_availability(
        &self,
        account: &DirectoryAccount,
    ) -> Result<FollowAvailabilityRefreshStatus, DirectoryError> {
        match self.begin_availability_refresh(&account.account_id_hex) {
            RefreshAdmission::Throttled(status) => Ok(status),
            RefreshAdmission::Follower(mut updates) => loop {
                let status = updates.borrow_and_update().clone();
                if status.phase.is_terminal() {
                    return Ok(status);
                }
                updates
                    .changed()
                    .await
                    .map_err(|_| DirectoryError::TransportClosed)?;
            },
            RefreshAdmission::Leader(leader) => {
                let directory = self.clone();
                let account = account.clone();
                let task_leader = leader.clone();
                let task = tokio::spawn(async move {
                    let result = directory
                        .run_availability_refresh(&account, task_leader.clone())
                        .await;
                    match result {
                        Ok(()) => {
                            let phase = if task_leader.is_cancelled() {
                                FollowAvailabilityRefreshPhase::Cancelled
                            } else if task_leader.status.borrow().truncated
                                || task_leader.status.borrow().failed != 0
                            {
                                FollowAvailabilityRefreshPhase::Partial
                            } else {
                                FollowAvailabilityRefreshPhase::Complete
                            };
                            task_leader.finish(phase);
                            Ok(task_leader.status.borrow().clone())
                        }
                        Err(error) => {
                            task_leader.finish(FollowAvailabilityRefreshPhase::Failed);
                            Err(error)
                        }
                    }
                });
                task.await
                    .map_err(|error| DirectoryError::BlockingTask(error.to_string()))?
            }
        }
    }

    async fn run_availability_refresh(
        &self,
        account: &DirectoryAccount,
        leader: Arc<RefreshLeader>,
    ) -> Result<(), DirectoryError> {
        let directory = self.clone();
        let account = account.clone();
        let snapshot_account = account.clone();
        let follows = blocking_directory_task(move || {
            let cache = directory.resources.cache_for_account(&snapshot_account)?;
            cache.prune_follow_availability(&snapshot_account.account_id_hex)?;
            cache.direct_follows(&snapshot_account.account_id_hex)
        })
        .await?;
        leader.status.send_if_modified(|status| {
            status.total = follows.len().min(MAX_FOLLOW_AVAILABILITY_TARGETS) as u32;
            status.truncated = follows.len() > MAX_FOLLOW_AVAILABILITY_TARGETS;
            true
        });
        let targets = follows
            .into_iter()
            .take(MAX_FOLLOW_AVAILABILITY_TARGETS)
            .collect::<Vec<_>>();

        let work = futures::stream::iter(targets.into_iter().map(|follow| {
            let directory = self.clone();
            let account = account.clone();
            let leader = leader.clone();
            async move {
                if leader.is_cancelled() {
                    return Ok(());
                }
                let lookup = tokio::time::timeout(
                    FOLLOW_AVAILABILITY_TARGET_TIMEOUT,
                    directory.lookup_follow_availability(&follow),
                );
                tokio::pin!(lookup);
                let value = tokio::select! {
                    _ = leader.cancelled() => return Ok(()),
                    result = &mut lookup => match result {
                        Ok(Ok(value)) => value,
                        Ok(Err(error)) if error_is_host_failure(&error) => return Err(error),
                        Ok(Err(_)) | Err(_) => {
                            AvailabilityWrite::unknown(directory.directory_freshness().now)
                        }
                    },
                };
                if leader.is_cancelled() {
                    return Ok(());
                }
                let resources = directory.resources.clone();
                let write_account = account.clone();
                let write_follow = follow.clone();
                let write_value = value.clone();
                let committed = blocking_directory_task(move || {
                    if resources.account_id_for_label(&write_account.label)?
                        != write_account.account_id_hex
                    {
                        return Ok(false);
                    }
                    let cache = resources.cache_for_account(&write_account)?;
                    cache.record_follow_availability(
                        &write_account.account_id_hex,
                        &write_follow,
                        &write_value,
                    )
                })
                .await?;
                leader.status.send_if_modified(|status| {
                    status.completed = status.completed.saturating_add(1);
                    let projected = if committed {
                        value.state
                    } else {
                        FollowAvailabilityState::Unknown
                    };
                    match projected {
                        FollowAvailabilityState::Ready => {
                            status.ready = status.ready.saturating_add(1)
                        }
                        FollowAvailabilityState::Unknown => {
                            status.unknown = status.unknown.saturating_add(1)
                        }
                        FollowAvailabilityState::NotFound => {
                            status.not_found = status.not_found.saturating_add(1)
                        }
                    }
                    if value.failed || !committed {
                        status.failed = status.failed.saturating_add(1);
                    }
                    true
                });
                Ok(())
            }
        }))
        .buffer_unordered(FOLLOW_AVAILABILITY_CONCURRENCY);
        tokio::pin!(work);
        let completed = tokio::time::timeout(FOLLOW_AVAILABILITY_REFRESH_TIMEOUT, async {
            while let Some(result) = work.next().await {
                result?;
            }
            Ok(())
        })
        .await;
        match completed {
            Ok(result) => result,
            Err(_) => {
                leader.status.send_if_modified(|status| {
                    status.truncated = true;
                    true
                });
                Ok(())
            }
        }
    }

    async fn lookup_follow_availability(
        &self,
        account_id_hex: &str,
    ) -> Result<AvailabilityWrite, DirectoryError> {
        let now = self.directory_freshness().now;
        let result = self.lookup_availability_inner(account_id_hex).await;
        match result {
            Ok(value) => self.apply_shared_candidates(account_id_hex, value).await,
            Err(error) if error_is_host_failure(&error) => Err(error),
            Err(_) => Ok(AvailabilityWrite::unknown(now)),
        }
    }

    async fn lookup_availability_inner(
        &self,
        account_id_hex: &str,
    ) -> Result<AvailabilityWrite, DirectoryError> {
        let read_started_at = self.directory_freshness().now;
        let directory = self.clone();
        let account = account_id_hex.to_owned();

        let mut relay_lists =
            blocking_directory_task(move || directory.cached_relay_list_status(&account)).await?;

        let mut source_relays = self.relay_plane.retain_safe_discovered_endpoints(
            relay_lists
                .nip65
                .relays
                .iter()
                .cloned()
                .map(TransportEndpoint)
                .collect(),
            "follow availability KeyPackage fetch",
        );
        if source_relays.is_empty() {
            relay_lists = self
                .fetch_relay_list_status_with_cap(
                    account_id_hex,
                    Vec::new(),
                    Some(MAX_FOLLOW_AVAILABILITY_RELAYS_PER_TARGET),
                )
                .await?;
            source_relays = self.relay_plane.retain_safe_discovered_endpoints(
                relay_lists
                    .nip65
                    .relays
                    .iter()
                    .cloned()
                    .map(TransportEndpoint)
                    .collect(),
                "follow availability KeyPackage fetch",
            );
        }
        let discovery_relays = self.directory_source_relays(&[]);
        let used_safe_nip65 = !source_relays.is_empty();
        if source_relays.is_empty() {
            source_relays = discovery_relays.clone();
        }
        let coverage_truncated =
            used_safe_nip65 && source_relays.len() > MAX_FOLLOW_AVAILABILITY_RELAYS_PER_TARGET;
        source_relays.truncate(MAX_FOLLOW_AVAILABILITY_RELAYS_PER_TARGET);
        if source_relays.is_empty() {
            return Ok(AvailabilityWrite::unknown(self.directory_freshness().now));
        }

        let outcome = self
            .relay_plane
            .fetch_directory_events_with_completion(
                source_relays.clone(),
                key_package_queries(vec![account_id_hex.to_owned()]),
            )
            .await
            .map_err(|error| DirectoryError::RelayDirectory(error.to_string()))?;
        let mut observed_event_ids = outcome
            .records
            .iter()
            .map(|record| record.event.id.clone())
            .collect::<HashSet<_>>();
        self.journal_key_package_records(account_id_hex, &outcome.records)
            .await?;
        if key_package_read_page_full(account_id_hex, &outcome.records) {
            return Ok(AvailabilityWrite::unknown(self.directory_freshness().now));
        }

        let direct_selection = select_key_packages_from_records(
            account_id_hex,
            &outcome.records,
            self.directory_freshness(),
            None,
        );
        let (records, freshness, complete_negative) = if direct_selection
            .as_ref()
            .is_ok_and(|selection| !selection.value.is_empty())
        {
            (outcome.records, self.directory_freshness(), false)
        } else {
            let recovered = self
                .recover_key_package_records(KeyPackageRecoveryRequest {
                    account: account_id_hex,
                    searched: &source_relays,
                    observed: outcome.records,
                    hints: Vec::new(),
                    primary_complete: outcome.complete,
                    // Availability needs only the primary coverage evidence. Candidate
                    // deletion proofs belong to member invitation, not this projection.
                    discovery: &[],
                    requirements: None,
                    fence: None,
                    cached_target: None,
                    wanted: 0,
                })
                .await?;
            observed_event_ids.extend(
                recovered
                    .records
                    .iter()
                    .map(|record| record.event.id.clone()),
            );
            self.journal_key_package_records(account_id_hex, &recovered.records)
                .await?;
            (
                recovered.records,
                recovered.freshness,
                used_safe_nip65 && !coverage_truncated && recovered.cache_evidence.is_some(),
            )
        };
        let selection = select_key_packages_from_records(account_id_hex, &records, freshness, None);
        let checked_at = self.directory_freshness().now;
        match selection {
            Ok(selection) if !selection.value.is_empty() => {
                let mut candidates = selection.value.into_iter();
                let first = candidates.next().expect("selected package");
                let alternatives = candidates.collect();
                let mut value = self.remember_availability(first, checked_at).await?;
                value.alternatives = alternatives;
                Ok(value)
            }
            Ok(selection) if complete_negative && !selection.rejected_future => {
                let error = selection.into_value_or_missing(account_id_hex);
                match error {
                    Err(DirectoryError::MissingKeyPackage { .. }) => Ok(AvailabilityWrite {
                        state: FollowAvailabilityState::NotFound,
                        checked_at: read_started_at,
                        fresh_until: Some(
                            read_started_at
                                .saturating_add(FOLLOW_AVAILABILITY_NEGATIVE_TTL.as_secs()),
                        ),
                        key_package_event_id: None,
                        key_package_id: None,
                        key_package_created_at: None,
                        source: FollowAvailabilitySource::Network,
                        failed: false,
                        observed_event_ids: observed_event_ids.clone(),
                        evidence_revision: 0,
                        alternatives: Vec::new(),
                    }),
                    Err(error) => Err(error),
                    Ok(_) => unreachable!("empty selection reports a missing KeyPackage"),
                }
            }
            Ok(_) => Ok(AvailabilityWrite::unknown(checked_at)),
            Err(DirectoryError::MissingKeyPackage {
                reason: MissingKeyPackageReason::NotFound | MissingKeyPackageReason::ObsoleteOnly,
                ..
            }) if complete_negative => Ok(AvailabilityWrite {
                state: FollowAvailabilityState::NotFound,
                checked_at: read_started_at,
                fresh_until: Some(
                    read_started_at.saturating_add(FOLLOW_AVAILABILITY_NEGATIVE_TTL.as_secs()),
                ),
                key_package_event_id: None,
                key_package_id: None,
                key_package_created_at: None,
                source: FollowAvailabilitySource::Network,
                failed: false,
                observed_event_ids,
                evidence_revision: 0,
                alternatives: Vec::new(),
            }),
            Err(_) => Ok(AvailabilityWrite::unknown(checked_at)),
        }
    }

    async fn apply_shared_candidates(
        &self,
        account_id_hex: &str,
        mut value: AvailabilityWrite,
    ) -> Result<AvailabilityWrite, DirectoryError> {
        let checked_at = value.checked_at;
        let alternatives = std::mem::take(&mut value.alternatives);
        let first = self
            .apply_shared_replacements(account_id_hex, value)
            .await?;
        if first.state == FollowAvailabilityState::Ready || alternatives.is_empty() {
            return Ok(first);
        }
        for fetched in alternatives {
            let candidate = self.remember_availability(fetched, checked_at).await?;
            let candidate = self
                .apply_shared_replacements(account_id_hex, candidate)
                .await?;
            if candidate.state == FollowAvailabilityState::Ready {
                return Ok(candidate);
            }
        }
        Ok(first)
    }

    async fn apply_shared_replacements(
        &self,
        account_id_hex: &str,
        mut value: AvailabilityWrite,
    ) -> Result<AvailabilityWrite, DirectoryError> {
        if value.state == FollowAvailabilityState::Unknown {
            return Ok(value);
        }
        let directory = self.clone();
        let account = account_id_hex.to_owned();
        let PublicKeyPackageEvidenceSnapshot {
            replacements,
            global_eviction,
            barriers,
            watermark,
            revision: evidence_revision,
        } = blocking_directory_task(move || {
            Ok(directory
                .resources
                .shared_storage()?
                .key_package_evidence_snapshot(&account)?)
        })
        .await?;
        let now = self.directory_freshness().now;
        let future_skew_secs = self.config.max_future_skew.as_secs();
        let current = match value.state {
            FollowAvailabilityState::Ready => value
                .key_package_event_id
                .as_deref()
                .zip(value.key_package_created_at)
                .is_some_and(|(event_id, created_at)| {
                    created_at.saturating_add(KEY_PACKAGE_FRESHNESS.as_secs()) > now
                        && barriers.iter().all(|barrier| {
                            if barrier.deleted_event_id.is_none()
                                && Some(&barrier.key_package_id) != value.key_package_id.as_ref()
                            {
                                return true;
                            }
                            barrier_allows(event_id, created_at, barrier)
                        })
                        && watermark.as_ref().is_none_or(|barrier| {
                            watermark_allows(event_id, created_at, now, future_skew_secs, barrier)
                        })
                        && global_eviction.as_ref().is_none_or(|barrier| {
                            watermark_allows(event_id, created_at, now, future_skew_secs, barrier)
                        })
                        && replacements
                            .iter()
                            .filter(|replacement| {
                                Some(&replacement.key_package_id) == value.key_package_id.as_ref()
                            })
                            .all(|replacement| {
                                replacement_allows(event_id, created_at, replacement)
                            })
                }),
            FollowAvailabilityState::NotFound => {
                let read_started_at = value.checked_at;
                let covered = |event_id: &str, observed_at: u64| {
                    observed_at < read_started_at || value.observed_event_ids.contains(event_id)
                };
                replacements
                    .iter()
                    .all(|replacement| covered(&replacement.event_id_hex, replacement.observed_at))
                    && barriers
                        .iter()
                        .all(|barrier| covered(&barrier.event_id_hex, barrier.observed_at))
                    && watermark
                        .as_ref()
                        .is_none_or(|barrier| covered(&barrier.event_id_hex, barrier.observed_at))
                    && global_eviction
                        .as_ref()
                        .is_none_or(|barrier| covered(&barrier.event_id_hex, barrier.observed_at))
            }
            FollowAvailabilityState::Unknown => true,
        };
        if current {
            if value.state == FollowAvailabilityState::NotFound {
                value.checked_at = self.directory_freshness().now;
                value.evidence_revision = evidence_revision;
            }
            Ok(value)
        } else {
            Ok(AvailabilityWrite::unknown(self.directory_freshness().now))
        }
    }

    async fn remember_availability(
        &self,
        fetched: FetchedKeyPackage,
        checked_at: u64,
    ) -> Result<AvailabilityWrite, DirectoryError> {
        let metadata = key_package_metadata(&fetched.key_package)
            .map_err(|error| DirectoryError::InvalidKeyPackageEvent(error.to_string()))?;
        let fresh_until = metadata.not_after.min(
            fetched
                .created_at
                .saturating_add(KEY_PACKAGE_FRESHNESS.as_secs()),
        );
        if fresh_until <= checked_at {
            return Ok(AvailabilityWrite::unknown(checked_at));
        }
        let directory = self.clone();
        let remembered = fetched.clone();
        blocking_directory_task(move || directory.remember_directory_key_package(&remembered))
            .await?;
        Ok(AvailabilityWrite {
            state: FollowAvailabilityState::Ready,
            checked_at,
            fresh_until: Some(fresh_until),
            key_package_event_id: Some(fetched.key_package_event_id),
            key_package_id: Some(fetched.key_package_id),
            key_package_created_at: Some(fetched.created_at),
            source: FollowAvailabilitySource::Network,
            failed: false,
            observed_event_ids: HashSet::new(),
            evidence_revision: 0,
            alternatives: Vec::new(),
        })
    }
}

fn error_is_host_failure(error: &DirectoryError) -> bool {
    matches!(
        error,
        DirectoryError::Storage(_)
            | DirectoryError::Io(_)
            | DirectoryError::Json(_)
            | DirectoryError::Sqlite(_)
            | DirectoryError::BlockingTask(_)
            | DirectoryError::Resource(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use storage_sqlite::{PublicKeyPackageBarrierKind, SqlCipherKey};

    fn account_id(value: u8) -> String {
        format!("{value:064x}")
    }

    fn insert_follow(cache: &DirectoryCache, owner: &str, follow: &str, position: usize) {
        cache
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO directory_user_follows (
                     account_id_hex, follow_account_id_hex, position, updated_at
                 ) VALUES (?1, ?2, ?3, 0)",
                params![owner, follow, position as i64],
            )
            .unwrap();
    }

    fn insert_package(cache: &DirectoryCache, account: &str, event: &str, created_at: u64) {
        cache
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO directory_users (
                     account_id_hex, npub, relay_lists_json, key_package_json, updated_at
                 ) VALUES (?1, 'npub', '{}', ?2, 0)
                 ON CONFLICT(account_id_hex) DO UPDATE SET
                     key_package_json = excluded.key_package_json",
                params![
                    account,
                    serde_json::json!({
                        "key_package_event_id": event,
                        "key_package_id": "slot",
                        "created_at": created_at,
                    })
                    .to_string(),
                ],
            )
            .unwrap();
    }

    fn ready(checked_at: u64, fresh_until: u64, event_id: String) -> AvailabilityWrite {
        AvailabilityWrite {
            state: FollowAvailabilityState::Ready,
            checked_at,
            fresh_until: Some(fresh_until),
            key_package_event_id: Some(event_id),
            key_package_id: Some("slot".into()),
            key_package_created_at: Some(900),
            source: FollowAvailabilitySource::Network,
            failed: false,
            observed_event_ids: HashSet::new(),
            evidence_revision: 0,
            alternatives: Vec::new(),
        }
    }

    fn project_with_watermark(kind: PublicKeyPackageBarrierKind) -> FollowAvailabilityState {
        let event_id = "aa".repeat(32);
        StoredAvailability {
            account_id_hex: account_id(1),
            state: Some("ready".into()),
            checked_at: Some(1_000),
            fresh_until: Some(2_000),
            key_package_event_id: Some(event_id.clone()),
            key_package_id: Some("slot".into()),
            key_package_created_at: Some(900),
            source: Some(1),
            evidence_revision: 0,
            current: Publication {
                event_id: Some(event_id.clone()),
                key_package_id: Some("slot".into()),
                created_at: Some(900),
            },
            shared: None,
            replacements: Vec::new(),
            replacement_evicted_at: Some(1_100),
            global_eviction: None,
            shared_evidence_revision: None,
            barriers: Vec::new(),
            eviction_watermark: Some(PublicKeyPackageBarrierRecord {
                account_id_hex: account_id(1),
                key_package_id: "other-slot".into(),
                event_id_hex: "ff".repeat(32),
                deleted_event_id: None,
                event_created_at: 900,
                observed_at: 1_100,
                kind,
            }),
        }
        .project(1_000, 0)
        .state
    }

    #[test]
    fn watermarks_cover_lost_slots_without_blocking_live_replacements() {
        assert_eq!(
            project_with_watermark(PublicKeyPackageBarrierKind::Replacement),
            FollowAvailabilityState::Ready
        );
        assert_eq!(
            project_with_watermark(PublicKeyPackageBarrierKind::Deletion),
            FollowAvailabilityState::Unknown
        );
    }

    fn project_with_global_eviction(created_at: u64, now: u64) -> FollowAvailabilityState {
        let event_id = "aa".repeat(32);
        StoredAvailability {
            account_id_hex: account_id(1),
            state: Some("ready".into()),
            checked_at: Some(1_000),
            fresh_until: Some((now + 1_000) as i64),
            key_package_event_id: Some(event_id.clone()),
            key_package_id: Some("slot".into()),
            key_package_created_at: Some(created_at as i64),
            source: Some(1),
            evidence_revision: 0,
            current: Publication {
                event_id: Some(event_id.clone()),
                key_package_id: Some("slot".into()),
                created_at: Some(created_at as i64),
            },
            shared: None,
            replacements: Vec::new(),
            replacement_evicted_at: Some(1_100),
            global_eviction: Some(PublicKeyPackageBarrierRecord {
                account_id_hex: String::new(),
                key_package_id: String::new(),
                event_id_hex: "ff".repeat(32),
                deleted_event_id: None,
                event_created_at: 1_000,
                observed_at: 1_100,
                kind: PublicKeyPackageBarrierKind::Deletion,
            }),
            shared_evidence_revision: None,
            barriers: Vec::new(),
            eviction_watermark: Some(PublicKeyPackageBarrierRecord {
                account_id_hex: account_id(1),
                key_package_id: "other-slot".into(),
                event_id_hex: event_id,
                deleted_event_id: None,
                event_created_at: 900,
                observed_at: 1_100,
                kind: PublicKeyPackageBarrierKind::Replacement,
            }),
        }
        .project(now, 0)
        .state
    }

    #[test]
    fn global_fallback_allows_newer_publications() {
        assert_eq!(
            project_with_global_eviction(1_000, 1_000),
            FollowAvailabilityState::Unknown,
            "an equal-timestamp publication stays fenced"
        );
        assert_eq!(
            project_with_global_eviction(1_001, 1_000),
            FollowAvailabilityState::Ready
        );
    }

    #[test]
    fn expired_fence_does_not_restore_stale_ready() {
        assert_eq!(
            project_with_global_eviction(1_000, 1_000 + KEY_PACKAGE_FRESHNESS.as_secs()),
            FollowAvailabilityState::Unknown
        );
    }

    #[test]
    fn discarded_exact_deletion_expires_after_freshness() {
        let barrier = PublicKeyPackageBarrierRecord {
            account_id_hex: account_id(1),
            key_package_id: String::new(),
            event_id_hex: "ff".repeat(32),
            deleted_event_id: None,
            event_created_at: 90,
            observed_at: 1_000,
            kind: PublicKeyPackageBarrierKind::ExactDeletion,
        };
        assert!(!watermark_allows("cc", 1_200, 1_000, 300, &barrier));
        assert!(watermark_allows("bb", 1_301, 1_000, 300, &barrier));
        assert!(!watermark_allows(
            "aa",
            100,
            1_000 + KEY_PACKAGE_FRESHNESS.as_secs() + 299,
            300,
            &barrier,
        ));
        assert!(watermark_allows(
            "aa",
            100,
            1_000 + KEY_PACKAGE_FRESHNESS.as_secs() + 300,
            300,
            &barrier,
        ));
    }

    #[test]
    fn availability_reopen() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("directory.sqlite3");
        let key = SqlCipherKey::raw([0x51; 32]);
        let owner = account_id(1);
        let ready_id = account_id(2);
        let missing_id = account_id(3);
        let unknown_id = account_id(4);
        let event_id = "aa".repeat(32);
        let cache = DirectoryCache::open(path.clone(), &key).unwrap();
        for (position, follow) in [&ready_id, &missing_id, &unknown_id]
            .into_iter()
            .enumerate()
        {
            insert_follow(&cache, &owner, follow, position);
        }
        insert_package(&cache, &ready_id, &event_id, 900);
        assert!(
            cache
                .record_follow_availability(
                    &owner,
                    &ready_id,
                    &ready(1_000, 2_000, event_id.clone())
                )
                .unwrap()
        );
        assert!(
            cache
                .record_follow_availability(
                    &owner,
                    &missing_id,
                    &AvailabilityWrite {
                        state: FollowAvailabilityState::NotFound,
                        checked_at: 1_000,
                        fresh_until: Some(1_500),
                        key_package_event_id: None,
                        key_package_id: None,
                        key_package_created_at: None,
                        source: FollowAvailabilitySource::Network,
                        failed: false,
                        observed_event_ids: HashSet::new(),
                        evidence_revision: 0,
                        alternatives: Vec::new(),
                    },
                )
                .unwrap()
        );

        let first = cache
            .follow_availability_page(&owner, None, 0, 1_200)
            .unwrap();
        assert_eq!(first.rows.len(), 1, "zero clamps to one row");
        assert_eq!(first.rows[0].state, FollowAvailabilityState::Ready);
        assert_eq!(first.next_cursor, Some(ready_id.clone()));
        let second = cache
            .follow_availability_page(&owner, first.next_cursor.as_deref(), 100, 1_200)
            .unwrap();
        assert_eq!(second.next_cursor, None);
        assert_eq!(
            second
                .rows
                .iter()
                .map(|row| (row.account_id_hex.clone(), row.state))
                .collect::<Vec<_>>(),
            vec![
                (missing_id.clone(), FollowAvailabilityState::NotFound),
                (unknown_id.clone(), FollowAvailabilityState::Unknown),
            ]
        );

        drop(cache);
        let cache = DirectoryCache::open(path, &key).unwrap();
        let reopened = cache
            .follow_availability_page(&owner, None, 100, 1_200)
            .unwrap();
        assert_eq!(reopened.rows.len(), 3);
        assert_eq!(reopened.rows[0].state, FollowAvailabilityState::Ready);
        assert_eq!(reopened.rows[1].state, FollowAvailabilityState::NotFound);

        insert_package(&cache, &ready_id, &"bb".repeat(32), 1_100);
        let expiring_id = account_id(5);
        insert_follow(&cache, &owner, &expiring_id, 3);
        insert_package(&cache, &expiring_id, &"dd".repeat(32), 900);
        assert!(
            cache
                .record_follow_availability(
                    &owner,
                    &expiring_id,
                    &ready(1_000, 2_000, "dd".repeat(32)),
                )
                .unwrap()
        );
        assert_eq!(
            cache
                .follow_availability_page(&owner, None, 100, 1_999)
                .unwrap()
                .rows[3]
                .state,
            FollowAvailabilityState::Ready
        );
        assert_eq!(
            cache
                .follow_availability_page(&owner, None, 100, 2_000)
                .unwrap()
                .rows[3]
                .state,
            FollowAvailabilityState::Unknown,
            "MLS not_after is exclusive"
        );
        assert_eq!(
            cache
                .follow_availability_page(&owner, None, 100, 1_500)
                .unwrap()
                .rows[1]
                .state,
            FollowAvailabilityState::Unknown,
            "a completed negative expires"
        );
        insert_package(&cache, &missing_id, &"cc".repeat(32), 1_100);
        assert_eq!(
            cache
                .follow_availability_page(&owner, None, 100, 1_200)
                .unwrap()
                .rows[1]
                .state,
            FollowAvailabilityState::Unknown,
            "a newer publication invalidates a negative before its TTL"
        );

        cache
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM directory_user_follows
                 WHERE account_id_hex = ?1 AND follow_account_id_hex = ?2",
                params![owner, ready_id],
            )
            .unwrap();
        cache.prune_follow_availability(&owner).unwrap();
        let remaining = cache
            .follow_availability_page(&owner, None, 100, 1_200)
            .unwrap();
        assert_eq!(
            remaining
                .rows
                .iter()
                .map(|row| row.account_id_hex.clone())
                .collect::<Vec<_>>(),
            vec![missing_id, unknown_id, expiring_id]
        );
        let orphaned: i64 = cache
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM follow_availability WHERE follow_account_id_hex = ?1",
                [ready_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(orphaned, 0);
    }

    #[test]
    fn availability_requires_follow() {
        let root = tempfile::tempdir().unwrap();
        let cache = DirectoryCache::open(
            root.path().join("directory.sqlite3"),
            &SqlCipherKey::raw([0x52; 32]),
        )
        .unwrap();
        assert!(
            !cache
                .record_follow_availability(
                    &account_id(1),
                    &account_id(2),
                    &AvailabilityWrite::unknown(1_000),
                )
                .unwrap()
        );
        assert!(
            cache
                .follow_availability_page(&account_id(1), None, 100, 1_000)
                .unwrap()
                .rows
                .is_empty()
        );
    }

    #[test]
    fn availability_rotation() {
        let root = tempfile::tempdir().unwrap();
        let cache = DirectoryCache::open(
            root.path().join("directory.sqlite3"),
            &SqlCipherKey::raw([0x53; 32]),
        )
        .unwrap();
        let owner = account_id(1);
        for index in 1..=101_u8 {
            let follow = account_id(index);
            insert_follow(&cache, &owner, &follow, usize::from(index));
            if index <= 100 {
                assert!(
                    cache
                        .record_follow_availability(
                            &owner,
                            &follow,
                            &AvailabilityWrite::unknown(1_000),
                        )
                        .unwrap()
                );
            }
        }
        let follows = cache.direct_follows(&owner).unwrap();
        assert_eq!(follows.first(), Some(&account_id(101)));
    }
}
