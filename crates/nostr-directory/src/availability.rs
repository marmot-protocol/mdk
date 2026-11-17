//! Bounded, account-local Marmot availability for direct follows.
//!
//! The cache belongs to the selected local account, so these rows never enter
//! the shared public directory tier. Only publication metadata is persisted;
//! KeyPackage bytes stay in the existing directory record.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cgka_engine::key_package::key_package_metadata;
use cgka_traits::TransportEndpoint;
use futures::StreamExt;
use rusqlite::params;
use tokio::sync::watch;

use super::cache::DirectoryCache;
use super::error::{DirectoryError, MissingKeyPackageReason, blocking_directory_task};
use super::observer::DirectoryObserver;
use super::published_records::{
    key_package_queries, key_package_read_page_full, select_key_packages_from_records,
};
use super::resources::{DirectoryAccount, DirectoryResources};
use super::{Directory, FetchedKeyPackage};

pub const MAX_FOLLOW_AVAILABILITY_TARGETS: usize = 100;
pub const MAX_FOLLOW_AVAILABILITY_PAGE_SIZE: usize = 100;
pub const FOLLOW_AVAILABILITY_CONCURRENCY: usize = 4;
pub const FOLLOW_AVAILABILITY_TARGET_TIMEOUT: Duration = Duration::from_secs(10);
pub const FOLLOW_AVAILABILITY_REFRESH_TIMEOUT: Duration = Duration::from_secs(300);
pub const FOLLOW_AVAILABILITY_REFRESH_CADENCE: Duration = Duration::from_secs(60);
pub const FOLLOW_AVAILABILITY_NEGATIVE_TTL: Duration = Duration::from_secs(15 * 60);
pub const MAX_FOLLOW_AVAILABILITY_RELAY_FETCHES: usize = 2 * MAX_FOLLOW_AVAILABILITY_TARGETS;

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

#[derive(Clone)]
struct AvailabilityWrite {
    state: FollowAvailabilityState,
    checked_at: u64,
    fresh_until: Option<u64>,
    key_package_event_id: Option<String>,
    source: FollowAvailabilitySource,
    failed: bool,
}

impl AvailabilityWrite {
    fn unknown(checked_at: u64) -> Self {
        Self {
            state: FollowAvailabilityState::Unknown,
            checked_at,
            fresh_until: None,
            key_package_event_id: None,
            source: FollowAvailabilitySource::None,
            failed: true,
        }
    }
}

impl DirectoryCache {
    fn direct_follows(&self, account_id_hex: &str) -> Result<Vec<String>, DirectoryError> {
        let conn = self.lock()?;
        let mut statement = conn.prepare(
            "SELECT follow_account_id_hex FROM directory_user_follows
             WHERE account_id_hex = ?1 ORDER BY follow_account_id_hex",
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
                 key_package_event_id, source, updated_at
             )
             SELECT ?2, ?3, ?4, ?5, ?6, ?7, ?4
             WHERE EXISTS (
                 SELECT 1 FROM directory_user_follows
                 WHERE account_id_hex = ?1 AND follow_account_id_hex = ?2
             )
             ON CONFLICT(follow_account_id_hex) DO UPDATE SET
                 state = excluded.state,
                 checked_at = excluded.checked_at,
                 fresh_until = excluded.fresh_until,
                 key_package_event_id = excluded.key_package_event_id,
                 source = excluded.source,
                 updated_at = excluded.updated_at",
            params![
                account_id_hex,
                follow_account_id_hex,
                availability_state_token(value.state),
                value.checked_at as i64,
                value.fresh_until.map(|timestamp| timestamp as i64),
                value.key_package_event_id,
                availability_source_token(value.source),
            ],
        )?;
        Ok(changed != 0)
    }

    fn follow_availability_page(
        &self,
        account_id_hex: &str,
        after: Option<&str>,
        limit: usize,
        now: u64,
    ) -> Result<FollowAvailabilityPage, DirectoryError> {
        let limit = limit.clamp(1, MAX_FOLLOW_AVAILABILITY_PAGE_SIZE);
        let conn = self.lock()?;
        let mut statement = conn.prepare(
            "SELECT follows.follow_account_id_hex,
                    availability.state, availability.checked_at,
                    availability.fresh_until, availability.key_package_event_id,
                    availability.source,
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
                (limit + 1) as i64
            ],
            |row| {
                Ok(StoredAvailability {
                    account_id_hex: row.get(0)?,
                    state: row.get(1)?,
                    checked_at: row.get(2)?,
                    fresh_until: row.get(3)?,
                    key_package_event_id: row.get(4)?,
                    source: row.get(5)?,
                    current_event_id: row.get(6)?,
                    current_created_at: row.get(7)?,
                })
            },
        )?;
        let mut stored = rows.collect::<Result<Vec<_>, _>>()?;
        let has_more = stored.len() > limit;
        stored.truncate(limit);
        let next_cursor = has_more
            .then(|| stored.last().map(|row| row.account_id_hex.clone()))
            .flatten();
        let rows = stored.into_iter().map(|row| row.project(now)).collect();
        Ok(FollowAvailabilityPage { rows, next_cursor })
    }

    fn invalidate_follow(
        &self,
        follow_account_id_hex: &str,
        event_id: &str,
        created_at: u64,
        now: u64,
    ) -> Result<(), DirectoryError> {
        self.lock()?.execute(
            "UPDATE follow_availability
             SET state = 'unknown', checked_at = ?4, fresh_until = NULL,
                 key_package_event_id = NULL, source = 0, updated_at = ?4
             WHERE follow_account_id_hex = ?1
               AND key_package_event_id IS NOT NULL
               AND key_package_event_id != ?2
               AND EXISTS (
                   SELECT 1 FROM directory_users
                   WHERE account_id_hex = ?1
                     AND COALESCE(json_extract(key_package_json, '$.created_at'), 0) <= ?3
               )",
            params![
                follow_account_id_hex,
                event_id,
                created_at as i64,
                now as i64
            ],
        )?;
        Ok(())
    }
}

struct StoredAvailability {
    account_id_hex: String,
    state: Option<String>,
    checked_at: Option<i64>,
    fresh_until: Option<i64>,
    key_package_event_id: Option<String>,
    source: Option<i64>,
    current_event_id: Option<String>,
    current_created_at: Option<i64>,
}

impl StoredAvailability {
    fn project(self, now: u64) -> FollowAvailability {
        let checked_at = self.checked_at.and_then(|value| u64::try_from(value).ok());
        let fresh_until = self.fresh_until.and_then(|value| u64::try_from(value).ok());
        let source = match self.source {
            Some(1) => FollowAvailabilitySource::Network,
            _ => FollowAvailabilitySource::None,
        };
        let state = match self.state.as_deref() {
            Some("ready")
                if fresh_until.is_some_and(|expiry| expiry > now)
                    && self.key_package_event_id.is_some()
                    && self.current_event_id == self.key_package_event_id =>
            {
                FollowAvailabilityState::Ready
            }
            Some("not_found")
                if self
                    .current_created_at
                    .and_then(|value| u64::try_from(value).ok())
                    < checked_at =>
            {
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
        self.status.send_if_modified(|status| {
            status.phase = phase;
            true
        });
        let mut operations = self.operations.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = operations.by_account.get_mut(&self.account_id_hex)
            && entry.status.borrow().operation_id == Some(self.operation_id)
        {
            entry.finished_at = Some(Instant::now());
        }
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
        cache.follow_availability_page(&account.account_id_hex, after, limit, now)
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
        entry.cancel.send(true).is_ok()
    }

    pub(crate) fn invalidate_availability(
        &self,
        account_id_hex: &str,
        event_id: &str,
        created_at: u64,
    ) -> Result<(), DirectoryError> {
        let now = self.directory_freshness().now;
        for cache in self.resources.current_caches()? {
            cache.invalidate_follow(account_id_hex, event_id, created_at, now)?;
        }
        Ok(())
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
                return RefreshAdmission::Follower(entry.status.subscribe());
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
                let result = self.run_availability_refresh(account, leader.clone()).await;
                match result {
                    Ok(()) => {
                        let phase = if leader.is_cancelled() {
                            FollowAvailabilityRefreshPhase::Cancelled
                        } else if leader.status.borrow().truncated
                            || leader.status.borrow().failed != 0
                        {
                            FollowAvailabilityRefreshPhase::Partial
                        } else {
                            FollowAvailabilityRefreshPhase::Complete
                        };
                        leader.finish(phase);
                    }
                    Err(error) => {
                        leader.finish(FollowAvailabilityRefreshPhase::Failed);
                        return Err(error);
                    }
                }
                Ok(leader.status.borrow().clone())
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
                if leader.is_cancelled() {
                    return Ok(());
                }
                leader.status.send_if_modified(|status| {
                    status.completed = status.completed.saturating_add(1);
                    match value.state {
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
                    if value.failed {
                        status.failed = status.failed.saturating_add(1);
                    }
                    if !committed {
                        status.truncated = true;
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
            Ok(value) => Ok(value),
            Err(error) if error_is_host_failure(&error) => Err(error),
            Err(_) => Ok(AvailabilityWrite::unknown(now)),
        }
    }

    async fn lookup_availability_inner(
        &self,
        account_id_hex: &str,
    ) -> Result<AvailabilityWrite, DirectoryError> {
        let directory = self.clone();
        let account = account_id_hex.to_owned();
        let mut relay_lists =
            blocking_directory_task(move || directory.cached_relay_list_status(&account)).await?;
        if relay_lists.nip65.relays.is_empty() {
            relay_lists = self
                .fetch_relay_list_status(account_id_hex, Vec::new())
                .await?;
        }
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
            source_relays = self.directory_source_relays(&[]);
        }
        if source_relays.is_empty() {
            return Ok(AvailabilityWrite::unknown(self.directory_freshness().now));
        }
        let outcome = self
            .relay_plane
            .fetch_directory_events_with_completion(
                source_relays,
                key_package_queries(vec![account_id_hex.to_owned()]),
            )
            .await
            .map_err(|error| DirectoryError::RelayDirectory(error.to_string()))?;
        if key_package_read_page_full(account_id_hex, &outcome.records) {
            return Ok(AvailabilityWrite::unknown(self.directory_freshness().now));
        }
        let selection = select_key_packages_from_records(
            account_id_hex,
            &outcome.records,
            self.directory_freshness(),
            None,
        );
        let checked_at = self.directory_freshness().now;
        match selection {
            Ok(selection) if !selection.value.is_empty() => {
                let fetched = selection
                    .value
                    .into_iter()
                    .next()
                    .expect("selected package");
                self.remember_availability(fetched, checked_at).await
            }
            Ok(selection) if outcome.complete => {
                let error = selection.into_value_or_missing(account_id_hex);
                match error {
                    Err(DirectoryError::MissingKeyPackage { .. }) => Ok(AvailabilityWrite {
                        state: FollowAvailabilityState::NotFound,
                        checked_at,
                        fresh_until: Some(
                            checked_at.saturating_add(FOLLOW_AVAILABILITY_NEGATIVE_TTL.as_secs()),
                        ),
                        key_package_event_id: None,
                        source: FollowAvailabilitySource::Network,
                        failed: false,
                    }),
                    Err(error) => Err(error),
                    Ok(_) => unreachable!("empty selection reports a missing KeyPackage"),
                }
            }
            Ok(_) => Ok(AvailabilityWrite::unknown(checked_at)),
            Err(DirectoryError::MissingKeyPackage {
                reason: MissingKeyPackageReason::NotFound | MissingKeyPackageReason::ObsoleteOnly,
                ..
            }) if outcome.complete => Ok(AvailabilityWrite {
                state: FollowAvailabilityState::NotFound,
                checked_at,
                fresh_until: Some(
                    checked_at.saturating_add(FOLLOW_AVAILABILITY_NEGATIVE_TTL.as_secs()),
                ),
                key_package_event_id: None,
                source: FollowAvailabilitySource::Network,
                failed: false,
            }),
            Err(_) => Ok(AvailabilityWrite::unknown(checked_at)),
        }
    }

    async fn remember_availability(
        &self,
        fetched: FetchedKeyPackage,
        checked_at: u64,
    ) -> Result<AvailabilityWrite, DirectoryError> {
        let metadata = key_package_metadata(&fetched.key_package)
            .map_err(|error| DirectoryError::InvalidKeyPackageEvent(error.to_string()))?;
        if metadata.not_after <= checked_at {
            return Ok(AvailabilityWrite::unknown(checked_at));
        }
        let directory = self.clone();
        let remembered = fetched.clone();
        blocking_directory_task(move || directory.remember_directory_key_package(&remembered))
            .await?;
        Ok(AvailabilityWrite {
            state: FollowAvailabilityState::Ready,
            checked_at,
            fresh_until: Some(metadata.not_after),
            key_package_event_id: Some(fetched.key_package_event_id),
            source: FollowAvailabilitySource::Network,
            failed: false,
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
    use storage_sqlite::SqlCipherKey;

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
            source: FollowAvailabilitySource::Network,
            failed: false,
        }
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
                        source: FollowAvailabilitySource::Network,
                        failed: false,
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
        assert_eq!(
            cache
                .follow_availability_page(&owner, None, 1, 1_200)
                .unwrap()
                .rows[0]
                .state,
            FollowAvailabilityState::Unknown,
            "a cached replacement invalidates the previous ready row"
        );
        insert_package(&cache, &ready_id, &event_id, 900);
        assert_eq!(
            cache
                .follow_availability_page(&owner, None, 1, 2_000)
                .unwrap()
                .rows[0]
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
            vec![missing_id, unknown_id]
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
}
