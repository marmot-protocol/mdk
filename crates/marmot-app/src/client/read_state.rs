//! A: the account's published read state (mdk#3273).
//!
//! At each quiescent point the account worker publishes an immutable,
//! versioned copy of the answers that moved host reads give, behind a
//! `watch` of `Arc`s. Each answer is computed by today's read code on the
//! writer at the moment of publishing, so a read that answers from one
//! version never mixes two states. The account reads answer from it (PR 3):
//! a host takes the worker's lane as before, then reads one version through
//! its [`ReadStateReader`] instead of queueing on the worker.
//!
//! Cost: account answers are rebuilt at every publish, except the owned
//! KeyPackages, whose read re-checks every stored bundle's signatures. That
//! list, and each group entry, is reused only while its validity holds: a
//! typed value the build returns with the answers, recording what they were
//! read at and how long they hold (`KeyPackagesValidity`, `EntryValidity`).
//! The list is keyed on its own write count, which only its inputs move, so a
//! send keeps it.
//! Reuse checks that value alone, so every input of a reused answer must be
//! either a write those counts see or a field of its validity. App components
//! are reused while the group's hydrated generation holds. A publish whose
//! answers all equal the published ones keeps the current version, rebuilt
//! group entries included: a rebuild that finds its answers unchanged keeps
//! the published entry. Writes are counted across every connection this
//! process has open on the account database; another process's writes are
//! not, and the root runtime lease keeps other runtimes off the database
//! while this one runs.
//!
//! Each version carries `valid_until`, the earliest time an answer in it can
//! change with no write. The worker publishes when it passes
//! ([`AppClient::read_state_deadline`]); a deadline that passes inside a long
//! unit is published at that unit's next quiescent point, as a write in it
//! would be.
//!
//! Left out: profiles, which a read attaches at read time, and secrets.
//! Errors are kept as `Arc<AppError>`: `AppError` is not `Clone`. A read
//! serves an exact copy of a failure it can rebuild ([`reissue`]); any other
//! published failure is answered by the worker, as before.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cgka_traits::app_components::AppComponentId;
use cgka_traits::engine::KeyPackage;
use cgka_traits::error::EngineError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::types::{GroupId, MemberId};
use cgka_traits::{
    GroupMaintenanceStatus, KeyPackageLifecycleState, PeriodicMaintenancePolicy, StorageError,
    Timestamp,
};
use marmot_session::{GroupChangeGeneration, GroupMaintenanceRows, WallClockWindow};
use storage_sqlite::SelfMembership;
use tokio::sync::watch;

use super::AppClient;
use crate::groups::AppGroupRosterSession;
use crate::{
    AppError, AppGroupMemberIds, AppGroupMemberRecord, AppGroupMlsState, AppGroupRecord,
    AppPreparedGroupImageUpload, AppPreparedGroupImageUploadState, AppQuarantinedGroup,
    BackupRestoreStatus, BackupRestoreWatch, ChatHistoryImport, GroupCommitDelivery,
};

const TRACE_TARGET: &str = "marmot_app::read_state";

/// An answer as A holds it.
pub(crate) type ReadAnswer<T> = Result<T, Arc<AppError>>;

/// The in-flight prepared group image uploads, shared with the worker's media
/// context; their statuses read `Uploading`.
pub(crate) type UploadsInFlight = Arc<Mutex<HashSet<String>>>;

/// One published version of A.
#[derive(Debug)]
pub(crate) struct ReadState {
    /// Moves with every published change; never reused.
    pub(crate) version: u64,
    /// The earliest time an answer in this version can change with no
    /// write: a commit-delivery deadline (on the account's wall clock) or an
    /// owned KeyPackage's lifetime bound (on the system clock OpenMLS checks
    /// lifetimes against). The account's wall clock is that system clock
    /// except where a test injects one. The worker publishes when it passes.
    pub(crate) valid_until: Option<Timestamp>,
    pub(crate) account: Arc<AccountAnswers>,
    /// One entry per group in the account's group mirror.
    pub(crate) groups: Arc<HashMap<GroupId, Arc<GroupAnswers>>>,
}

/// The per-account answers.
#[derive(Debug)]
pub(crate) struct AccountAnswers {
    pub(crate) quarantined_groups: Vec<AppQuarantinedGroup>,
    pub(crate) key_package_maintenance_status: ReadAnswer<Option<KeyPackageLifecycleState>>,
    pub(crate) durably_owned_key_packages: ReadAnswer<Vec<KeyPackage>>,
    pub(crate) periodic_maintenance_policy: ReadAnswer<PeriodicMaintenancePolicy>,
    #[cfg_attr(not(test), allow(dead_code))] // Only the oracle reads it.
    pub(crate) maintenance_paused: bool,
    pub(crate) backup_restore_status: BackupRestoreStatus,
    /// A receiver of the client's backup-restore progress channel, which
    /// `WatchBackupRestore` hands out a copy of.
    pub(crate) backup_restore_updates: watch::Receiver<BackupRestoreStatus>,
    /// With the in-flight upload overlay applied.
    #[cfg_attr(not(test), allow(dead_code))] // Account reads answer from A (mdk#3273 PR 5).
    pub(crate) prepared_group_images: ReadAnswer<Vec<AppPreparedGroupImageUpload>>,
    #[cfg_attr(not(test), allow(dead_code))] // Account reads answer from A (mdk#3273 PR 5).
    pub(crate) started_fresh: ReadAnswer<bool>,
    #[cfg_attr(not(test), allow(dead_code))] // Account reads answer from A (mdk#3273 PR 5).
    pub(crate) chat_history_imports: ReadAnswer<Vec<ChatHistoryImport>>,
}

impl AccountAnswers {
    /// Whether every answer equals `other`'s, failures compared by their
    /// debug form as the oracle compares them.
    fn same_as(&self, other: &Self) -> bool {
        let Self {
            quarantined_groups,
            key_package_maintenance_status,
            durably_owned_key_packages,
            periodic_maintenance_policy,
            maintenance_paused,
            backup_restore_status,
            backup_restore_updates,
            prepared_group_images,
            started_fresh,
            chat_history_imports,
        } = self;
        *quarantined_groups == other.quarantined_groups
            && same_answer(
                key_package_maintenance_status,
                &other.key_package_maintenance_status,
                PartialEq::eq,
            )
            && same_answer(
                durably_owned_key_packages,
                &other.durably_owned_key_packages,
                |ours, theirs| {
                    // `KeyPackage` equality leaves out the transport source.
                    ours == theirs
                        && ours
                            .iter()
                            .zip(theirs)
                            .all(|(ours, theirs)| ours.source == theirs.source)
                },
            )
            && same_answer(
                periodic_maintenance_policy,
                &other.periodic_maintenance_policy,
                PartialEq::eq,
            )
            && *maintenance_paused == other.maintenance_paused
            && *backup_restore_status == other.backup_restore_status
            && backup_restore_updates.same_channel(&other.backup_restore_updates)
            && same_answer(
                prepared_group_images,
                &other.prepared_group_images,
                PartialEq::eq,
            )
            && same_answer(started_fresh, &other.started_fresh, PartialEq::eq)
            && same_answer(
                chat_history_imports,
                &other.chat_history_imports,
                PartialEq::eq,
            )
    }
}

/// Whether two answers are the same: two successes `equal`, or two failures
/// with the same debug form.
fn same_answer<T>(
    ours: &ReadAnswer<T>,
    theirs: &ReadAnswer<T>,
    equal: impl FnOnce(&T, &T) -> bool,
) -> bool {
    match (ours, theirs) {
        (Ok(ours), Ok(theirs)) => equal(ours, theirs),
        (Err(ours), Err(theirs)) => format!("{ours:?}") == format!("{theirs:?}"),
        _ => false,
    }
}

/// The answers for one group in the mirror.
#[derive(Debug)]
pub(crate) struct GroupAnswers {
    /// The group's mirror record.
    pub(crate) record: AppGroupRecord,
    /// Whether the host may see the group: false for a device group.
    pub(crate) host_may_see: bool,
    /// Member accounts and their device counts, without profiles.
    pub(crate) members: ReadAnswer<Vec<(MemberId, u32)>>,
    /// The stored self membership the roster overlays on the mirror record.
    pub(crate) self_membership: ReadAnswer<Option<SelfMembership>>,
    pub(crate) mls_state: ReadAnswer<AppGroupMlsState>,
    pub(crate) commit_delivery: ReadAnswer<Option<GroupCommitDelivery>>,
    pub(crate) maintenance_status: ReadAnswer<GroupMaintenanceStatus>,
    /// Every app-owned component the group holds, in id order.
    pub(crate) app_components: ReadAnswer<Vec<(AppComponentId, Vec<u8>)>>,
}

impl GroupAnswers {
    /// Whether every answer equals `other`'s, failures compared by their
    /// debug form as the oracle compares them: a rebuilt entry that is the
    /// same keeps the published one, and the version (mdk#3273 PR 3).
    fn same_as(&self, other: &Self) -> bool {
        let Self {
            record,
            host_may_see,
            members,
            self_membership,
            mls_state,
            commit_delivery,
            maintenance_status,
            app_components,
        } = self;
        *record == other.record
            && *host_may_see == other.host_may_see
            && same_answer(members, &other.members, PartialEq::eq)
            && same_answer(self_membership, &other.self_membership, PartialEq::eq)
            && same_answer(mls_state, &other.mls_state, PartialEq::eq)
            && same_answer(commit_delivery, &other.commit_delivery, PartialEq::eq)
            && same_answer(maintenance_status, &other.maintenance_status, PartialEq::eq)
            && same_answer(app_components, &other.app_components, PartialEq::eq)
    }
}

fn unknown_group(group_id: &GroupId) -> Arc<AppError> {
    Arc::new(AppError::UnknownGroup(hex::encode(group_id.as_slice())))
}

#[cfg_attr(not(test), allow(dead_code))] // Group reads answer from A (mdk#3273 PRs 4–5).
fn with_profiles(
    members: &[(MemberId, u32)],
    profiles: &HashMap<String, String>,
) -> Vec<AppGroupMemberRecord> {
    members
        .iter()
        .map(|(member_id, device_count)| {
            let member_id_hex = hex::encode(member_id.as_slice());
            let account = profiles.get(&member_id_hex).cloned();
            AppGroupMemberRecord {
                member_id_hex,
                local: account.is_some(),
                account,
                device_count: *device_count,
            }
        })
        .collect()
}

/// The answers the moved reads give, from this version alone.
#[cfg_attr(not(test), allow(dead_code))] // Group reads answer from A (mdk#3273 PRs 4–5).
impl ReadState {
    fn group(&self, group_id: &GroupId) -> ReadAnswer<&GroupAnswers> {
        self.groups
            .get(group_id)
            .map(Arc::as_ref)
            .ok_or_else(|| unknown_group(group_id))
    }

    /// `Members`: `profiles` is loaded at read time, before anything else.
    pub(crate) fn members(
        &self,
        group_id: &GroupId,
        profiles: &HashMap<String, String>,
    ) -> ReadAnswer<Vec<AppGroupMemberRecord>> {
        let members = self.group(group_id)?.members.as_ref().map_err(Arc::clone)?;
        Ok(with_profiles(members, profiles))
    }

    /// `MemberIdsPage`.
    pub(crate) fn member_ids_page(
        &self,
        group_ids: &[GroupId],
    ) -> ReadAnswer<Vec<AppGroupMemberIds>> {
        group_ids
            .iter()
            .map(|group_id| {
                let group = self.group(group_id)?;
                let members = group.members.as_ref().map_err(Arc::clone)?;
                Ok(AppGroupMemberIds {
                    group_id_hex: hex::encode(group_id.as_slice()),
                    member_ids_hex: members
                        .iter()
                        .map(|(member_id, _)| hex::encode(member_id.as_slice()))
                        .collect(),
                    admin_ids_hex: group.record.admin_policy.admins.clone(),
                })
            })
            .collect()
    }

    /// `GroupRoster`: `profiles` runs once the group is known, as today.
    pub(crate) fn group_roster(
        &self,
        group_id: &GroupId,
        profiles: impl FnOnce() -> Result<HashMap<String, String>, AppError>,
    ) -> ReadAnswer<AppGroupRosterSession> {
        let group = self.group(group_id)?;
        let profiles = profiles().map_err(Arc::new)?;
        let members = with_profiles(group.members.as_ref().map_err(Arc::clone)?, &profiles);
        let mut group_record = group.record.clone();
        if let Some(membership) = group.self_membership.as_ref().map_err(Arc::clone)? {
            group_record.self_membership = *membership;
        }
        let mls_state = group.mls_state.clone()?;
        Ok(AppGroupRosterSession {
            group_record,
            members,
            mls_state,
        })
    }

    /// `GroupMlsState`.
    pub(crate) fn group_mls_state(&self, group_id: &GroupId) -> ReadAnswer<AppGroupMlsState> {
        self.group(group_id)?.mls_state.clone()
    }

    /// `GroupAppComponent`.
    pub(crate) fn group_app_component(
        &self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> ReadAnswer<Option<Vec<u8>>> {
        super::validate_app_component(component_id, &[]).map_err(Arc::new)?;
        let components = self
            .group(group_id)?
            .app_components
            .as_ref()
            .map_err(Arc::clone)?;
        Ok(components
            .iter()
            .find(|(id, _)| *id == component_id)
            .map(|(_, data)| data.clone()))
    }

    /// `GroupCommitDelivery`.
    pub(crate) fn group_commit_delivery(
        &self,
        group_id: &GroupId,
    ) -> ReadAnswer<Option<GroupCommitDelivery>> {
        self.group(group_id)?.commit_delivery.clone()
    }

    /// `MaintenanceStatus`.
    pub(crate) fn maintenance_status(
        &self,
        group_id: &GroupId,
    ) -> ReadAnswer<GroupMaintenanceStatus> {
        self.group(group_id)?.maintenance_status.clone()
    }

    /// Whether the host may see a group in the mirror; `None` outside it,
    /// where every group read already answers `UnknownGroup`.
    pub(crate) fn host_may_see(&self, group_id: &GroupId) -> Option<bool> {
        self.groups.get(group_id).map(|group| group.host_may_see)
    }

    /// `PreparedGroupImageStatus`.
    pub(crate) fn prepared_group_image_status(
        &self,
        upload_id: &str,
    ) -> ReadAnswer<AppPreparedGroupImageUpload> {
        self.account
            .prepared_group_images
            .as_ref()
            .map_err(Arc::clone)?
            .iter()
            .find(|status| status.upload_id == upload_id)
            .cloned()
            .ok_or_else(|| {
                Arc::new(AppError::InvalidEncryptedMedia(
                    "prepared group image upload was not found".into(),
                ))
            })
    }
}

/// The account reads that answer from A (mdk#3273 PR 3), from this version
/// alone.
impl ReadState {
    /// `QuarantinedGroups`.
    pub(crate) fn quarantined_groups(&self) -> Vec<AppQuarantinedGroup> {
        self.account.quarantined_groups.clone()
    }

    /// `KeyPackageMaintenanceStatus`.
    pub(crate) fn key_package_maintenance_status(
        &self,
    ) -> ReadAnswer<Option<KeyPackageLifecycleState>> {
        self.account.key_package_maintenance_status.clone()
    }

    /// `DurablyOwnedKeyPackages`.
    pub(crate) fn durably_owned_key_packages(&self) -> ReadAnswer<Vec<KeyPackage>> {
        self.account.durably_owned_key_packages.clone()
    }

    /// `PeriodicMaintenancePolicy`.
    pub(crate) fn periodic_maintenance_policy(&self) -> ReadAnswer<PeriodicMaintenancePolicy> {
        self.account.periodic_maintenance_policy.clone()
    }

    /// `BackupRestoreStatus`.
    pub(crate) fn backup_restore_status(&self) -> BackupRestoreStatus {
        self.account.backup_restore_status.clone()
    }

    /// `WatchBackupRestore`: a receiver of the client's progress channel
    /// that has seen the status published here, as subscribing at this
    /// publish gave. A change sent since then is still news to it.
    pub(crate) fn watch_backup_restore(&self) -> BackupRestoreWatch {
        BackupRestoreWatch {
            receiver: self.account.backup_restore_updates.clone(),
        }
    }
}

/// An exact copy of a published answer for the host, or `None` when it is a
/// failure [`reissue_error`] cannot copy: the caller then asks the worker.
pub(crate) fn reissue<T>(answer: ReadAnswer<T>) -> Option<Result<T, AppError>> {
    match answer {
        Ok(value) => Some(Ok(value)),
        Err(error) => reissue_error(&error).map(Err),
    }
}

/// An exact copy of `error`, for the failures the moved reads give whose
/// payloads can be copied: an unknown group in the mirror or the engine, a
/// group not hydrated yet, and a storage failure, from the app or the engine.
/// An engine failure keeps its wrapping, whether the account or its session
/// raised it. Any other failure (SQLite, I/O, JSON, the rest of the engine's)
/// has no copy, so it is never rebuilt into a different error.
pub(crate) fn reissue_error(error: &AppError) -> Option<AppError> {
    use marmot_session::{AccountError, SessionError};
    fn copy_engine(engine: &EngineError) -> Option<EngineError> {
        match engine {
            EngineError::UnknownGroup(group) => Some(EngineError::UnknownGroup(group.clone())),
            EngineError::GroupNotHydrated(group) => {
                Some(EngineError::GroupNotHydrated(group.clone()))
            }
            EngineError::Storage(storage) => Some(EngineError::Storage(storage.clone())),
            _ => None,
        }
    }
    match error {
        AppError::UnknownGroup(group) => Some(AppError::UnknownGroup(group.clone())),
        AppError::Storage(storage) => Some(AppError::Storage(storage.clone())),
        AppError::Account(AccountError::Engine(engine)) => {
            copy_engine(engine).map(|engine| AppError::Account(AccountError::Engine(engine)))
        }
        AppError::Account(AccountError::Session(SessionError::Engine(engine))) => {
            copy_engine(engine).map(|engine| {
                AppError::Account(AccountError::Session(SessionError::Engine(engine)))
            })
        }
        _ => None,
    }
}

/// The failure every moved read gives once account storage is closed.
fn storage_closed_error() -> AppError {
    AppError::Storage(StorageError::Closed(
        "account read state unavailable: app storage is closed".to_owned(),
    ))
}

/// A host's handle on one account worker's A, carried by the worker's lane.
#[derive(Clone, Debug)]
pub(crate) struct ReadStateReader {
    receiver: watch::Receiver<Arc<ReadState>>,
}

/// The worker's half of A's channel, which its publisher sends on.
pub(crate) struct ReadStateSender(watch::Sender<Arc<ReadState>>);

/// A new channel for one account worker's A, holding the empty version 0
/// until the worker's first publish.
pub(crate) fn read_state_channel() -> (ReadStateSender, ReadStateReader) {
    let (sender, receiver) = watch::channel(Arc::new(ReadState {
        version: 0,
        valid_until: None,
        account: Arc::new(AccountAnswers {
            quarantined_groups: Vec::new(),
            key_package_maintenance_status: Ok(None),
            durably_owned_key_packages: Ok(Vec::new()),
            periodic_maintenance_policy: Ok(PeriodicMaintenancePolicy::default()),
            maintenance_paused: false,
            backup_restore_status: BackupRestoreStatus::default(),
            backup_restore_updates: watch::channel(BackupRestoreStatus::default()).1,
            prepared_group_images: Ok(Vec::new()),
            started_fresh: Ok(false),
            chat_history_imports: Ok(Vec::new()),
        }),
        groups: Arc::new(HashMap::new()),
    }));
    (ReadStateSender(sender), ReadStateReader { receiver })
}

/// A reader whose worker never publishes, so every read is sent to the
/// worker: for tests that hand-build a worker's lane.
#[cfg(test)]
impl Default for ReadStateReader {
    fn default() -> Self {
        read_state_channel().1
    }
}

impl ReadStateReader {
    /// A receiver of every version this reader sees, for tests that await
    /// one.
    #[cfg(test)]
    pub(crate) fn subscribe(&self) -> watch::Receiver<Arc<ReadState>> {
        self.receiver.clone()
    }

    /// The version a moved read answers from, or `None` before the worker's
    /// first publish, when the read is sent to the worker. Storage closed is
    /// checked after the version is taken and before any of its answers is
    /// read: `close_storage` sets `storage_closed` before it closes any
    /// database, so a version that holds a closed-storage failure was
    /// published after the flag, and a check made after taking it sees the
    /// flag. Checked first, a close starting between the check and the take
    /// would let a version published across it through, some answers read
    /// open and some closed. A worker that has exited, its publisher gone,
    /// answers `TransportClosed`, as a send to its closed lane does.
    pub(crate) fn version(
        &self,
        storage_closed: &AtomicBool,
    ) -> Result<Option<Arc<ReadState>>, AppError> {
        let state = Arc::clone(&self.receiver.borrow());
        if storage_closed.load(Ordering::Acquire) {
            return Err(storage_closed_error());
        }
        if state.version == 0 {
            return Ok(None);
        }
        if self.receiver.has_changed().is_err() {
            return Err(AppError::TransportClosed);
        }
        Ok(Some(state))
    }
}

/// What a group entry was read at and how long it holds. The build returns it
/// with the entry, and reuse checks it alone: every input of a group's
/// answers is either a write the group's change generation counts or a field
/// here.
#[derive(Clone)]
struct EntryValidity {
    /// The group's change generation, read before the entry was built.
    generation: GroupChangeGeneration,
    /// The mirror record the entry was built from, held in memory.
    record: AppGroupRecord,
    /// The account-wide maintenance pause the maintenance status projects,
    /// held in memory.
    maintenance_paused: bool,
    /// The wall-clock window the commit-delivery answer holds in: from the
    /// clock reading it was computed at until a delivery deadline passes.
    window: WallClockWindow,
    /// False when a read failed on something other than a fact about the
    /// group ([`settled_failure`]), whether its answer keeps the failure or
    /// swallows it (the device-group check, which hides the group). Such a
    /// failure can clear with no write.
    reusable: bool,
}

impl EntryValidity {
    /// Whether an entry built at `self` still holds for a group now at
    /// `generation`, `record` and `maintenance_paused`, at `now`. A clock
    /// moved back before the reading the commit-delivery answer was computed
    /// at can bring an expired bound back into force.
    fn holds(
        &self,
        generation: &GroupChangeGeneration,
        record: &AppGroupRecord,
        maintenance_paused: bool,
        now: Timestamp,
    ) -> bool {
        self.reusable
            && generation.state.unchanged_since(&self.generation.state)
            && *record == self.record
            && maintenance_paused == self.maintenance_paused
            && self.window.contains(now)
    }

    /// Whether the entry's app components still hold for a group now at
    /// `generation`: they read only the loaded group.
    fn components_hold(&self, generation: &GroupChangeGeneration) -> bool {
        self.reusable
            && generation
                .hydrated
                .unchanged_since(&self.generation.hydrated)
    }
}

/// Whether a failed answer is a fact about the group that only a move of the
/// entry's inputs can change: the engine does not know the group, or has not
/// hydrated it yet. Any other failure, a busy or failing database above all,
/// can clear without a write.
fn settled_failure(error: &AppError) -> bool {
    use cgka_traits::error::EngineError;
    matches!(error, AppError::UnknownGroup(_))
        || matches!(
            error.as_engine_error(),
            Some(EngineError::UnknownGroup(_) | EngineError::GroupNotHydrated(_))
        )
}

/// Whether `answer` is a success or a settled failure.
fn settled<T>(answer: &Result<T, impl std::ops::Deref<Target = AppError>>) -> bool {
    answer
        .as_ref()
        .err()
        .is_none_or(|error| settled_failure(error))
}

/// What the owned KeyPackage list was read at and how long it holds. The
/// build returns it with the list, and reuse checks it alone. The list reads
/// the stored bundles and the private KeyPackages issued to siblings, both in
/// the account database, keeps the bundles of the engine's protocol profile,
/// and checks each bundle's lifetime against the system clock.
#[derive(Clone)]
struct KeyPackagesValidity {
    /// The account database's KeyPackage write count before the read: every
    /// write to a stored bundle or an issued private KeyPackage, through any
    /// connection this process has open on it, and every change of the file
    /// it cannot attribute to a row. `None` once the database is closed.
    key_package_writes: Option<u64>,
    /// The engine's protocol profile, read before the read.
    profile: ProtocolProfile,
    /// The system-clock window the lifetimes leave the list in: from the one
    /// reading every lifetime was judged at until the first bound ahead.
    window: WallClockWindow,
    /// Whether the read fully succeeded: no failure, no lifetime check on the
    /// other side of a bound from the window's reading, and no stored bundle
    /// skipped because it did not decode.
    reusable: bool,
}

impl KeyPackagesValidity {
    /// Whether a list read at `self` still holds with the database's
    /// KeyPackage write count at `key_package_writes`, the engine's protocol
    /// profile at `profile` and the system clock at `now`.
    fn holds(
        &self,
        key_package_writes: Option<u64>,
        profile: ProtocolProfile,
        now: Timestamp,
    ) -> bool {
        self.reusable
            && self.key_package_writes.is_some()
            && self.key_package_writes == key_package_writes
            && self.profile == profile
            && self.window.contains(now)
    }
}

/// The owned KeyPackage list, by today's read code, with its validity.
fn owned_key_packages(
    client: &AppClient,
    key_package_writes: Option<u64>,
    profile: ProtocolProfile,
) -> (ReadAnswer<Vec<KeyPackage>>, KeyPackagesValidity) {
    key_package_answer(
        client.durably_owned_key_packages_with_validity(),
        key_package_writes,
        profile,
    )
}

/// The answer and validity of a KeyPackage list `read` with the database's
/// KeyPackage write count at `key_package_writes` and the engine's protocol
/// profile at `profile`: it holds from the clock reading its lifetimes were
/// judged at until the first lifetime bound ahead, and only a full success,
/// with no lifetime check on the other side of a bound from that reading, is
/// reused.
fn key_package_answer(
    read: Result<marmot_session::OwnedKeyPackages, AppError>,
    key_package_writes: Option<u64>,
    profile: ProtocolProfile,
) -> (ReadAnswer<Vec<KeyPackage>>, KeyPackagesValidity) {
    match read {
        Ok(owned) => (
            Ok(owned.key_packages),
            KeyPackagesValidity {
                key_package_writes,
                profile,
                window: WallClockWindow {
                    from: owned.checked_at,
                    until: owned.changes_at,
                },
                reusable: !owned.skipped_undecodable && !owned.clock_moved,
            },
        ),
        Err(error) => (
            Err(Arc::new(error)),
            KeyPackagesValidity {
                key_package_writes,
                profile,
                window: WallClockWindow::ALWAYS,
                reusable: false,
            },
        ),
    }
}

/// Seconds since the Unix epoch on the system clock, which OpenMLS checks
/// KeyPackage lifetimes against.
fn system_clock_now() -> Timestamp {
    Timestamp(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
}

/// The earlier of two optional times; `None` is never.
fn earliest(ours: Option<Timestamp>, theirs: Option<Timestamp>) -> Option<Timestamp> {
    ours.into_iter().chain(theirs).min()
}

/// Builds and publishes A on the account worker. A directly owned client
/// has none and publishes nothing.
pub(crate) struct ReadStatePublisher {
    sender: watch::Sender<Arc<ReadState>>,
    uploads_in_flight: UploadsInFlight,
    /// The owned KeyPackage list the last publish read or reused.
    key_packages: Option<(ReadAnswer<Vec<KeyPackage>>, KeyPackagesValidity)>,
    entries: HashMap<GroupId, EntryValidity>,
    /// The earliest commit-delivery bound among `entries`, on the account's
    /// wall clock.
    groups_valid_until: Option<Timestamp>,
    /// Whether any account handle the publish reads was still open when the
    /// last publish began: the oracle's window for a terminal close.
    #[cfg(any(test, feature = "test-support"))]
    storage_open_at_publish: bool,
    /// Whether the last publish reused the owned KeyPackage list, which the
    /// oracle then checks even when nothing changed.
    #[cfg(any(test, feature = "test-support"))]
    key_packages_reused: bool,
    /// The owned KeyPackage list's raw inputs, read before its build: the
    /// oracle's check of the list while it is reused.
    #[cfg(any(test, feature = "test-support"))]
    key_package_inputs: Option<oracle::KeyPackageInputs>,
    /// Whether the oracle read the owned KeyPackage list afresh after the
    /// last publish.
    #[cfg(any(test, feature = "test-support"))]
    key_packages_read_afresh: bool,
}

impl ReadStatePublisher {
    /// How long until an answer in the published version can change with no
    /// write, each bound measured on its own clock: KeyPackage lifetimes on
    /// the system clock, commit-delivery bounds on the account's wall clock.
    /// Never under a second, the clocks' resolution, so a bound the clock
    /// does not show as passed yet is waited for rather than spun on.
    fn deadline(&self, wall_now: Timestamp, system_now: Timestamp) -> Option<Duration> {
        let remaining = |until: Timestamp, now: Timestamp| until.0.saturating_sub(now.0);
        let key_packages = self
            .key_packages
            .as_ref()
            .and_then(|(_, validity)| validity.window.until)
            .map(|until| remaining(until, system_now));
        let groups = self
            .groups_valid_until
            .map(|until| remaining(until, wall_now));
        let seconds = match (key_packages, groups) {
            (Some(key_packages), Some(groups)) => key_packages.min(groups),
            (key_packages, groups) => key_packages.or(groups)?,
        };
        Some(Duration::from_secs(seconds.max(1)))
    }

    pub(crate) fn new(sender: ReadStateSender, uploads_in_flight: UploadsInFlight) -> Self {
        let ReadStateSender(sender) = sender;
        Self {
            sender,
            uploads_in_flight,
            key_packages: None,
            entries: HashMap::new(),
            groups_valid_until: None,
            #[cfg(any(test, feature = "test-support"))]
            storage_open_at_publish: true,
            #[cfg(any(test, feature = "test-support"))]
            key_packages_reused: false,
            #[cfg(any(test, feature = "test-support"))]
            key_package_inputs: None,
            #[cfg(any(test, feature = "test-support"))]
            key_packages_read_afresh: false,
        }
    }

    /// Rebuild every answer at the next publish.
    fn forget_inputs(&mut self) {
        self.key_packages = None;
        self.entries.clear();
        #[cfg(any(test, feature = "test-support"))]
        {
            self.key_package_inputs = None;
        }
    }

    #[cfg(test)]
    pub(crate) fn subscribe(&self) -> watch::Receiver<Arc<ReadState>> {
        self.sender.subscribe()
    }

    pub(crate) fn current(&self) -> Arc<ReadState> {
        self.sender.borrow().clone()
    }

    fn uploads_in_flight(&self) -> Option<HashSet<String>> {
        self.uploads_in_flight
            .lock()
            .ok()
            .map(|uploads| uploads.clone())
    }

    /// Publish a new version if any input changed; whether one did.
    fn publish(&mut self, client: &AppClient) -> bool {
        let started = Instant::now();
        #[cfg(any(test, feature = "test-support"))]
        {
            // `close_storage` sets the app's flag, which refuses the app's
            // handle openers, and then latches each database closed. So the
            // engine's connection (which the session shares) can still read
            // after the flag is set; storage is closed for the publish only
            // once both are.
            self.storage_open_at_publish = !(client
                .app
                .storage_closed
                .load(std::sync::atomic::Ordering::Acquire)
                && client.engine_storage.is_closed());
        }
        let current = self.current();
        let uploads_in_flight = self.uploads_in_flight();
        let maintenance_paused = client.runtime.maintenance_is_paused();
        let now = client.runtime.wall_clock_now();

        // Read before the build, so a write that lands during it ends the
        // reuse at the next publish.
        let key_package_writes = (!client.engine_storage.is_closed())
            .then(|| client.engine_storage.key_package_write_count());
        let profile = client.runtime.new_protocol_profile();
        let (key_packages, key_package_validity, key_packages_reused) =
            match self.key_packages.take() {
                Some((answer, validity))
                    if validity.holds(key_package_writes, profile, system_clock_now()) =>
                {
                    (answer, validity, true)
                }
                _ => {
                    // The oracle's copy of the inputs, read before the
                    // build's own reads: a write landing during the build
                    // shows up as a change.
                    #[cfg(any(test, feature = "test-support"))]
                    {
                        self.key_package_inputs = oracle::enabled()
                            .then(|| oracle::KeyPackageInputs::read(client).ok())
                            .flatten();
                    }
                    let (answer, validity) =
                        owned_key_packages(client, key_package_writes, profile);
                    (answer, validity, false)
                }
            };
        #[cfg(any(test, feature = "test-support"))]
        {
            self.key_packages_reused = key_packages_reused;
        }
        let account = account_answers(
            client,
            maintenance_paused,
            uploads_in_flight.as_ref(),
            key_packages.clone(),
        );
        let key_packages_valid_until = key_package_validity.window.until;
        self.key_packages = Some((key_packages, key_package_validity));
        let account_changed = !account.same_as(&current.account);
        let account = if account_changed {
            Arc::new(account)
        } else {
            Arc::clone(&current.account)
        };

        // Borrowed: only a rebuilt entry copies its record (mdk#3273 PR 3
        // measured the copy at two fifths of an unchanged publish).
        let mirror: Vec<(GroupId, &AppGroupRecord)> = client
            .state
            .groups
            .iter()
            .filter_map(|record| {
                hex::decode(&record.group_id_hex)
                    .ok()
                    .map(|bytes| (GroupId::new(bytes), record))
            })
            .collect();
        let generations = client
            .runtime
            .group_change_generations(mirror.iter().map(|(group_id, _)| group_id));
        let mut groups = HashMap::with_capacity(mirror.len());
        let mut entries = HashMap::with_capacity(mirror.len());
        let mut rebuilt = 0usize;
        let mut changed = 0usize;
        let mut groups_valid_until = None;
        // Loaded once, for the first entry rebuilt. A failed load leaves each
        // entry to the per-group reads, so its errors are theirs.
        let mut maintenance_rows = None;
        let mut earlier_entries = std::mem::take(&mut self.entries);
        for ((group_id, record), generation) in mirror.into_iter().zip(generations) {
            let earlier = earlier_entries
                .remove(&group_id)
                .zip(current.groups.get(&group_id));
            let (answers, validity) = match earlier {
                Some((validity, answers))
                    if validity.holds(&generation, record, maintenance_paused, now) =>
                {
                    (Arc::clone(answers), validity)
                }
                earlier => {
                    rebuilt += 1;
                    let rows = maintenance_rows
                        .get_or_insert_with(|| client.runtime.group_maintenance_rows())
                        .as_ref()
                        .ok();
                    let (answers, validity) = group_entry(
                        client,
                        &group_id,
                        record.clone(),
                        generation,
                        maintenance_paused,
                        earlier
                            .as_ref()
                            .map(|(validity, answers)| (validity, *answers)),
                        rows,
                    );
                    // A rebuild whose answers are the published ones keeps
                    // them, and so does not by itself move the version.
                    match current.groups.get(&group_id) {
                        Some(published) if answers.same_as(published) => {
                            (Arc::clone(published), validity)
                        }
                        _ => {
                            changed += 1;
                            (Arc::new(answers), validity)
                        }
                    }
                }
            };
            groups_valid_until = earliest(groups_valid_until, validity.window.until);
            entries.insert(group_id.clone(), validity);
            groups.insert(group_id, answers);
        }
        let dropped = current
            .groups
            .keys()
            .any(|group_id| !groups.contains_key(group_id));
        self.entries = entries;
        self.groups_valid_until = groups_valid_until;
        let valid_until = earliest(key_packages_valid_until, groups_valid_until);
        // Version 0 is the channel's empty state, never a publish.
        let first = current.version == 0;
        if !first
            && !account_changed
            && changed == 0
            && !dropped
            && valid_until == current.valid_until
        {
            return false;
        }
        let version = current.version + 1;
        let group_count = groups.len();
        self.sender.send_replace(Arc::new(ReadState {
            version,
            valid_until,
            account,
            groups: Arc::new(groups),
        }));
        let elapsed = started.elapsed();
        if let Some(telemetry) = client.runtime_telemetry.as_ref() {
            telemetry.record_runtime(
                marmot_observability::RuntimePerformanceOperation::ReadStatePublish,
                elapsed,
                marmot_observability::Outcome::Success,
            );
        }
        tracing::debug!(
            target: TRACE_TARGET,
            method = "publish",
            version,
            account_changed,
            key_packages_reused,
            groups = group_count,
            groups_rebuilt = rebuilt,
            groups_changed = changed,
            elapsed_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            "published read state"
        );
        true
    }
}

fn arc_err<T>(result: Result<T, AppError>) -> ReadAnswer<T> {
    result.map_err(Arc::new)
}

/// The account answers, by today's read code, around the owned KeyPackage
/// list the caller read or reused.
fn account_answers(
    client: &AppClient,
    maintenance_paused: bool,
    uploads_in_flight: Option<&HashSet<String>>,
    durably_owned_key_packages: ReadAnswer<Vec<KeyPackage>>,
) -> AccountAnswers {
    AccountAnswers {
        quarantined_groups: client.quarantined_groups(),
        key_package_maintenance_status: arc_err(client.key_package_maintenance_status()),
        durably_owned_key_packages,
        periodic_maintenance_policy: arc_err(client.periodic_maintenance_policy()),
        maintenance_paused,
        backup_restore_status: client.backup_restore_status(),
        backup_restore_updates: client.watch_backup_restore().receiver,
        prepared_group_images: arc_err(
            client
                .prepared_initial_group_images()
                .map(|statuses| with_uploads_in_flight(statuses, uploads_in_flight)),
        ),
        started_fresh: arc_err(client.started_fresh()),
        chat_history_imports: arc_err(client.chat_history_imports()),
    }
}

/// Mark each status whose upload is in flight `Uploading`, as the worker's
/// image reads do. A set that cannot be read marks none.
pub(crate) fn with_uploads_in_flight(
    mut statuses: Vec<AppPreparedGroupImageUpload>,
    uploads_in_flight: Option<&HashSet<String>>,
) -> Vec<AppPreparedGroupImageUpload> {
    for status in &mut statuses {
        if uploads_in_flight.is_some_and(|uploads| uploads.contains(&status.upload_id)) {
            status.state = AppPreparedGroupImageUploadState::Uploading;
        }
    }
    statuses
}

/// One mirror group's answers, by today's read code past its mirror gate,
/// with what they were read at. `earlier` is the entry this one replaces,
/// whose app components are kept while they hold.
fn group_entry(
    client: &AppClient,
    group_id: &GroupId,
    record: AppGroupRecord,
    generation: GroupChangeGeneration,
    maintenance_paused: bool,
    earlier: Option<(&EntryValidity, &Arc<GroupAnswers>)>,
    maintenance_rows: Option<&GroupMaintenanceRows>,
) -> (GroupAnswers, EntryValidity) {
    let app_components = match earlier {
        Some((validity, answers)) if validity.components_hold(&generation) => {
            answers.app_components.clone()
        }
        _ => client
            .runtime
            .app_owned_components(group_id)
            .map_err(|error| Arc::new(AppError::from(error))),
    };
    // `host_may_see_group`, which hides the group when the check fails,
    // keeping whether it did: the entry is then not reusable.
    let device_group = client.is_device_group(group_id);
    // A failed read depends on no clock reading, and is never reused.
    let (commit_delivery, window) =
        match client.group_commit_delivery_until(group_id, maintenance_rows) {
            Ok((delivery, window)) => (Ok(delivery), window),
            Err(error) => (Err(Arc::new(error)), WallClockWindow::ALWAYS),
        };
    let answers = GroupAnswers {
        host_may_see: matches!(device_group, Ok(false)),
        members: client
            .runtime
            .members(group_id)
            .map(|members| crate::groups::member_accounts(&members))
            .map_err(|error| Arc::new(AppError::from(error))),
        self_membership: arc_err(
            client
                .app
                .stored_group_self_membership(&client.state.label, &record.group_id_hex),
        ),
        mls_state: arc_err(client.group_mls_state_unchecked(group_id)),
        commit_delivery,
        maintenance_status: client
            .runtime
            .maintenance_status_in(group_id, maintenance_rows)
            .map_err(|error| Arc::new(AppError::from(error))),
        app_components,
        record: record.clone(),
    };
    let reusable = device_group.is_ok()
        && settled(&answers.members)
        && settled(&answers.self_membership)
        && settled(&answers.mls_state)
        && settled(&answers.commit_delivery)
        && settled(&answers.maintenance_status)
        && settled(&answers.app_components);
    let validity = EntryValidity {
        generation,
        record,
        maintenance_paused,
        window,
        reusable,
    };
    (answers, validity)
}

/// Where the account worker keeps its publisher. A lock, so a publish needs
/// only a shared borrow of the client: the worker publishes from wherever it
/// replies or emits an event.
pub(crate) type ReadStateSlot = Mutex<ReadStatePublisher>;

impl AppClient {
    /// Start publishing A from this client: the account worker calls this
    /// once, before its first unit.
    pub(crate) fn start_read_state(
        &mut self,
        sender: ReadStateSender,
        uploads_in_flight: UploadsInFlight,
    ) {
        self.read_state = Some(Box::new(Mutex::new(ReadStatePublisher::new(
            sender,
            uploads_in_flight,
        ))));
        self.publish_read_state();
    }

    /// How long until the published version's `valid_until` passes, when it
    /// has one: the worker publishes then (mdk#3273).
    pub(crate) fn read_state_deadline(&self) -> Option<Duration> {
        let slot = self.read_state.as_ref()?;
        slot.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .deadline(self.runtime.wall_clock_now(), system_clock_now())
    }

    /// Publish A at a quiescent point: the end of a unit, before a reply or
    /// a host event, and on a catch-up drain turn. A no-op without a
    /// publisher, and when nothing changed since the last publish.
    pub(crate) fn publish_read_state(&self) {
        let Some(slot) = self.read_state.as_ref() else {
            return;
        };
        let mut publisher = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _changed = publisher.publish(self);
        // Every changed publish checks every answer, reused entries included.
        // An unchanged one rebuilt account answers equal to the published
        // ones and found every group entry holding or rebuilt to its
        // published answers, so it skips the full check: the oracle's live reads hydrate on demand, and a
        // worker answering a tight poll would spend its time here. A reused
        // KeyPackage list is still checked at every publish: against a fresh
        // read, unless its raw inputs are the ones read before its build and
        // the clock has reached none of their lifetime bounds.
        #[cfg(any(test, feature = "test-support"))]
        if oracle::enabled() {
            let read_afresh = if _changed {
                oracle::note_check();
                oracle::check(
                    self,
                    &publisher.current(),
                    publisher.uploads_in_flight().as_ref(),
                    publisher.storage_open_at_publish,
                );
                true
            } else if publisher.key_packages_reused {
                oracle::note_check();
                oracle::check_reused_key_packages(
                    self,
                    &publisher.current(),
                    publisher.storage_open_at_publish,
                    publisher.key_package_inputs.as_ref(),
                )
            } else {
                false
            };
            publisher.key_packages_read_afresh = read_afresh;
        }
    }

    /// Take the publisher off a client the worker is about to drop, so the
    /// client that replaces it continues A's versions.
    pub(crate) fn take_read_state(&mut self) -> Option<Box<ReadStateSlot>> {
        self.read_state.take()
    }

    /// Continue publishing A on a client that replaced the one `slot` was
    /// taken from. Every answer rebuilds at the next publish: the new
    /// client's write counts start over, so no stamp taken on the old one
    /// may be compared with them.
    pub(crate) fn resume_read_state(&mut self, slot: Option<Box<ReadStateSlot>>) {
        if let Some(slot) = slot {
            slot.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .forget_inputs();
            self.read_state = Some(slot);
            self.publish_read_state();
        }
    }

    /// Whether the oracle read the owned KeyPackage list afresh after this
    /// client's last publish.
    #[cfg(test)]
    pub(crate) fn read_state_read_key_packages_afresh(&self) -> bool {
        self.read_state.as_ref().is_some_and(|slot| {
            slot.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .key_packages_read_afresh
        })
    }

    /// Whether this client's last publish reused the owned KeyPackage list.
    #[cfg(test)]
    pub(crate) fn read_state_reused_key_packages(&self) -> bool {
        self.read_state.as_ref().is_some_and(|slot| {
            slot.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .key_packages_reused
        })
    }

    /// A receiver of every version this client publishes, if it publishes.
    #[cfg(test)]
    pub(crate) fn subscribe_read_state(&self) -> Option<watch::Receiver<Arc<ReadState>>> {
        self.read_state.as_ref().map(|slot| {
            slot.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .subscribe()
        })
    }
}

/// The differential: after every publish, every published answer equals
/// today's read code called live on the writer at the same point. For a
/// group that is not hydrated, the oracle runs without on-demand hydration.
#[cfg(any(test, feature = "test-support"))]
pub(crate) mod oracle {
    use std::cell::OnceCell;
    use std::collections::BTreeSet;

    use cgka_traits::StorageError;
    use cgka_traits::storage::StoredKeyPackageBundle;

    use super::*;

    /// Publishes the oracle checked in this process.
    static CHECKS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// Whether this process runs the oracle: only marmot-app's own tests do.
    /// Its unit tests always do. Its integration tests do because Cargo and
    /// nextest start each test process with `CARGO_PKG_NAME` set to the
    /// test's package, archived runs included. A downstream crate's tests
    /// link this crate with `test-support` too (a dev-dependency turns it on,
    /// and workspace feature unification turns it on for every crate built
    /// with it), so the feature alone cannot scope the oracle. Their
    /// processes carry their own package's name and run without it, as does
    /// a test binary started directly, with no runner to name its package.
    pub(crate) fn enabled() -> bool {
        #[cfg(test)]
        {
            true
        }
        #[cfg(not(test))]
        {
            static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
            *ENABLED.get_or_init(|| {
                std::env::var_os("CARGO_PKG_NAME")
                    .is_some_and(|package| package == env!("CARGO_PKG_NAME"))
            })
        }
    }

    pub(crate) fn note_check() {
        CHECKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn checks() -> u64 {
        CHECKS.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether `error` is a closed-storage error, at any depth.
    fn closed(error: &AppError) -> bool {
        format!("{error:?}").contains("Storage(Closed(")
    }

    /// The span from the publish to this check. Terminal storage close runs
    /// off the worker (`MarmotAppRuntime::shutdown_and_close`), so it can land
    /// inside it: a publish that read open storage then meets a live read of
    /// closed storage. Close never reverts, so only open-then-closed spans.
    #[derive(Clone, Copy)]
    pub(super) struct Window<'a> {
        pub(super) storage_open_at_publish: bool,
        pub(super) storage_closed: &'a std::sync::atomic::AtomicBool,
    }

    impl Window<'_> {
        fn closed_inside(&self) -> bool {
            self.storage_open_at_publish
                && self
                    .storage_closed
                    .load(std::sync::atomic::Ordering::Acquire)
        }
    }

    /// Assert that a published answer equals the live one. The only pair
    /// let through unequal is one where storage closed inside the window
    /// and a side is a closed-storage error: the two sides read either side
    /// of the close. Ok against Ok, or two other errors, compare strictly.
    pub(super) fn same<T: PartialEq + std::fmt::Debug>(
        window: Window<'_>,
        name: &str,
        published: &ReadAnswer<T>,
        live: &Result<T, AppError>,
    ) {
        let equal = match (published, live) {
            (Ok(published), Ok(live)) => published == live,
            (Err(published), Err(live)) => format!("{published:?}") == format!("{live:?}"),
            _ => false,
        };
        let across_close = window.closed_inside()
            && (published.as_ref().err().is_some_and(|error| closed(error))
                || live.as_ref().err().is_some_and(closed));
        assert!(
            equal || across_close,
            "read state differs from the live read for {name}: published {published:?}, live {live:?}"
        );
    }

    /// A group id no account holds.
    fn unknown_group_id() -> GroupId {
        GroupId::new(vec![0xa5; 16])
    }

    /// An app-owned component id no group in these tests sets.
    const ABSENT_APP_COMPONENT: AppComponentId = 0xfffe;
    /// A protocol-space id the component read refuses.
    const PROTOCOL_COMPONENT: AppComponentId = 0x0001;

    /// The owned KeyPackage list against a fresh read.
    fn key_packages(client: &AppClient, state: &ReadState, window: Window<'_>) {
        let published = state
            .account
            .durably_owned_key_packages
            .as_ref()
            .map(|packages| format!("{packages:?}"))
            .map_err(Arc::clone);
        let live = client
            .durably_owned_key_packages()
            .map(|packages| format!("{packages:?}"));
        same(window, "durably owned key packages", &published, &live);
    }

    /// A reused owned KeyPackage list, at a publish that changed nothing
    /// else. The full check reads the list afresh, which re-validates every
    /// stored bundle. It is skipped only when the list's raw inputs, read
    /// now, are `built_from`, the ones read before its build, and the clock
    /// has reached none of their lifetime bounds since: a fresh read would
    /// then decide every bundle as the build did. A failed read, or no
    /// inputs, checks in full. Returns whether it read the list afresh.
    pub(crate) fn check_reused_key_packages(
        client: &AppClient,
        state: &ReadState,
        storage_open_at_publish: bool,
        built_from: Option<&KeyPackageInputs>,
    ) -> bool {
        if let Some(built_from) = built_from
            && KeyPackageInputs::read(client).is_ok_and(|now| built_from.holds_at(&now))
        {
            return false;
        }
        let window = Window {
            storage_open_at_publish,
            storage_closed: &client.app.storage_closed,
        };
        key_packages(client, state, window);
        true
    }

    /// What the owned KeyPackage list is a function of, read raw: the stored
    /// bundle rows, which the build's by-reference lookups read too; the refs
    /// of the private KeyPackages issued to siblings, which it leaves out;
    /// and the protocol profile. With the system-clock reading taken before
    /// them.
    pub(crate) struct KeyPackageInputs {
        pub(crate) taken_at: Timestamp,
        rows: Vec<StoredKeyPackageBundle>,
        private_refs: BTreeSet<Vec<u8>>,
        profile: ProtocolProfile,
        /// [`Self::first_bound`], decoded at its first use.
        first_bound: OnceCell<LifetimeBound>,
    }

    /// The first lifetime bound after an input reading.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum LifetimeBound {
        At(Timestamp),
        /// No stored bundle has a bound ahead.
        Never,
        /// A stored row's lifetime could not be found, so no clock reading
        /// is known to decide as this one did.
        Unknown,
    }

    impl KeyPackageInputs {
        pub(crate) fn read(client: &AppClient) -> Result<Self, StorageError> {
            use cgka_traits::storage::{KeyPackageBundleStorage as _, StorageProvider as _};

            let taken_at = system_clock_now();
            let storage = &client.engine_storage;
            let private_refs = match storage.private_key_package_storage() {
                Some(private) => private
                    .list_issued_private_key_packages()?
                    .into_iter()
                    .map(|record| record.key_package_ref)
                    .collect(),
                None => BTreeSet::new(),
            };
            Ok(Self {
                taken_at,
                rows: storage.stored_key_package_bundles()?,
                private_refs,
                profile: client.runtime.new_protocol_profile(),
                first_bound: OnceCell::new(),
            })
        }

        /// Whether a list built from these inputs is what a full read at
        /// `now` would give: the same inputs, and the clock at or after this
        /// reading and short of the first lifetime bound after it, so every
        /// stored bundle's lifetime decides as it did here.
        pub(crate) fn holds_at(&self, now: &Self) -> bool {
            now.rows == self.rows
                && now.private_refs == self.private_refs
                && now.profile == self.profile
                && now.taken_at >= self.taken_at
                && match self.first_bound() {
                    LifetimeBound::At(bound) => now.taken_at < bound,
                    LifetimeBound::Never => true,
                    LifetimeBound::Unknown => false,
                }
        }

        /// The soonest `not_before` or `not_after` after this reading of any
        /// stored bundle, read from the serialized rows without OpenMLS or
        /// the engine's rule: a bound of a bundle the list leaves out for
        /// another reason counts too.
        pub(crate) fn first_bound(&self) -> LifetimeBound {
            *self.first_bound.get_or_init(|| {
                let mut first: Option<u64> = None;
                for row in &self.rows {
                    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&row.value) else {
                        return LifetimeBound::Unknown;
                    };
                    let mut found = false;
                    lifetimes(&value, &mut |not_before, not_after| {
                        found = true;
                        for bound in [not_before, not_after] {
                            if bound > self.taken_at.0 {
                                first = Some(first.map_or(bound, |first| first.min(bound)));
                            }
                        }
                    });
                    if !found {
                        return LifetimeBound::Unknown;
                    }
                }
                first.map_or(LifetimeBound::Never, |bound| {
                    LifetimeBound::At(Timestamp(bound))
                })
            })
        }
    }

    /// Call `found` with every object in `value` that has integer
    /// `not_before` and `not_after` fields, as an OpenMLS `Lifetime` does.
    fn lifetimes(value: &serde_json::Value, found: &mut dyn FnMut(u64, u64)) {
        match value {
            serde_json::Value::Object(fields) => {
                if let (Some(not_before), Some(not_after)) = (
                    fields.get("not_before").and_then(serde_json::Value::as_u64),
                    fields.get("not_after").and_then(serde_json::Value::as_u64),
                ) {
                    found(not_before, not_after);
                }
                for field in fields.values() {
                    lifetimes(field, found);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    lifetimes(item, found);
                }
            }
            _ => {}
        }
    }

    pub(crate) fn check(
        client: &AppClient,
        state: &ReadState,
        uploads_in_flight: Option<&HashSet<String>>,
        storage_open_at_publish: bool,
    ) {
        let window = Window {
            storage_open_at_publish,
            storage_closed: &client.app.storage_closed,
        };
        // Account answers.
        assert_eq!(
            state.account.quarantined_groups,
            client.quarantined_groups(),
            "read state differs from the live read for quarantined groups"
        );
        same(
            window,
            "key package maintenance status",
            &state.account.key_package_maintenance_status,
            &client.key_package_maintenance_status(),
        );
        key_packages(client, state, window);
        same(
            window,
            "periodic maintenance policy",
            &state.account.periodic_maintenance_policy,
            &client.periodic_maintenance_policy(),
        );
        assert_eq!(
            state.account.maintenance_paused,
            client.runtime.maintenance_is_paused(),
            "read state differs from the live read for the maintenance pause"
        );
        assert_eq!(
            state.account.backup_restore_status,
            client.backup_restore_status(),
            "read state differs from the live read for backup restore status"
        );
        assert!(
            state
                .account
                .backup_restore_updates
                .same_channel(&client.watch_backup_restore().receiver),
            "read state holds another backup restore channel than the client's"
        );
        let images = client
            .prepared_initial_group_images()
            .map(|statuses| with_uploads_in_flight(statuses, uploads_in_flight));
        same(
            window,
            "prepared group images",
            &state.account.prepared_group_images,
            &images,
        );
        let mut upload_ids: Vec<String> = images
            .as_ref()
            .map(|statuses| {
                statuses
                    .iter()
                    .map(|status| status.upload_id.clone())
                    .collect()
            })
            .unwrap_or_default();
        upload_ids.push("no-such-upload".to_owned());
        for upload_id in &upload_ids {
            let live = client
                .prepared_initial_group_image_status(upload_id)
                .map(|status| {
                    with_uploads_in_flight(vec![status], uploads_in_flight)
                        .pop()
                        .expect("one status in, one out")
                });
            same(
                window,
                "prepared group image status",
                &state.prepared_group_image_status(upload_id),
                &live,
            );
        }
        same(
            window,
            "started fresh",
            &state.account.started_fresh,
            &client.started_fresh(),
        );
        same(
            window,
            "chat history imports",
            &state.account.chat_history_imports,
            &client.chat_history_imports(),
        );

        // Group answers: every group in the mirror, every group the engine
        // or the device-group table knows (hidden, unhydrated, quarantined,
        // a failed rewind restore), and an id no one holds.
        let mut group_ids: Vec<GroupId> = client
            .state
            .groups
            .iter()
            .filter_map(|record| hex::decode(&record.group_id_hex).ok().map(GroupId::new))
            .collect();
        group_ids.extend(client.runtime.live_group_ids().unwrap_or_default());
        group_ids.extend(client.runtime.unhydrated_group_ids());
        group_ids.extend(
            client
                .runtime
                .quarantined_groups()
                .into_iter()
                .map(|(group_id, _)| group_id),
        );
        if let Ok(storage) = client.app.account_storage(&client.state.label) {
            group_ids.extend(
                storage
                    .app_storage()
                    .device_groups()
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|record| hex::decode(&record.group_id_hex).ok().map(GroupId::new)),
            );
        }
        group_ids.push(unknown_group_id());
        let mut seen = HashSet::new();
        group_ids.retain(|group_id| seen.insert(group_id.clone()));

        let profiles = client.app.profiles_by_id();
        for group_id in &group_ids {
            if let Ok(profiles) = &profiles {
                same(
                    window,
                    "members",
                    &state.members(group_id, profiles),
                    &client.members(group_id),
                );
            }
            same(
                window,
                "member ids page",
                &state.member_ids_page(std::slice::from_ref(group_id)),
                &client.member_ids_page(std::slice::from_ref(group_id)),
            );
            same(
                window,
                "group roster",
                &state.group_roster(group_id, || client.app.profiles_by_id()),
                &client.group_roster_session(group_id),
            );
            same(
                window,
                "group MLS state",
                &state.group_mls_state(group_id),
                &client.group_mls_state(group_id),
            );
            same(
                window,
                "group commit delivery",
                &state.group_commit_delivery(group_id),
                &client.group_commit_delivery(group_id),
            );
            same(
                window,
                "maintenance status",
                &state.maintenance_status(group_id),
                &client.maintenance_status(group_id),
            );
            let mut component_ids = vec![ABSENT_APP_COMPONENT, PROTOCOL_COMPONENT];
            if let Some(Ok(components)) = state
                .groups
                .get(group_id)
                .map(|group| group.app_components.as_ref())
            {
                component_ids.extend(components.iter().map(|(id, _)| *id));
            }
            for component_id in component_ids {
                same(
                    window,
                    "group app component",
                    &state.group_app_component(group_id, component_id),
                    &client.group_app_component(group_id, component_id),
                );
            }
            if let Some(host_may_see) = state.host_may_see(group_id) {
                // `host_may_see_group`, which folds a failed lookup into
                // `false`, except a closed-storage failure inside the close
                // window, kept for `same`.
                let live = match client.is_device_group(group_id) {
                    Ok(is_device_group) => Ok(!is_device_group),
                    Err(error) if window.closed_inside() && closed(&error) => Err(error),
                    Err(_) => Ok(false),
                };
                same(window, "device-group visibility", &Ok(host_may_see), &live);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use cgka_traits::StorageError;
    use cgka_traits::error::EngineError;

    use super::*;
    use crate::AccountError;

    /// A KeyPackage list is reused only while the database's KeyPackage
    /// write count and the engine's protocol profile are the ones it was read
    /// at, the system clock is inside its window (not moved back before the
    /// reading its lifetimes were judged at, not past the next lifetime
    /// bound), and the read fully succeeded with every lifetime check
    /// agreeing with that reading.
    #[test]
    fn a_key_package_list_holds_only_inside_its_validity() {
        use ProtocolProfile::{Current, Legacy};
        let owned = marmot_session::OwnedKeyPackages {
            key_packages: Vec::new(),
            checked_at: Timestamp(100),
            changes_at: Some(Timestamp(200)),
            skipped_undecodable: false,
            clock_moved: false,
        };
        let (_, validity) = key_package_answer(Ok(owned.clone()), Some(5), Current);
        assert!(validity.holds(Some(5), Current, Timestamp(150)));
        assert!(!validity.holds(Some(6), Current, Timestamp(150)));
        assert!(!validity.holds(None, Current, Timestamp(150)));
        assert!(!validity.holds(Some(5), Legacy, Timestamp(150)));
        assert!(!validity.holds(Some(5), Current, Timestamp(99)));
        assert!(!validity.holds(Some(5), Current, Timestamp(200)));
        let (_, closed) = key_package_answer(Ok(owned.clone()), None, Current);
        assert!(!closed.holds(None, Current, Timestamp(150)));
        let (_, skipped) = key_package_answer(
            Ok(marmot_session::OwnedKeyPackages {
                skipped_undecodable: true,
                ..owned.clone()
            }),
            Some(5),
            Current,
        );
        assert!(!skipped.holds(Some(5), Current, Timestamp(150)));
        let (_, moved) = key_package_answer(
            Ok(marmot_session::OwnedKeyPackages {
                clock_moved: true,
                ..owned
            }),
            Some(5),
            Current,
        );
        assert!(!moved.holds(Some(5), Current, Timestamp(150)));
        let (_, failed) = key_package_answer(Err(closed_storage()), Some(5), Current);
        assert!(!failed.holds(Some(5), Current, Timestamp(150)));
    }

    /// Only a fact about the group keeps a failed answer in a reused entry;
    /// a busy database clears without a write, so it never does.
    #[test]
    fn only_a_fact_about_the_group_settles_a_failure() {
        let group = GroupId::new(vec![0x11; 16]);
        let engine = |error| AppError::Account(AccountError::Engine(error));
        assert!(settled_failure(&engine(EngineError::GroupNotHydrated(
            group.clone()
        ))));
        assert!(settled_failure(&engine(EngineError::UnknownGroup(group))));
        assert!(settled_failure(&AppError::UnknownGroup("11".to_owned())));
        assert!(!settled_failure(&engine(EngineError::Storage(
            StorageError::Busy("locked".to_owned())
        ))));
        assert!(!settled_failure(&AppError::Storage(StorageError::Busy(
            "locked".to_owned()
        ))));
    }

    fn closed_storage() -> AppError {
        AppError::Account(AccountError::Engine(EngineError::Storage(
            StorageError::Closed("sqlite account storage is closed".to_owned()),
        )))
    }

    /// Whether the oracle rejects `published` against `live` in a window
    /// where storage was open at the publish (`open_at_publish`) and is
    /// closed now (`closed_now`).
    fn rejects(
        open_at_publish: bool,
        closed_now: bool,
        published: ReadAnswer<u8>,
        live: Result<u8, AppError>,
    ) -> bool {
        let storage_closed = std::sync::atomic::AtomicBool::new(closed_now);
        let window = oracle::Window {
            storage_open_at_publish: open_at_publish,
            storage_closed: &storage_closed,
        };
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            oracle::same(window, "answer", &published, &live)
        }))
        .is_err()
    }

    /// Storage closing between the publish and the check lets through only
    /// a pair with a closed-storage error on one side: two successes still
    /// compare strictly.
    #[test]
    fn a_close_inside_the_window_still_compares_two_successes() {
        assert!(rejects(true, true, Ok(1), Ok(2)));
        assert!(!rejects(true, true, Ok(1), Err(closed_storage())));
        assert!(!rejects(true, true, Err(Arc::new(closed_storage())), Ok(1)));
    }

    /// Without a close inside the window, a closed-storage error on one side
    /// is a mismatch: storage already closed at the publish, or never closed.
    #[test]
    fn a_one_sided_closed_error_without_a_close_in_the_window_is_a_mismatch() {
        assert!(rejects(false, true, Ok(1), Err(closed_storage())));
        assert!(rejects(true, false, Ok(1), Err(closed_storage())));
    }

    /// A published failure reaches the host as an exact copy, or not at all:
    /// a failure with no copy is left for the worker to answer.
    #[test]
    fn a_reissued_failure_is_an_exact_copy_or_none() {
        let group = GroupId::new(vec![0x11; 16]);
        let account = |error| AppError::Account(AccountError::Engine(error));
        // The session's wrapping, which the account reads' engine failures
        // carry.
        let session = |error| {
            AppError::Account(AccountError::Session(marmot_session::SessionError::Engine(
                error,
            )))
        };
        let copied = [
            AppError::UnknownGroup("11".to_owned()),
            AppError::Storage(StorageError::Closed("closed".to_owned())),
            account(EngineError::UnknownGroup(group.clone())),
            account(EngineError::GroupNotHydrated(group.clone())),
            session(EngineError::UnknownGroup(group.clone())),
            session(EngineError::GroupNotHydrated(group)),
            session(EngineError::Storage(StorageError::Closed(
                "closed".to_owned(),
            ))),
            closed_storage(),
        ];
        for error in copied {
            let copy = reissue_error(&error).expect("a copyable failure");
            assert_eq!(format!("{copy:?}"), format!("{error:?}"));
        }
        let uncopied = [
            AppError::Sqlite(rusqlite::Error::InvalidQuery),
            account(EngineError::UnknownPending),
            session(EngineError::UnknownPending),
            AppError::TransportClosed,
        ];
        for error in uncopied {
            assert!(reissue_error(&error).is_none(), "{error:?} has no copy");
        }
        assert_eq!(reissue::<u8>(Ok(7)).unwrap().unwrap(), 7);
        assert!(reissue::<u8>(Err(Arc::new(AppError::TransportClosed))).is_none());
    }

    /// The worker wakes when the first time-bound answer can change, each
    /// bound measured on its own clock, and never sooner than a second.
    #[test]
    fn the_deadline_measures_each_bound_on_its_own_clock() {
        let (sender, _) = read_state_channel();
        let mut publisher = ReadStatePublisher::new(sender, UploadsInFlight::default());
        assert_eq!(publisher.deadline(Timestamp(0), Timestamp(0)), None);
        publisher.groups_valid_until = Some(Timestamp(1_100));
        assert_eq!(
            publisher.deadline(Timestamp(1_000), Timestamp(50_000)),
            Some(Duration::from_secs(100))
        );
        let owned = marmot_session::OwnedKeyPackages {
            key_packages: Vec::new(),
            checked_at: Timestamp(50_000),
            changes_at: Some(Timestamp(50_030)),
            skipped_undecodable: false,
            clock_moved: false,
        };
        publisher.key_packages = Some(key_package_answer(
            Ok(owned),
            Some(1),
            ProtocolProfile::Current,
        ));
        assert_eq!(
            publisher.deadline(Timestamp(1_000), Timestamp(50_000)),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            publisher.deadline(Timestamp(1_100), Timestamp(50_000)),
            Some(Duration::from_secs(1)),
            "a bound the clock reached waits a second, not zero"
        );
        publisher.groups_valid_until = None;
        assert_eq!(
            publisher.deadline(Timestamp(0), Timestamp(50_010)),
            Some(Duration::from_secs(20))
        );
    }

    /// Before the worker's first publish a read is sent to the worker; once
    /// storage is closed every read answers so, whatever was published; and
    /// a worker gone answers as its closed lane would.
    #[test]
    fn a_reader_answers_from_a_published_version_only() {
        let open = AtomicBool::new(false);
        let closed = AtomicBool::new(true);
        let (ReadStateSender(sender), reader) = read_state_channel();
        assert!(reader.version(&open).unwrap().is_none());
        assert!(matches!(
            reader.version(&closed),
            Err(AppError::Storage(StorageError::Closed(_)))
        ));
        let published = {
            let empty = reader.receiver.borrow();
            Arc::new(ReadState {
                version: 1,
                valid_until: None,
                account: Arc::clone(&empty.account),
                groups: Arc::clone(&empty.groups),
            })
        };
        sender.send_replace(Arc::clone(&published));
        let state = reader.version(&open).unwrap().unwrap();
        assert!(Arc::ptr_eq(&state, &published));
        assert!(matches!(
            reader.version(&closed),
            Err(AppError::Storage(StorageError::Closed(_)))
        ));
        drop(sender);
        assert!(matches!(
            reader.version(&open),
            Err(AppError::TransportClosed)
        ));
    }

    /// A watch handed out from A has seen the status published there and no
    /// more, as a subscription made at that publish would have: a change sent
    /// since that publish wakes it.
    #[tokio::test]
    async fn a_backup_restore_watch_wakes_for_a_change_since_its_publish() {
        let published = BackupRestoreStatus {
            revision: 1,
            ..Default::default()
        };
        let (updates, _) = watch::channel(published.clone());
        let state = ReadState {
            version: 1,
            valid_until: None,
            account: Arc::new(AccountAnswers {
                quarantined_groups: Vec::new(),
                key_package_maintenance_status: Ok(None),
                durably_owned_key_packages: Ok(Vec::new()),
                periodic_maintenance_policy: Ok(PeriodicMaintenancePolicy::default()),
                maintenance_paused: false,
                backup_restore_status: published.clone(),
                backup_restore_updates: updates.subscribe(),
                prepared_group_images: Ok(Vec::new()),
                started_fresh: Ok(false),
                chat_history_imports: Ok(Vec::new()),
            }),
            groups: Arc::default(),
        };
        assert!(!state.watch_backup_restore().receiver.has_changed().unwrap());

        let later = BackupRestoreStatus {
            phase: crate::BackupRestorePhase::Discovering,
            revision: 2,
            ..Default::default()
        };
        updates.send_replace(later.clone());
        assert_eq!(state.backup_restore_status(), published);
        let mut watch = state.watch_backup_restore();
        assert!(watch.receiver.has_changed().unwrap());
        assert_eq!(watch.changed().await.unwrap(), later);
    }
}
