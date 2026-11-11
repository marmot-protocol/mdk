//! A: the account's published read state (mdk#3273).
//!
//! At each quiescent point the account worker publishes an immutable,
//! versioned copy of the answers that moved host reads will give, behind a
//! `watch` of `Arc`s. Each answer is computed by today's read code on the
//! writer at the moment of publishing, so a read that answers from one
//! version never mixes two states. Nothing reads A yet except tests.
//!
//! Cost: account answers are rebuilt at every publish, except the owned
//! KeyPackages, whose read re-checks every stored bundle's signatures. That
//! list, and each group entry, is reused only while its validity holds: a
//! typed value the build returns with the answers, recording what they were
//! read at and how long they hold (`KeyPackagesValidity`, `EntryValidity`).
//! Reuse checks that value alone, so every input of a reused answer must be
//! either a write those counts see or a field of its validity. App components
//! are reused while the group's hydrated generation holds. A publish that
//! finds nothing changed keeps the current version. Writes are counted across
//! every connection this process has open on the account database; another
//! process's writes are not, and the root runtime lease keeps other runtimes
//! off the database while this one runs.
//!
//! Each version carries `valid_until`, the earliest time an answer in it can
//! change with no write. Nothing publishes at that time yet (mdk#3273 PR 3).
//!
//! Left out: profiles, which a read attaches at read time, and secrets.
//! Errors are kept as `Arc<AppError>`: `AppError` is not `Clone`.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use cgka_traits::app_components::AppComponentId;
use cgka_traits::engine::KeyPackage;
use cgka_traits::types::{GroupId, MemberId};
use cgka_traits::{
    GroupMaintenanceStatus, KeyPackageLifecycleState, PeriodicMaintenancePolicy, Timestamp,
};
use marmot_session::{GroupChangeGeneration, GroupMaintenanceRows, WallClockWindow};
use storage_sqlite::SelfMembership;
use tokio::sync::watch;

use super::AppClient;
use crate::groups::AppGroupRosterSession;
use crate::{
    AppError, AppGroupMemberIds, AppGroupMemberRecord, AppGroupMlsState, AppGroupRecord,
    AppPreparedGroupImageUpload, AppPreparedGroupImageUploadState, AppQuarantinedGroup,
    BackupRestoreStatus, ChatHistoryImport, GroupCommitDelivery,
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
    /// except where a test injects one. Nothing publishes at it yet (mdk#3273
    /// PR 3).
    #[cfg_attr(not(test), allow(dead_code))] // Read by PR 3.
    pub(crate) valid_until: Option<Timestamp>,
    pub(crate) account: Arc<AccountAnswers>,
    /// One entry per group in the account's group mirror.
    pub(crate) groups: Arc<HashMap<GroupId, Arc<GroupAnswers>>>,
}

/// The per-account answers.
#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))] // Moved reads answer from A (mdk#3273 PRs 3–5).
pub(crate) struct AccountAnswers {
    pub(crate) quarantined_groups: Vec<AppQuarantinedGroup>,
    pub(crate) key_package_maintenance_status: ReadAnswer<Option<KeyPackageLifecycleState>>,
    pub(crate) durably_owned_key_packages: ReadAnswer<Vec<KeyPackage>>,
    pub(crate) periodic_maintenance_policy: ReadAnswer<PeriodicMaintenancePolicy>,
    pub(crate) maintenance_paused: bool,
    pub(crate) backup_restore_status: BackupRestoreStatus,
    /// With the in-flight upload overlay applied.
    pub(crate) prepared_group_images: ReadAnswer<Vec<AppPreparedGroupImageUpload>>,
    pub(crate) started_fresh: ReadAnswer<bool>,
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
#[cfg_attr(not(test), allow(dead_code))] // Moved reads answer from A (mdk#3273 PRs 3–5).
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

#[cfg_attr(not(test), allow(dead_code))] // Moved reads answer from A (mdk#3273 PRs 3–5).
fn unknown_group(group_id: &GroupId) -> Arc<AppError> {
    Arc::new(AppError::UnknownGroup(hex::encode(group_id.as_slice())))
}

#[cfg_attr(not(test), allow(dead_code))] // Moved reads answer from A (mdk#3273 PRs 3–5).
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
#[cfg_attr(not(test), allow(dead_code))] // Moved reads answer from A (mdk#3273 PRs 3–5).
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
/// the account database, and checks each bundle's lifetime against the
/// system clock.
#[derive(Clone)]
struct KeyPackagesValidity {
    /// The account database's total write count before the read: every write
    /// to the file, through any connection this process has open on it.
    /// `None` once the database is closed.
    write_count: Option<u64>,
    /// The system-clock window the lifetimes leave the list in: from the one
    /// reading every lifetime was judged at until the first bound ahead.
    window: WallClockWindow,
    /// Whether the read fully succeeded: no failure, no lifetime check on the
    /// other side of a bound from the window's reading, and no stored bundle
    /// skipped because it did not decode.
    reusable: bool,
}

impl KeyPackagesValidity {
    /// Whether a list read at `self` still holds with the database at
    /// `write_count` and the system clock at `now`.
    fn holds(&self, write_count: Option<u64>, now: Timestamp) -> bool {
        self.reusable
            && self.write_count.is_some()
            && self.write_count == write_count
            && self.window.contains(now)
    }
}

/// The owned KeyPackage list, by today's read code, with its validity.
fn owned_key_packages(
    client: &AppClient,
    write_count: Option<u64>,
) -> (ReadAnswer<Vec<KeyPackage>>, KeyPackagesValidity) {
    key_package_answer(
        client.durably_owned_key_packages_with_validity(),
        write_count,
    )
}

/// The answer and validity of a KeyPackage list `read` with the database at
/// `write_count`: it holds from the clock reading its lifetimes were judged
/// at until the first lifetime bound ahead, and only a full success, with no
/// lifetime check on the other side of a bound from that reading, is reused.
fn key_package_answer(
    read: Result<marmot_session::OwnedKeyPackages, AppError>,
    write_count: Option<u64>,
) -> (ReadAnswer<Vec<KeyPackage>>, KeyPackagesValidity) {
    match read {
        Ok(owned) => (
            Ok(owned.key_packages),
            KeyPackagesValidity {
                write_count,
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
                write_count,
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
    /// Whether any account handle the publish reads was still open when the
    /// last publish began: the oracle's window for a terminal close.
    #[cfg(any(test, feature = "test-support"))]
    storage_open_at_publish: bool,
    /// Whether the last publish reused the owned KeyPackage list, which the
    /// oracle then checks even when nothing changed.
    #[cfg(any(test, feature = "test-support"))]
    key_packages_reused: bool,
}

impl ReadStatePublisher {
    pub(crate) fn new(uploads_in_flight: UploadsInFlight) -> Self {
        let (sender, _) = watch::channel(Arc::new(ReadState {
            version: 0,
            valid_until: None,
            account: Arc::new(AccountAnswers {
                quarantined_groups: Vec::new(),
                key_package_maintenance_status: Ok(None),
                durably_owned_key_packages: Ok(Vec::new()),
                periodic_maintenance_policy: Ok(PeriodicMaintenancePolicy::default()),
                maintenance_paused: false,
                backup_restore_status: BackupRestoreStatus::default(),
                prepared_group_images: Ok(Vec::new()),
                started_fresh: Ok(false),
                chat_history_imports: Ok(Vec::new()),
            }),
            groups: Arc::new(HashMap::new()),
        }));
        Self {
            sender,
            uploads_in_flight,
            key_packages: None,
            entries: HashMap::new(),
            #[cfg(any(test, feature = "test-support"))]
            storage_open_at_publish: true,
            #[cfg(any(test, feature = "test-support"))]
            key_packages_reused: false,
        }
    }

    /// Rebuild every answer at the next publish.
    fn forget_inputs(&mut self) {
        self.key_packages = None;
        self.entries.clear();
    }

    #[cfg_attr(not(test), allow(dead_code))] // Moved reads subscribe (mdk#3273 PR 3).
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
        let write_count =
            (!client.engine_storage.is_closed()).then(|| client.engine_storage.write_count());
        let (key_packages, key_package_validity, key_packages_reused) =
            match self.key_packages.take() {
                Some((answer, validity)) if validity.holds(write_count, system_clock_now()) => {
                    (answer, validity, true)
                }
                _ => {
                    let (answer, validity) = owned_key_packages(client, write_count);
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
        let mut valid_until = key_package_validity.window.until;
        self.key_packages = Some((key_packages, key_package_validity));
        let account_changed = !account.same_as(&current.account);
        let account = if account_changed {
            Arc::new(account)
        } else {
            Arc::clone(&current.account)
        };

        let mirror: Vec<(GroupId, AppGroupRecord)> = client
            .state
            .groups
            .iter()
            .filter_map(|record| {
                hex::decode(&record.group_id_hex)
                    .ok()
                    .map(|bytes| (GroupId::new(bytes), record.clone()))
            })
            .collect();
        let generations = client
            .runtime
            .group_change_generations(mirror.iter().map(|(group_id, _)| group_id));
        let mut groups = HashMap::with_capacity(mirror.len());
        let mut entries = HashMap::with_capacity(mirror.len());
        let mut rebuilt = 0usize;
        // Loaded once, for the first entry rebuilt. A failed load leaves each
        // entry to the per-group reads, so its errors are theirs.
        let mut maintenance_rows = None;
        for ((group_id, record), generation) in mirror.into_iter().zip(generations) {
            let earlier = self
                .entries
                .get(&group_id)
                .zip(current.groups.get(&group_id));
            let (answers, validity) = match earlier {
                Some((validity, answers))
                    if validity.holds(&generation, &record, maintenance_paused, now) =>
                {
                    (Arc::clone(answers), validity.clone())
                }
                _ => {
                    rebuilt += 1;
                    let rows = maintenance_rows
                        .get_or_insert_with(|| client.runtime.group_maintenance_rows())
                        .as_ref()
                        .ok();
                    let (answers, validity) = group_entry(
                        client,
                        &group_id,
                        record,
                        generation,
                        maintenance_paused,
                        earlier,
                        rows,
                    );
                    (Arc::new(answers), validity)
                }
            };
            valid_until = earliest(valid_until, validity.window.until);
            entries.insert(group_id.clone(), validity);
            groups.insert(group_id, answers);
        }
        let dropped = current
            .groups
            .keys()
            .any(|group_id| !groups.contains_key(group_id));
        self.entries = entries;
        if !account_changed && rebuilt == 0 && !dropped && valid_until == current.valid_until {
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
    pub(crate) fn start_read_state(&mut self, uploads_in_flight: UploadsInFlight) {
        self.read_state = Some(Box::new(Mutex::new(ReadStatePublisher::new(
            uploads_in_flight,
        ))));
        self.publish_read_state();
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
        // ones and found every group entry's validity holding, so it skips
        // the full check: the oracle's live reads hydrate on demand, and a
        // worker answering a tight poll would spend its time here. A reused
        // KeyPackage list is still checked against a fresh read at every
        // publish.
        #[cfg(any(test, feature = "test-support"))]
        if _changed {
            oracle::check(
                self,
                &publisher.current(),
                publisher.uploads_in_flight().as_ref(),
                publisher.storage_open_at_publish,
            );
        } else if publisher.key_packages_reused {
            oracle::check_key_packages(
                self,
                &publisher.current(),
                publisher.storage_open_at_publish,
            );
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
    use super::*;

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

    /// The owned KeyPackage list alone: a publish that reused it and changed
    /// nothing else.
    pub(crate) fn check_key_packages(
        client: &AppClient,
        state: &ReadState,
        storage_open_at_publish: bool,
    ) {
        let window = Window {
            storage_open_at_publish,
            storage_closed: &client.app.storage_closed,
        };
        key_packages(client, state, window);
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

    /// A KeyPackage list is reused only while the database's write count is
    /// the one it was read at, the system clock is inside its window (not
    /// moved back before the reading its lifetimes were judged at, not past
    /// the next lifetime bound), and the read fully succeeded with every
    /// lifetime check agreeing with that reading.
    #[test]
    fn a_key_package_list_holds_only_inside_its_validity() {
        let owned = marmot_session::OwnedKeyPackages {
            key_packages: Vec::new(),
            checked_at: Timestamp(100),
            changes_at: Some(Timestamp(200)),
            skipped_undecodable: false,
            clock_moved: false,
        };
        let (_, validity) = key_package_answer(Ok(owned.clone()), Some(5));
        assert!(validity.holds(Some(5), Timestamp(150)));
        assert!(!validity.holds(Some(6), Timestamp(150)));
        assert!(!validity.holds(None, Timestamp(150)));
        assert!(!validity.holds(Some(5), Timestamp(99)));
        assert!(!validity.holds(Some(5), Timestamp(200)));
        let (_, closed) = key_package_answer(Ok(owned.clone()), None);
        assert!(!closed.holds(None, Timestamp(150)));
        let (_, skipped) = key_package_answer(
            Ok(marmot_session::OwnedKeyPackages {
                skipped_undecodable: true,
                ..owned.clone()
            }),
            Some(5),
        );
        assert!(!skipped.holds(Some(5), Timestamp(150)));
        let (_, moved) = key_package_answer(
            Ok(marmot_session::OwnedKeyPackages {
                clock_moved: true,
                ..owned
            }),
            Some(5),
        );
        assert!(!moved.holds(Some(5), Timestamp(150)));
        let (_, failed) = key_package_answer(Err(closed_storage()), Some(5));
        assert!(!failed.holds(Some(5), Timestamp(150)));
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
}
