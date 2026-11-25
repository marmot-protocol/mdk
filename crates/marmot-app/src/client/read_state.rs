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
//! send keeps it. The account's recovery answer (R9, mdk#3273 PR 8) is reused
//! too: its read while the recovery-notice write count, the routing version
//! and the runner's survey hold, and the status built from it while every
//! group it asked a fact of holds its change stamp ([`RecoveryAnswer`]).
//! Each group's recovery status is part of its entry, rebuilt when the
//! group's notices in the account's read change as well as when its
//! generation moves.
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

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cgka_traits::app_components::AppComponentId;
use cgka_traits::engine::KeyPackage;
use cgka_traits::error::EngineError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::storage::{CommittedMembers, CommittedRosterStorage, RosterRevision};
use cgka_traits::types::{GroupId, MemberId};
use cgka_traits::{
    GroupMaintenanceStatus, KeyPackageLifecycleState, PeriodicMaintenancePolicy, StorageError,
    Timestamp,
};
use marmot_session::{ChangeStamp, GroupChangeGeneration, GroupMaintenanceRows, WallClockWindow};
use storage_sqlite::{SelfMembership, StoredGroupStanding};
use tokio::sync::watch;

use super::AppClient;
use super::history_recovery::history_notices::reuse::RecoveryAnswer;
use super::history_recovery::history_notices::{
    Fact, GroupFacts, GroupNotices, LiveFacts, RecoveryRead,
};
use super::invite_recovery::InvitationRows;
use crate::groups::AppGroupRosterSession;
use crate::{
    AccountRecoveryStatus, AppError, AppGroupMemberIds, AppGroupMemberRecord, AppGroupMlsState,
    AppGroupRecord, AppPreparedGroupImageUpload, AppPreparedGroupImageUploadState,
    AppQuarantinedGroup, BackupRestoreStatus, BackupRestoreWatch, ChatHistoryImport,
    GroupCommitDelivery, GroupRecoveryStatus, HistoryNotice,
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

/// The worker's answer to a hydration request (mdk#3273 PR 4): the version
/// it published after it hydrated the named groups, and the first failure a
/// hydration returned, which the reads that return that failure today hand
/// back.
#[derive(Debug)]
pub(crate) struct HydrationAck {
    pub(crate) state: Arc<ReadState>,
    pub(crate) failure: Option<AppError>,
}

impl HydrationAck {
    /// The acknowledging version, checked as [`ReadStateReader::version`]
    /// checks the version it takes: storage closed is checked now that the
    /// acknowledgement has arrived, before any of its answers is read.
    pub(crate) fn version(&self, storage_closed: &AtomicBool) -> Result<Arc<ReadState>, AppError> {
        if storage_closed.load(Ordering::Acquire) {
            return Err(storage_closed_error());
        }
        Ok(Arc::clone(&self.state))
    }
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
    /// With the in-flight upload overlay applied: the worker's set as it
    /// stood at the publish, which only the worker changes.
    pub(crate) prepared_group_images: ReadAnswer<Vec<AppPreparedGroupImageUpload>>,
    /// The listed uploads whose record the worker's status read fails to read
    /// (a column only it decodes holds another type), from the list's own
    /// statement: their status goes to the worker. Empty when the list failed.
    pub(crate) prepared_group_image_records_unread: HashSet<String>,
    pub(crate) started_fresh: ReadAnswer<bool>,
    pub(crate) chat_history_imports: ReadAnswer<Vec<ChatHistoryImport>>,
    /// The account's recovery status, whose notices `HistoryNotices` lists
    /// (mdk#3273 PR 8). Shared with the publisher's kept answer.
    pub(crate) recovery_status: ReadAnswer<Arc<AccountRecoveryStatus>>,
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
            prepared_group_image_records_unread,
            started_fresh,
            chat_history_imports,
            recovery_status,
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
            && *prepared_group_image_records_unread == other.prepared_group_image_records_unread
            && same_answer(started_fresh, &other.started_fresh, PartialEq::eq)
            && same_answer(
                chat_history_imports,
                &other.chat_history_imports,
                PartialEq::eq,
            )
            && same_answer(recovery_status, &other.recovery_status, |ours, theirs| {
                Arc::ptr_eq(ours, theirs) || ours == theirs
            })
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
    /// Whether the engine has seeded the group without hydrating it yet: a
    /// read that hydrates on demand asks the worker to hydrate it first.
    pub(crate) awaits_hydration: bool,
    /// Whether the engine serves the group's gated reads: it is neither
    /// quarantined nor awaiting hydration. Its committed roster is trusted
    /// only while this holds (mdk#3273 PR 6).
    pub(crate) serves_reads: bool,
    /// The group's committed roster revision, `None` when it has none
    /// (mdk#3273 PR 6). A read of the roster tables matches the group only
    /// at this revision ([`ReadState::trusted_rosters`]).
    pub(crate) roster_revision: ReadAnswer<Option<RosterRevision>>,
    /// Member accounts and their device counts, without profiles.
    pub(crate) members: ReadAnswer<Vec<(MemberId, u32)>>,
    /// The saved row's standing, `None` when the group has no saved row:
    /// the roster overlays its self membership on the mirror record, and
    /// co-members judge the group by it alone.
    pub(crate) standing: ReadAnswer<Option<StoredGroupStanding>>,
    pub(crate) mls_state: ReadAnswer<AppGroupMlsState>,
    pub(crate) commit_delivery: ReadAnswer<Option<GroupCommitDelivery>>,
    pub(crate) maintenance_status: ReadAnswer<GroupMaintenanceStatus>,
    /// Every app-owned component the group holds, in id order.
    pub(crate) app_components: ReadAnswer<Vec<(AppComponentId, Vec<u8>)>>,
    /// `GroupRecoveryStatus`, from the publish's recovery read (mdk#3273
    /// PR 8).
    pub(crate) recovery_status: ReadAnswer<GroupRecoveryStatus>,
}

impl GroupAnswers {
    /// Whether every answer equals `other`'s, failures compared by their
    /// debug form as the oracle compares them: a rebuilt entry that is the
    /// same keeps the published one, and the version (mdk#3273 PR 3).
    fn same_as(&self, other: &Self) -> bool {
        let Self {
            record,
            host_may_see,
            awaits_hydration,
            serves_reads,
            roster_revision,
            members,
            standing,
            mls_state,
            commit_delivery,
            maintenance_status,
            app_components,
            recovery_status,
        } = self;
        *record == other.record
            && *host_may_see == other.host_may_see
            && *awaits_hydration == other.awaits_hydration
            && *serves_reads == other.serves_reads
            && same_answer(roster_revision, &other.roster_revision, PartialEq::eq)
            && same_answer(members, &other.members, PartialEq::eq)
            && same_answer(standing, &other.standing, PartialEq::eq)
            && same_answer(mls_state, &other.mls_state, PartialEq::eq)
            && same_answer(commit_delivery, &other.commit_delivery, PartialEq::eq)
            && same_answer(maintenance_status, &other.maintenance_status, PartialEq::eq)
            && same_answer(app_components, &other.app_components, PartialEq::eq)
            && same_answer(recovery_status, &other.recovery_status, PartialEq::eq)
    }
}

/// Whether `group` counts toward co-members, by its saved row alone: the
/// local account is a member and no invite awaits its confirmation, as
/// [`crate::runtime::group_contributes_co_members`] judges a saved row
/// (mdk#3273 PR 4). A group with no saved row counts nobody. The saved row
/// keeps no `unrecoverable` mark, so that term of the judgement never
/// excludes a saved row, and there is nothing here to read for it. No fact
/// of the mirror decides, so a crash after a failed save cannot take an
/// answer back.
fn counts_toward_co_members(group: &GroupAnswers) -> ReadAnswer<bool> {
    Ok(group
        .standing
        .as_ref()
        .map_err(Arc::clone)?
        .is_some_and(|standing| {
            !standing.pending_confirmation
                && matches!(standing.self_membership, SelfMembership::Member)
        }))
}

fn unknown_group(group_id: &GroupId) -> Arc<AppError> {
    Arc::new(AppError::UnknownGroup(hex::encode(group_id.as_slice())))
}

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
        if let Some(standing) = group.standing.as_ref().map_err(Arc::clone)? {
            group_record.self_membership = standing.self_membership;
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
    #[cfg_attr(not(test), allow(dead_code))] // Only the oracle reads it.
    pub(crate) fn host_may_see(&self, group_id: &GroupId) -> Option<bool> {
        self.groups.get(group_id).map(|group| group.host_may_see)
    }

    /// The groups of `group_ids`, in order, that this version shows seeded
    /// but not hydrated: a read that hydrates on demand today sends them to
    /// the worker first. A group outside the mirror awaits nothing; every
    /// read answers it `UnknownGroup`.
    pub(crate) fn awaiting_hydration(&self, group_ids: &[GroupId]) -> Vec<GroupId> {
        group_ids
            .iter()
            .filter(|group_id| {
                self.groups
                    .get(*group_id)
                    .is_some_and(|group| group.awaits_hydration)
            })
            .cloned()
            .collect()
    }

    /// Whether this version holds every group in `group_ids` or lists it
    /// quarantined. Every stored group is in the mirror, so a group whose
    /// chat-list row has committed is held by the first version published
    /// after it (mdk#3273 PR 4; the oracle checks it at every publish).
    pub(crate) fn holds(&self, group_ids: &[GroupId]) -> bool {
        group_ids.iter().all(|group_id| {
            self.groups.contains_key(group_id)
                || self
                    .account
                    .quarantined_groups
                    .iter()
                    .any(|group| group.group_id_hex == hex::encode(group_id.as_slice()))
        })
    }

    /// The groups [`Self::co_members`] reads, in id order: those whose saved
    /// row [`counts_toward_co_members`]. A read hydrates the ones awaiting
    /// hydration first, as each member read hydrated its group.
    pub(crate) fn co_member_groups(&self) -> Vec<GroupId> {
        let mut groups = self
            .groups
            .iter()
            .filter(|(_, group)| matches!(counts_toward_co_members(group), Ok(true)))
            .map(|(group_id, _)| group_id.clone())
            .collect::<Vec<_>>();
        groups.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
        groups
    }

    /// `GroupCoMembers`: every other account that shares with
    /// `local_account_id_hex` one of [`Self::co_member_groups`], from
    /// this version alone (mdk#3273 PR 4). A group this version doesn't hold
    /// yet counts from the version that does. A failed read of a saved row
    /// fails the read, as it failed the saved group listing; otherwise the
    /// first group in id order whose members failed gives the failure.
    pub(crate) fn co_members(&self, local_account_id_hex: &str) -> ReadAnswer<Vec<String>> {
        for group in self.groups.values() {
            group.standing.as_ref().map_err(Arc::clone)?;
        }
        let mut co_members = BTreeSet::new();
        for group_id in self.co_member_groups() {
            let members = self
                .group(&group_id)?
                .members
                .as_ref()
                .map_err(Arc::clone)?;
            for (member_id, _) in members {
                let member_id_hex = hex::encode(member_id.as_slice());
                if member_id_hex != local_account_id_hex {
                    co_members.insert(member_id_hex);
                }
            }
        }
        Ok(co_members.into_iter().collect())
    }

    /// The committed rosters this version trusts (mdk#3273 PR 6), in group
    /// id order: each group it holds that the engine serves (neither
    /// quarantined nor awaiting hydration) and the host may see, at the
    /// committed roster revision it recorded. A group with no roster, or
    /// whose revision read failed, is not trusted.
    #[cfg_attr(not(test), allow(dead_code))] // People search reads it (mdk#2983 slice 6).
    pub(crate) fn trusted_rosters(&self) -> Vec<(GroupId, RosterRevision)> {
        let mut trusted: Vec<(GroupId, RosterRevision)> = self
            .groups
            .iter()
            .filter(|(_, group)| group.serves_reads && group.host_may_see)
            .filter_map(|(group_id, group)| {
                let revision = (*group.roster_revision.as_ref().ok()?)?;
                Some((group_id.clone(), revision))
            })
            .collect();
        trusted.sort_by(|(left, _), (right, _)| left.as_slice().cmp(right.as_slice()));
        trusted
    }

    /// The members of each roster this version trusts, read from `storage`
    /// at the revisions it recorded alone (mdk#3273 PR 6): a roster written
    /// since, which no version has published yet, never matches.
    #[cfg_attr(not(test), allow(dead_code))] // People search reads it (mdk#2983 slice 6).
    pub(crate) fn trusted_roster_members(
        &self,
        storage: &storage_sqlite::SqliteAppStorage,
    ) -> Result<Vec<(GroupId, CommittedMembers)>, AppError> {
        Ok(storage.trusted_roster_members(&self.trusted_rosters())?)
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

    /// `WatchBackupRestore`: a watch of the client's progress channel that
    /// has seen the status published here, even before the channel
    /// announces it. A change sent since then is still news to it.
    pub(crate) fn watch_backup_restore(&self) -> BackupRestoreWatch {
        BackupRestoreWatch {
            receiver: self.account.backup_restore_updates.clone(),
            seen: self.account.backup_restore_status.clone(),
        }
    }
}

/// The prepared group image reads (R1) and the account's device-group
/// history reads (R2), from this version alone (mdk#3273 PR 5).
impl ReadState {
    /// `PreparedGroupImages`, with the in-flight overlay applied.
    pub(crate) fn prepared_group_images(&self) -> ReadAnswer<Vec<AppPreparedGroupImageUpload>> {
        self.account.prepared_group_images.clone()
    }

    /// `PreparedGroupImageStatus`: the listed upload's status, or today's
    /// not-found failure for an id the list does not hold. Both storage
    /// reads decode the same status columns, so where both succeed they
    /// agree. `None` while the list failed, or for an upload whose record
    /// the worker's read fails on a column the list does not decode: this
    /// version then holds no answer for it, which the worker's read of that
    /// one row gives, since another row's failure does not fail it.
    pub(crate) fn prepared_group_image_status(
        &self,
        upload_id: &str,
    ) -> Option<ReadAnswer<AppPreparedGroupImageUpload>> {
        let statuses = self.account.prepared_group_images.as_ref().ok()?;
        if self
            .account
            .prepared_group_image_records_unread
            .contains(upload_id)
        {
            return None;
        }
        Some(
            statuses
                .iter()
                .find(|status| status.upload_id == upload_id)
                .cloned()
                .ok_or_else(|| {
                    Arc::new(AppError::InvalidEncryptedMedia(
                        "prepared group image upload was not found".into(),
                    ))
                }),
        )
    }

    /// `StartedFresh`.
    pub(crate) fn started_fresh(&self) -> ReadAnswer<bool> {
        self.account.started_fresh.clone()
    }

    /// `ChatHistoryImports`.
    pub(crate) fn chat_history_imports(&self) -> ReadAnswer<Vec<ChatHistoryImport>> {
        self.account.chat_history_imports.clone()
    }
}

/// The account's recovery reads (R9, mdk#3273 PR 8), from this version
/// alone.
impl ReadState {
    /// `HistoryNotices`: the recovery status's notices, which today's read
    /// computes from the same read, so it gives the same success and the
    /// same failure.
    pub(crate) fn history_notices(&self) -> ReadAnswer<Vec<HistoryNotice>> {
        Ok(self
            .account
            .recovery_status
            .as_ref()
            .map_err(Arc::clone)?
            .notices
            .clone())
    }

    /// `AccountRecoveryStatus`.
    pub(crate) fn account_recovery_status(&self) -> ReadAnswer<AccountRecoveryStatus> {
        Ok(AccountRecoveryStatus::clone(
            self.account.recovery_status.as_ref().map_err(Arc::clone)?,
        ))
    }

    /// `GroupRecoveryStatus` of a group in the mirror. `None` for any other
    /// id, which the worker answers as it did before A: today's read
    /// answers a locally deleted group, outside the mirror, from its kept
    /// MLS state (mdk#3273 decision 1).
    pub(crate) fn group_recovery_status(
        &self,
        group_id: &GroupId,
    ) -> Option<ReadAnswer<GroupRecoveryStatus>> {
        self.groups
            .get(group_id)
            .map(|group| group.recovery_status.clone())
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
/// group not hydrated yet, a storage failure, from the app or the engine,
/// a KeyPackage outside its lifetime (a group's recovery status judges
/// its reinvites' KeyPackages), and an encrypted-media failure, whose payload
/// is its message (a prepared group image upload the list does not hold).
/// An engine failure keeps its wrapping, whether
/// the app's session, the account or the account's session raised it. Any
/// other failure (SQLite, I/O, JSON, the rest of the engine's) has no copy,
/// so it is never rebuilt into a different error.
pub(crate) fn reissue_error(error: &AppError) -> Option<AppError> {
    use marmot_session::{AccountError, SessionError};
    fn copy_engine(engine: &EngineError) -> Option<EngineError> {
        match engine {
            EngineError::UnknownGroup(group) => Some(EngineError::UnknownGroup(group.clone())),
            EngineError::GroupNotHydrated(group) => {
                Some(EngineError::GroupNotHydrated(group.clone()))
            }
            EngineError::Storage(storage) => Some(EngineError::Storage(storage.clone())),
            EngineError::InvalidKeyPackageLifetime {
                not_before,
                not_after,
            } => Some(EngineError::InvalidKeyPackageLifetime {
                not_before: *not_before,
                not_after: *not_after,
            }),
            _ => None,
        }
    }
    match error {
        AppError::UnknownGroup(group) => Some(AppError::UnknownGroup(group.clone())),
        AppError::Storage(storage) => Some(AppError::Storage(storage.clone())),
        AppError::InvalidEncryptedMedia(message) => {
            Some(AppError::InvalidEncryptedMedia(message.clone()))
        }
        AppError::Session(SessionError::Engine(engine)) => {
            copy_engine(engine).map(|engine| AppError::Session(SessionError::Engine(engine)))
        }
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
        account: Arc::new(empty_account_answers()),
        groups: Arc::new(HashMap::new()),
    }));
    (ReadStateSender(sender), ReadStateReader { receiver })
}

/// The account answers of version 0, before the worker's first publish.
fn empty_account_answers() -> AccountAnswers {
    AccountAnswers {
        quarantined_groups: Vec::new(),
        key_package_maintenance_status: Ok(None),
        durably_owned_key_packages: Ok(Vec::new()),
        periodic_maintenance_policy: Ok(PeriodicMaintenancePolicy::default()),
        maintenance_paused: false,
        backup_restore_status: BackupRestoreStatus::default(),
        backup_restore_updates: watch::channel(BackupRestoreStatus::default()).1,
        prepared_group_images: Ok(Vec::new()),
        prepared_group_image_records_unread: HashSet::new(),
        started_fresh: Ok(false),
        chat_history_imports: Ok(Vec::new()),
        recovery_status: Ok(Arc::default()),
    }
}

#[cfg(test)]
impl ReadStateSender {
    /// Publish the next version, holding the empty account answers as `edit`
    /// leaves them and no groups: for tests that hand-build a worker's lane.
    pub(crate) fn publish_for_test(&self, edit: impl FnOnce(&mut AccountAnswers)) {
        let mut account = empty_account_answers();
        edit(&mut account);
        let version = self.0.borrow().version + 1;
        self.0.send_replace(Arc::new(ReadState {
            version,
            valid_until: None,
            account: Arc::new(account),
            groups: Arc::default(),
        }));
    }
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

    /// Resolves once a version [`ReadState::holds`] every group in
    /// `group_ids` still stored, or before the worker's first publish (the
    /// reads then go to the worker). When a version does not hold them,
    /// `still_stored` narrows them to the ones whose stored rows remain: a
    /// group forgotten or deleted since the caller read its row is in no
    /// later version, so it is not waited for. Waits on the caller's task;
    /// the caller bounds it. Fails as [`Self::version`] does, or as
    /// `still_stored` does.
    pub(crate) async fn holding(
        &self,
        storage_closed: &AtomicBool,
        group_ids: &[GroupId],
        mut still_stored: impl FnMut(Vec<GroupId>) -> Result<Vec<GroupId>, AppError>,
    ) -> Result<(), AppError> {
        let mut waiting = group_ids.to_vec();
        let mut receiver = self.receiver.clone();
        loop {
            let state = Arc::clone(&receiver.borrow_and_update());
            if storage_closed.load(Ordering::Acquire) {
                return Err(storage_closed_error());
            }
            if state.version == 0 || state.holds(&waiting) {
                return Ok(());
            }
            waiting = still_stored(waiting)?;
            if state.holds(&waiting) {
                return Ok(());
            }
            receiver
                .changed()
                .await
                .map_err(|_| AppError::TransportClosed)?;
        }
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
    /// The system-clock window the recovery status's KeyPackage lifetimes
    /// leave it in: a retained reinvite's KeyPackage past its `not_after`
    /// fails the status, with no write.
    key_packages: WallClockWindow,
    /// The group's notices in the recovery read its recovery status was
    /// built from, `None` when that read failed: a park, a dismissal or a
    /// route gone moves them and no write of the group (mdk#3273 PR 8).
    notices: Option<GroupNotices>,
    /// The group's facts the account's recovery status takes from the
    /// entry: both read only what the generation counts.
    recovery_facts: OwnFacts,
    /// False when a read failed on something other than a fact about the
    /// group ([`settled_failure`]), whether its answer keeps the failure or
    /// swallows it (the device-group check, which hides the group). Such a
    /// failure can clear with no write.
    reusable: bool,
}

impl EntryValidity {
    /// Whether an entry built at `self` still holds for a group now at
    /// `generation`, `record` and `maintenance_paused`, at `now` on the
    /// account's wall clock and `system_now` on the system clock. A clock
    /// moved back before the reading an answer was computed at can bring an
    /// expired bound back into force.
    fn holds(
        &self,
        generation: &GroupChangeGeneration,
        record: &AppGroupRecord,
        maintenance_paused: bool,
        now: Timestamp,
        system_now: Timestamp,
    ) -> bool {
        self.reusable
            && generation.state.unchanged_since(&self.generation.state)
            && *record == self.record
            && maintenance_paused == self.maintenance_paused
            && self.window.contains(now)
            && self.key_packages.contains(system_now)
    }

    /// Whether the entry's recovery status still holds for the group's
    /// notices in this publish's recovery read, `None` when it failed.
    fn notices_hold(&self, notices: Option<&GroupNotices>) -> bool {
        self.notices.as_ref() == notices
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
/// can clear without a write. The account's recovery answer judges the
/// group facts it uses by the same rule.
pub(crate) fn settled_failure(error: &AppError) -> bool {
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

/// One group's recovery facts as its entry read them: whether the host may
/// see it (the device-group check, a failure hiding it) and whether its copy
/// is Unrecoverable (the engine record, a failure reading as recoverable),
/// each with whether its check settled.
#[derive(Clone, Copy)]
struct OwnFacts {
    host_may_see: Fact,
    unrecoverable: Fact,
}

/// An entry's own status asks facts of its own group only.
impl GroupFacts for OwnFacts {
    fn host_may_see(&self, _: &[u8]) -> Fact {
        self.host_may_see
    }

    fn unrecoverable(&self, _: &[u8]) -> Fact {
        self.unrecoverable
    }

    fn stamp(&self, _: &[u8]) -> Option<ChangeStamp> {
        None
    }
}

/// The account recovery status's group facts, from each mirror group's entry
/// in this publish, at the generation the entry was built at. A group
/// outside the mirror has no entry: its facts are read live, at no stamp, so
/// a status that used them is never kept (mdk#3273 decision 3, condition 2).
struct EntryFacts<'a> {
    client: &'a AppClient,
    entries: &'a HashMap<GroupId, EntryValidity>,
}

impl EntryFacts<'_> {
    fn entry(&self, group_id: &[u8]) -> Option<&EntryValidity> {
        self.entries.get(&GroupId::new(group_id.to_vec()))
    }
}

impl GroupFacts for EntryFacts<'_> {
    fn host_may_see(&self, group_id: &[u8]) -> Fact {
        self.entry(group_id).map_or_else(
            || LiveFacts(self.client).host_may_see(group_id),
            |entry| entry.recovery_facts.host_may_see,
        )
    }

    fn unrecoverable(&self, group_id: &[u8]) -> Fact {
        self.entry(group_id).map_or_else(
            || LiveFacts(self.client).unrecoverable(group_id),
            |entry| entry.recovery_facts.unrecoverable,
        )
    }

    fn stamp(&self, group_id: &[u8]) -> Option<ChangeStamp> {
        self.entry(group_id)
            .map(|entry| entry.generation.state.clone())
    }
}

/// A publish's recovery read: the kept answer's while it holds, else a
/// fresh one.
enum PublishRecoveryRead {
    Kept(RecoveryAnswer),
    Fresh(Result<RecoveryRead, Arc<AppError>>),
}

impl PublishRecoveryRead {
    fn read(&self) -> Result<&RecoveryRead, &Arc<AppError>> {
        match self {
            Self::Kept(answer) => answer.read(),
            Self::Fresh(read) => read.as_ref(),
        }
    }
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
pub(crate) fn system_clock_now() -> Timestamp {
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
    /// The account's recovery answer the last publish read or kept.
    recovery: Option<RecoveryAnswer>,
    /// The earliest commit-delivery bound among `entries`, on the account's
    /// wall clock.
    groups_valid_until: Option<Timestamp>,
    /// The earliest KeyPackage bound among `entries`' recovery statuses, on
    /// the system clock.
    groups_key_packages_until: Option<Timestamp>,
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
    /// write, each bound measured on its own clock: KeyPackage lifetimes (the
    /// owned list's and the recovery statuses') on the system clock,
    /// commit-delivery bounds on the account's wall clock.
    /// Never under a second, the clocks' resolution, so a bound the clock
    /// does not show as passed yet is waited for rather than spun on.
    fn deadline(&self, wall_now: Timestamp, system_now: Timestamp) -> Option<Duration> {
        let remaining = |until: Timestamp, now: Timestamp| until.0.saturating_sub(now.0);
        let key_packages = earliest(
            self.key_packages
                .as_ref()
                .and_then(|(_, validity)| validity.window.until),
            self.groups_key_packages_until,
        )
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
            recovery: None,
            groups_valid_until: None,
            groups_key_packages_until: None,
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
        self.recovery = None;
        #[cfg(any(test, feature = "test-support"))]
        {
            self.key_package_inputs = None;
        }
    }

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
        // Read before every recovery status's KeyPackage check, so a check on
        // the other side of a bound shows as a moved clock.
        let system_now = system_clock_now();

        // Read before the build, so a write that lands during it ends the
        // reuse at the next publish.
        let key_package_writes = (!client.engine_storage.is_closed())
            .then(|| client.engine_storage.key_package_write_count());
        let recovery_inputs = client.recovery_inputs();
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
        let durably_owned_key_packages = key_packages.clone();
        let key_packages_valid_until = key_package_validity.window.until;
        self.key_packages = Some((key_packages, key_package_validity));

        // The account's recovery read, kept while it holds. Every group's
        // recovery status below is built from it, and the account status
        // after them from the facts their entries hold.
        let recovery_read = match self.recovery.take() {
            Some(answer) if answer.read_holds(&recovery_inputs) => {
                PublishRecoveryRead::Kept(answer)
            }
            _ => PublishRecoveryRead::Fresh(client.read_recovery().map_err(Arc::new)),
        };
        // A kept read is the one every entry carried over was last checked
        // against, so their notices in it hold.
        let recovery_read_kept = matches!(recovery_read, PublishRecoveryRead::Kept(_));

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
        let mut groups_key_packages_until = None;
        // Loaded once, for the first entry rebuilt. A failed load leaves each
        // entry to the per-group reads, so its errors are theirs.
        let mut maintenance_rows = None;
        let mut invitation_rows = None;
        let mut earlier_entries = std::mem::take(&mut self.entries);
        for ((group_id, record), generation) in mirror.into_iter().zip(generations) {
            let earlier = earlier_entries
                .remove(&group_id)
                .zip(current.groups.get(&group_id));
            let (answers, validity) = match earlier {
                Some((validity, answers))
                    if validity.holds(&generation, record, maintenance_paused, now, system_now)
                        && (recovery_read_kept
                            || validity.notices_hold(
                                recovery_read
                                    .read()
                                    .ok()
                                    .map(|read| read.group_notices(&group_id)),
                            )) =>
                {
                    (Arc::clone(answers), validity)
                }
                earlier => {
                    rebuilt += 1;
                    let rows = maintenance_rows
                        .get_or_insert_with(|| client.runtime.group_maintenance_rows())
                        .as_ref()
                        .ok();
                    let invitations = invitation_rows
                        .get_or_insert_with(|| client.invitation_rows())
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
                        invitations,
                        recovery_read.read(),
                        system_now,
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
            groups_key_packages_until =
                earliest(groups_key_packages_until, validity.key_packages.until);
            entries.insert(group_id.clone(), validity);
            groups.insert(group_id, answers);
        }
        let dropped = current
            .groups
            .keys()
            .any(|group_id| !groups.contains_key(group_id));

        let facts = EntryFacts {
            client,
            entries: &entries,
        };
        let (recovery, recovery_status_kept) = match recovery_read {
            PublishRecoveryRead::Kept(answer)
                if answer.status_holds(&|group_id: &[u8]| facts.stamp(group_id)) =>
            {
                (answer, true)
            }
            PublishRecoveryRead::Kept(answer) => (answer.refresh(&facts), false),
            PublishRecoveryRead::Fresh(read) => {
                (RecoveryAnswer::build(recovery_inputs, read, &facts), false)
            }
        };
        let account = account_answers(
            client,
            maintenance_paused,
            uploads_in_flight.as_ref(),
            durably_owned_key_packages,
            recovery.status().clone(),
        );
        self.recovery = Some(recovery);
        let account_changed = !account.same_as(&current.account);
        let account = if account_changed {
            Arc::new(account)
        } else {
            Arc::clone(&current.account)
        };
        self.entries = entries;
        self.groups_valid_until = groups_valid_until;
        self.groups_key_packages_until = groups_key_packages_until;
        let valid_until = earliest(
            earliest(key_packages_valid_until, groups_valid_until),
            groups_key_packages_until,
        );
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
            recovery_read_kept,
            recovery_status_kept,
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
/// list and the recovery status the caller read or kept.
fn account_answers(
    client: &AppClient,
    maintenance_paused: bool,
    uploads_in_flight: Option<&HashSet<String>>,
    durably_owned_key_packages: ReadAnswer<Vec<KeyPackage>>,
    recovery_status: ReadAnswer<Arc<AccountRecoveryStatus>>,
) -> AccountAnswers {
    let (prepared_group_images, prepared_group_image_records_unread) =
        match client.prepared_initial_group_images_with_record_check() {
            Ok((statuses, unread)) => (
                Ok(with_uploads_in_flight(statuses, uploads_in_flight)),
                unread,
            ),
            Err(error) => (Err(Arc::new(error)), HashSet::new()),
        };
    AccountAnswers {
        quarantined_groups: client.quarantined_groups(),
        key_package_maintenance_status: arc_err(client.key_package_maintenance_status()),
        durably_owned_key_packages,
        periodic_maintenance_policy: arc_err(client.periodic_maintenance_policy()),
        maintenance_paused,
        backup_restore_status: client.backup_restore_status(),
        backup_restore_updates: client.watch_backup_restore().receiver,
        prepared_group_images,
        prepared_group_image_records_unread,
        started_fresh: arc_err(client.started_fresh()),
        chat_history_imports: arc_err(client.chat_history_imports()),
        recovery_status,
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
/// whose app components are kept while they hold; `recovery` is the
/// publish's recovery read.
#[allow(clippy::too_many_arguments)]
fn group_entry(
    client: &AppClient,
    group_id: &GroupId,
    record: AppGroupRecord,
    generation: GroupChangeGeneration,
    maintenance_paused: bool,
    earlier: Option<(&EntryValidity, &Arc<GroupAnswers>)>,
    maintenance_rows: Option<&GroupMaintenanceRows>,
    invitation_rows: Option<&InvitationRows>,
    recovery: Result<&RecoveryRead, &Arc<AppError>>,
    system_now: Timestamp,
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
    // The engine record gives whether the group's copy is Unrecoverable (a
    // group not hydrated yet reads its stored record) and its recovery
    // status, which reads it once, as `group_recovery_status`.
    let engine_record = client
        .runtime
        .group_record(group_id)
        .map_err(AppError::from);
    let recovery_facts = OwnFacts {
        host_may_see: Fact {
            value: matches!(device_group, Ok(false)),
            settled: device_group.is_ok(),
        },
        unrecoverable: client.unrecoverable_fact(group_id, engine_record.as_ref()),
    };
    // The recovery read fails first, then the record, as today's read. A
    // failed status depends on no clock reading, and is never reused.
    let (recovery_status, recovery_inputs) = match (recovery, engine_record) {
        (Err(error), _) => (Err(Arc::clone(error)), None),
        (Ok(_), Err(error)) => (Err(Arc::new(error)), None),
        (Ok(read), Ok(group)) => match client.group_recovery_status_in(
            group_id,
            &group,
            read,
            &recovery_facts,
            invitation_rows,
            system_now,
        ) {
            Ok((status, inputs)) => (Ok(status), Some(inputs)),
            Err(error) => (Err(Arc::new(error)), None),
        },
    };
    // A failed read depends on no clock reading, and is never reused.
    let (commit_delivery, window) =
        match client.group_commit_delivery_until(group_id, maintenance_rows) {
            Ok((delivery, window)) => (Ok(delivery), window),
            Err(error) => (Err(Arc::new(error)), WallClockWindow::ALWAYS),
        };
    let answers = GroupAnswers {
        host_may_see: matches!(device_group, Ok(false)),
        awaits_hydration: generation.awaits_hydration(),
        serves_reads: generation.serves_reads(),
        roster_revision: client
            .engine_storage
            .committed_roster_revision(group_id)
            .map_err(|error| Arc::new(AppError::from(error))),
        members: client
            .runtime
            .members(group_id)
            .map(|members| crate::groups::member_accounts(&members))
            .map_err(|error| Arc::new(AppError::from(error))),
        standing: arc_err(
            client
                .app
                .stored_group_standing(&client.state.label, &record.group_id_hex),
        ),
        mls_state: arc_err(client.group_mls_state_unchecked(group_id)),
        commit_delivery,
        maintenance_status: client
            .runtime
            .maintenance_status_in(group_id, maintenance_rows)
            .map_err(|error| Arc::new(AppError::from(error))),
        app_components,
        recovery_status,
        record: record.clone(),
    };
    let reusable = device_group.is_ok()
        && recovery_facts.unrecoverable.settled
        && settled(&answers.roster_revision)
        && settled(&answers.members)
        && settled(&answers.standing)
        && settled(&answers.mls_state)
        && settled(&answers.commit_delivery)
        && settled(&answers.maintenance_status)
        && settled(&answers.app_components)
        && settled(&answers.recovery_status)
        && recovery_inputs
            .as_ref()
            .is_none_or(|inputs| inputs.reusable);
    let validity = EntryValidity {
        generation,
        record,
        maintenance_paused,
        window,
        key_packages: recovery_inputs.map_or(WallClockWindow::ALWAYS, |inputs| inputs.key_packages),
        notices: recovery
            .ok()
            .map(|read| read.group_notices(group_id).clone()),
        recovery_facts,
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
            // The recovery answers, kept or rebuilt, at every publish
            // (mdk#3273 decision 3).
            oracle::recovery(
                self,
                &publisher.current(),
                publisher.recovery.as_ref(),
                publisher.storage_open_at_publish,
            );
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
    /// may be compared with them. The worker resumes A only on a client
    /// whose deferred hydration it has drained, so A never shows a group a
    /// reopen only seeded.
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

    /// The account recovery status this client's last publish read or kept:
    /// the same `Arc` while the answer is kept.
    #[cfg(test)]
    pub(crate) fn read_state_recovery_status(
        &self,
    ) -> Option<ReadAnswer<Arc<AccountRecoveryStatus>>> {
        let slot = self.read_state.as_ref()?;
        let publisher = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        publisher
            .recovery
            .as_ref()
            .map(|answer| answer.status().clone())
    }

    /// A receiver of every version this client publishes, if it publishes:
    /// a long unit that holds the client acknowledges a hydration request
    /// that needs no hydration from its latest version (mdk#3273 PR 4).
    pub(crate) fn subscribe_read_state(&self) -> Option<watch::Receiver<Arc<ReadState>>> {
        self.read_state.as_ref().map(|slot| {
            slot.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .subscribe()
        })
    }

    /// The version this client published last, if it publishes.
    pub(crate) fn published_read_state(&self) -> Option<Arc<ReadState>> {
        self.read_state.as_ref().map(|slot| {
            slot.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .current()
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

    /// The recovery answers against the live reads, at every publish,
    /// changed or not (mdk#3273 decision 3, condition 1): the account status
    /// as `answer` holds it, under decision 2's window for a survey that
    /// landed since its read, and every mirror group's status, strictly.
    /// A closed-storage failure on either side inside the close window is
    /// let through, as [`same`] lets it.
    pub(crate) fn recovery(
        client: &AppClient,
        state: &ReadState,
        answer: Option<&RecoveryAnswer>,
        storage_open_at_publish: bool,
    ) {
        let window = Window {
            storage_open_at_publish,
            storage_closed: &client.app.storage_closed,
        };
        if let Some(answer) = answer {
            let published = &state.account.recovery_status;
            assert!(
                same_answer(published, answer.status(), |ours, theirs| ours == theirs),
                "the published recovery status is not the kept answer's"
            );
            let live = client.account_recovery_status();
            let across_close = window.closed_inside()
                && (published.as_ref().err().is_some_and(|error| closed(error))
                    || live.as_ref().err().is_some_and(closed));
            if let Some(field) = answer.differs_from_live(published, &live)
                && !across_close
            {
                panic!(
                    "read state differs from the live read for the account recovery status \
                     ({field}): published {published:?}, live {live:?}"
                );
            }
        }
        for (group_id, group) in state.groups.iter() {
            same(
                window,
                "group recovery status",
                &group.recovery_status,
                &client.group_recovery_status(group_id),
            );
        }
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
            // A version whose list failed, or whose list holds the upload
            // with a record that does not read, sends the read to the
            // worker, whose single read is the live one.
            let unread = state
                .account
                .prepared_group_image_records_unread
                .contains(upload_id);
            match state.prepared_group_image_status(upload_id) {
                Some(published) => {
                    same(window, "prepared group image status", &published, &live);
                }
                None if unread => assert!(
                    live.is_err(),
                    "a record the version marks unread reads: {live:?}"
                ),
                None => assert!(
                    state.account.prepared_group_images.is_err(),
                    "a version with a list answers every upload id"
                ),
            }
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

        // Every stored group is in this version or listed quarantined: a
        // read whose groups come from stored rows waits for the first
        // version published after its rows commit (mdk#3273 PR 4).
        if let Ok(storage) = client.app.account_storage(&client.state.label)
            && let Ok(stored) = storage.app_storage().account_groups(None)
        {
            for row in stored {
                let group_id = GroupId::new(hex::decode(&row.group_id_hex).expect("stored hex"));
                assert!(
                    state.holds(std::slice::from_ref(&group_id)),
                    "a stored group is outside the read state"
                );
            }
        }
        // Co-members: this version's saved-row standings and members against
        // the saved group listing, judged as `group_co_members` judged it
        // before it answered from A, and the live engine reads.
        if let Ok(local) = client.app.account_home().account(&client.state.label) {
            same(
                window,
                "co members",
                &state.co_members(&local.account_id_hex),
                &client
                    .co_member_groups()
                    .and_then(|groups| client.co_members(&groups)),
            );
            if let Ok(live) = client.co_member_groups()
                && state.groups.values().all(|group| group.standing.is_ok())
            {
                assert_eq!(
                    state.co_member_groups(),
                    live,
                    "read state differs from the live read for co-member groups"
                );
            }
        }

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
        let unhydrated: HashSet<GroupId> =
            client.runtime.unhydrated_group_ids().into_iter().collect();
        let quarantined: HashSet<GroupId> = client
            .runtime
            .quarantined_groups()
            .into_iter()
            .map(|(group_id, _)| group_id)
            .collect();
        for group_id in &group_ids {
            if let Some(group) = state.groups.get(group_id) {
                assert_eq!(
                    group.awaits_hydration,
                    unhydrated.contains(group_id),
                    "read state differs from the live read for awaiting hydration"
                );
                // What the trusted rosters are built from (mdk#3273 PR 6).
                assert_eq!(
                    group.serves_reads,
                    !unhydrated.contains(group_id) && !quarantined.contains(group_id),
                    "read state differs from the live read for serving reads"
                );
                same(
                    window,
                    "committed roster revision",
                    &group.roster_revision,
                    &client
                        .engine_storage
                        .committed_roster_revision(group_id)
                        .map_err(AppError::from),
                );
            }
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
        // A recovery status's KeyPackage bound is on the system clock too.
        publisher.groups_key_packages_until = Some(Timestamp(50_015));
        assert_eq!(
            publisher.deadline(Timestamp(50_014), Timestamp(50_010)),
            Some(Duration::from_secs(5))
        );
    }

    /// A group entry holds only while the system clock is inside the window
    /// its recovery status's reinvite KeyPackages leave it in: from the
    /// reading they were judged at until the first `not_after`, exclusive.
    /// Nothing else about the group moves here, so the window alone decides
    /// (mdk#3273 PR 8).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_entry_holds_only_inside_its_key_package_window() {
        let dir = tempfile::tempdir().unwrap();
        marmot_account::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(std::sync::Arc::new(
                crate::tests::ScriptedPushRelayClient::default(),
            ));
        let mut client = app.client("alice").await.unwrap();
        let group = client
            .create_group("windowed", &[])
            .await
            .unwrap()
            .operation
            .unwrap();
        let record = client
            .state
            .groups
            .iter()
            .find(|record| record.group_id_hex == hex::encode(group.as_slice()))
            .unwrap()
            .clone();
        let generation = client
            .runtime
            .group_change_generations(std::iter::once(&group))
            .remove(0);
        let settled = |value| Fact {
            value,
            settled: true,
        };
        let validity = EntryValidity {
            generation: generation.clone(),
            record: record.clone(),
            maintenance_paused: false,
            window: WallClockWindow::ALWAYS,
            key_packages: WallClockWindow {
                from: Timestamp(1_000),
                until: Some(Timestamp(2_000)),
            },
            notices: None,
            recovery_facts: OwnFacts {
                host_may_see: settled(true),
                unrecoverable: settled(false),
            },
            reusable: true,
        };
        let holds_at = |system_now| {
            validity.holds(
                &generation,
                &record,
                false,
                Timestamp(0),
                Timestamp(system_now),
            )
        };
        assert!(holds_at(1_000));
        assert!(holds_at(1_999), "just before not_after");
        assert!(!holds_at(2_000), "at not_after");
        assert!(
            !holds_at(999),
            "a system clock moved back before the reading"
        );
    }

    /// A publish judges a kept group entry's KeyPackage window against the
    /// system-clock reading it took, and rebuilds the group's answers once
    /// that reading is past the window (mdk#3273 PR 8). The window is planted
    /// to end no later than that reading and to hold every other time the
    /// publish has at hand: the account's wall clock, an hour back; the owned
    /// KeyPackage list's judged reading, two hours back; and the window's
    /// own start. The published answers carry a marker no rebuild gives, so
    /// they stay only while the entry is kept. Readings are whole seconds,
    /// so this says nothing of a system reading kept from an earlier publish
    /// in the same second.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_publish_rebuilds_an_entry_once_its_key_package_window_ends() {
        use cgka_traits::engine::SendIntent;
        use cgka_traits::storage::{
            OutboundIntentStorage as _, OwnCommitBaseline, OwnCommitIntent, ReinviteRetry,
        };

        let dir = tempfile::tempdir().unwrap();
        marmot_account::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(std::sync::Arc::new(
                crate::tests::ScriptedPushRelayClient::default(),
            ));
        let mut client = app.client("alice").await.unwrap();
        client.publish_key_package().await.unwrap();
        let group = client
            .create_group("windowed", &[])
            .await
            .unwrap()
            .operation
            .unwrap();
        // A retained reinvite of Alice's own live KeyPackage, which the
        // group's recovery status judges against the system clock.
        let key_package = client.durably_owned_key_packages().unwrap().remove(0);
        app.account_storage("alice")
            .unwrap()
            .put_own_commit_intent(&OwnCommitIntent {
                commit_id: cgka_traits::MessageId::new(vec![0xc1; 32]),
                group_id: group.clone(),
                source_epoch: cgka_traits::EpochId(0),
                intent: SendIntent::Invite {
                    group_id: group.clone(),
                    key_packages: vec![key_package],
                    initial_admins: vec![],
                },
                baseline: OwnCommitBaseline::None,
                reinvite: Some(ReinviteRetry::default()),
                reissue_attempts: 0,
                created_at_ms: 0,
            })
            .unwrap();
        // The account's wall clock, an hour behind the system clock from
        // the first publish on, so the entry's wall-clock window holds it.
        struct BehindClock(u64);
        impl marmot_session::WallClock for BehindClock {
            fn now(&self) -> Timestamp {
                Timestamp(self.0)
            }
            fn now_ms(&self) -> u64 {
                self.0 * 1_000
            }
        }
        client.runtime = client.runtime.with_maintenance_sources(
            Arc::new(BehindClock(system_clock_now().0 - 3_600)),
            Arc::new(marmot_session::SystemMonotonicClock::default()),
            Arc::new(marmot_session::OsEntropy),
        );

        let (sender, _reader) = read_state_channel();
        let mut publisher = ReadStatePublisher::new(sender, UploadsInFlight::default());
        assert!(publisher.publish(&client));
        let window = publisher.entries[&group].key_packages;
        assert!(
            window.until.is_some_and(|until| until > system_clock_now()),
            "the live reinvite bounds the entry: {window:?}"
        );
        assert!(publisher.current().groups[&group].recovery_status.is_ok());

        let mut marked = None;
        publisher.sender.send_modify(|state| {
            let published = &state.groups[&group];
            let answers = Arc::new(GroupAnswers {
                record: published.record.clone(),
                host_may_see: published.host_may_see,
                awaits_hydration: published.awaits_hydration,
                serves_reads: published.serves_reads,
                roster_revision: published.roster_revision.clone(),
                members: published.members.clone(),
                standing: published.standing.clone(),
                mls_state: published.mls_state.clone(),
                commit_delivery: published.commit_delivery.clone(),
                maintenance_status: published.maintenance_status.clone(),
                app_components: published.app_components.clone(),
                recovery_status: Err(Arc::new(AppError::UnknownGroup("marker".to_owned()))),
            });
            let mut groups = HashMap::clone(&state.groups);
            groups.insert(group.clone(), Arc::clone(&answers));
            marked = Some(answers);
            *state = Arc::new(ReadState {
                version: state.version,
                valid_until: state.valid_until,
                account: Arc::clone(&state.account),
                groups: Arc::new(groups),
            });
        });
        let marked = marked.unwrap();
        let keeps_marker = |publisher: &ReadStatePublisher| {
            Arc::ptr_eq(&publisher.current().groups[&group], &marked)
        };

        publisher.publish(&client);
        assert!(
            keeps_marker(&publisher),
            "an entry inside its window is kept"
        );

        // The window ends at or before the reading the next publish takes,
        // and holds every earlier time: the owned list's judged reading is
        // moved two hours back, where the list still holds.
        let reading = system_clock_now();
        publisher.entries.get_mut(&group).unwrap().key_packages = WallClockWindow {
            from: Timestamp(0),
            until: Some(reading),
        };
        publisher.key_packages.as_mut().unwrap().1.window.from = Timestamp(reading.0 - 7_200);
        assert!(publisher.publish(&client));
        assert!(
            publisher.key_packages_reused,
            "the owned list is kept with its earlier reading"
        );
        assert!(
            !keeps_marker(&publisher),
            "an entry past its window is rebuilt"
        );
        assert!(publisher.current().groups[&group].recovery_status.is_ok());
        assert_eq!(
            publisher.entries[&group].key_packages.until, window.until,
            "the rebuilt entry is bounded by the live KeyPackage again"
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
                backup_restore_status: published.clone(),
                backup_restore_updates: updates.subscribe(),
                ..empty_account_answers()
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

        // A version is published before the channel announces its status.
        // A watch handed out from it in between has seen that status: it
        // shows it, and its announcement is no news. Only a later one is.
        use futures::FutureExt as _;
        let announced = BackupRestoreStatus {
            phase: crate::BackupRestorePhase::Cancelled,
            revision: 3,
            ..Default::default()
        };
        let state = ReadState {
            version: 2,
            valid_until: None,
            account: Arc::new(AccountAnswers {
                backup_restore_status: announced.clone(),
                backup_restore_updates: updates.subscribe(),
                ..empty_account_answers()
            }),
            groups: Arc::default(),
        };
        let mut watch = state.watch_backup_restore();
        assert_eq!(watch.snapshot(), announced);
        updates.send_replace(announced.clone());
        assert!(watch.changed().now_or_never().is_none());
        assert_eq!(watch.snapshot(), announced);
        let next = BackupRestoreStatus {
            phase: crate::BackupRestorePhase::Discovering,
            revision: 4,
            ..Default::default()
        };
        updates.send_replace(next.clone());
        assert_eq!(watch.changed().await.unwrap(), next);
    }

    /// A read whose groups come from stored rows waits for a version that
    /// holds them, here by listing them quarantined, and for no group whose
    /// stored row is gone: resolving at once before the first publish and
    /// for a forgotten group, and on the publish that holds a stored one.
    #[tokio::test]
    async fn a_wait_for_stored_groups_ends_on_the_version_that_holds_them() {
        use futures::FutureExt as _;
        let open = AtomicBool::new(false);
        let group = GroupId::new(vec![0x31; 16]);
        let quarantined = |account: &mut AccountAnswers| {
            account.quarantined_groups = vec![AppQuarantinedGroup {
                group_id_hex: hex::encode(group.as_slice()),
                reason: crate::AppGroupHydrationQuarantineReason::OpenMlsGroupMissing,
            }];
        };
        let (publisher, reader) = read_state_channel();
        let group_ids = std::slice::from_ref(&group);
        let unexpected = |_: Vec<GroupId>| -> Result<Vec<GroupId>, AppError> {
            panic!("a held group needs no storage read")
        };
        reader
            .holding(&open, group_ids, unexpected)
            .now_or_never()
            .expect("no wait before the first publish")
            .expect("before the first publish the reads go to the worker");

        publisher.publish_for_test(|_| {});
        reader
            .holding(&open, group_ids, |_| Ok(Vec::new()))
            .now_or_never()
            .expect("no wait for a group whose stored row is gone")
            .expect("a group whose stored row is gone is not waited for");

        let mut waiting = Box::pin(reader.holding(&open, group_ids, Ok));
        assert!(
            futures::poll!(&mut waiting).is_pending(),
            "a stored group not yet in A is waited for"
        );
        publisher.publish_for_test(|_| {});
        assert!(futures::poll!(&mut waiting).is_pending());
        publisher.publish_for_test(quarantined);
        tokio::time::timeout(std::time::Duration::from_secs(5), waiting)
            .await
            .expect("the version that holds it ends the wait")
            .unwrap();
        reader
            .holding(&open, group_ids, unexpected)
            .now_or_never()
            .expect("no wait for a held group")
            .expect("a quarantined group is held");

        let closed = AtomicBool::new(true);
        assert!(matches!(
            reader
                .holding(&closed, group_ids, unexpected)
                .now_or_never()
                .expect("no wait once storage closes"),
            Err(AppError::Storage(StorageError::Closed(_)))
        ));
    }
}
