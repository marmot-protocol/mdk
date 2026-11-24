//! The account worker's sign-in slot read (mdk#3466).
//!
//! A sign-in check reads every KeyPackage slot of the account from its
//! relays. That read runs beside the writer, and its continuation runs on
//! the writer as one unit (see `client::sign_ins`). This keeps the one read
//! of the worker's current client, what it serves (the scheduled check, a
//! host check, or both), and the host check waiting on it.
//!
//! A host check keeps its place. While one waits, the worker parks each
//! later command that names no group, up to [`PARKED_LIMIT`]; commands that
//! name a group, and the worker's own work, go ahead.
//!
//! A read belongs to the client that started it. Before the worker replaces
//! its client it cancels the read ([`SignInReads::replace`]); a waiting host
//! check keeps its place, and the next client reads again
//! ([`SignInReads::adopt`]). Before the worker returns it cancels the read
//! and waits for its task ([`SignInReads::end`]).

use std::time::Instant;

use tokio::sync::oneshot;

use super::AccountWorkerCommand;
use crate::client::sign_ins::{RunningSlotRead, SlotReadEnd, SlotReadResult, SlotReadStart};
use crate::{AppClient, AppError, UnrecognizedSignIn};

/// How many commands that name no group may park behind a waiting host
/// check. At the limit the worker takes no more host commands until the
/// check is answered, so a caller waits for admission and none is dropped.
/// The worker's own retries come through their own channel and still run.
pub(super) const PARKED_LIMIT: usize = 64;

/// A host check's reply.
pub(super) type HostCheckReply = oneshot::Sender<Result<Vec<UnrecognizedSignIn>, AppError>>;

/// What a continuation leaves for the worker to do on the writer.
pub(super) enum Settled {
    /// Nothing to answer.
    Quiet,
    /// Answer the host check that waited on the read.
    Answer(HostCheckReply, Result<Vec<UnrecognizedSignIn>, AppError>),
}

struct Read {
    running: RunningSlotRead,
    /// The read is the second of its check: this device's own KeyPackages
    /// changed during the first.
    again: bool,
    /// It serves the scheduled check.
    scheduled: bool,
    /// When its check began.
    started: Instant,
}

#[derive(Default)]
pub(super) struct SignInReads {
    read: Option<Read>,
    host: Option<HostCheckReply>,
    /// Reads cancelled at a client replacement whose tasks may still run a
    /// stage that is left to finish. The worker waits for them when it
    /// returns.
    retired: Vec<RunningSlotRead>,
}

impl SignInReads {
    /// Take the scheduled check `client` asked for since the last call, and
    /// start a read for a host check that has none, as after a client
    /// replacement.
    pub(super) fn adopt(&mut self, client: &mut AppClient) -> Option<Settled> {
        if client.take_sign_in_check_request() {
            match &mut self.read {
                Some(read) => read.scheduled = true,
                None => match client.begin_sign_in_slot_read() {
                    Ok(Some(start)) => self.start(client, start, false, true, Instant::now()),
                    // Device groups went off: today's check does nothing.
                    Ok(None) => {}
                    Err(error) => client.scheduled_sign_in_check_ended(Instant::now(), Err(&error)),
                },
            }
        }
        if self.read.is_none() && self.host.is_some() {
            let host = self.host.take().expect("checked above");
            return self.check_now(client, host);
        }
        None
    }

    /// The host asks for a check now. It joins the read in flight, or
    /// starts one after the look, which changes nothing but the removed
    /// slots it records first; the look's early answers are given at once.
    pub(super) fn check_now(
        &mut self,
        client: &mut AppClient,
        respond: HostCheckReply,
    ) -> Option<Settled> {
        // A second host check parks behind the first (`holds_place`).
        debug_assert!(self.host.is_none());
        if self.read.is_some() {
            self.host = Some(respond);
            return None;
        }
        match client.begin_sign_in_slot_read() {
            Ok(Some(start)) => {
                self.host = Some(respond);
                self.start(client, start, false, false, Instant::now());
                None
            }
            // Device groups are off: today's check answers at once.
            Ok(None) => {
                let answer =
                    client.host_sign_in_check_ended(Instant::now(), Ok(Default::default()));
                Some(Settled::Answer(respond, answer))
            }
            Err(error) => Some(Settled::Answer(respond, Err(error))),
        }
    }

    fn start(
        &mut self,
        client: &mut AppClient,
        start: SlotReadStart,
        again: bool,
        scheduled: bool,
        started: Instant,
    ) {
        client.sign_in_reading(true);
        self.read = Some(Read {
            running: start.spawn(),
            again,
            scheduled,
            started,
        });
    }

    pub(super) fn is_running(&self) -> bool {
        self.read.is_some()
    }

    /// Whether a host check waits: later commands that name no group park.
    pub(super) fn holds_place(&self) -> bool {
        self.host.is_some()
    }

    /// The read's result, once its task ends. Pending while none runs.
    pub(super) async fn next(&mut self) -> SlotReadResult {
        match &mut self.read {
            Some(read) => read.running.result().await,
            None => std::future::pending().await,
        }
    }

    /// The continuation, on the writer: judge the read against current
    /// state, or read once more when this device's own KeyPackages changed
    /// under it.
    pub(super) async fn settle(
        &mut self,
        client: &mut AppClient,
        result: SlotReadResult,
    ) -> Settled {
        let Some(Read {
            running,
            again,
            scheduled,
            started,
        }) = self.read.take()
        else {
            return Settled::Quiet;
        };
        client.sign_in_reading(false);
        // The scheduled check runs only while today's would: with device
        // groups on and maintenance running. Alone, it then ends here.
        let scheduled = scheduled && client.scheduled_sign_in_check_may_run();
        if !scheduled && self.host.is_none() {
            return Settled::Quiet;
        }
        match client
            .finish_sign_in_slot_read(running.into_own(), result, again)
            .await
        {
            SlotReadEnd::ReadAgain(start) => {
                self.start(client, *start, true, scheduled, started);
                Settled::Quiet
            }
            SlotReadEnd::Checked(report) => {
                // The scheduled check's tail, as `drive_sign_ins` runs it.
                if scheduled {
                    client.scheduled_sign_in_check_ended(started, report.as_ref());
                    client.commit_sign_in_rejections_best_effort().await;
                }
                match self.host.take() {
                    Some(respond) => {
                        let answer = client.host_sign_in_check_ended(started, report);
                        Settled::Answer(respond, answer)
                    }
                    None => Settled::Quiet,
                }
            }
            // Changed again: record nothing, and leave the schedule, so the
            // scheduled check comes again at its next turn.
            SlotReadEnd::Unjudged => match self.host.take() {
                Some(respond) => Settled::Answer(respond, client.unrecognized_sign_ins()),
                None => Settled::Quiet,
            },
        }
    }

    /// Before the worker replaces `client`: cancel the read. A waiting host
    /// check keeps its place; the next client reads again.
    pub(super) fn replace(&mut self) {
        self.retired.retain(|read| !read.is_finished());
        if let Some(read) = self.read.take() {
            read.running.cancel();
            self.retired.push(read.running);
        }
    }

    /// When the worker returns: cancel the read and wait for its task. A
    /// waiting host check gets the error a queued command gets when the
    /// worker exits.
    pub(super) async fn end(&mut self) {
        self.host = None;
        let reads = self.read.take().map(|read| read.running);
        for read in reads.into_iter().chain(self.retired.drain(..)) {
            read.end().await;
        }
    }
}

impl AccountWorkerCommand {
    /// Whether this command keeps its order behind a waiting host sign-in
    /// check: every host command that names no existing group. A command
    /// that names a group goes ahead, and so do the worker's own sends.
    pub(super) fn waits_behind_sign_in_check(&self) -> bool {
        match self {
            // The worker's own: its timers' retries, and startup's replayed
            // catch-up result.
            Self::RetryPushRegistration { .. }
            | Self::RetryRuntimeGroupSubscriptions { .. }
            | Self::StartupCatchUpResult { .. } => false,
            // A read of one group's invites names that group; an account-wide
            // one names none.
            Self::InviteDeliveries { group_id, .. } => group_id.is_none(),
            // Commands that name an existing group.
            Self::Members { .. }
            | Self::MemberIdsPage { .. }
            | Self::CaptureConversation { .. }
            | Self::GroupMlsState { .. }
            | Self::GroupRoster { .. }
            | Self::HydrateGroups { .. }
            | Self::EnableGroupDisbanding { .. }
            | Self::AccountDevicesActivation { .. }
            | Self::EnableAccountDevices { .. }
            | Self::DisbandGroup { .. }
            | Self::AcknowledgeDisbandFailure { .. }
            | Self::RetryHydrateQuarantinedGroup { .. }
            | Self::SafeExportSecret { .. }
            | Self::ExporterSecret { .. }
            | Self::InviteMembers { .. }
            | Self::RemoveMembers { .. }
            | Self::LeaveGroup { .. }
            | Self::CancelLeave { .. }
            | Self::LeaveGroupForSignOut { .. }
            | Self::SignOutAdminLeave { .. }
            | Self::ForgetGroupLocal { .. }
            | Self::DeleteGroupLocal { .. }
            | Self::GroupRecoveryStatus { .. }
            | Self::HistoryImportProvenance { .. }
            | Self::BackupHistoryAvailability { .. }
            | Self::AcknowledgeGroupCatchingUp { .. }
            | Self::AcknowledgeGroupCommitUndelivered { .. }
            | Self::GroupCommitDelivery { .. }
            | Self::GroupChangesNotDelivered { .. }
            | Self::GroupPendingCommit { .. }
            | Self::AcknowledgeChangeNotDelivered { .. }
            | Self::AcceptGroupInvite { .. }
            | Self::DeclineGroupInvite { .. }
            | Self::SetGroupArchived { .. }
            | Self::PromoteAdmin { .. }
            | Self::DemoteAdmin { .. }
            | Self::SelfDemoteAdmin { .. }
            | Self::UpdateGroupProfile { .. }
            | Self::UpdateGroupImage { .. }
            | Self::DownloadGroupImage { .. }
            | Self::GroupAppComponent { .. }
            | Self::UpdateAppComponent { .. }
            | Self::UpdateMessageRetention { .. }
            | Self::ReplaceEncryptedMediaBlobEndpoints { .. }
            | Self::UpdateGroupAvatarUrl { .. }
            | Self::SendMessageDraft { .. }
            | Self::SendMessage { .. }
            | Self::SendAppEvent { .. }
            | Self::BuildMediaImetaTag { .. }
            | Self::UploadMedia { .. }
            | Self::DownloadMedia { .. }
            | Self::SecureDeleteExpiredPlaintext { .. }
            | Self::DiscardFailedSend { .. }
            | Self::RetryGroupConvergence { .. }
            | Self::MaintenanceStatus { .. }
            | Self::ScheduleManualSelfUpdate { .. }
            | Self::GroupPushDebugInfo { .. } => false,
            #[cfg(test)]
            Self::HoldMediaHttp { .. }
            | Self::UnhydratedGroupCount { .. }
            | Self::UnlinkDeviceForTest { .. }
            | Self::OverdueComponentRecheckForTest { .. }
            | Self::RecoveryRunnerPassForTest { .. }
            | Self::SubscribeReadStateForTest { .. } => false,
            // Account, KeyPackage, device, backup, push, relay and lifecycle
            // commands, a create, and Welcome and rejoin commands, which name
            // no existing group.
            Self::CatchUp { .. }
            | Self::ConnectivityRestored { .. }
            | Self::RepairFullHistory { .. }
            | Self::CreateGroup { .. }
            | Self::StagePreparedGroupImage { .. }
            | Self::UploadPreparedGroupImage { .. }
            | Self::PreparedGroupImageStatus { .. }
            | Self::PreparedGroupImages { .. }
            | Self::GroupCoMembers { .. }
            | Self::QuarantinedGroups { .. }
            | Self::NetworkStartupSettled { .. }
            | Self::Drain { .. }
            | Self::HistoryNotices { .. }
            | Self::AccountRecoveryStatus { .. }
            | Self::LinkedDevices { .. }
            | Self::ChatHistoryImports { .. }
            | Self::KeyPackageRefreshOverdue { .. }
            | Self::UnrecognizedSignIns { .. }
            | Self::AnswerSignIn { .. }
            | Self::CheckSignIns { .. }
            | Self::StartFresh { .. }
            | Self::StartedFresh { .. }
            | Self::CompromiseWarning { .. }
            | Self::DismissCompromiseWarning { .. }
            | Self::RenameLinkedDevice { .. }
            | Self::UpdateLinkedDeviceSettings { .. }
            | Self::RemoveLinkedDevice { .. }
            | Self::RemovedDeviceLeftoverChats { .. }
            | Self::ChatsClosedToLinkedDevices { .. }
            | Self::SignOutThroughSiblingsStep { .. }
            | Self::BeginRecoveryWords { .. }
            | Self::ConfirmRecoveryWords { .. }
            | Self::CancelRecoveryWords { .. }
            | Self::TurnOffBackups { .. }
            | Self::RunDueBackupPass { .. }
            | Self::BeginBackupRestore { .. }
            | Self::CancelBackupRestore { .. }
            | Self::BackupRestoreStatus { .. }
            | Self::WatchBackupRestore { .. }
            | Self::BackupSettings { .. }
            | Self::DismissHistoryNotice { .. }
            | Self::ConfirmGroupRejoin { .. }
            | Self::DeclineGroupRejoin { .. }
            | Self::SweepExpiredRetention { .. }
            | Self::PendingWelcomeDeliveries { .. }
            | Self::RedeliverWelcome { .. }
            | Self::PublishKeyPackage { .. }
            | Self::DeviceLink { .. }
            | Self::PublishSetupKeyPackage { .. }
            | Self::RotateKeyPackage { .. }
            | Self::WithdrawKeyPackageSlot { .. }
            | Self::KeyPackageMaintenanceStatus { .. }
            | Self::DurablyOwnedKeyPackages { .. }
            | Self::PeriodicMaintenancePolicy { .. }
            | Self::SetPeriodicMaintenancePolicy { .. }
            | Self::PauseMaintenance { .. }
            | Self::ResumeMaintenance { .. }
            | Self::RunDueMaintenance { .. }
            | Self::SharePushRegistration { .. }
            | Self::UpsertPushRegistration { .. }
            | Self::ClearPushRegistration { .. }
            | Self::SetNativePushEnabled { .. }
            | Self::RemovePushRegistration { .. }
            | Self::ReconnectRelay { .. }
            | Self::DeleteAuditLog { .. }
            | Self::ApplyAuditLogSetting { .. } => true,
        }
    }
}
