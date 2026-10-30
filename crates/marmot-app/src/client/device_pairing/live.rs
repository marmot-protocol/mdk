//! Pairing as it runs on this device: its own new-device session, the
//! prompts for sign-ins it can link, the pairing messages it owes, the links
//! it approved that are not made yet, and the device group it joined until
//! its first commit there lands.
//!
//! Pairing secrets live only in the `marmot-pairing` sessions held here, in
//! memory. Nothing here persists or logs a code, key, session id, slot or
//! label; a restart ends every session.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cgka_traits::app_components::{
    AppComponentSet, DEVICE_ROSTER_COMPONENT_ID, DEVICE_ROSTER_TEXT_MAX_LEN, DeviceEntryV1,
    DeviceRosterOperationV1, DeviceRosterUpdateV1, DeviceRosterV1, DeviceSettingsV1, DeviceSlotId,
    MAX_LEAVES_PER_ACCOUNT, NOSTR_ROUTING_COMPONENT_ID, encode_device_roster_update_v1,
};
use cgka_traits::engine::SendIntent;
use cgka_traits::storage::{MaintenanceStorage as _, StorageError};
use cgka_traits::{
    EngineError, EpochState, GroupCapabilities, GroupId, KeyPackage, MemberId, MessageId, Timestamp,
};
use marmot_pairing::{
    AccountKey, CancelReason, ConfirmedLink, EndReason, ExistingDeviceEvent, ExistingDevicePairing,
    KeyPackageEventId, KeyPackageRef, NewDeviceConfirmation, NewDeviceEvent, NewDevicePairing,
    PairingCancel, PairingError, PairingMessage, PublishedKeyPackage, REQUEST_TTL_SECS,
    SESSION_TTL_SECS, SasCode, SessionId, SignatureKey, SlotId,
};
use nostr::nips::nip59::UnwrappedGift;
use nostr::prelude::PublicKey;
use rand::RngCore;
use rand::rngs::OsRng;
use storage_sqlite::{DeviceGroupTrust, DeviceLinkOutcome, DeviceLinkRecord};
use transport_nostr_adapter::pairing::{
    InboundPairingMessage, PairingEventError, read_pairing_rumor, wrap_pairing_message,
};

use super::{
    DeviceLinkChoices, DeviceLinkEmoji, DeviceLinkEndReason, DeviceLinkOp, DeviceLinkPrompt,
    DeviceLinkPromptState, DeviceLinkSnapshot, NewDeviceLinkState,
};
use crate::client::device_group::{
    ConfirmedDeviceLink, LINK_DEADLINE_SECS, WELCOME_WAIT_SECS, device_slot,
};
use crate::client::device_renames::fresh_rename_id;
use crate::client::{AppClient, WelcomeDelivery};
use crate::{AccountRelayListStatus, AppError, unix_now_seconds};

const TARGET: &str = "marmot_app::client::device_pairing";

/// Pairing messages the inbox holds before the client reads them. A flood
/// drops the oldest; a lost message only ends a session early.
const INBOX_CAPACITY: usize = 64;

// The new device waits for the Welcome as long as its session lived.
const _: () = assert!(WELCOME_WAIT_SECS == SESSION_TTL_SECS);

/// How long after the new device sent its confirmation this device may still
/// add it: the new device's Welcome wait, which began then, less a minute for
/// the Welcome to reach it.
const LINK_RETRY_SECS: u64 = WELCOME_WAIT_SECS - 60;

/// How often to look again for a KeyPackage a request named but the relays
/// did not have yet.
const KEY_PACKAGE_RETRY_SECS: u64 = 5;

/// How often to publish again a link's Welcome the relays have not taken.
const WELCOME_REDELIVER_SECS: u64 = 5;

/// MLS group ids this device picks for a first link, in bytes: OpenMLS's own
/// length.
const DEVICE_GROUP_ID_LEN: usize = 16;

/// Pairing messages the Welcome peeler split off the account inbox, waiting
/// for the client. Shared between the peeler and the client.
#[derive(Clone)]
pub(crate) struct PairingInbox {
    account: PublicKey,
    queue: Arc<Mutex<VecDeque<InboundPairingMessage>>>,
}

impl PairingInbox {
    pub(crate) fn new(account: PublicKey) -> Self {
        Self {
            account,
            queue: Arc::default(),
        }
    }

    /// Keep the pairing message in `unwrapped`, if it holds one the account
    /// sent. Anything else is dropped.
    pub(crate) fn offer(&self, unwrapped: &UnwrappedGift) {
        match read_pairing_rumor(&self.account, unwrapped) {
            Ok(Some(message)) => {
                let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
                if queue.len() >= INBOX_CAPACITY {
                    queue.pop_front();
                }
                queue.push_back(message);
            }
            Ok(None) => {}
            Err(error) => tracing::debug!(
                target: TARGET,
                method = "offer",
                error_kind = pairing_event_error_kind(error),
                "dropped a pairing message that could not be read"
            ),
        }
    }

    fn take(&self) -> Vec<InboundPairingMessage> {
        self.queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .drain(..)
            .collect()
    }
}

fn pairing_event_error_kind(error: PairingEventError) -> &'static str {
    match error {
        PairingEventError::Signer => "signer",
        PairingEventError::NotForAccount => "not_for_account",
        PairingEventError::Unwrap => "unwrap",
        PairingEventError::ForeignSender => "foreign_sender",
        PairingEventError::Content(_) => "content",
    }
}

/// This device's pairing state. One per open account.
#[derive(Default)]
pub(crate) struct DevicePairing {
    /// `None` unless device groups are on.
    inbox: Option<PairingInbox>,
    new_device: Option<NewDeviceLink>,
    /// Created on first use, from this device's KeyPackage slot.
    existing: Option<ExistingDevicePairing>,
    prompts: Vec<Prompt>,
    /// Messages to send, oldest first, each with the time it was stamped.
    outbox: VecDeque<(PairingMessage, u64)>,
    /// No KeyPackage fetch before this time.
    fetch_after: u64,
    /// Linking as hosts were last told it changed; empty when the client
    /// opens, which announces it.
    last_view: DeviceLinkSnapshot,
    /// When each pending link was first seen missing from its quiet device
    /// group's roster, keyed by group and slot; the settlement window counts
    /// from then. In memory, so a restart starts the window again.
    quiet_since: HashMap<(String, String), Instant>,
    /// This device was removed from the device group it joined through a
    /// link before its first commit there landed: its user is told linking
    /// failed until it starts another link.
    removed_after_join: bool,
}

impl DevicePairing {
    pub(crate) fn new(inbox: Option<PairingInbox>) -> Self {
        Self {
            inbox,
            ..Self::default()
        }
    }

    fn send(&mut self, message: PairingMessage, now: u64) {
        self.outbox.push_back((message, now));
    }

    fn prompt_mut(&mut self, session_id: &SessionId) -> Option<&mut Prompt> {
        self.prompts
            .iter_mut()
            .find(|prompt| &prompt.session_id == session_id)
    }
}

/// This device's own session as a new device.
struct NewDeviceLink {
    pairing: NewDevicePairing,
    key_package_event_id: KeyPackageEventId,
    user_confirmed: bool,
    /// Once both users confirmed: the device group whose Welcome to wait
    /// for, and until when.
    joining: Option<(GroupId, u64)>,
    /// The user cancelled while joining. The wait ends once the engine's
    /// expectation is withdrawn, retried each drive until that succeeds.
    cancelling: bool,
    /// How the link ended; `None` while it runs.
    outcome: Option<NewDeviceOutcome>,
}

#[derive(Clone, Copy)]
enum NewDeviceOutcome {
    Linked,
    Ended(DeviceLinkEndReason),
}

/// A sign-in that asked this device to link it.
struct Prompt {
    id: String,
    session_id: SessionId,
    key_package_event_id: KeyPackageEventId,
    key_package_ref: KeyPackageRef,
    requested_at: u64,
    found: Option<FoundKeyPackage>,
    stage: Stage,
    /// When `stage` last changed.
    updated_at: u64,
    /// Both users confirmed while the device group was unsettled: the link
    /// to commit on a later drive, while it is still useful.
    approval: Option<Approval>,
    /// This device committed the link, or created the device group for it.
    /// The prompt stays linking until [`AppClient::decide_device_links`]
    /// decides the link.
    publication: Option<LinkPublication>,
}

struct Approval {
    link: ConfirmedLink,
    retry_until: u64,
    /// When the new device stops waiting for its Welcome.
    wait_ends: u64,
}

/// A link this device committed, or created the device group for, that is
/// not decided yet.
struct LinkPublication {
    group_id: GroupId,
    /// The Welcomes the link sent: those this device's engine tracked after
    /// the link and not before it.
    welcomes: HashSet<MessageId>,
    /// When the new device stops waiting for its Welcome.
    wait_ends: u64,
    /// No undelivered Welcome is published again before this time.
    redeliver_at: u64,
}

/// Where a link this device approved stands in its device group's roster,
/// as the selected branch leaves it (D40).
#[derive(Debug, PartialEq, Eq)]
enum LinkVerdict {
    /// The new device's first commit set its tag signature key: the link is
    /// made, and stays made.
    Made,
    /// The roster lists the device as this device's link, and its deadline
    /// has not passed.
    Waiting,
    /// The deadline passed with no commit from the new device.
    TimedOut,
    /// The roster does not list the device as this device's link: the
    /// approving commit never landed, or lost.
    Lost,
}

struct FoundKeyPackage {
    slot: DeviceSlotId,
    key_package: KeyPackage,
}

enum Stage {
    /// Looking for the KeyPackage, checking it, or waiting to answer.
    Checking,
    RateLimited {
        retry_at: u64,
    },
    Answered,
    CannotLink(Vec<String>),
    TooManyDevices,
    Rejected,
    Linking(DeviceLinkChoices),
    Linked,
    Ended(DeviceLinkEndReason),
}

impl Stage {
    fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::CannotLink(_)
                | Self::TooManyDevices
                | Self::Rejected
                | Self::Linked
                | Self::Ended(_)
        )
    }
}

impl AppClient {
    pub(super) async fn device_link_live(
        &mut self,
        op: DeviceLinkOp,
    ) -> Result<DeviceLinkSnapshot, AppError> {
        if !self.app.device_groups_enabled() {
            return Err(AppError::DeviceGroupRefused("pairing_unsupported"));
        }
        let now = unix_now_seconds();
        let result = match op {
            DeviceLinkOp::Start => self.start_new_device_link(now),
            DeviceLinkOp::ConfirmMatch => self.confirm_new_device_match(now),
            DeviceLinkOp::Cancel => self.cancel_new_device_link(now),
            DeviceLinkOp::Link { prompt_id, choices } => {
                self.choose_link_device(&prompt_id, choices, now)
            }
            DeviceLinkOp::Decline { prompt_id } => self.decline_link(&prompt_id, now),
            DeviceLinkOp::Read => Ok(()),
        };
        // Send what the op owes even when it was refused.
        self.drive_device_pairing_live().await;
        result?;
        self.device_link_snapshot()
    }

    pub(super) async fn drive_device_pairing_live(&mut self) {
        self.drive_device_pairing_at(unix_now_seconds()).await;
    }

    /// [`Self::drive_device_pairing_live`] as of `now`.
    pub(crate) async fn drive_device_pairing_at(&mut self, now: u64) {
        if !self.app.device_groups_enabled() {
            return;
        }
        let messages = self
            .device_pairing
            .inbox
            .as_ref()
            .map(PairingInbox::take)
            .unwrap_or_default();
        for inbound in messages {
            self.receive_pairing_message(inbound, now).await;
        }
        self.expire_pairing(now);
        self.retry_link_approvals(now).await;
        self.follow_link_publications(now).await;
        self.check_prompts(now).await;
        self.follow_joining(now);
        if let Err(error) = self.end_welcome_waits(now) {
            tracing::warn!(
                target: TARGET,
                method = "drive_device_pairing_at",
                error_kind = error.privacy_safe_kind(),
                "could not end the Welcome waits that ran out"
            );
        }
        self.follow_device_group_joins().await;
        self.decide_device_links(now).await;
        self.device_pairing.prompts.retain(|prompt| {
            !prompt.stage.is_terminal() || now < prompt.updated_at.saturating_add(SESSION_TTL_SECS)
        });
        self.flush_pairing_outbox(now).await;
        self.note_device_link_view();
    }

    /// Raise `DeviceLinkChanged` when linking, as hosts would read it,
    /// differs from what they were last told. A view that can't be read now
    /// is compared at the next drive.
    fn note_device_link_view(&mut self) {
        let Ok(view) = self.device_link_snapshot() else {
            return;
        };
        if view != self.device_pairing.last_view {
            self.device_pairing.last_view = view;
            self.device_link_changed = true;
        }
    }

    async fn receive_pairing_message(&mut self, inbound: InboundPairingMessage, now: u64) {
        if let Some(link) = self.device_pairing.new_device.as_mut()
            && link.outcome.is_none()
        {
            let event = link.pairing.receive(&inbound.message, now);
            self.on_new_device_event(event, now);
            return;
        }
        let Some(existing) = self.existing_pairing() else {
            return;
        };
        let event = existing.receive(&inbound.message, inbound.created_at, now);
        match event {
            ExistingDeviceEvent::Ignored(_) | ExistingDeviceEvent::CodeReady { .. } => {}
            ExistingDeviceEvent::Requested { session_id, .. } => {
                let PairingMessage::Request(request) = &inbound.message else {
                    return;
                };
                // This device's own request, delivered after its session ended.
                if self
                    .device_pairing
                    .new_device
                    .as_ref()
                    .is_some_and(|link| link.pairing.session_id() == &session_id)
                {
                    if let Some(existing) = self.device_pairing.existing.as_mut() {
                        existing.cancel(&session_id);
                    }
                    return;
                }
                self.device_pairing.prompts.push(Prompt {
                    id: new_prompt_id(),
                    session_id,
                    key_package_event_id: request.key_package_event_id,
                    key_package_ref: request.key_package_ref.clone(),
                    requested_at: inbound.created_at.min(now),
                    found: None,
                    stage: Stage::Checking,
                    updated_at: now,
                    approval: None,
                    publication: None,
                });
                // Look for the KeyPackage now, whatever an earlier miss set.
                self.device_pairing.fetch_after = 0;
            }
            ExistingDeviceEvent::Linked(link) => {
                self.on_existing_linked(link, inbound.created_at, now).await;
            }
            ExistingDeviceEvent::Ended {
                session_id,
                reason,
                cancel,
            } => {
                if let Some(cancel) = cancel {
                    self.device_pairing
                        .send(PairingMessage::Cancel(cancel), now);
                }
                if let Some(prompt) = self.device_pairing.prompt_mut(&session_id)
                    && !matches!(prompt.stage, Stage::Linked)
                {
                    prompt.stage = Stage::Ended(end_reason(&reason));
                    prompt.updated_at = now;
                }
            }
        }
    }

    /// This device's existing-device state, created from its KeyPackage slot
    /// on first use. `None` until it has one.
    fn existing_pairing(&mut self) -> Option<&mut ExistingDevicePairing> {
        if self.device_pairing.existing.is_none() {
            let account = self.account_key().ok()?;
            let slot = self.own_slot().ok()?;
            self.device_pairing.existing =
                Some(ExistingDevicePairing::new(account, SlotId::new(slot)));
        }
        self.device_pairing.existing.as_mut()
    }

    fn account_key(&self) -> Result<AccountKey, AppError> {
        let account = self.app.account_home().account(&self.state.label)?;
        let bytes: [u8; 32] = hex::decode(&account.account_id_hex)?
            .try_into()
            .map_err(|_| AppError::DeviceGroupRefused("account_key_invalid"))?;
        Ok(AccountKey::new(bytes))
    }

    // New device.

    fn start_new_device_link(&mut self, now: u64) -> Result<(), AppError> {
        if self
            .device_pairing
            .new_device
            .as_ref()
            .is_some_and(|link| link.outcome.is_none())
        {
            return Err(AppError::DeviceGroupRefused("pairing_in_progress"));
        }
        if self.trusted_device_group()?.is_some() {
            return Err(AppError::DeviceGroupRefused("device_group_exists"));
        }
        let lifecycle = self
            .app
            .account_storage(&self.state.label)?
            .key_package_lifecycle()?;
        // Never a KeyPackage this device already joined by: the link binds
        // its Welcome by KeyPackage alone, so a used one would also admit the
        // Welcome that installed a discarded copy of the same device group.
        // The start waits for its replacement's publication.
        let lifecycle = lifecycle.filter(|lifecycle| {
            lifecycle.last_consumed_key_package_ref.is_none()
                || lifecycle.current_key_package_ref != lifecycle.last_consumed_key_package_ref
        });
        let (Some(event_id), Some(key_package_ref)) = (
            lifecycle
                .as_ref()
                .and_then(|lifecycle| lifecycle.authored_event_id.as_ref())
                .and_then(|id| <[u8; 32]>::try_from(id.as_slice()).ok()),
            lifecycle
                .as_ref()
                .and_then(|lifecycle| lifecycle.current_key_package_ref.clone())
                .and_then(KeyPackageRef::new),
        ) else {
            return Err(AppError::DeviceGroupRefused("key_package_not_published"));
        };
        let key_package_event_id = KeyPackageEventId::new(event_id);
        self.device_pairing.removed_after_join = false;
        let (pairing, request) = NewDevicePairing::start(
            self.account_key()?,
            key_package_event_id,
            key_package_ref,
            now,
        );
        self.device_pairing.new_device = Some(NewDeviceLink {
            pairing,
            key_package_event_id,
            user_confirmed: false,
            joining: None,
            cancelling: false,
            outcome: None,
        });
        self.device_pairing
            .send(PairingMessage::Request(request), now);
        Ok(())
    }

    fn confirm_new_device_match(&mut self, now: u64) -> Result<(), AppError> {
        let link = self
            .device_pairing
            .new_device
            .as_mut()
            .filter(|link| link.outcome.is_none() && link.joining.is_none())
            .ok_or(AppError::DeviceGroupRefused("no_link_in_progress"))?;
        let confirmation = link.pairing.confirm_match(now).map_err(pairing_refusal);
        if confirmation.is_err() {
            self.end_new_device_if_over(now);
        }
        match confirmation? {
            NewDeviceConfirmation::Waiting => {
                if let Some(link) = self.device_pairing.new_device.as_mut() {
                    link.user_confirmed = true;
                }
            }
            NewDeviceConfirmation::Linked { confirm, link } => {
                self.on_new_device_linked(confirm, link, now);
            }
        }
        Ok(())
    }

    /// Cancel this device's own link. While it waits for its Welcome, the
    /// engine's expectation is withdrawn first; if that fails, the link keeps
    /// waiting and each drive retries the withdrawal, so no Welcome under the
    /// link joins once it ends.
    fn cancel_new_device_link(&mut self, now: u64) -> Result<(), AppError> {
        let link = self
            .device_pairing
            .new_device
            .as_mut()
            .filter(|link| link.outcome.is_none())
            .ok_or(AppError::DeviceGroupRefused("no_link_in_progress"))?;
        if link.joining.is_some() {
            link.cancelling = true;
            return self.end_joining(now);
        }
        let cancel = link.pairing.cancel();
        link.outcome = Some(NewDeviceOutcome::Ended(DeviceLinkEndReason::Cancelled));
        if let Some(cancel) = cancel {
            self.device_pairing
                .send(PairingMessage::Cancel(cancel), now);
        }
        Ok(())
    }

    fn on_new_device_event(&mut self, event: NewDeviceEvent, now: u64) {
        match event {
            NewDeviceEvent::Ignored(_) | NewDeviceEvent::PeerConfirmed => {}
            NewDeviceEvent::Reveal(reveal) => self
                .device_pairing
                .send(PairingMessage::Reveal(reveal), now),
            NewDeviceEvent::Linked { confirm, link } => {
                self.on_new_device_linked(confirm, link, now);
            }
            NewDeviceEvent::Ended { cancel, .. } => {
                if let Some(cancel) = cancel {
                    self.device_pairing
                        .send(PairingMessage::Cancel(cancel), now);
                }
                self.end_new_device_if_over(now);
            }
        }
    }

    /// Both users confirmed. Wait for the Welcome into the device group the
    /// existing device's confirmation named, from the leaf it named, then
    /// send this device's confirmation, which lets the existing device add it.
    fn on_new_device_linked(
        &mut self,
        confirm: marmot_pairing::PairingConfirm,
        link: ConfirmedLink,
        now: u64,
    ) {
        let Some(new_device) = self.device_pairing.new_device.as_ref() else {
            return;
        };
        let confirmed = ConfirmedDeviceLink {
            key_package_event_id_hex: hex::encode(new_device.key_package_event_id.as_bytes()),
            key_package_ref_hex: hex::encode(link.key_package_ref.as_slice()),
            device_group_id: link.device_group_id.clone(),
            welcome_sender_key: link.welcome_sender_key.as_slice().to_vec(),
        };
        let session_id = *new_device.pairing.session_id();
        let recorded = self.record_confirmed_device_link(&confirmed);
        let Some(new_device) = self.device_pairing.new_device.as_mut() else {
            return;
        };
        match recorded {
            Ok(()) => {
                new_device.joining =
                    Some((link.device_group_id, now.saturating_add(WELCOME_WAIT_SECS)));
                self.device_pairing
                    .send(PairingMessage::Confirm(confirm), now);
            }
            Err(error) => {
                tracing::warn!(
                    target: TARGET,
                    method = "on_new_device_linked",
                    error_kind = error.privacy_safe_kind(),
                    "could not wait for the confirmed device group; cancelling the link"
                );
                new_device.outcome = Some(NewDeviceOutcome::Ended(DeviceLinkEndReason::LinkFailed));
                self.device_pairing.send(
                    PairingMessage::Cancel(PairingCancel {
                        session_id,
                        reason: CancelReason::CannotLink,
                    }),
                    now,
                );
            }
        }
    }

    /// Record how the new-device session ended, once it has, unless it is
    /// waiting for its Welcome, where [`Self::follow_joining`] decides.
    fn end_new_device_if_over(&mut self, _now: u64) {
        let Some(link) = self.device_pairing.new_device.as_mut() else {
            return;
        };
        if link.outcome.is_some() || link.joining.is_some() {
            return;
        }
        if let Some(reason) = link.pairing.end_reason() {
            link.outcome = Some(NewDeviceOutcome::Ended(end_reason(reason)));
        }
    }

    /// While waiting for the Welcome: done once the device group is trusted,
    /// and over if the user cancelled, the existing device withdrew the link
    /// or time ran out.
    fn follow_joining(&mut self, now: u64) {
        if let Err(error) = self.end_joining(now) {
            tracing::warn!(
                target: TARGET,
                method = "follow_joining",
                error_kind = error.privacy_safe_kind(),
                "could not withdraw a Welcome wait; retrying"
            );
        }
    }

    /// Settle a Welcome wait that is over. Ending it withdraws the engine's
    /// expectation first, and the wait stays until that succeeds; a Welcome
    /// that joined meanwhile leaves the link linked.
    fn end_joining(&mut self, now: u64) -> Result<(), AppError> {
        let Some(link) = self.device_pairing.new_device.as_ref() else {
            return Ok(());
        };
        let Some((group_id, deadline)) = link.joining.clone() else {
            return Ok(());
        };
        let trusted = self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .device_group(&hex::encode(group_id.as_slice()))?
            .is_some_and(|record| record.trust == DeviceGroupTrust::Linked);
        let ended = if trusted {
            None
        } else if link.cancelling {
            Some(DeviceLinkEndReason::Cancelled)
        } else if link.pairing.linked().is_none() {
            Some(
                link.pairing
                    .end_reason()
                    .map_or(DeviceLinkEndReason::CancelledElsewhere, end_reason),
            )
        } else if now >= deadline {
            Some(DeviceLinkEndReason::TimedOut)
        } else {
            return Ok(());
        };
        let outcome = match ended {
            Some(reason) if self.withdraw_confirmed_device_link(&group_id)? => {
                NewDeviceOutcome::Ended(reason)
            }
            // The Welcome joined before the wait ended.
            _ => NewDeviceOutcome::Linked,
        };
        if let Some(link) = self.device_pairing.new_device.as_mut() {
            link.joining = None;
            link.outcome = Some(outcome);
        }
        Ok(())
    }

    // Existing device.

    /// Find, check and answer the requests this device has not answered.
    async fn check_prompts(&mut self, now: u64) {
        for prompt in &mut self.device_pairing.prompts {
            if let Stage::RateLimited { retry_at } = prompt.stage
                && now >= retry_at
            {
                prompt.stage = Stage::Checking;
            }
        }
        if self
            .device_pairing
            .prompts
            .iter()
            .any(|prompt| matches!(prompt.stage, Stage::Checking) && prompt.found.is_none())
            && now >= self.device_pairing.fetch_after
        {
            self.find_requested_key_packages(now).await;
        }
        let ready: Vec<SessionId> = self
            .device_pairing
            .prompts
            .iter()
            .filter(|prompt| matches!(prompt.stage, Stage::Checking) && prompt.found.is_some())
            .map(|prompt| prompt.session_id)
            .collect();
        for session_id in ready {
            if let Err(error) = self.check_and_answer(&session_id, now) {
                tracing::warn!(
                    target: TARGET,
                    method = "check_prompts",
                    error_kind = error.privacy_safe_kind(),
                    "could not check a sign-in's KeyPackage"
                );
            }
        }
    }

    async fn find_requested_key_packages(&mut self, now: u64) {
        let fetched = match self
            .app
            .fetch_validated_account_key_packages(&self.state.label, Vec::new(), "device_pairing")
            .await
        {
            Ok(fetched) => fetched,
            Err(error) => {
                tracing::debug!(
                    target: TARGET,
                    method = "find_requested_key_packages",
                    error_kind = error.privacy_safe_kind(),
                    "could not fetch this account's KeyPackages"
                );
                self.device_pairing.fetch_after = now.saturating_add(KEY_PACKAGE_RETRY_SECS);
                return;
            }
        };
        let mut missing = false;
        for prompt in &mut self.device_pairing.prompts {
            if !matches!(prompt.stage, Stage::Checking) || prompt.found.is_some() {
                continue;
            }
            let event_id_hex = hex::encode(prompt.key_package_event_id.as_bytes());
            let ref_hex = hex::encode(prompt.key_package_ref.as_slice());
            prompt.found = fetched
                .iter()
                .find(|fetched| {
                    fetched.key_package_event_id == event_id_hex
                        && fetched.key_package_ref_hex == ref_hex
                })
                .and_then(|fetched| {
                    Some(FoundKeyPackage {
                        slot: device_slot(&fetched.key_package_id).ok()?,
                        key_package: fetched.key_package.clone(),
                    })
                });
            missing |= prompt.found.is_none();
        }
        if missing {
            self.device_pairing.fetch_after = now.saturating_add(KEY_PACKAGE_RETRY_SECS);
        }
    }

    /// Check a found KeyPackage against the device group and answer its
    /// request, or say why it can't be linked.
    fn check_and_answer(&mut self, session_id: &SessionId, now: u64) -> Result<(), AppError> {
        let own_slot = self.own_slot()?;
        let account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        let device_group = self.trusted_device_roster()?;
        let required = match &device_group {
            Some((group_id, _)) => self
                .stored_group(group_id)?
                .map(|group| group.required_capabilities)
                .unwrap_or_default(),
            None => first_link_requirements(),
        };
        let roster = device_group.map(|(_, roster)| roster);
        let Some(prompt) = self.device_pairing.prompt_mut(session_id) else {
            return Ok(());
        };
        let Some(found) = prompt.found.as_ref() else {
            return Ok(());
        };
        let metadata = marmot_session::key_package_metadata(&found.key_package)
            .map_err(|error| AppError::InvalidKeyPackageEvent(error.to_string()))?;
        if metadata.credential_identity_hex != account_id_hex || found.slot == own_slot {
            // Not a sign-in this device could link: drop it unanswered.
            self.device_pairing
                .prompts
                .retain(|prompt| &prompt.session_id != session_id);
            if let Some(existing) = self.device_pairing.existing.as_mut() {
                existing.cancel(session_id);
            }
            return Ok(());
        }
        let refusal = if roster
            .as_ref()
            .is_some_and(|roster| roster.devices.contains_key(&found.slot))
        {
            // Already linked; the prompt shows who added it.
            return Ok(());
        } else if roster.as_ref().is_some_and(|roster| {
            roster.rejected_slots.contains_key(&found.slot)
                || roster
                    .rejected_key_packages
                    .contains_key(prompt.key_package_ref.as_slice())
        }) {
            Some(Stage::Rejected)
        } else {
            let missing = missing_capabilities(&required, &metadata);
            if !missing.is_empty() {
                Some(Stage::CannotLink(missing))
            } else if roster
                .as_ref()
                .is_some_and(|roster| roster.devices.len() >= MAX_LEAVES_PER_ACCOUNT)
            {
                Some(Stage::TooManyDevices)
            } else {
                None
            }
        };
        if let Some(stage) = refusal {
            let tell_new_device = matches!(stage, Stage::CannotLink(_) | Stage::TooManyDevices);
            prompt.stage = stage;
            prompt.updated_at = now;
            if let Some(existing) = self.device_pairing.existing.as_mut() {
                existing.cancel(session_id);
            }
            if tell_new_device {
                self.device_pairing.send(
                    PairingMessage::Cancel(PairingCancel {
                        session_id: *session_id,
                        reason: CancelReason::CannotLink,
                    }),
                    now,
                );
            }
            return Ok(());
        }
        let published = PublishedKeyPackage {
            event_id: prompt.key_package_event_id,
            key_package_ref: prompt.key_package_ref.clone(),
        };
        let Some(existing) = self.device_pairing.existing.as_mut() else {
            return Ok(());
        };
        let answered = existing.answer(session_id, &published, now);
        let ended = existing.end_reason(session_id).map(end_reason);
        let Some(prompt) = self.device_pairing.prompt_mut(session_id) else {
            return Ok(());
        };
        match answered {
            Ok(answer) => {
                prompt.stage = Stage::Answered;
                prompt.updated_at = now;
                self.device_pairing
                    .send(PairingMessage::Answer(answer), now);
            }
            // Answered once the other request ends.
            Err(PairingError::CompetingRequests) => {}
            Err(PairingError::RateLimited { retry_at }) => {
                prompt.stage = Stage::RateLimited { retry_at };
                prompt.updated_at = now;
            }
            Err(PairingError::KeyPackageMismatch) => {
                prompt.stage = Stage::Ended(DeviceLinkEndReason::VerificationFailed);
                prompt.updated_at = now;
            }
            Err(_) => {
                prompt.stage = Stage::Ended(ended.unwrap_or(DeviceLinkEndReason::TimedOut));
                prompt.updated_at = now;
            }
        }
        Ok(())
    }

    fn choose_link_device(
        &mut self,
        prompt_id: &str,
        choices: DeviceLinkChoices,
        now: u64,
    ) -> Result<(), AppError> {
        if choices.label.trim().is_empty() || choices.label.len() > DEVICE_ROSTER_TEXT_MAX_LEN {
            return Err(AppError::DeviceGroupRefused("label_invalid"));
        }
        let (session_id, slot) = self
            .device_pairing
            .prompts
            .iter()
            .find(|prompt| prompt.id == prompt_id)
            .filter(|prompt| matches!(prompt.stage, Stage::Answered))
            .and_then(|prompt| Some((prompt.session_id, prompt.found.as_ref()?.slot)))
            .ok_or(AppError::DeviceGroupRefused("unknown_prompt"))?;
        let device_group = self.trusted_device_roster()?;
        if let Some((_, roster)) = &device_group {
            if roster.devices.contains_key(&slot) {
                return Err(AppError::DeviceGroupRefused("device_already_linked"));
            }
            if roster.devices.len() >= MAX_LEAVES_PER_ACCOUNT {
                return Err(AppError::DeviceGroupRefused("too_many_devices"));
            }
        }
        let device_group_id = device_group
            .map(|(group_id, _)| group_id)
            .unwrap_or_else(|| {
                let mut id = [0_u8; DEVICE_GROUP_ID_LEN];
                OsRng.fill_bytes(&mut id);
                GroupId::new(id.to_vec())
            });
        // This device's leaf key in the device group: its MLS signer never
        // rotates, so a first link names the key it will create the group
        // with (D28, D33).
        let signature_key = SignatureKey::new(self.runtime.own_signature_key())
            .ok_or(AppError::DeviceGroupRefused("signature_key_invalid"))?;
        let existing = self
            .device_pairing
            .existing
            .as_mut()
            .ok_or(AppError::DeviceGroupRefused("unknown_prompt"))?;
        if !existing.can_offer_link(&session_id, now) {
            return Err(AppError::DeviceGroupRefused("link_unavailable"));
        }
        let confirm = existing
            .confirm_link(&session_id, device_group_id, signature_key, now)
            .map_err(pairing_refusal)?;
        if let Some(prompt) = self.device_pairing.prompt_mut(&session_id) {
            prompt.stage = Stage::Linking(choices);
            prompt.updated_at = now;
        }
        self.device_pairing
            .send(PairingMessage::Confirm(confirm), now);
        Ok(())
    }

    fn decline_link(&mut self, prompt_id: &str, now: u64) -> Result<(), AppError> {
        let index = self
            .device_pairing
            .prompts
            .iter()
            .position(|prompt| prompt.id == prompt_id)
            .ok_or(AppError::DeviceGroupRefused("unknown_prompt"))?;
        // Once both users confirmed, the new device waits for its Welcome and
        // no cancel reaches it, so the link runs to its outcome.
        let prompt = &self.device_pairing.prompts[index];
        if prompt.approval.is_some() || prompt.publication.is_some() {
            return Err(AppError::DeviceGroupRefused("link_in_progress"));
        }
        let prompt = self.device_pairing.prompts.remove(index);
        if let Some(cancel) = self
            .device_pairing
            .existing
            .as_mut()
            .and_then(|existing| existing.cancel(&prompt.session_id))
        {
            self.device_pairing
                .send(PairingMessage::Cancel(cancel), now);
        }
        Ok(())
    }

    /// The new device's confirmation, sent at `sent_at`, verified: add it.
    /// That commit, or the creation on a first link, is the approval. The new
    /// device began waiting for its Welcome when it sent the confirmation, so
    /// the time to add it counts from then, or from `now` if that is earlier.
    async fn on_existing_linked(&mut self, link: ConfirmedLink, sent_at: u64, now: u64) {
        let began = sent_at.min(now);
        let approval = Approval {
            link,
            retry_until: began.saturating_add(LINK_RETRY_SECS),
            wait_ends: began.saturating_add(WELCOME_WAIT_SECS),
        };
        self.approve_link(approval, now).await;
    }

    /// Retry each link the device group was too unsettled to commit. The
    /// engine never queues a link, so the retry lives here, bounded by the new
    /// device's Welcome wait.
    async fn retry_link_approvals(&mut self, now: u64) {
        let waiting: Vec<Approval> = self
            .device_pairing
            .prompts
            .iter_mut()
            .filter(|prompt| matches!(prompt.stage, Stage::Linking(_)))
            .filter_map(|prompt| prompt.approval.take())
            .collect();
        for approval in waiting {
            self.approve_link(approval, now).await;
        }
    }

    async fn approve_link(&mut self, approval: Approval, now: u64) {
        let Some(prompt) = self.device_pairing.prompt_mut(&approval.link.session_id) else {
            return;
        };
        let (Stage::Linking(choices), Some(found)) = (&prompt.stage, prompt.found.as_ref()) else {
            return;
        };
        let choices = choices.clone();
        let slot = found.slot;
        let key_package = found.key_package.clone();
        // Past the new device's Welcome wait, a link would add a device that
        // no longer waits for it.
        let result = if now < approval.retry_until {
            self.add_linked_device(
                &approval.link,
                slot,
                key_package,
                &choices,
                now,
                approval.wait_ends,
            )
            .await
        } else {
            Err(AppError::DeviceGroupRefused("link_expired"))
        };
        let session_id = approval.link.session_id;
        match result {
            Ok((group_id, welcomes)) => {
                // A first link's founding Welcome goes out now, and a link
                // commit's once the commit is confirmed. One the relays did
                // not take is published again after the backoff, and
                // [`Self::follow_link_publications`] ends the link if it
                // never lands.
                let redeliver_at = match self.drive_unpublished_welcome_delivery(None).await {
                    WelcomeDelivery::Delivered => now,
                    WelcomeDelivery::Undelivered => now.saturating_add(WELCOME_REDELIVER_SECS),
                };
                if let Some(prompt) = self.device_pairing.prompt_mut(&session_id) {
                    prompt.publication = Some(LinkPublication {
                        group_id,
                        welcomes,
                        wait_ends: approval.wait_ends,
                        redeliver_at,
                    });
                }
            }
            Err(error) if link_waits(&error, now, approval.retry_until) => {
                tracing::debug!(
                    target: TARGET,
                    method = "approve_link",
                    "the device group is unsettled; the link waits"
                );
                if let Some(prompt) = self.device_pairing.prompt_mut(&session_id) {
                    prompt.approval = Some(approval);
                }
            }
            Err(error) => {
                tracing::warn!(
                    target: TARGET,
                    method = "approve_link",
                    error_kind = error.privacy_safe_kind(),
                    "could not add a confirmed device; cancelling the link"
                );
                self.device_pairing.send(
                    PairingMessage::Cancel(PairingCancel {
                        session_id,
                        reason: CancelReason::CannotLink,
                    }),
                    now,
                );
                if let Some(prompt) = self.device_pairing.prompt_mut(&session_id) {
                    prompt.stage = Stage::Ended(DeviceLinkEndReason::LinkFailed);
                    prompt.updated_at = now;
                }
            }
        }
    }

    /// Add the confirmed device by the link commit, or by creating the device
    /// group on a first link. Its Welcome is never published from
    /// `wait_ends` on, when the new device stops waiting for it (D40).
    async fn add_linked_device(
        &mut self,
        link: &ConfirmedLink,
        slot: DeviceSlotId,
        key_package: KeyPackage,
        choices: &DeviceLinkChoices,
        now: u64,
        wait_ends: u64,
    ) -> Result<(GroupId, HashSet<MessageId>), AppError> {
        let key_package_ref_hex = hex::encode(link.key_package_ref.as_slice());
        let roster_update = if self.trusted_device_group()?.as_ref() == Some(&link.device_group_id)
        {
            // A fresh rename id (3.6a): a slot linked again after a failed
            // link never matches a rename kept for its earlier entry.
            let entry = DeviceEntryV1 {
                label: choices.label.clone(),
                rename_id: Some(fresh_rename_id()),
                linked_at: now,
                linked_by: Some(self.own_slot()?),
                settings: device_settings(choices),
                announced_key_package: Some(link.key_package_ref.as_slice().to_vec()),
                ..DeviceEntryV1::default()
            };
            let update =
                DeviceRosterUpdateV1::new(vec![DeviceRosterOperationV1::SetDevice(slot, entry)])
                    .and_then(|update| {
                        encode_device_roster_update_v1(&update).map_err(|e| e.to_string())
                    })
                    .map_err(|_| AppError::DeviceGroupRefused("roster_invalid"))?;
            Some(update)
        } else {
            None
        };
        let leaf_signature_key = marmot_session::key_package_metadata(&key_package)
            .map_err(|_| AppError::DeviceGroupRefused("key_package_not_confirmed"))?
            .leaf_signature_key;
        // Record the approval before its commit, so no crash can lose it,
        // with the KeyPackage's ref, which also finds the link's Welcome, and
        // the leaf it adds: the new device's first commit sets that key as
        // its tag key, and a failed link removes that leaf. One whose commit
        // never lands fails.
        self.app
            .account_storage(&self.state.label)?
            .app_storage()
            .record_device_link(
                &hex::encode(link.device_group_id.as_slice()),
                &hex::encode(slot),
                &key_package_ref_hex,
                &hex::encode(&leaf_signature_key),
                now,
            )?;
        match roster_update {
            Some(update) => {
                self.link_device_into_group(&link.device_group_id, key_package, update, wait_ends)
                    .await?;
            }
            None => {
                let confirmed = ConfirmedDeviceLink {
                    key_package_event_id_hex: hex::encode(link.key_package_event_id.as_bytes()),
                    key_package_ref_hex,
                    device_group_id: link.device_group_id.clone(),
                    welcome_sender_key: link.welcome_sender_key.as_slice().to_vec(),
                };
                self.create_device_group(&confirmed, choices, wait_ends)
                    .await?;
            }
        }
        // The commit is made, so a failed read here must not end the link as
        // though it were not: the link's gate never reads its Welcome, which
        // is published only to reach the new device. A link that fails finds
        // its Welcome by the KeyPackage's ref again to withdraw it.
        let welcomes: HashSet<MessageId> = match self
            .runtime
            .welcomes_for_key_package(&link.device_group_id, link.key_package_ref.as_slice())
        {
            Ok(welcomes) => welcomes.into_iter().collect(),
            Err(error) => {
                tracing::warn!(
                    target: TARGET,
                    method = "add_linked_device",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "could not read a link's Welcome; it is not published again"
                );
                HashSet::new()
            }
        };
        Ok((link.device_group_id.clone(), welcomes))
    }

    /// Add the confirmed KeyPackage to the device group in one commit that
    /// also writes its roster entry. The runtime publishes it as a group
    /// evolution, releasing its Welcome only once the commit is confirmed,
    /// now or on a later retry, so the new device never joins an epoch that
    /// rolls back, and never once the new device stopped waiting at
    /// `wait_ends`. Only a commit the runtime rolled back is an error.
    async fn link_device_into_group(
        &mut self,
        group_id: &GroupId,
        key_package: KeyPackage,
        roster_update: Vec<u8>,
        wait_ends: u64,
    ) -> Result<(), AppError> {
        let account = self.app.account_home().account(&self.state.label)?;
        self.refresh_member_inbox_routes(std::iter::once(account.account_id_hex.as_str()))?;
        let audit_context = Self::local_human_action_context(
            "link_device",
            vec!["members"],
            vec![DEVICE_ROSTER_COMPONENT_ID],
            Some(1),
        );
        let sent = match self
            .runtime
            .send_with_audit_context(
                SendIntent::LinkDevice {
                    group_id: group_id.clone(),
                    key_package,
                    roster_update,
                    deliver_until: Timestamp(wait_ends),
                },
                audit_context,
            )
            .await
            .map_err(AppError::from)
        {
            Ok(effects) => self
                .observe_recovery_evidence_then_fail_if_publish_failed(&effects)
                .await
                .map(|()| effects),
            Err(error) => Err(error),
        };
        // Refused as unsettled, the link made no commit: a commit resolving
        // in the device group is another one, and the approval waits.
        if let Err(error) = &sent
            && matches!(
                error.as_engine_error(),
                Some(EngineError::LinkDeviceUnsettled { .. })
            )
        {
            return sent.map(drop);
        }
        // The runtime rolled the commit back, or kept it to retry; only the
        // rollback ends the link. The engine never queues a link, so a
        // commit resolving in the device group now is this one.
        if self
            .runtime
            .epoch_state(group_id)
            .is_some_and(|state| state.is_resolving_local_publish())
        {
            return Ok(());
        }
        let effects = sent?;
        self.note_welcome_delivery_failures(&effects);
        Ok(())
    }

    /// Publish again each Welcome of a link this device committed, or created
    /// the device group for, that the relays have not taken, until the new
    /// device stops waiting for it. Whether the link is made is decided only
    /// by [`Self::decide_device_links`].
    async fn follow_link_publications(&mut self, now: u64) {
        let pending: Vec<SessionId> = self
            .device_pairing
            .prompts
            .iter_mut()
            .filter_map(|prompt| {
                prompt.publication.as_ref()?;
                if matches!(prompt.stage, Stage::Linking(_)) {
                    Some(prompt.session_id)
                } else {
                    // The link was decided; nothing waits for its Welcome.
                    prompt.publication = None;
                    None
                }
            })
            .collect();
        for session_id in pending {
            let Some((group_id, welcomes)) = self
                .device_pairing
                .prompt_mut(&session_id)
                .and_then(|prompt| prompt.publication.as_ref())
                .filter(|publication| {
                    now < publication.wait_ends && now >= publication.redeliver_at
                })
                .map(|publication| (publication.group_id.clone(), publication.welcomes.clone()))
            else {
                continue;
            };
            let undelivered = match self.undelivered_welcomes(&group_id, &welcomes) {
                Ok(undelivered) => undelivered,
                Err(error) => {
                    tracing::warn!(
                        target: TARGET,
                        method = "follow_link_publications",
                        error_kind = error.privacy_safe_kind(),
                        "could not read a link's Welcome; it is published again later"
                    );
                    continue;
                }
            };
            if let Some(publication) = self
                .device_pairing
                .prompt_mut(&session_id)
                .and_then(|prompt| prompt.publication.as_mut())
            {
                publication.redeliver_at = now.saturating_add(WELCOME_REDELIVER_SECS);
            }
            for id in undelivered {
                if let Err(error) = self.redeliver_welcome(&hex::encode(id.as_slice())).await {
                    tracing::debug!(
                        target: TARGET,
                        method = "follow_link_publications",
                        error_kind = error.privacy_safe_kind(),
                        "a link's Welcome is still undelivered; it is published again later"
                    );
                }
            }
        }
    }

    /// The Welcomes among `welcomes` that `group_id` still owes: those the
    /// engine has not seen reach the relays.
    fn undelivered_welcomes(
        &self,
        group_id: &GroupId,
        welcomes: &HashSet<MessageId>,
    ) -> Result<Vec<MessageId>, AppError> {
        Ok(self
            .runtime
            .outstanding_welcome_deliveries()?
            .into_iter()
            .filter(|(welcome_group, welcome)| {
                welcome_group == group_id && welcomes.contains(&welcome.id)
            })
            .map(|(_, welcome)| welcome.id)
            .collect())
    }

    /// Decide every link this device approved, through one gate whether its
    /// prompt is here or a restart dropped it (D40). The link is made once
    /// the new device's first commit in the device group, which sets its tag
    /// signature key in its roster entry, is on the selected branch and the
    /// group holds no unprocessed input. It fails if the approving commit
    /// never landed or lost, or if [`LINK_DEADLINE_SECS`] after the entry's
    /// `linked_at` that commit is still absent; neither the approving
    /// commit's publication nor its Welcome's delivery decides it. A failed
    /// link this device still lists is removed again on every drive until
    /// it is gone.
    async fn decide_device_links(&mut self, now: u64) {
        let window = Duration::from_millis(self.app.settlement_quiescence_ms());
        let Ok(storage) = self.app.account_storage(&self.state.label) else {
            return;
        };
        let storage = storage.app_storage();
        let (Ok(links), Ok(own_slot)) = (storage.device_links(), self.own_slot()) else {
            return;
        };
        let mut pending = Vec::new();
        for link in links {
            match link.outcome {
                DeviceLinkOutcome::Linked => continue,
                DeviceLinkOutcome::Failed => {
                    self.unlink_failed_device(&link, &own_slot, false).await;
                    continue;
                }
                DeviceLinkOutcome::Pending => {}
            }
            let key = (link.group_id_hex.clone(), link.slot_hex.clone());
            pending.push(key.clone());
            if self.approval_waits(&link) {
                // Its last attempt was refused before any commit; the retry
                // re-records it, and decides nothing until it commits or ends.
                self.device_pairing.quiet_since.remove(&key);
                continue;
            }
            let Some(outcome) = self.link_outcome(&link, &own_slot, &key, window, now) else {
                continue;
            };
            // Withdraw a failing link's Welcome before recording the failure,
            // so no failed link ever has its Welcome still publishable. While
            // the Welcome's own deadline may be ahead, a withdrawal that fails
            // records nothing: the link stays pending and the next drive
            // decides it again. That deadline is never after `linked_at` plus
            // the new device's wait, and from then on the runtime refuses the
            // Welcome, so the failure is recorded and the removal does not
            // wait for the withdrawal.
            if outcome == DeviceLinkOutcome::Failed
                && let Err(error) = self.withdraw_link_welcomes(&link)
                && now < link.linked_at.saturating_add(WELCOME_WAIT_SECS)
            {
                tracing::warn!(
                    target: TARGET,
                    method = "decide_device_links",
                    error_kind = error.privacy_safe_kind(),
                    "could not withdraw a failing link's Welcome; deciding it again"
                );
                continue;
            }
            self.device_pairing.quiet_since.remove(&key);
            if let Err(error) =
                storage.decide_device_link(&link.group_id_hex, &link.slot_hex, outcome, now)
            {
                tracing::warn!(
                    target: TARGET,
                    method = "decide_device_links",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "could not record a decided device link"
                );
                continue;
            }
            self.end_link_prompt(&link, outcome, now);
            if outcome == DeviceLinkOutcome::Failed {
                self.unlink_failed_device(&link, &own_slot, true).await;
            }
        }
        self.device_pairing
            .quiet_since
            .retain(|key, _| pending.contains(key));
    }

    /// Whether `link`'s approval still waits to be retried: the engine refused
    /// its commit as unsettled, which it also does for reasons the device
    /// group's quiet state does not show, such as this device's own changes
    /// queued there.
    fn approval_waits(&self, link: &DeviceLinkRecord) -> bool {
        self.device_pairing.prompts.iter().any(|prompt| {
            prompt.approval.as_ref().is_some_and(|approval| {
                hex::encode(approval.link.device_group_id.as_slice()) == link.group_id_hex
            }) && prompt
                .found
                .as_ref()
                .is_some_and(|found| hex::encode(found.slot) == link.slot_hex)
        })
    }

    /// The outcome `link` has reached, if any. Its device group must be
    /// stable with no convergence input left to process, and its roster is
    /// read only when it is the group this device trusts. A link the roster
    /// does not list fails only after the settlement window, in milliseconds,
    /// since branch selection may still bring its commit back.
    fn link_outcome(
        &mut self,
        link: &DeviceLinkRecord,
        own_slot: &DeviceSlotId,
        key: &(String, String),
        window: Duration,
        now: u64,
    ) -> Option<DeviceLinkOutcome> {
        let group_id = GroupId::new(hex::decode(&link.group_id_hex).ok()?);
        if matches!(self.stored_group(&group_id), Ok(None)) {
            // The approval never made its group: a first link whose creation
            // failed, or a crash before it.
            return Some(DeviceLinkOutcome::Failed);
        }
        let quiet = matches!(
            self.runtime.epoch_state(&group_id),
            Some(EpochState::Stable { .. })
        ) && matches!(
            self.runtime.has_pending_convergence_inputs(&group_id),
            Ok(false)
        );
        if !quiet {
            self.device_pairing.quiet_since.remove(key);
            return None;
        }
        let roster = match self.trusted_device_roster() {
            Ok(Some((trusted, roster))) if trusted == group_id => roster,
            _ => return None,
        };
        let slot = device_slot(&link.slot_hex).ok()?;
        let leaf_signature_key = hex::decode(&link.leaf_signature_key_hex).ok()?;
        match link_verdict(&roster, &slot, own_slot, &leaf_signature_key, now) {
            LinkVerdict::Made => Some(DeviceLinkOutcome::Linked),
            LinkVerdict::Waiting => {
                self.device_pairing.quiet_since.remove(key);
                None
            }
            LinkVerdict::TimedOut => Some(DeviceLinkOutcome::Failed),
            LinkVerdict::Lost => {
                let since = *self
                    .device_pairing
                    .quiet_since
                    .entry(key.clone())
                    .or_insert_with(Instant::now);
                (since.elapsed() >= window).then_some(DeviceLinkOutcome::Failed)
            }
        }
    }

    /// Undo a failed link (D40) on every drive until it is undone: withdraw
    /// its Welcome until that succeeds, so no recovery publishes it again,
    /// and while the trusted roster still lists the device as this device's
    /// link, remove its leaf and roster entry in one commit once the group
    /// is quiet. A Welcome that cannot be withdrawn yet does not hold the
    /// removal back: one published later opens an epoch before the removal,
    /// and the new device's engine joins none once its wait ended. A removal
    /// the unsettled group refuses is tried again on the next drive.
    async fn unlink_failed_device(
        &mut self,
        link: &DeviceLinkRecord,
        own_slot: &DeviceSlotId,
        failed_now: bool,
    ) {
        if !link.welcome_withdrawn {
            self.withdraw_failed_link_welcome(link, failed_now);
        }
        let result = async {
            let group_id = GroupId::new(hex::decode(&link.group_id_hex)?);
            let slot = device_slot(&link.slot_hex)?;
            let listed = match self.trusted_device_roster()? {
                Some((trusted, roster)) if trusted == group_id => roster
                    .devices
                    .get(&slot)
                    .is_some_and(|device| device.linked_by.as_ref() == Some(own_slot)),
                _ => false,
            };
            if !listed {
                return Ok(());
            }
            // The engine reads its own tree for the leaf and removes it only
            // if it is there; the entry goes either way.
            self.unlink_device_from_group(
                &group_id,
                hex::decode(&link.leaf_signature_key_hex)?,
                vec![DeviceRosterOperationV1::RemoveDevice(slot)],
            )
            .await
        }
        .await;
        match result {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.as_engine_error(),
                    Some(EngineError::LinkDeviceUnsettled { .. })
                ) =>
            {
                tracing::debug!(
                    target: TARGET,
                    method = "unlink_failed_device",
                    "the device group is unsettled; the removal waits"
                );
            }
            Err(error) => tracing::warn!(
                target: TARGET,
                method = "unlink_failed_device",
                error_kind = error.privacy_safe_kind(),
                "could not remove a device whose link failed; retrying"
            ),
        }
    }

    /// Withdraw a failed link's Welcome and record it withdrawn. Any failure
    /// leaves it to withdraw on the next drive.
    fn withdraw_failed_link_welcome(&mut self, link: &DeviceLinkRecord, failed_now: bool) {
        let result = (|| -> Result<(), AppError> {
            self.withdraw_link_welcomes(link)?;
            self.app
                .account_storage(&self.state.label)?
                .app_storage()
                .mark_device_link_welcome_withdrawn(&link.group_id_hex, &link.slot_hex)?;
            Ok(())
        })();
        if let Err(error) = result {
            if failed_now {
                tracing::warn!(
                    target: TARGET,
                    method = "withdraw_failed_link_welcome",
                    error_kind = error.privacy_safe_kind(),
                    "could not withdraw a failed link's Welcome; retrying"
                );
            } else {
                tracing::debug!(
                    target: TARGET,
                    method = "withdraw_failed_link_welcome",
                    error_kind = error.privacy_safe_kind(),
                    "a failed link's Welcome is still not withdrawn; retrying"
                );
            }
        }
    }

    /// Withdraw every Welcome of `link`, found by its KeyPackage's ref. The
    /// lookup needs nothing written after the commit, so a crash right after
    /// it still leaves the Welcome to find, and it reads no group state, so
    /// it works before hydration. A Welcome the engine no longer retains is
    /// withdrawn: nothing can publish it.
    fn withdraw_link_welcomes(&self, link: &DeviceLinkRecord) -> Result<(), AppError> {
        let group_id = GroupId::new(hex::decode(&link.group_id_hex)?);
        let key_package_ref = hex::decode(&link.key_package_ref_hex)?;
        for welcome in self
            .runtime
            .welcomes_for_key_package(&group_id, &key_package_ref)?
        {
            match self
                .runtime
                .withdraw_welcome(&welcome)
                .map_err(AppError::from)
            {
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.as_engine_error(),
                        Some(EngineError::Storage(StorageError::NotFound))
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// End the linking prompt of `link` with its outcome, telling the new
    /// device when the link failed.
    fn end_link_prompt(&mut self, link: &DeviceLinkRecord, outcome: DeviceLinkOutcome, now: u64) {
        let Some(prompt) = self.device_pairing.prompts.iter_mut().find(|prompt| {
            matches!(prompt.stage, Stage::Linking(_))
                && hex::encode(prompt.key_package_ref.as_slice()) == link.key_package_ref_hex
                && prompt
                    .found
                    .as_ref()
                    .is_some_and(|found| hex::encode(found.slot) == link.slot_hex)
        }) else {
            return;
        };
        prompt.publication = None;
        prompt.approval = None;
        prompt.updated_at = now;
        if outcome == DeviceLinkOutcome::Linked {
            prompt.stage = Stage::Linked;
            return;
        }
        prompt.stage = Stage::Ended(DeviceLinkEndReason::LinkFailed);
        let session_id = prompt.session_id;
        self.device_pairing.send(
            PairingMessage::Cancel(PairingCancel {
                session_id,
                reason: CancelReason::CannotLink,
            }),
            now,
        );
    }

    /// Test hook: date every prompt's request `secs` earlier, as a code
    /// comparison that took that long would.
    #[cfg(test)]
    pub(crate) fn backdate_link_requests(&mut self, secs: u64) {
        for prompt in &mut self.device_pairing.prompts {
            prompt.requested_at = prompt.requested_at.saturating_sub(secs);
        }
    }

    // New device, after its link's Welcome joined.

    /// Make this device's first commit in the device group it joined through
    /// a link as soon as it can, rather than on the next maintenance pass,
    /// and forget the join once that commit is on the selected branch. A
    /// device removed from its device group forgets its copy, so its next
    /// Welcome is a first join; one removed before its first commit there
    /// landed tells its user that linking failed (D40).
    async fn follow_device_group_joins(&mut self) {
        if let Err(error) = self.follow_device_group_joins_inner().await {
            tracing::warn!(
                target: TARGET,
                method = "follow_device_group_joins",
                error_kind = error.privacy_safe_kind(),
                "could not follow this device's device group join; retrying"
            );
        }
    }

    async fn follow_device_group_joins_inner(&mut self) -> Result<(), AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let trusted = self.trusted_device_group()?;
        let joins = storage.device_group_joins()?;
        if let Some(group_id) = &trusted
            && self
                .stored_group(group_id)?
                .is_some_and(|group| group.removed)
        {
            let joined = joins
                .iter()
                .any(|(group_id_hex, _)| *group_id_hex == hex::encode(group_id.as_slice()));
            self.forget_group_local(group_id).await?;
            self.linked_devices_changed = true;
            self.sync_device_tag_group()?;
            if joined {
                match self.device_pairing.new_device.as_mut() {
                    Some(link) if matches!(link.outcome, Some(NewDeviceOutcome::Linked)) => {
                        link.outcome =
                            Some(NewDeviceOutcome::Ended(DeviceLinkEndReason::LinkFailed));
                    }
                    Some(_) => {}
                    None => self.device_pairing.removed_after_join = true,
                }
            }
            return Ok(());
        }
        for (group_id_hex, _) in joins {
            let joined = trusted
                .as_ref()
                .is_some_and(|group_id| hex::encode(group_id.as_slice()) == group_id_hex);
            let linked = joined
                && storage
                    .device_group(&group_id_hex)?
                    .is_some_and(|record| record.trust == DeviceGroupTrust::Linked);
            if !linked || self.own_first_commit_landed()? {
                storage.delete_device_group_join(&group_id_hex)?;
                continue;
            }
            self.set_device_tag_key().await?;
        }
        Ok(())
    }

    /// Whether this device's first commit in its trusted device group is on
    /// the selected branch: the group is stable with no convergence input
    /// left, and this device's roster entry carries its tag signature key.
    fn own_first_commit_landed(&mut self) -> Result<bool, AppError> {
        let Some((group_id, roster)) = self.trusted_device_roster()? else {
            return Ok(false);
        };
        let quiet = matches!(
            self.runtime.epoch_state(&group_id),
            Some(EpochState::Stable { .. })
        ) && !self.runtime.has_pending_convergence_inputs(&group_id)?;
        let own_key = self.runtime.own_signature_key();
        Ok(quiet
            && roster
                .devices
                .get(&self.own_slot()?)
                .is_some_and(|device| device.tag_signature_key.as_ref() == Some(&own_key)))
    }

    /// End sessions whose time ran out, and send the cancels owed.
    fn expire_pairing(&mut self, now: u64) {
        let mut owed = Vec::new();
        if let Some(link) = self.device_pairing.new_device.as_mut()
            && link.outcome.is_none()
        {
            owed.extend(link.pairing.expire(now));
        }
        self.end_new_device_if_over(now);
        if let Some(existing) = self.device_pairing.existing.as_mut() {
            owed.extend(existing.expire(now));
            for prompt in &mut self.device_pairing.prompts {
                // A pending approval, and a link waiting on its publication,
                // end by their own deadlines.
                if prompt.stage.is_terminal()
                    || prompt.approval.is_some()
                    || prompt.publication.is_some()
                {
                    continue;
                }
                let ended = existing.end_reason(&prompt.session_id).map(end_reason);
                // A forgotten request ran out long ago.
                let forgotten = now
                    >= prompt
                        .requested_at
                        .saturating_add(REQUEST_TTL_SECS + SESSION_TTL_SECS);
                if let Some(reason) = ended.or(forgotten.then_some(DeviceLinkEndReason::TimedOut)) {
                    prompt.stage = Stage::Ended(reason);
                    prompt.updated_at = now;
                }
            }
        }
        for cancel in owed {
            self.device_pairing
                .send(PairingMessage::Cancel(cancel), now);
        }
    }

    async fn flush_pairing_outbox(&mut self, now: u64) {
        while let Some((message, created_at)) = self.device_pairing.outbox.front() {
            if created_at.saturating_add(SESSION_TTL_SECS) <= now {
                self.device_pairing.outbox.pop_front();
                continue;
            }
            let (message, created_at) = (message.clone(), *created_at);
            if let Err(error) = self.publish_pairing_message(&message, created_at).await {
                tracing::warn!(
                    target: TARGET,
                    method = "flush_pairing_outbox",
                    error_kind = error.privacy_safe_kind(),
                    "could not send a pairing message; retrying later"
                );
                return;
            }
            self.device_pairing.outbox.pop_front();
        }
    }

    /// Gift-wrap `message` to the account and publish it to the account's
    /// inbox relays, where every device of the account reads it.
    async fn publish_pairing_message(
        &self,
        message: &PairingMessage,
        created_at: u64,
    ) -> Result<(), AppError> {
        let account = self.app.account_home().account(&self.state.label)?;
        let event = wrap_pairing_message(self.transport_signer.clone(), message, created_at)
            .await
            .map_err(|_| AppError::Publish("could not wrap a pairing message".into()))?;
        let relay_lists = self
            .app
            .directory()
            .account_relay_list_status_for_account_id(&account.account_id_hex)
            .unwrap_or_else(|_| AccountRelayListStatus::empty());
        let endpoints = self
            .app
            .account_inbox_endpoints(&self.state.label, &relay_lists);
        let account_id = MemberId::new(hex::decode(&account.account_id_hex)?);
        let outcome = self
            .app
            .relay_client_for_account_id(&account.account_id_hex, self.transport_signer.clone())
            .publish_event_for_account(&account_id, &endpoints, &event, 1)
            .await?;
        if outcome.accepted.is_empty() {
            return Err(AppError::Publish(
                "no account relay acknowledged a pairing message".into(),
            ));
        }
        Ok(())
    }

    // The view.

    fn device_link_snapshot(&mut self) -> Result<DeviceLinkSnapshot, AppError> {
        let now = unix_now_seconds();
        // Only prompts show the roster.
        let roster = if self.device_pairing.prompts.is_empty() {
            None
        } else {
            self.trusted_device_roster()?.map(|(_, roster)| roster)
        };
        let new_device = match self.device_pairing.new_device.as_ref() {
            Some(link) => Some(new_device_state(link, now)),
            None => self
                .device_pairing
                .removed_after_join
                .then_some(NewDeviceLinkState::Ended {
                    reason: DeviceLinkEndReason::LinkFailed,
                }),
        };
        let existing = self.device_pairing.existing.as_ref();
        let competing = existing.is_some_and(|existing| existing.competing_requests(now));
        let prompts = self
            .device_pairing
            .prompts
            .iter()
            .map(|prompt| DeviceLinkPrompt {
                prompt_id: prompt.id.clone(),
                slot_id_hex: prompt
                    .found
                    .as_ref()
                    .map(|found| &found.slot)
                    .or_else(|| {
                        roster
                            .as_ref()
                            .and_then(|roster| roster_entry(prompt, roster))
                            .map(|(slot, _)| slot)
                    })
                    .map(hex::encode),
                requested_at: prompt.requested_at,
                state: prompt_state(prompt, existing, competing, roster.as_ref(), now),
            })
            .collect();
        Ok(DeviceLinkSnapshot {
            new_device,
            prompts,
        })
    }
}

fn new_device_state(link: &NewDeviceLink, now: u64) -> NewDeviceLinkState {
    match link.outcome {
        Some(NewDeviceOutcome::Linked) => return NewDeviceLinkState::Linked,
        Some(NewDeviceOutcome::Ended(reason)) => return NewDeviceLinkState::Ended { reason },
        None => {}
    }
    if link.joining.is_some() {
        return NewDeviceLinkState::Joining;
    }
    if let Some(code) = link.pairing.code(now) {
        return NewDeviceLinkState::Comparing { code: emoji(code) };
    }
    if link.user_confirmed {
        return NewDeviceLinkState::WaitingForOtherDevice;
    }
    match link.pairing.end_reason() {
        Some(reason) => NewDeviceLinkState::Ended {
            reason: end_reason(reason),
        },
        None => NewDeviceLinkState::WaitingForAnswer,
    }
}

fn prompt_state(
    prompt: &Prompt,
    existing: Option<&ExistingDevicePairing>,
    competing: bool,
    roster: Option<&DeviceRosterV1>,
    now: u64,
) -> DeviceLinkPromptState {
    match &prompt.stage {
        Stage::Linking(_) => return DeviceLinkPromptState::Linking,
        Stage::Linked => return DeviceLinkPromptState::Linked,
        // Only this device's own link fails, so the roster listing the
        // device, as a creation whose Welcome never landed leaves it, does
        // not mean another device added it.
        Stage::Ended(reason @ DeviceLinkEndReason::LinkFailed) => {
            return DeviceLinkPromptState::Ended { reason: *reason };
        }
        _ => {}
    }
    // Another device added it: say so rather than drop the prompt.
    if let Some((_, device)) = roster.and_then(|roster| roster_entry(prompt, roster)) {
        let added_by_label = device
            .linked_by
            .and_then(|slot| roster.and_then(|roster| roster.devices.get(&slot)))
            .map(|linker| linker.label.clone())
            .unwrap_or_default();
        return DeviceLinkPromptState::AddedElsewhere {
            device_label: device.label.clone(),
            added_by_label,
        };
    }
    match &prompt.stage {
        Stage::Checking if competing => DeviceLinkPromptState::CompetingRequests,
        Stage::Checking => DeviceLinkPromptState::Preparing,
        Stage::RateLimited { retry_at } => DeviceLinkPromptState::RateLimited {
            retry_at: *retry_at,
        },
        Stage::Answered => {
            let code = existing.and_then(|existing| existing.code(&prompt.session_id, now));
            let can_link =
                existing.is_some_and(|existing| existing.can_offer_link(&prompt.session_id, now));
            match code {
                Some(code) if can_link => DeviceLinkPromptState::Comparing { code: emoji(code) },
                _ if competing => DeviceLinkPromptState::CompetingRequests,
                _ => DeviceLinkPromptState::Preparing,
            }
        }
        Stage::CannotLink(missing) => DeviceLinkPromptState::CannotLink {
            missing: missing.clone(),
        },
        Stage::TooManyDevices => DeviceLinkPromptState::TooManyDevices,
        Stage::Rejected => DeviceLinkPromptState::Ended {
            reason: DeviceLinkEndReason::Rejected,
        },
        Stage::Ended(reason) => DeviceLinkPromptState::Ended { reason: *reason },
        Stage::Linking(_) | Stage::Linked => unreachable!("handled above"),
    }
}

/// The roster entry of the sign-in `prompt` names: the entry for its
/// KeyPackage's slot, or, before this device found that KeyPackage, the entry
/// announcing the `KeyPackageRef` its request named.
fn roster_entry<'a>(
    prompt: &Prompt,
    roster: &'a DeviceRosterV1,
) -> Option<(&'a DeviceSlotId, &'a DeviceEntryV1)> {
    match &prompt.found {
        Some(found) => roster.devices.get_key_value(&found.slot),
        None => roster.devices.iter().find(|(_, device)| {
            device.announced_key_package.as_deref() == Some(prompt.key_package_ref.as_slice())
        }),
    }
}

/// Where the link of `slot` this device approved stands in `roster` at
/// `now`. The link stands only as this device's link of the slot; the
/// announced KeyPackage is no evidence, since the device replaces it whenever
/// it refreshes its KeyPackage. It is made once the entry carries
/// `leaf_signature_key`, the key of the leaf the link added, as its tag
/// signature key: only that device's first commit sets it.
fn link_verdict(
    roster: &DeviceRosterV1,
    slot: &DeviceSlotId,
    own_slot: &DeviceSlotId,
    leaf_signature_key: &[u8],
    now: u64,
) -> LinkVerdict {
    let Some(device) = roster
        .devices
        .get(slot)
        .filter(|device| device.linked_by.as_ref() == Some(own_slot))
    else {
        return LinkVerdict::Lost;
    };
    if device.tag_signature_key.as_deref() == Some(leaf_signature_key) {
        LinkVerdict::Made
    } else if now >= device.linked_at.saturating_add(LINK_DEADLINE_SECS) {
        LinkVerdict::TimedOut
    } else {
        LinkVerdict::Waiting
    }
}

fn emoji(code: &SasCode) -> Vec<DeviceLinkEmoji> {
    code.emoji()
        .iter()
        .map(|emoji| DeviceLinkEmoji {
            emoji: emoji.emoji.to_owned(),
            description: emoji.description.to_owned(),
        })
        .collect()
}

fn end_reason(reason: &EndReason) -> DeviceLinkEndReason {
    match reason {
        EndReason::UserCancelled => DeviceLinkEndReason::Cancelled,
        EndReason::MismatchedCode => DeviceLinkEndReason::CodesDiffer,
        EndReason::MismatchedCommitment | EndReason::MismatchedConfirm | EndReason::InvalidKey => {
            DeviceLinkEndReason::VerificationFailed
        }
        EndReason::Timeout => DeviceLinkEndReason::TimedOut,
        EndReason::AnsweredElsewhere => DeviceLinkEndReason::AnsweredElsewhere,
        EndReason::Cancelled(reason) => match reason {
            CancelReason::Timeout => DeviceLinkEndReason::TimedOut,
            CancelReason::MismatchedCode => DeviceLinkEndReason::CodesDiffer,
            CancelReason::MismatchedCommitment
            | CancelReason::MismatchedConfirm
            | CancelReason::UnexpectedMessage => DeviceLinkEndReason::VerificationFailed,
            CancelReason::CannotLink => DeviceLinkEndReason::CannotLink,
            CancelReason::User
            | CancelReason::CompetingRequests
            | CancelReason::RateLimited
            | CancelReason::Other(_) => DeviceLinkEndReason::CancelledElsewhere,
        },
    }
}

/// A prompt id no earlier prompt had: random, so an id a host kept from
/// before this client reopened names no prompt after it.
fn new_prompt_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("link-{}", hex::encode(bytes))
}

/// Whether a link that failed with `error` waits for a later drive: only while
/// the device group is unsettled, and only until `retry_until`.
fn link_waits(error: &AppError, now: u64, retry_until: u64) -> bool {
    matches!(
        error.as_engine_error(),
        Some(EngineError::LinkDeviceUnsettled { .. })
    ) && now < retry_until
}

fn pairing_refusal(error: PairingError) -> AppError {
    AppError::DeviceGroupRefused(match error {
        PairingError::UnknownSession => "pairing_unknown_session",
        PairingError::WrongStep => "pairing_wrong_step",
        PairingError::Expired => "pairing_expired",
        PairingError::CompetingRequests => "competing_requests",
        PairingError::RateLimited { .. } => "rate_limited",
        PairingError::KeyPackageMismatch => "key_package_mismatch",
        PairingError::InvalidGroupId => "invalid_group_id",
    })
}

fn device_settings(choices: &DeviceLinkChoices) -> DeviceSettingsV1 {
    DeviceSettingsV1 {
        add_to_all_chats: choices.add_to_all_chats,
        bring_history: choices.bring_history,
        keep_while_inactive: false,
    }
}

/// What a first link's device group requires of the new device, before the
/// group exists: its two app components. Creation checks the rest.
fn first_link_requirements() -> GroupCapabilities {
    GroupCapabilities {
        app_components: AppComponentSet::new([
            DEVICE_ROSTER_COMPONENT_ID,
            NOSTR_ROUTING_COMPONENT_ID,
        ]),
        ..GroupCapabilities::default()
    }
}

/// What `metadata`'s KeyPackage lacks of `required`, by name.
fn missing_capabilities(
    required: &GroupCapabilities,
    metadata: &marmot_session::KeyPackageMetadata,
) -> Vec<String> {
    let had = GroupCapabilities {
        proposals: metadata.mls_proposals.iter().copied().collect(),
        extensions: metadata.mls_extensions.iter().copied().collect(),
        app_components: AppComponentSet::new(metadata.app_components.iter().copied()),
    };
    let missing = required.missing_from(&had);
    missing
        .proposals
        .iter()
        .map(|id| format!("mls_proposal:{id:#06x}"))
        .chain(
            missing
                .extensions
                .iter()
                .map(|id| format!("mls_extension:{id:#06x}")),
        )
        .chain(
            missing
                .app_components
                .ids
                .iter()
                .map(|id| format!("app_component:{id:#06x}")),
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A link the device group was too unsettled to commit waits for a later
    /// drive until the new device's Welcome wait would end; any other refusal
    /// ends it at once.
    #[test]
    fn a_link_waits_only_while_the_device_group_is_unsettled_and_the_new_device_waits() {
        let engine = |error| AppError::Account(marmot_session::AccountError::Engine(error));
        let unsettled = engine(EngineError::LinkDeviceUnsettled {
            group_id: GroupId::new(vec![1; 16]),
        });
        assert!(link_waits(&unsettled, 99, 100));
        assert!(!link_waits(&unsettled, 100, 100));
        assert!(!link_waits(
            &engine(EngineError::Other("refused".into())),
            99,
            100
        ));
        assert!(!link_waits(
            &AppError::DeviceGroupRefused("roster_invalid"),
            99,
            100
        ));
    }

    #[test]
    fn a_link_is_made_only_by_the_new_devices_first_commit_before_the_deadline() {
        let (phone, laptop, tablet) = ([1; 32], [2; 32], [3; 32]);
        let leaf_key = vec![9; 32];
        let roster = |linked_by: DeviceSlotId, tag_key: Option<Vec<u8>>| DeviceRosterV1 {
            devices: [(
                tablet,
                DeviceEntryV1 {
                    linked_by: Some(linked_by),
                    linked_at: 1_000,
                    announced_key_package: Some(vec![7; 32]),
                    tag_signature_key: tag_key,
                    ..DeviceEntryV1::default()
                },
            )]
            .into(),
            ..DeviceRosterV1::default()
        };
        let verdict =
            |roster: &DeviceRosterV1, now| link_verdict(roster, &tablet, &phone, &leaf_key, now);
        let deadline = 1_000 + LINK_DEADLINE_SECS;

        assert_eq!(verdict(&roster(phone, None), 1_000), LinkVerdict::Waiting);
        assert_eq!(
            verdict(&roster(phone, None), deadline - 1),
            LinkVerdict::Waiting
        );
        assert_eq!(
            verdict(&roster(phone, None), deadline),
            LinkVerdict::TimedOut
        );
        // The first commit set the leaf's key: made, even past the deadline.
        assert_eq!(
            verdict(&roster(phone, Some(leaf_key.clone())), deadline + 5),
            LinkVerdict::Made
        );
        // A key the link's leaf does not hold is no evidence.
        assert_eq!(
            verdict(&roster(phone, Some(vec![8; 32])), 1_000),
            LinkVerdict::Waiting
        );
        // Another device's link of the same slot won.
        assert_eq!(
            verdict(&roster(laptop, Some(leaf_key.clone())), 1_000),
            LinkVerdict::Lost
        );
        assert_eq!(
            verdict(&DeviceRosterV1::default(), 1_000),
            LinkVerdict::Lost
        );
    }
}
