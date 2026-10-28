//! The existing device's side: every request it sees, the one it answers,
//! and its rate limit.

use std::collections::{BTreeMap, VecDeque};

use cgka_traits::GroupId;

use crate::code::SasCode;
use crate::message::{
    ConfirmSender, PairingAnswer, PairingCancel, PairingConfirm, PairingMessage, PairingRequest,
    PairingReveal,
};
use crate::sas::{EphemeralKey, MacItem, MacSender, SessionBinding, SharedSecret, commitment};
use crate::session::{
    ANSWER_WINDOW_SECS, ConfirmedLink, EndReason, IgnoreReason, MAX_ANSWERS_PER_WINDOW,
    MAX_TRACKED_REQUESTS, PairingError, REQUEST_MAX_FUTURE_SECS, REQUEST_TTL_SECS,
    SESSION_TTL_SECS,
};
use crate::types::{
    AccountKey, KeyPackageEventId, KeyPackageRef, SessionId, SlotId, valid_group_id_len,
};

/// The new device's KeyPackage as the existing device found it: fetched by the
/// request's event id, validated under the KeyPackage and transport rules,
/// and its `KeyPackageRef` computed from its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedKeyPackage {
    pub event_id: KeyPackageEventId,
    pub key_package_ref: KeyPackageRef,
}

/// An existing device's pairing state, one per device.
///
/// It tracks every live request sent to the account. While more than one is
/// live it answers none and confirms none: two requests at once mean no Link
/// is offered. A request it has no room to track still counts as live until
/// it would have expired. It answers at most [`MAX_ANSWERS_PER_WINDOW`] sessions in any
/// [`ANSWER_WINDOW_SECS`]. Its user confirms first: the new device's
/// confirmation follows this device's, and the session ends linked when it
/// verifies.
pub struct ExistingDevicePairing {
    account: AccountKey,
    slot: SlotId,
    sessions: BTreeMap<SessionId, Tracked>,
    /// Until when a request it had no room to track may still be live.
    untracked_live_until: u64,
    answered_at: VecDeque<u64>,
    /// Timeout cancels for answered sessions that ran out, until
    /// [`Self::expire`] hands them out.
    owed_cancels: VecDeque<PairingCancel>,
}

struct Tracked {
    request: PairingRequest,
    /// When the request or the session expires.
    deadline: u64,
    /// When a replay of the request stops being fresh, so its id can be
    /// forgotten.
    keep_until: u64,
    state: State,
}

enum State {
    Requested,
    Answered { key: EphemeralKey },
    Comparing(Box<Comparing>),
    Linked(ConfirmedLink),
    Ended(EndReason),
}

struct Comparing {
    binding: SessionBinding,
    shared: SharedSecret,
    code: SasCode,
    device_group_id: Option<GroupId>,
}

impl Tracked {
    fn is_live(&self, now: u64) -> bool {
        now < self.deadline
            && matches!(
                self.state,
                State::Requested | State::Answered { .. } | State::Comparing(_)
            )
    }
}

/// What a message did.
#[derive(Debug, PartialEq, Eq)]
pub enum ExistingDeviceEvent {
    Ignored(IgnoreReason),
    /// A new live request. `competing` is set when another request is live
    /// too, so no session may offer Link.
    Requested {
        session_id: SessionId,
        competing: bool,
    },
    /// The new device revealed the key it committed to. The code is now
    /// available.
    CodeReady {
        session_id: SessionId,
    },
    /// The new device's confirmation verified. Act on this link: the
    /// device forgets the session once it would have expired.
    Linked(ConfirmedLink),
    /// A session ended. Send `cancel` when present.
    Ended {
        session_id: SessionId,
        reason: EndReason,
        cancel: Option<PairingCancel>,
    },
}

/// A live request, for the prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveRequest {
    pub session_id: SessionId,
    pub key_package_event_id: KeyPackageEventId,
    pub key_package_ref: KeyPackageRef,
    pub answered: bool,
}

impl ExistingDevicePairing {
    /// Pairing state for the device in `slot` of `account`.
    pub fn new(account: AccountKey, slot: SlotId) -> Self {
        Self {
            account,
            slot,
            sessions: BTreeMap::new(),
            untracked_live_until: 0,
            answered_at: VecDeque::new(),
            owed_cancels: VecDeque::new(),
        }
    }

    /// Whether more than one request is live at `now`.
    pub fn competing_requests(&self, now: u64) -> bool {
        self.live_count(now) > 1
    }

    pub fn live_requests(&self, now: u64) -> Vec<LiveRequest> {
        self.sessions
            .iter()
            .filter(|(_, tracked)| tracked.is_live(now))
            .map(|(session_id, tracked)| LiveRequest {
                session_id: *session_id,
                key_package_event_id: tracked.request.key_package_event_id,
                key_package_ref: tracked.request.key_package_ref.clone(),
                answered: !matches!(tracked.state, State::Requested),
            })
            .collect()
    }

    /// The code to show for `session_id` at `now`. `None` until the new
    /// device revealed its key, once this user decided, and once the session
    /// ended or its time ran out.
    pub fn code(&self, session_id: &SessionId, now: u64) -> Option<&SasCode> {
        let tracked = self.sessions.get(session_id)?;
        match &tracked.state {
            State::Comparing(comparing)
                if comparing.device_group_id.is_none() && tracked.is_live(now) =>
            {
                Some(&comparing.code)
            }
            _ => None,
        }
    }

    /// Whether to offer Link for `session_id` at `now`: its code is shown,
    /// this user hasn't decided, and no other request is live.
    pub fn can_offer_link(&self, session_id: &SessionId, now: u64) -> bool {
        let Some(tracked) = self.sessions.get(session_id) else {
            return false;
        };
        let undecided = matches!(
            &tracked.state,
            State::Comparing(comparing) if comparing.device_group_id.is_none()
        );
        undecided && tracked.is_live(now) && self.live_count(now) == 1
    }

    /// How many sessions still hold a key or a shared secret, for tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn sessions_holding_secrets(&self) -> usize {
        self.sessions
            .values()
            .filter(|tracked| matches!(tracked.state, State::Answered { .. } | State::Comparing(_)))
            .count()
    }

    /// The verified link for `session_id`, until the session would have
    /// expired. A confirmed link never times out, but this device keeps no
    /// session past its replay window.
    pub fn linked(&self, session_id: &SessionId) -> Option<&ConfirmedLink> {
        match &self.sessions.get(session_id)?.state {
            State::Linked(link) => Some(link),
            _ => None,
        }
    }

    pub fn end_reason(&self, session_id: &SessionId) -> Option<&EndReason> {
        match &self.sessions.get(session_id)?.state {
            State::Ended(reason) => Some(reason),
            _ => None,
        }
    }

    /// Applies a message sent to the account. `created_at` is the time its
    /// sender stamped on it and `now` this device's time, both Unix seconds.
    pub fn receive(
        &mut self,
        message: &PairingMessage,
        created_at: u64,
        now: u64,
    ) -> ExistingDeviceEvent {
        let timed_out = self.tick(now);
        if let PairingMessage::Request(request) = message {
            return self.on_request(request, created_at, now);
        }
        let session_id = *message.session_id();
        if timed_out.contains(&session_id) {
            return ExistingDeviceEvent::Ended {
                session_id,
                reason: EndReason::Timeout,
                cancel: self.take_owed_cancel(&session_id),
            };
        }
        let Some(tracked) = self.sessions.get_mut(&session_id) else {
            return ExistingDeviceEvent::Ignored(IgnoreReason::OtherSession);
        };
        match &tracked.state {
            State::Ended(_) => return ExistingDeviceEvent::Ignored(IgnoreReason::Ended),
            State::Linked(_) => return ExistingDeviceEvent::Ignored(IgnoreReason::WrongStep),
            State::Requested | State::Answered { .. } | State::Comparing(_) => {}
        }
        match message {
            PairingMessage::Request(_) => unreachable!("handled above"),
            PairingMessage::Answer(_) => ExistingDeviceEvent::Ignored(IgnoreReason::OwnRole),
            PairingMessage::Reveal(reveal) => self.on_reveal(reveal),
            PairingMessage::Confirm(confirm) => self.on_confirm(confirm),
            PairingMessage::Cancel(cancel) => {
                let reason = EndReason::Cancelled(cancel.reason.clone());
                tracked.state = State::Ended(reason.clone());
                ExistingDeviceEvent::Ended {
                    session_id,
                    reason,
                    cancel: None,
                }
            }
        }
    }

    fn on_request(
        &mut self,
        request: &PairingRequest,
        created_at: u64,
        now: u64,
    ) -> ExistingDeviceEvent {
        if self.sessions.contains_key(&request.session_id) {
            return ExistingDeviceEvent::Ignored(IgnoreReason::Duplicate);
        }
        let stale = created_at.saturating_add(REQUEST_TTL_SECS) <= now
            || created_at > now.saturating_add(REQUEST_MAX_FUTURE_SECS);
        if stale {
            return ExistingDeviceEvent::Ignored(IgnoreReason::Stale);
        }
        if self.sessions.len() >= MAX_TRACKED_REQUESTS {
            // Dropping it must not hide it from the competing-request rule.
            self.untracked_live_until = self
                .untracked_live_until
                .max(created_at.min(now).saturating_add(REQUEST_TTL_SECS));
            return ExistingDeviceEvent::Ignored(IgnoreReason::Capacity);
        }
        self.sessions.insert(
            request.session_id,
            Tracked {
                request: request.clone(),
                deadline: created_at.min(now).saturating_add(REQUEST_TTL_SECS),
                keep_until: created_at.max(now).saturating_add(REQUEST_TTL_SECS),
                state: State::Requested,
            },
        );
        ExistingDeviceEvent::Requested {
            session_id: request.session_id,
            competing: self.competing_requests(now),
        }
    }

    /// Answers `session_id` at `now` for the KeyPackage this device fetched
    /// and validated. Send the answer to the account.
    pub fn answer(
        &mut self,
        session_id: &SessionId,
        key_package: &PublishedKeyPackage,
        now: u64,
    ) -> Result<PairingAnswer, PairingError> {
        self.answer_with_key(session_id, key_package, EphemeralKey::generate(), now)
    }

    /// [`Self::answer`] with a pinned ephemeral secret, for known-answer
    /// tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn answer_pinned(
        &mut self,
        session_id: &SessionId,
        key_package: &PublishedKeyPackage,
        secret: [u8; 32],
        now: u64,
    ) -> Result<PairingAnswer, PairingError> {
        self.answer_with_key(
            session_id,
            key_package,
            EphemeralKey::from_secret_bytes(secret),
            now,
        )
    }

    fn answer_with_key(
        &mut self,
        session_id: &SessionId,
        key_package: &PublishedKeyPackage,
        key: EphemeralKey,
        now: u64,
    ) -> Result<PairingAnswer, PairingError> {
        if self.tick(now).contains(session_id) {
            return Err(PairingError::Expired);
        }
        let competing = self.competing_requests(now);
        let retry_at = self.rate_limited_until(now);
        let tracked = self
            .sessions
            .get_mut(session_id)
            .ok_or(PairingError::UnknownSession)?;
        if !matches!(tracked.state, State::Requested) {
            return Err(PairingError::WrongStep);
        }
        if competing {
            return Err(PairingError::CompetingRequests);
        }
        if let Some(retry_at) = retry_at {
            return Err(PairingError::RateLimited { retry_at });
        }
        if key_package.event_id != tracked.request.key_package_event_id
            || key_package.key_package_ref != tracked.request.key_package_ref
        {
            return Err(PairingError::KeyPackageMismatch);
        }
        let answer = PairingAnswer {
            session_id: *session_id,
            slot: self.slot,
            key: key.public(),
        };
        tracked.state = State::Answered { key };
        tracked.deadline = now.saturating_add(SESSION_TTL_SECS);
        tracked.keep_until = tracked.keep_until.max(tracked.deadline);
        self.answered_at.push_back(now);
        Ok(answer)
    }

    fn on_reveal(&mut self, reveal: &PairingReveal) -> ExistingDeviceEvent {
        let session_id = reveal.session_id;
        let account = self.account;
        let own_slot = self.slot;
        let tracked = self
            .sessions
            .get_mut(&session_id)
            .expect("receive checked the session");
        if matches!(tracked.state, State::Comparing(_)) {
            return ExistingDeviceEvent::Ignored(IgnoreReason::WrongStep);
        }
        if reveal.answer_slot != own_slot {
            return end_tracked(&session_id, tracked, EndReason::AnsweredElsewhere);
        }
        if !matches!(tracked.state, State::Answered { .. }) {
            return ExistingDeviceEvent::Ignored(IgnoreReason::WrongStep);
        }
        let request = tracked.request.binding(account);
        if commitment(&reveal.key, &request) != tracked.request.commitment {
            return end_tracked(&session_id, tracked, EndReason::MismatchedCommitment);
        }
        let State::Answered { key } =
            std::mem::replace(&mut tracked.state, State::Ended(EndReason::InvalidKey))
        else {
            unreachable!("checked above");
        };
        let own_key = key.public();
        let Some(shared) = key.agree(&reveal.key) else {
            return end_tracked(&session_id, tracked, EndReason::InvalidKey);
        };
        let binding = SessionBinding::new(&request, own_slot);
        let code = shared.code(&binding, &reveal.key, &own_key);
        tracked.state = State::Comparing(Box::new(Comparing {
            binding,
            shared,
            code,
            device_group_id: None,
        }));
        ExistingDeviceEvent::CodeReady { session_id }
    }

    fn on_confirm(&mut self, confirm: &PairingConfirm) -> ExistingDeviceEvent {
        let session_id = confirm.session_id;
        let tracked = self
            .sessions
            .get_mut(&session_id)
            .expect("receive checked the session");
        if !matches!(confirm.sender, ConfirmSender::NewDevice) {
            return ExistingDeviceEvent::Ignored(IgnoreReason::OwnRole);
        }
        // The new device confirms only after this device did.
        let State::Comparing(comparing) = &mut tracked.state else {
            return ExistingDeviceEvent::Ignored(IgnoreReason::WrongStep);
        };
        if comparing.device_group_id.is_none() {
            return ExistingDeviceEvent::Ignored(IgnoreReason::WrongStep);
        }
        if !comparing.shared.verify_mac(
            &comparing.binding,
            MacSender::NewDevice,
            MacItem::KeyPackageRef,
            tracked.request.key_package_ref.as_slice(),
            &confirm.mac,
        ) {
            return end_tracked(&session_id, tracked, EndReason::MismatchedConfirm);
        }
        ExistingDeviceEvent::Linked(link_tracked(&session_id, tracked))
    }

    /// This user confirmed at `now` that the codes match and chose the device
    /// group to add the new device to. Send the confirmation; the link is
    /// confirmed when the new device's follows. One decision per session, and
    /// only while no other request is live.
    pub fn confirm_link(
        &mut self,
        session_id: &SessionId,
        device_group_id: GroupId,
        now: u64,
    ) -> Result<PairingConfirm, PairingError> {
        let competing = self.competing_requests(now);
        let tracked = self.live_comparing(session_id, now)?;
        if !valid_group_id_len(device_group_id.as_slice()) {
            return Err(PairingError::InvalidGroupId);
        }
        let State::Comparing(comparing) = &mut tracked.state else {
            unreachable!("live_comparing checked the state");
        };
        if comparing.device_group_id.is_some() {
            return Err(PairingError::WrongStep);
        }
        if competing {
            return Err(PairingError::CompetingRequests);
        }
        let confirm = PairingConfirm {
            session_id: *session_id,
            mac: comparing.shared.mac(
                &comparing.binding,
                MacSender::ExistingDevice,
                MacItem::DeviceGroupId,
                device_group_id.as_slice(),
            ),
            sender: ConfirmSender::ExistingDevice {
                device_group_id: device_group_id.clone(),
            },
        };
        comparing.device_group_id = Some(device_group_id);
        Ok(confirm)
    }

    /// This user said at `now` that the codes differ. Ends the session.
    pub fn reject_link(
        &mut self,
        session_id: &SessionId,
        now: u64,
    ) -> Result<PairingCancel, PairingError> {
        let tracked = self.live_comparing(session_id, now)?;
        if matches!(
            &tracked.state,
            State::Comparing(comparing) if comparing.device_group_id.is_some()
        ) {
            return Err(PairingError::WrongStep);
        }
        tracked.state = State::Ended(EndReason::MismatchedCode);
        Ok(cancel_message(session_id, &EndReason::MismatchedCode))
    }

    /// This user cancelled `session_id`. `None` when it had already ended or
    /// this device never answered it.
    pub fn cancel(&mut self, session_id: &SessionId) -> Option<PairingCancel> {
        let tracked = self.sessions.get_mut(session_id)?;
        let answered = match tracked.state {
            State::Requested => false,
            State::Answered { .. } | State::Comparing(_) => true,
            State::Linked(_) | State::Ended(_) => return None,
        };
        tracked.state = State::Ended(EndReason::UserCancelled);
        answered.then(|| cancel_message(session_id, &EndReason::UserCancelled))
    }

    /// Ends every session whose time ran out at `now`. Send the returned
    /// cancels: one for each session this device answered that ran out, here
    /// or in an earlier call. Call it on a timer while a session is live.
    pub fn expire(&mut self, now: u64) -> Vec<PairingCancel> {
        self.tick(now);
        self.owed_cancels.drain(..).collect()
    }

    fn live_comparing(
        &mut self,
        session_id: &SessionId,
        now: u64,
    ) -> Result<&mut Tracked, PairingError> {
        if self.tick(now).contains(session_id) {
            return Err(PairingError::Expired);
        }
        let tracked = self
            .sessions
            .get_mut(session_id)
            .ok_or(PairingError::UnknownSession)?;
        match tracked.state {
            State::Comparing(_) => Ok(tracked),
            _ => Err(PairingError::WrongStep),
        }
    }

    fn live_count(&self, now: u64) -> usize {
        let tracked = self
            .sessions
            .values()
            .filter(|tracked| tracked.is_live(now))
            .count();
        tracked + usize::from(now < self.untracked_live_until)
    }

    /// When the next answer is allowed, if the rate limit holds at `now`.
    fn rate_limited_until(&self, now: u64) -> Option<u64> {
        (self.answered_at.len() >= MAX_ANSWERS_PER_WINDOW).then(|| {
            self.answered_at
                .front()
                .expect("the window is full")
                .saturating_add(ANSWER_WINDOW_SECS)
                .max(now)
        })
    }

    /// Ends every session whose time ran out at `now`, dropping its secrets
    /// and owing a timeout cancel for each one this device answered. Then
    /// drops old answers, and sessions whose request a replay could no
    /// longer present as fresh. Every `&mut self` call that takes `now`
    /// starts here. Returns the sessions it ended.
    fn tick(&mut self, now: u64) -> Vec<SessionId> {
        self.forget_old_answers(now);
        let mut timed_out = Vec::new();
        for (session_id, tracked) in &mut self.sessions {
            let answered = match tracked.state {
                State::Requested => false,
                State::Answered { .. } | State::Comparing(_) => true,
                State::Linked(_) | State::Ended(_) => continue,
            };
            if now < tracked.deadline {
                continue;
            }
            tracked.state = State::Ended(EndReason::Timeout);
            if answered {
                if self.owed_cancels.len() == MAX_TRACKED_REQUESTS {
                    self.owed_cancels.pop_front();
                }
                self.owed_cancels
                    .push_back(cancel_message(session_id, &EndReason::Timeout));
            }
            timed_out.push(*session_id);
        }
        self.sessions.retain(|_, tracked| now < tracked.keep_until);
        timed_out
    }

    fn take_owed_cancel(&mut self, session_id: &SessionId) -> Option<PairingCancel> {
        let index = self
            .owed_cancels
            .iter()
            .position(|cancel| &cancel.session_id == session_id)?;
        self.owed_cancels.remove(index)
    }

    /// Drops answers older than the rate-limit window.
    fn forget_old_answers(&mut self, now: u64) {
        while self
            .answered_at
            .front()
            .is_some_and(|answered| answered.saturating_add(ANSWER_WINDOW_SECS) <= now)
        {
            self.answered_at.pop_front();
        }
    }
}

fn end_tracked(
    session_id: &SessionId,
    tracked: &mut Tracked,
    reason: EndReason,
) -> ExistingDeviceEvent {
    tracked.state = State::Ended(reason.clone());
    ExistingDeviceEvent::Ended {
        session_id: *session_id,
        cancel: reason
            .outgoing_cancel()
            .is_some()
            .then(|| cancel_message(session_id, &reason)),
        reason,
    }
}

fn link_tracked(session_id: &SessionId, tracked: &mut Tracked) -> ConfirmedLink {
    let State::Comparing(comparing) = &tracked.state else {
        unreachable!("linking starts from a comparison");
    };
    let link = ConfirmedLink {
        session_id: *session_id,
        key_package_event_id: tracked.request.key_package_event_id,
        key_package_ref: tracked.request.key_package_ref.clone(),
        device_group_id: comparing
            .device_group_id
            .clone()
            .expect("linking needs this user's confirmation"),
        existing_device_slot: comparing.binding.existing_device_slot,
    };
    tracked.state = State::Linked(link.clone());
    link
}

fn cancel_message(session_id: &SessionId, reason: &EndReason) -> PairingCancel {
    PairingCancel {
        session_id: *session_id,
        reason: reason
            .outgoing_cancel()
            .expect("only reasons that send a cancel reach here"),
    }
}
