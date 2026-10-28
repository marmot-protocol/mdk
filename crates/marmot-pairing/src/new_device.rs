//! The new device's side: one session, from its request to a verified link.

use cgka_traits::GroupId;
use rand::RngCore;
use rand::rngs::OsRng;

use crate::code::SasCode;
use crate::message::{
    ConfirmSender, PairingAnswer, PairingCancel, PairingConfirm, PairingMessage, PairingRequest,
    PairingReveal,
};
use crate::sas::{
    EphemeralKey, MacItem, MacSender, RequestBinding, SessionBinding, SharedSecret, commitment,
};
use crate::session::{
    ConfirmedLink, EndReason, IgnoreReason, PairingError, REQUEST_TTL_SECS, SESSION_TTL_SECS,
};
use crate::types::{AccountKey, KeyPackageEventId, KeyPackageRef, SessionId, SlotId};

/// The new device's pairing session.
///
/// It sends a request, takes the first valid answer, reveals its key to that
/// answer and only then has a code to show. Its user decides once whether the
/// codes match. Its own confirmation goes out only once the existing device's
/// has verified, whichever came first, so the existing device never adds a
/// device that does not yet know which group to trust. The session ends linked
/// when it sends that confirmation; the link names the one device group whose
/// Welcome it accepts, and a cancel arriving before that Welcome withdraws it.
pub struct NewDevicePairing {
    request: RequestBinding,
    state: State,
    /// The timeout cancel, from when the session ran out until
    /// [`Self::expire`] hands it out.
    owed_cancel: Option<PairingCancel>,
}

enum State {
    AwaitingAnswer { key: EphemeralKey, deadline: u64 },
    Comparing(Box<Comparing>),
    Linked(ConfirmedLink),
    Ended(EndReason),
}

struct Comparing {
    binding: SessionBinding,
    shared: SharedSecret,
    code: SasCode,
    deadline: u64,
    user_confirmed: bool,
    device_group_id: Option<GroupId>,
}

/// What a message did to the session.
#[derive(Debug, PartialEq, Eq)]
pub enum NewDeviceEvent {
    Ignored(IgnoreReason),
    /// The first answer arrived. Send the reveal; the code is now available.
    Reveal(PairingReveal),
    /// The existing device confirmed. The link waits for this user.
    PeerConfirmed,
    /// The existing device confirmed after this user did. Send `confirm`;
    /// the link is confirmed.
    Linked {
        confirm: PairingConfirm,
        link: ConfirmedLink,
    },
    /// The session ended. Send `cancel` when present.
    Ended {
        reason: EndReason,
        cancel: Option<PairingCancel>,
    },
}

/// What this user's confirmation did.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq)]
pub enum NewDeviceConfirmation {
    /// The existing device's confirmation has not verified yet. This
    /// device's waits for it and goes out with [`NewDeviceEvent::Linked`].
    Waiting,
    /// The existing device had confirmed. Send `confirm`; the link is
    /// confirmed.
    Linked {
        confirm: PairingConfirm,
        link: ConfirmedLink,
    },
}

impl NewDevicePairing {
    /// Starts a session for the device's published KeyPackage at `now`, in
    /// Unix seconds. Send the request to the account.
    pub fn start(
        account: AccountKey,
        key_package_event_id: KeyPackageEventId,
        key_package_ref: KeyPackageRef,
        now: u64,
    ) -> (Self, PairingRequest) {
        let mut session_id = [0_u8; 32];
        OsRng.fill_bytes(&mut session_id);
        Self::start_with_key(
            SessionId::new(session_id),
            EphemeralKey::generate(),
            account,
            key_package_event_id,
            key_package_ref,
            now,
        )
    }

    /// [`Self::start`] with a pinned session id and ephemeral secret, for
    /// known-answer tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn start_pinned(
        session_id: SessionId,
        secret: [u8; 32],
        account: AccountKey,
        key_package_event_id: KeyPackageEventId,
        key_package_ref: KeyPackageRef,
        now: u64,
    ) -> (Self, PairingRequest) {
        Self::start_with_key(
            session_id,
            EphemeralKey::from_secret_bytes(secret),
            account,
            key_package_event_id,
            key_package_ref,
            now,
        )
    }

    fn start_with_key(
        session_id: SessionId,
        key: EphemeralKey,
        account: AccountKey,
        key_package_event_id: KeyPackageEventId,
        key_package_ref: KeyPackageRef,
        now: u64,
    ) -> (Self, PairingRequest) {
        let request = RequestBinding {
            session_id,
            account,
            key_package_event_id,
            key_package_ref,
        };
        let message = PairingRequest {
            session_id,
            key_package_event_id,
            key_package_ref: request.key_package_ref.clone(),
            commitment: commitment(&key.public(), &request),
        };
        let pairing = Self {
            request,
            state: State::AwaitingAnswer {
                key,
                deadline: now.saturating_add(REQUEST_TTL_SECS),
            },
            owed_cancel: None,
        };
        (pairing, message)
    }

    pub fn session_id(&self) -> &SessionId {
        &self.request.session_id
    }

    /// The code to show at `now`. `None` until an answer arrived, once this
    /// user decided, and once the session ended or its time ran out.
    pub fn code(&self, now: u64) -> Option<&SasCode> {
        match &self.state {
            State::Comparing(comparing)
                if !comparing.user_confirmed && now < comparing.deadline =>
            {
                Some(&comparing.code)
            }
            _ => None,
        }
    }

    /// The existing device's slot this session compares with, once it took
    /// an answer.
    pub fn existing_device_slot(&self) -> Option<SlotId> {
        match &self.state {
            State::Comparing(comparing) => Some(comparing.binding.existing_device_slot),
            State::Linked(link) => Some(link.existing_device_slot),
            _ => None,
        }
    }

    /// The verified link, once both sides confirmed. It never expires; a
    /// cancel withdraws it, and the host bounds the wait for the Welcome.
    pub fn linked(&self) -> Option<&ConfirmedLink> {
        match &self.state {
            State::Linked(link) => Some(link),
            _ => None,
        }
    }

    /// Whether to accept a Welcome into `group_id`: only into the device
    /// group a verified confirmation named.
    pub fn accepts_welcome_for(&self, group_id: &GroupId) -> bool {
        self.linked()
            .is_some_and(|link| link.allows_welcome_for(group_id))
    }

    /// Whether the session still holds a key or a shared secret, for tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn holds_secrets(&self) -> bool {
        matches!(
            self.state,
            State::AwaitingAnswer { .. } | State::Comparing(_)
        )
    }

    pub fn end_reason(&self) -> Option<&EndReason> {
        match &self.state {
            State::Ended(reason) => Some(reason),
            _ => None,
        }
    }

    /// Applies a message sent to the account at `now`.
    pub fn receive(&mut self, message: &PairingMessage, now: u64) -> NewDeviceEvent {
        let timed_out = self.tick(now);
        if message.session_id() != self.session_id() {
            return NewDeviceEvent::Ignored(IgnoreReason::OtherSession);
        }
        if timed_out {
            return NewDeviceEvent::Ended {
                reason: EndReason::Timeout,
                cancel: self.owed_cancel.take(),
            };
        }
        match &self.state {
            State::Ended(_) => return NewDeviceEvent::Ignored(IgnoreReason::Ended),
            // A cancel withdraws the link: the existing device ran out
            // without this device's confirmation, so no Welcome is coming.
            State::Linked(_) if !matches!(message, PairingMessage::Cancel(_)) => {
                return NewDeviceEvent::Ignored(IgnoreReason::WrongStep);
            }
            State::AwaitingAnswer { .. } | State::Comparing(_) | State::Linked(_) => {}
        }
        match message {
            PairingMessage::Request(_) | PairingMessage::Reveal(_) => {
                NewDeviceEvent::Ignored(IgnoreReason::OwnRole)
            }
            PairingMessage::Answer(answer) => self.on_answer(answer, now),
            PairingMessage::Confirm(confirm) => self.on_confirm(confirm),
            PairingMessage::Cancel(cancel) => {
                let reason = EndReason::Cancelled(cancel.reason.clone());
                self.state = State::Ended(reason.clone());
                NewDeviceEvent::Ended {
                    reason,
                    cancel: None,
                }
            }
        }
    }

    fn on_answer(&mut self, answer: &PairingAnswer, now: u64) -> NewDeviceEvent {
        if !matches!(self.state, State::AwaitingAnswer { .. }) {
            return NewDeviceEvent::Ignored(IgnoreReason::WrongStep);
        }
        let State::AwaitingAnswer { key, .. } =
            std::mem::replace(&mut self.state, State::Ended(EndReason::InvalidKey))
        else {
            unreachable!("checked above");
        };
        let own_key = key.public();
        let Some(shared) = key.agree(&answer.key) else {
            return self.end(EndReason::InvalidKey);
        };
        let binding = SessionBinding::new(&self.request, answer.slot);
        let code = shared.code(&binding, &own_key, &answer.key);
        self.state = State::Comparing(Box::new(Comparing {
            binding,
            shared,
            code,
            deadline: now.saturating_add(SESSION_TTL_SECS),
            user_confirmed: false,
            device_group_id: None,
        }));
        NewDeviceEvent::Reveal(PairingReveal {
            session_id: self.request.session_id,
            answer_slot: answer.slot,
            key: own_key,
        })
    }

    fn on_confirm(&mut self, confirm: &PairingConfirm) -> NewDeviceEvent {
        let ConfirmSender::ExistingDevice { device_group_id } = &confirm.sender else {
            return NewDeviceEvent::Ignored(IgnoreReason::OwnRole);
        };
        let State::Comparing(comparing) = &mut self.state else {
            return NewDeviceEvent::Ignored(IgnoreReason::WrongStep);
        };
        if comparing.device_group_id.is_some() {
            return NewDeviceEvent::Ignored(IgnoreReason::WrongStep);
        }
        if !comparing.shared.verify_mac(
            &comparing.binding,
            MacSender::ExistingDevice,
            MacItem::DeviceGroupId,
            device_group_id.as_slice(),
            &confirm.mac,
        ) {
            return self.end(EndReason::MismatchedConfirm);
        }
        comparing.device_group_id = Some(device_group_id.clone());
        if comparing.user_confirmed {
            let (confirm, link) = self.confirm_and_link();
            NewDeviceEvent::Linked { confirm, link }
        } else {
            NewDeviceEvent::PeerConfirmed
        }
    }

    /// This user confirmed that the codes match. One decision per session.
    /// The confirmation goes out now only if the existing device's has
    /// verified; otherwise it waits for it.
    pub fn confirm_match(&mut self, now: u64) -> Result<NewDeviceConfirmation, PairingError> {
        self.live_comparing(now)?;
        let State::Comparing(comparing) = &mut self.state else {
            return Err(PairingError::WrongStep);
        };
        if comparing.user_confirmed {
            return Err(PairingError::WrongStep);
        }
        comparing.user_confirmed = true;
        if comparing.device_group_id.is_none() {
            return Ok(NewDeviceConfirmation::Waiting);
        }
        let (confirm, link) = self.confirm_and_link();
        Ok(NewDeviceConfirmation::Linked { confirm, link })
    }

    /// This user said the codes differ. Ends the session.
    pub fn reject_match(&mut self, now: u64) -> Result<PairingCancel, PairingError> {
        self.live_comparing(now)?;
        if let State::Comparing(comparing) = &self.state
            && comparing.user_confirmed
        {
            return Err(PairingError::WrongStep);
        }
        self.state = State::Ended(EndReason::MismatchedCode);
        Ok(self.cancel_message(&EndReason::MismatchedCode))
    }

    /// This user cancelled. `None` when the session had already ended.
    pub fn cancel(&mut self) -> Option<PairingCancel> {
        match self.state {
            State::AwaitingAnswer { .. } | State::Comparing(_) => {
                let reason = EndReason::UserCancelled;
                self.state = State::Ended(reason.clone());
                Some(self.cancel_message(&reason))
            }
            State::Linked(_) | State::Ended(_) => None,
        }
    }

    /// Ends the session if its time ran out at `now`. Send the returned
    /// cancel: the timeout cancel, once, whichever call noticed the timeout.
    /// Call it on a timer while the session is live.
    pub fn expire(&mut self, now: u64) -> Option<PairingCancel> {
        self.tick(now);
        self.owed_cancel.take()
    }

    /// Ends the session if its time ran out at `now`, dropping its secrets
    /// and owing the timeout cancel. Every `&mut self` call that takes `now`
    /// starts here. Returns whether this call ended it.
    fn tick(&mut self, now: u64) -> bool {
        let deadline = match &self.state {
            State::AwaitingAnswer { deadline, .. } => *deadline,
            State::Comparing(comparing) => comparing.deadline,
            State::Linked(_) | State::Ended(_) => return false,
        };
        if now < deadline {
            return false;
        }
        self.state = State::Ended(EndReason::Timeout);
        self.owed_cancel = Some(self.cancel_message(&EndReason::Timeout));
        true
    }

    fn live_comparing(&mut self, now: u64) -> Result<(), PairingError> {
        if self.tick(now) {
            return Err(PairingError::Expired);
        }
        match &self.state {
            State::Comparing(_) => Ok(()),
            _ => Err(PairingError::WrongStep),
        }
    }

    /// This device's confirmation, and the link it confirms. Only once both
    /// users confirmed and the existing device's confirmation verified.
    fn confirm_and_link(&mut self) -> (PairingConfirm, ConfirmedLink) {
        let State::Comparing(comparing) = &self.state else {
            unreachable!("linking starts from a comparison");
        };
        let confirm = PairingConfirm {
            session_id: self.request.session_id,
            sender: ConfirmSender::NewDevice,
            mac: comparing.shared.mac(
                &comparing.binding,
                MacSender::NewDevice,
                MacItem::KeyPackageRef,
                self.request.key_package_ref.as_slice(),
            ),
        };
        let link = ConfirmedLink {
            session_id: self.request.session_id,
            key_package_event_id: self.request.key_package_event_id,
            key_package_ref: self.request.key_package_ref.clone(),
            device_group_id: comparing
                .device_group_id
                .clone()
                .expect("linking needs the existing device's confirmation"),
            existing_device_slot: comparing.binding.existing_device_slot,
        };
        self.state = State::Linked(link.clone());
        (confirm, link)
    }

    fn end(&mut self, reason: EndReason) -> NewDeviceEvent {
        self.state = State::Ended(reason.clone());
        NewDeviceEvent::Ended {
            cancel: reason
                .outgoing_cancel()
                .is_some()
                .then(|| self.cancel_message(&reason)),
            reason,
        }
    }

    fn cancel_message(&self, reason: &EndReason) -> PairingCancel {
        PairingCancel {
            session_id: self.request.session_id,
            reason: reason
                .outgoing_cancel()
                .expect("only reasons that send a cancel reach here"),
        }
    }
}
