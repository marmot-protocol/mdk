//! Fixtures shared by the pairing tests: one account, one new device, and
//! existing devices by slot number.

#![allow(dead_code)]

use cgka_traits::GroupId;
use marmot_pairing::{
    AccountKey, ExistingDeviceEvent, ExistingDevicePairing, KeyPackageEventId, KeyPackageRef,
    NewDeviceConfirmation, NewDeviceEvent, NewDevicePairing, PairingAnswer, PairingConfirm,
    PairingMessage, PairingRequest, PairingReveal, PublishedKeyPackage, SessionId, SlotId,
};

/// A fixed start time, in Unix seconds.
pub const T0: u64 = 1_800_000_000;

pub fn account() -> AccountKey {
    AccountKey::new([0xa1; 32])
}

pub fn key_package_event_id() -> KeyPackageEventId {
    KeyPackageEventId::new([0xe1; 32])
}

pub fn key_package_ref() -> KeyPackageRef {
    KeyPackageRef::new([0x4b; 32]).expect("32 bytes is a valid ref")
}

pub fn published() -> PublishedKeyPackage {
    PublishedKeyPackage {
        event_id: key_package_event_id(),
        key_package_ref: key_package_ref(),
    }
}

pub fn slot(number: u8) -> SlotId {
    SlotId::new([number; 32])
}

pub fn device_group() -> GroupId {
    GroupId::new(vec![0xd6; 16])
}

pub fn existing(number: u8) -> ExistingDevicePairing {
    ExistingDevicePairing::new(account(), slot(number))
}

/// A new device's session, pinned so two runs differ only where a test
/// changes the inputs.
pub fn new_device(session: u8, now: u64) -> (NewDevicePairing, PairingRequest) {
    NewDevicePairing::start_pinned(
        SessionId::new([session; 32]),
        [0x11 ^ session; 32],
        account(),
        key_package_event_id(),
        key_package_ref(),
        now,
    )
}

/// Both sides up to the codes: request, answer and reveal delivered at `now`.
pub struct Comparison {
    pub new: NewDevicePairing,
    pub existing: ExistingDevicePairing,
    pub request: PairingRequest,
    pub answer: PairingAnswer,
    pub reveal: PairingReveal,
}

impl Comparison {
    pub fn session_id(&self) -> SessionId {
        self.request.session_id
    }
}

pub fn to_comparison(now: u64) -> Comparison {
    let (mut new, request) = new_device(1, now);
    let mut existing = existing(1);
    deliver_request(&mut existing, &request, now);
    let answer = existing
        .answer_pinned(&request.session_id, &published(), [0x22; 32], now)
        .expect("a lone live request can be answered");
    let reveal = match new.receive(&PairingMessage::Answer(answer.clone()), now) {
        NewDeviceEvent::Reveal(reveal) => reveal,
        other => panic!("expected a reveal, got {other:?}"),
    };
    assert_eq!(
        existing.receive(&PairingMessage::Reveal(reveal.clone()), now, now),
        ExistingDeviceEvent::CodeReady {
            session_id: request.session_id
        }
    );
    Comparison {
        new,
        existing,
        request,
        answer,
        reveal,
    }
}

/// Both users tap Match, the existing device's first, and the existing
/// device's confirmation reaches the new device. Returns both confirmations;
/// the new device's has not reached the existing device yet.
pub fn confirm_both(pair: &mut Comparison, now: u64) -> (PairingConfirm, PairingConfirm) {
    let session_id = pair.session_id();
    let existing_confirm = pair
        .existing
        .confirm_link(&session_id, device_group(), now)
        .expect("the existing device confirms");
    assert_eq!(
        pair.new
            .receive(&PairingMessage::Confirm(existing_confirm.clone()), now),
        NewDeviceEvent::PeerConfirmed
    );
    let NewDeviceConfirmation::Linked { confirm, .. } = pair
        .new
        .confirm_match(now)
        .expect("the new device confirms")
    else {
        panic!("the existing device's confirmation verified, so the new device's goes out");
    };
    (existing_confirm, confirm)
}

pub fn deliver_request(existing: &mut ExistingDevicePairing, request: &PairingRequest, now: u64) {
    match existing.receive(&PairingMessage::Request(request.clone()), now, now) {
        ExistingDeviceEvent::Requested { .. } => {}
        other => panic!("expected the request to be tracked, got {other:?}"),
    }
}
