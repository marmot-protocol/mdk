//! Each attack in the pairing security argument, shown failing.
//!
//! The attacker holds the account key: it reads every pairing message, and
//! can drop, replay, alter or inject any of them, and run its own sessions
//! from its own installation. Only a user tapping Link on a code they did not
//! compare lets it through.

mod common;

use cgka_traits::GroupId;
use common::{
    T0, account, confirm_both, deliver_request, device_group, existing, key_package_event_id,
    key_package_ref, new_device, published, slot, to_comparison,
};
use marmot_pairing::{
    CancelReason, ConfirmSender, EndReason, ExistingDeviceEvent, ExistingDevicePairing,
    IgnoreReason, KeyPackageRef, NewDeviceConfirmation, NewDeviceEvent, NewDevicePairing,
    PairingConfirm, PairingError, PairingMessage, PairingReveal, PublishedKeyPackage, SessionId,
    commitment,
};

/// An attacker swaps the existing device's key for its own on the way to the
/// new device. The two screens then show different codes, and even if both
/// users confirm anyway, neither confirmation verifies.
#[test]
fn pairing_attack_substituted_answer_key_shows_different_codes() {
    let (mut new, request) = new_device(1, T0);
    let mut real = existing(1);
    deliver_request(&mut real, &request, T0);
    let real_answer = real
        .answer_pinned(&request.session_id, &published(), [0x22; 32], T0)
        .expect("answer");

    // The attacker's own installation answers the same request under the
    // real device's slot, and its answer is the one the new device sees.
    let mut attacker = existing(1);
    deliver_request(&mut attacker, &request, T0);
    let forged_answer = attacker
        .answer_pinned(&request.session_id, &published(), [0x66; 32], T0)
        .expect("attacker answer");
    assert_ne!(forged_answer.key, real_answer.key);
    let NewDeviceEvent::Reveal(reveal) = new.receive(&PairingMessage::Answer(forged_answer), T0)
    else {
        panic!("expected a reveal");
    };
    assert_eq!(
        real.receive(&PairingMessage::Reveal(reveal), T0, T0),
        ExistingDeviceEvent::CodeReady {
            session_id: request.session_id
        }
    );
    let new_code = new.code(T0).expect("new device code").clone();
    let real_code = real
        .code(&request.session_id, T0)
        .expect("real code")
        .clone();
    assert_ne!(new_code, real_code, "the screens differ");

    // Careless taps on both screens still link nothing: the real device's
    // confirmation fails at the new device, so the new device's never goes
    // out.
    assert_eq!(new.confirm_match(T0), Ok(NewDeviceConfirmation::Waiting));
    let real_confirm = real
        .confirm_link(&request.session_id, device_group(), T0)
        .expect("tap");
    assert!(matches!(
        new.receive(&PairingMessage::Confirm(real_confirm), T0),
        NewDeviceEvent::Ended {
            reason: EndReason::MismatchedConfirm,
            cancel: Some(_),
        }
    ));
    assert_eq!(real.linked(&request.session_id), None);
    assert!(!new.accepts_welcome_for(&device_group()));
}

/// An attacker swaps the new device's key in the reveal. The commitment the
/// request carried catches it before any code is shown.
#[test]
fn pairing_attack_substituted_reveal_key_fails_the_commitment() {
    let (mut new, request) = new_device(1, T0);
    let mut existing = existing(1);
    deliver_request(&mut existing, &request, T0);
    let answer = existing
        .answer_pinned(&request.session_id, &published(), [0x22; 32], T0)
        .expect("answer");
    let NewDeviceEvent::Reveal(real_reveal) = new.receive(&PairingMessage::Answer(answer), T0)
    else {
        panic!("expected a reveal");
    };
    let (_, attacker_request) = NewDevicePairing::start_pinned(
        request.session_id,
        [0x77; 32],
        account(),
        key_package_event_id(),
        key_package_ref(),
        T0,
    );
    assert_ne!(attacker_request.commitment, request.commitment);
    let attacker_key = attacker_key_for(&request.session_id);
    assert_ne!(attacker_key, real_reveal.key);
    let forged = PairingReveal {
        key: attacker_key,
        ..real_reveal
    };
    assert_eq!(
        existing.receive(&PairingMessage::Reveal(forged), T0, T0),
        ExistingDeviceEvent::Ended {
            session_id: request.session_id,
            reason: EndReason::MismatchedCommitment,
            cancel: Some(marmot_pairing::PairingCancel {
                session_id: request.session_id,
                reason: CancelReason::MismatchedCommitment,
            }),
        }
    );
    assert_eq!(existing.code(&request.session_id, T0), None);
}

/// The public key a pinned attacker installation would reveal.
fn attacker_key_for(session_id: &SessionId) -> marmot_pairing::ExchangeKey {
    let (mut attacker, _) = NewDevicePairing::start_pinned(
        *session_id,
        [0x77; 32],
        account(),
        key_package_event_id(),
        key_package_ref(),
        T0,
    );
    let mut answerer = existing(9);
    let request = attacker_request(session_id);
    deliver_request(&mut answerer, &request, T0);
    let answer = answerer
        .answer_pinned(session_id, &published(), [0x23; 32], T0)
        .expect("answer");
    match attacker.receive(&PairingMessage::Answer(answer), T0) {
        NewDeviceEvent::Reveal(reveal) => reveal.key,
        other => panic!("expected a reveal, got {other:?}"),
    }
}

fn attacker_request(session_id: &SessionId) -> marmot_pairing::PairingRequest {
    NewDevicePairing::start_pinned(
        *session_id,
        [0x77; 32],
        account(),
        key_package_event_id(),
        key_package_ref(),
        T0,
    )
    .1
}

/// A request whose KeyPackage doesn't match the one the existing device
/// fetched is never answered.
#[test]
fn pairing_attack_published_key_package_mismatch_is_not_answered() {
    let (_, request) = new_device(1, T0);
    let mut existing = existing(1);
    deliver_request(&mut existing, &request, T0);
    let other_ref = KeyPackageRef::new([0x5c; 32]).expect("ref");
    for wrong in [
        PublishedKeyPackage {
            event_id: key_package_event_id(),
            key_package_ref: other_ref,
        },
        PublishedKeyPackage {
            event_id: marmot_pairing::KeyPackageEventId::new([0xe2; 32]),
            key_package_ref: key_package_ref(),
        },
    ] {
        assert_eq!(
            existing.answer(&request.session_id, &wrong, T0),
            Err(PairingError::KeyPackageMismatch)
        );
    }
}

/// An attacker rewrites the request to name its own KeyPackage but cannot
/// rewrite the commitment to the new device's key: the reveal then fails.
#[test]
fn pairing_attack_swapped_key_package_ref_fails_the_commitment() {
    let (mut new, mut request) = new_device(1, T0);
    let attacker_ref = KeyPackageRef::new([0x5c; 32]).expect("ref");
    request.key_package_ref = attacker_ref.clone();
    let mut existing = existing(1);
    deliver_request(&mut existing, &request, T0);
    let answer = existing
        .answer_pinned(
            &request.session_id,
            &PublishedKeyPackage {
                event_id: key_package_event_id(),
                key_package_ref: attacker_ref,
            },
            [0x22; 32],
            T0,
        )
        .expect("the forged request names a KeyPackage the attacker published");
    let NewDeviceEvent::Reveal(reveal) = new.receive(&PairingMessage::Answer(answer), T0) else {
        panic!("expected a reveal");
    };
    assert!(matches!(
        existing.receive(&PairingMessage::Reveal(reveal), T0, T0),
        ExistingDeviceEvent::Ended {
            reason: EndReason::MismatchedCommitment,
            ..
        }
    ));
}

/// The new device's confirmation covers its exact `KeyPackageRef`: with the
/// key and commitment forged to match a swapped ref, the codes differ, and a
/// careless tap still fails the confirmation.
#[test]
fn pairing_attack_swapped_key_package_ref_changes_the_code() {
    let (mut new, request) = new_device(1, T0);
    let attacker_ref = KeyPackageRef::new([0x5c; 32]).expect("ref");
    // The attacker sends its own request under the same session id, for its
    // own KeyPackage, and drops the real one.
    let (mut attacker, forged_request) = NewDevicePairing::start_pinned(
        request.session_id,
        [0x77; 32],
        account(),
        key_package_event_id(),
        attacker_ref.clone(),
        T0,
    );
    let mut existing = existing(1);
    deliver_request(&mut existing, &forged_request, T0);
    let answer = existing
        .answer_pinned(
            &request.session_id,
            &PublishedKeyPackage {
                event_id: key_package_event_id(),
                key_package_ref: attacker_ref.clone(),
            },
            [0x22; 32],
            T0,
        )
        .expect("answer");
    // Both the attacker and the real new device see the answer.
    let NewDeviceEvent::Reveal(attacker_reveal) =
        attacker.receive(&PairingMessage::Answer(answer.clone()), T0)
    else {
        panic!("attacker reveal");
    };
    assert!(matches!(
        new.receive(&PairingMessage::Answer(answer), T0),
        NewDeviceEvent::Reveal(_)
    ));
    existing.receive(&PairingMessage::Reveal(attacker_reveal), T0, T0);
    let existing_code = existing
        .code(&request.session_id, T0)
        .expect("code")
        .clone();
    assert_ne!(new.code(T0), Some(&existing_code), "the screens differ");

    // Careless taps: the existing device's confirmation does not verify at
    // the real new device, which then never confirms, so nothing links the
    // real device's KeyPackage.
    assert_eq!(new.confirm_match(T0), Ok(NewDeviceConfirmation::Waiting));
    let confirm = existing
        .confirm_link(&request.session_id, device_group(), T0)
        .expect("tap");
    assert!(matches!(
        new.receive(&PairingMessage::Confirm(confirm), T0),
        NewDeviceEvent::Ended {
            reason: EndReason::MismatchedConfirm,
            ..
        }
    ));
    assert_eq!(existing.linked(&request.session_id), None);
}

/// The existing device's confirmation covers the device group. An attacker
/// that swaps the group id fails the check, so the new device accepts no
/// Welcome for the attacker's group.
#[test]
fn pairing_attack_wrong_group_id_fails_the_confirmation() {
    let mut pair = to_comparison(T0);
    let session_id = pair.session_id();
    pair.new.confirm_match(T0).expect("tap");
    let mut confirm = pair
        .existing
        .confirm_link(&session_id, device_group(), T0)
        .expect("tap");
    let attacker_group = GroupId::new(vec![0x0a; 16]);
    confirm.sender = ConfirmSender::ExistingDevice {
        device_group_id: attacker_group.clone(),
    };
    assert!(matches!(
        pair.new.receive(&PairingMessage::Confirm(confirm), T0),
        NewDeviceEvent::Ended {
            reason: EndReason::MismatchedConfirm,
            ..
        }
    ));
    assert!(!pair.new.accepts_welcome_for(&attacker_group));
    assert!(!pair.new.accepts_welcome_for(&device_group()));
}

/// After a link, the new device accepts a Welcome only for the confirmed
/// group: a group that merely calls itself a device group is refused.
#[test]
fn pairing_linked_new_device_accepts_only_the_confirmed_group() {
    let mut pair = to_comparison(T0);
    let session_id = pair.session_id();
    assert!(!pair.new.accepts_welcome_for(&device_group()), "not before");
    let (_, new_confirm) = confirm_both(&mut pair, T0);
    assert!(matches!(
        pair.existing
            .receive(&PairingMessage::Confirm(new_confirm), T0, T0),
        ExistingDeviceEvent::Linked(_)
    ));
    assert!(pair.existing.linked(&session_id).is_some());
    assert!(pair.new.accepts_welcome_for(&device_group()));
    assert!(!pair.new.accepts_welcome_for(&GroupId::new(vec![0x0a; 16])));
}

/// An attacker that answers first, as itself, gets the new device to show
/// a code, but the user's real device shows none: it sees the reveal name
/// another answer and drops the session.
#[test]
fn pairing_attack_posing_as_existing_device_leaves_the_real_device_blank() {
    let (mut new, request) = new_device(1, T0);
    let mut real = existing(1);
    let mut attacker = existing(7);
    deliver_request(&mut real, &request, T0);
    deliver_request(&mut attacker, &request, T0);
    let forged_answer = attacker
        .answer_pinned(&request.session_id, &published(), [0x66; 32], T0)
        .expect("attacker answer");
    let real_answer = real
        .answer_pinned(&request.session_id, &published(), [0x22; 32], T0)
        .expect("real answer");
    let NewDeviceEvent::Reveal(reveal) = new.receive(&PairingMessage::Answer(forged_answer), T0)
    else {
        panic!("expected a reveal");
    };
    assert_eq!(
        new.receive(&PairingMessage::Answer(real_answer), T0),
        NewDeviceEvent::Ignored(IgnoreReason::WrongStep),
        "one answer per session"
    );
    assert_eq!(
        real.receive(&PairingMessage::Reveal(reveal), T0, T0),
        ExistingDeviceEvent::Ended {
            session_id: request.session_id,
            reason: EndReason::AnsweredElsewhere,
            cancel: None,
        }
    );
    assert!(new.code(T0).is_some());
    assert_eq!(real.code(&request.session_id, T0), None);
}

/// A confirmation from an earlier session, replayed into a new session for
/// the same KeyPackage, does not verify: codes and keys are new every time.
#[test]
fn pairing_attack_replayed_confirmation_from_another_session_fails() {
    let mut first = to_comparison(T0);
    let (_, old_confirm) = confirm_both(&mut first, T0);

    let (mut new, request) = new_device(2, T0);
    let mut existing = existing(1);
    deliver_request(&mut existing, &request, T0);
    let answer = existing
        .answer_pinned(&request.session_id, &published(), [0x24; 32], T0)
        .expect("answer");
    let NewDeviceEvent::Reveal(reveal) = new.receive(&PairingMessage::Answer(answer), T0) else {
        panic!("expected a reveal");
    };
    existing.receive(&PairingMessage::Reveal(reveal), T0, T0);
    assert_ne!(
        existing.code(&request.session_id, T0),
        first.existing.code(&first.session_id(), T0),
        "a new session has a new code"
    );
    existing
        .confirm_link(&request.session_id, device_group(), T0)
        .expect("tap");
    let replayed = PairingConfirm {
        session_id: request.session_id,
        ..old_confirm
    };
    assert!(matches!(
        existing.receive(&PairingMessage::Confirm(replayed), T0, T0),
        ExistingDeviceEvent::Ended {
            reason: EndReason::MismatchedConfirm,
            ..
        }
    ));
}

/// Replays inside a session change nothing: a second request with the same
/// id, a second reveal, a second confirmation.
#[test]
fn pairing_attack_replayed_messages_are_ignored() {
    let mut pair = to_comparison(T0);
    let session_id = pair.session_id();
    assert_eq!(
        pair.existing
            .receive(&PairingMessage::Request(pair.request.clone()), T0, T0),
        ExistingDeviceEvent::Ignored(IgnoreReason::Duplicate)
    );
    assert_eq!(
        pair.existing
            .receive(&PairingMessage::Reveal(pair.reveal.clone()), T0, T0),
        ExistingDeviceEvent::Ignored(IgnoreReason::WrongStep)
    );
    assert_eq!(
        pair.new
            .receive(&PairingMessage::Answer(pair.answer.clone()), T0),
        NewDeviceEvent::Ignored(IgnoreReason::WrongStep)
    );
    let (_, confirm) = confirm_both(&mut pair, T0);
    assert!(matches!(
        pair.existing
            .receive(&PairingMessage::Confirm(confirm.clone()), T0, T0),
        ExistingDeviceEvent::Linked(_)
    ));
    assert!(pair.existing.linked(&session_id).is_some());
    assert_eq!(
        pair.existing
            .receive(&PairingMessage::Confirm(confirm), T0, T0),
        ExistingDeviceEvent::Ignored(IgnoreReason::WrongStep)
    );
}

/// A code is compared once. After the user said the codes differ, no later
/// tap or message revives the session.
#[test]
fn pairing_attack_reused_code_after_mismatch_is_refused() {
    let mut pair = to_comparison(T0);
    let session_id = pair.session_id();
    let cancel = pair.new.reject_match(T0).expect("mismatch");
    assert_eq!(cancel.reason, CancelReason::MismatchedCode);
    assert_eq!(pair.new.confirm_match(T0), Err(PairingError::WrongStep));
    assert_eq!(pair.new.code(T0), None);
    assert_eq!(
        pair.existing
            .receive(&PairingMessage::Cancel(cancel), T0, T0),
        ExistingDeviceEvent::Ended {
            session_id,
            reason: EndReason::Cancelled(CancelReason::MismatchedCode),
            cancel: None,
        }
    );
    assert_eq!(
        pair.existing.confirm_link(&session_id, device_group(), T0),
        Err(PairingError::WrongStep)
    );

    // A replayed request for the ended session is not a new session.
    assert_eq!(
        pair.existing
            .receive(&PairingMessage::Request(pair.request.clone()), T0, T0),
        ExistingDeviceEvent::Ignored(IgnoreReason::Duplicate)
    );
}

/// A low-order point as a key ends the session instead of producing a code.
#[test]
fn pairing_attack_low_order_answer_key_is_rejected() {
    let (mut new, request) = new_device(1, T0);
    let forged = marmot_pairing::PairingAnswer {
        session_id: request.session_id,
        slot: slot(1),
        key: marmot_pairing::ExchangeKey::new([0; 32]),
    };
    assert!(matches!(
        new.receive(&PairingMessage::Answer(forged), T0),
        NewDeviceEvent::Ended {
            reason: EndReason::InvalidKey,
            ..
        }
    ));
    assert_eq!(new.code(T0), None);
}

/// A reveal with a low-order key that also matches its commitment is still
/// refused by the existing device.
#[test]
fn pairing_attack_low_order_reveal_key_is_rejected() {
    let session_id = SessionId::new([3; 32]);
    let low_order = marmot_pairing::ExchangeKey::new([0; 32]);
    let request = marmot_pairing::PairingRequest {
        session_id,
        key_package_event_id: key_package_event_id(),
        key_package_ref: key_package_ref(),
        commitment: [0; 32],
    };
    let request = marmot_pairing::PairingRequest {
        commitment: commitment(&low_order, &request.binding(account())),
        ..request
    };
    let mut existing: ExistingDevicePairing = existing(1);
    deliver_request(&mut existing, &request, T0);
    existing
        .answer_pinned(&session_id, &published(), [0x22; 32], T0)
        .expect("answer");
    assert!(matches!(
        existing.receive(
            &PairingMessage::Reveal(PairingReveal {
                session_id,
                answer_slot: slot(1),
                key: low_order,
            }),
            T0,
            T0
        ),
        ExistingDeviceEvent::Ended {
            reason: EndReason::InvalidKey,
            ..
        }
    ));
}
