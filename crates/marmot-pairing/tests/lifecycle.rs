//! The session rules: when a code appears, expiry, the rate limit, competing
//! requests, both confirmation orders and cancellation.

mod common;

use cgka_traits::GroupId;
use common::{
    Comparison, T0, confirm_both, deliver_request, device_group, existing, new_device, published,
    slot, to_comparison,
};
use marmot_pairing::{
    ANSWER_WINDOW_SECS, CancelReason, ConfirmSender, EndReason, ExistingDeviceEvent, IgnoreReason,
    MAX_ANSWERS_PER_WINDOW, MAX_TRACKED_REQUESTS, NewDeviceConfirmation, NewDeviceEvent,
    PairingCancel, PairingConfirm, PairingError, PairingMessage, REQUEST_MAX_FUTURE_SECS,
    REQUEST_TTL_SECS, SESSION_TTL_SECS, SessionId,
};

#[test]
fn pairing_new_device_shows_no_code_before_an_answer() {
    let (mut new, request) = new_device(1, T0);
    assert_eq!(new.code(T0), None);
    assert_eq!(new.existing_device_slot(), None);
    assert_eq!(
        new.confirm_match(T0),
        Err(PairingError::WrongStep),
        "nothing to confirm"
    );
    assert_eq!(
        new.receive(&PairingMessage::Request(request.clone()), T0),
        NewDeviceEvent::Ignored(IgnoreReason::OwnRole)
    );
    assert_eq!(new.code(T0), None);

    let mut existing = existing(1);
    deliver_request(&mut existing, &request, T0);
    assert_eq!(existing.code(&request.session_id, T0), None);
    assert!(!existing.can_offer_link(&request.session_id, T0));
    let answer = existing
        .answer_pinned(&request.session_id, &published(), [0x22; 32], T0)
        .expect("answer");
    assert_eq!(
        existing.code(&request.session_id, T0),
        None,
        "not before the reveal"
    );
    assert!(matches!(
        new.receive(&PairingMessage::Answer(answer), T0),
        NewDeviceEvent::Reveal(_)
    ));
    assert!(new.code(T0).is_some());
    assert_eq!(new.existing_device_slot(), Some(slot(1)));
}

#[test]
fn pairing_request_expires_ten_minutes_without_an_answer() {
    let deadline = T0 + REQUEST_TTL_SECS;

    // The new device ends the session and cancels it.
    let (mut new, request) = new_device(1, T0);
    assert_eq!(new.expire(deadline - 1), None);
    assert_eq!(
        new.expire(deadline),
        Some(PairingCancel {
            session_id: request.session_id,
            reason: CancelReason::Timeout,
        })
    );
    assert_eq!(new.end_reason(), Some(&EndReason::Timeout));
    assert_eq!(new.expire(deadline), None, "once");

    // An answer arriving at the deadline is too late.
    let (mut late, request) = new_device(1, T0);
    let mut existing_device = existing(1);
    deliver_request(&mut existing_device, &request, T0);
    let answer = existing_device
        .answer_pinned(&request.session_id, &published(), [0x22; 32], deadline - 1)
        .expect("still live one second before");
    assert!(matches!(
        late.receive(&PairingMessage::Answer(answer), deadline),
        NewDeviceEvent::Ended {
            reason: EndReason::Timeout,
            cancel: Some(_),
        }
    ));
    assert_eq!(late.code(deadline), None);

    // The existing device stops offering the request, quietly: it never
    // answered, so it sends no cancel.
    let mut existing_device = existing(1);
    deliver_request(&mut existing_device, &request, T0);
    assert_eq!(existing_device.live_requests(deadline - 1).len(), 1);
    assert!(existing_device.live_requests(deadline).is_empty());
    assert_eq!(
        existing_device.answer(&request.session_id, &published(), deadline),
        Err(PairingError::Expired)
    );
    assert_eq!(
        existing_device.end_reason(&request.session_id),
        None,
        "a replay is stale by now too, so the request is forgotten"
    );
    assert!(existing_device.expire(deadline).is_empty());
}

#[test]
fn pairing_session_expires_ten_minutes_after_the_answer() {
    let answered = T0 + 300;
    let deadline = answered + SESSION_TTL_SECS;
    let run = || {
        let (mut new, request) = new_device(1, T0);
        let mut existing_device = existing(1);
        deliver_request(&mut existing_device, &request, T0);
        let answer = existing_device
            .answer_pinned(&request.session_id, &published(), [0x22; 32], answered)
            .expect("answer");
        let NewDeviceEvent::Reveal(reveal) = new.receive(&PairingMessage::Answer(answer), answered)
        else {
            panic!("expected a reveal");
        };
        existing_device.receive(&PairingMessage::Reveal(reveal), answered, answered);
        (new, existing_device, request.session_id)
    };

    // The answer restarts the clock: past the request's own ten minutes, the
    // comparison is still open.
    let (mut new, mut existing_device, session_id) = run();
    assert!(T0 + REQUEST_TTL_SECS < deadline - 1);
    assert!(new.confirm_match(deadline - 1).is_ok());
    assert!(
        existing_device
            .confirm_link(&session_id, device_group(), deadline - 1)
            .is_ok()
    );

    // The code goes at the deadline, whether or not anything noticed.
    let (new, existing_device, session_id) = run();
    assert!(new.code(deadline - 1).is_some());
    assert_eq!(new.code(deadline), None);
    assert!(existing_device.code(&session_id, deadline - 1).is_some());
    assert_eq!(existing_device.code(&session_id, deadline), None);

    let (mut new, mut existing_device, session_id) = run();
    assert_eq!(new.confirm_match(deadline), Err(PairingError::Expired));
    assert_eq!(new.code(deadline), None);
    assert_eq!(
        existing_device.confirm_link(&session_id, device_group(), deadline),
        Err(PairingError::Expired)
    );
    assert_eq!(existing_device.code(&session_id, deadline), None);
    assert_eq!(
        existing_device.expire(deadline),
        vec![PairingCancel {
            session_id,
            reason: CancelReason::Timeout,
        }],
        "the refused tap still leaves the cancel to send"
    );

    // An answered session that expires sends a cancel, however late this
    // device notices.
    let (_, mut existing_device, session_id) = run();
    assert_eq!(
        existing_device.expire(deadline + REQUEST_TTL_SECS),
        vec![PairingCancel {
            session_id,
            reason: CancelReason::Timeout,
        }]
    );
    let (mut new, mut existing_device, session_id) = run();
    let existing_confirm = existing_device
        .confirm_link(&session_id, device_group(), answered)
        .expect("tap");
    new.receive(&PairingMessage::Confirm(existing_confirm), answered);
    let Ok(NewDeviceConfirmation::Linked { confirm, .. }) = new.confirm_match(answered) else {
        panic!("the new device confirms after the existing device");
    };
    assert_eq!(
        existing_device.receive(&PairingMessage::Confirm(confirm), deadline, deadline),
        ExistingDeviceEvent::Ended {
            session_id,
            reason: EndReason::Timeout,
            cancel: Some(PairingCancel {
                session_id,
                reason: CancelReason::Timeout,
            }),
        }
    );
}

#[test]
fn pairing_later_traffic_ends_quiet_sessions() {
    // Every answered session goes quiet: no reveal comes, and nothing calls
    // `expire`. The next request arrives as the last session runs out, so
    // without the sweep the dead sessions would fill every slot.
    let mut existing_device = existing(1);
    let sessions = MAX_TRACKED_REQUESTS as u8 + 1;
    for session in 0..sessions {
        let now = T0 + u64::from(session) * SESSION_TTL_SECS;
        let (_, request) = new_device(session, now);
        deliver_request(&mut existing_device, &request, now);
        existing_device
            .answer_pinned(&request.session_id, &published(), [0x22; 32], now)
            .expect("the last session ran out, so this request is alone");
    }
    let end = T0 + u64::from(sessions) * SESSION_TTL_SECS;
    assert_eq!(
        existing_device.expire(end).len(),
        MAX_TRACKED_REQUESTS,
        "the newest cancels are still owed"
    );
    assert!(existing_device.expire(end).is_empty(), "once");
}

/// A `&mut` call that takes `now`, made as a comparison runs out, and any
/// cancel it returned.
type ExistingDeviceCall = fn(&mut Comparison, u64) -> Option<PairingCancel>;
type NewDeviceCall = fn(&mut Comparison, u64) -> Option<PairingCancel>;

fn existing_cancel(event: ExistingDeviceEvent) -> Option<PairingCancel> {
    match event {
        ExistingDeviceEvent::Ended { cancel, .. } => cancel,
        _ => None,
    }
}

fn new_cancel(event: NewDeviceEvent) -> Option<PairingCancel> {
    match event {
        NewDeviceEvent::Ended { cancel, .. } => cancel,
        _ => None,
    }
}

#[test]
fn pairing_every_timed_call_ends_a_session_that_ran_out() {
    let existing_device_calls: [(&str, ExistingDeviceCall); 7] = [
        ("receive for another session", |pair, now| {
            let (_, other) = new_device(9, now);
            existing_cancel(
                pair.existing
                    .receive(&PairingMessage::Request(other), now, now),
            )
        }),
        ("receive for this session", |pair, now| {
            let reveal = PairingMessage::Reveal(pair.reveal.clone());
            existing_cancel(pair.existing.receive(&reveal, now, now))
        }),
        ("answer", |pair, now| {
            let other = SessionId::new([9; 32]);
            let _ = pair.existing.answer(&other, &published(), now);
            None
        }),
        ("confirm_link with an invalid group id", |pair, now| {
            let session_id = pair.session_id();
            let _ = pair
                .existing
                .confirm_link(&session_id, GroupId::new(Vec::new()), now);
            None
        }),
        ("confirm_link", |pair, now| {
            let session_id = pair.session_id();
            let _ = pair.existing.confirm_link(&session_id, device_group(), now);
            None
        }),
        ("reject_link", |pair, now| {
            let session_id = pair.session_id();
            let _ = pair.existing.reject_link(&session_id, now);
            None
        }),
        ("expire", |pair, now| pair.existing.expire(now).pop()),
    ];
    let new_device_calls: [(&str, NewDeviceCall); 5] = [
        ("receive for another session", |pair, now| {
            let (_, other) = new_device(9, now);
            new_cancel(pair.new.receive(&PairingMessage::Request(other), now))
        }),
        ("receive for this session", |pair, now| {
            let answer = PairingMessage::Answer(pair.answer.clone());
            new_cancel(pair.new.receive(&answer, now))
        }),
        ("confirm_match", |pair, now| {
            let _ = pair.new.confirm_match(now);
            None
        }),
        ("reject_match", |pair, now| {
            let _ = pair.new.reject_match(now);
            None
        }),
        ("expire", |pair, now| pair.new.expire(now)),
    ];
    let ran_out = T0 + SESSION_TTL_SECS;

    for (name, call) in existing_device_calls {
        let mut pair = to_comparison(T0);
        let timeout = PairingCancel {
            session_id: pair.session_id(),
            reason: CancelReason::Timeout,
        };
        let first = call(&mut pair, ran_out);
        assert_eq!(
            pair.existing.sessions_holding_secrets(),
            0,
            "existing device, {name}"
        );
        let cancels: Vec<_> = first
            .into_iter()
            .chain(pair.existing.expire(ran_out))
            .collect();
        assert_eq!(
            cancels,
            vec![timeout],
            "existing device, {name}: one cancel"
        );
    }
    for (name, call) in new_device_calls {
        let mut pair = to_comparison(T0);
        let timeout = PairingCancel {
            session_id: pair.session_id(),
            reason: CancelReason::Timeout,
        };
        let first = call(&mut pair, ran_out);
        assert!(!pair.new.holds_secrets(), "new device, {name}");
        let cancels: Vec<_> = first.into_iter().chain(pair.new.expire(ran_out)).collect();
        assert_eq!(cancels, vec![timeout], "new device, {name}: one cancel");
    }
}

#[test]
fn pairing_request_dated_outside_the_window_is_ignored() {
    let now = T0 + 3_600;
    for (session, created_at, tracked) in [
        (1, now - REQUEST_TTL_SECS, false),
        (2, now - REQUEST_TTL_SECS + 1, true),
        (3, now + REQUEST_MAX_FUTURE_SECS, true),
        (4, now + REQUEST_MAX_FUTURE_SECS + 1, false),
    ] {
        let (_, request) = new_device(session, created_at);
        let mut existing_device = existing(1);
        let event = existing_device.receive(&PairingMessage::Request(request), created_at, now);
        if tracked {
            assert!(
                matches!(event, ExistingDeviceEvent::Requested { .. }),
                "{created_at}"
            );
        } else {
            assert_eq!(
                event,
                ExistingDeviceEvent::Ignored(IgnoreReason::Stale),
                "{created_at}"
            );
        }
    }

    // A request from the future expires ten minutes after this device's now,
    // not after its own date.
    let (_, request) = new_device(5, now + REQUEST_MAX_FUTURE_SECS);
    let mut existing_device = existing(1);
    existing_device.receive(
        &PairingMessage::Request(request),
        now + REQUEST_MAX_FUTURE_SECS,
        now,
    );
    assert_eq!(
        existing_device
            .live_requests(now + REQUEST_TTL_SECS - 1)
            .len(),
        1
    );
    assert!(
        existing_device
            .live_requests(now + REQUEST_TTL_SECS)
            .is_empty()
    );
}

#[test]
fn pairing_answers_at_most_ten_sessions_an_hour() {
    let mut existing_device = existing(1);
    let mut session = 0_u8;
    let mut request_at = |existing_device: &mut marmot_pairing::ExistingDevicePairing, now| {
        session += 1;
        let (_, request) = new_device(session, now);
        deliver_request(existing_device, &request, now);
        request.session_id
    };

    // Requests that go unanswered don't count.
    for _ in 0..MAX_ANSWERS_PER_WINDOW + 2 {
        let session_id = request_at(&mut existing_device, T0);
        assert_eq!(existing_device.cancel(&session_id), None);
    }

    for index in 0..MAX_ANSWERS_PER_WINDOW as u64 {
        let now = T0 + index * 60;
        let session_id = request_at(&mut existing_device, now);
        existing_device
            .answer(&session_id, &published(), now)
            .expect("within the limit");
        assert!(existing_device.cancel(&session_id).is_some());
    }

    let session_id = request_at(&mut existing_device, T0 + 700);
    assert_eq!(
        existing_device.answer(&session_id, &published(), T0 + 700),
        Err(PairingError::RateLimited {
            retry_at: T0 + ANSWER_WINDOW_SECS,
        })
    );
    existing_device.cancel(&session_id);

    let late = T0 + ANSWER_WINDOW_SECS - 1;
    let session_id = request_at(&mut existing_device, late);
    assert_eq!(
        existing_device.answer(&session_id, &published(), late),
        Err(PairingError::RateLimited {
            retry_at: T0 + ANSWER_WINDOW_SECS,
        })
    );
    assert!(
        existing_device
            .answer(&session_id, &published(), T0 + ANSWER_WINDOW_SECS)
            .is_ok(),
        "the oldest answer left the window"
    );

    // Another device of the account keeps its own limit.
    let mut other_device = existing(2);
    let (_, request) = new_device(200, T0 + 700);
    deliver_request(&mut other_device, &request, T0 + 700);
    assert!(
        other_device
            .answer(&request.session_id, &published(), T0 + 700)
            .is_ok()
    );
}

#[test]
fn pairing_competing_requests_offer_no_link() {
    let (_, first) = new_device(1, T0);
    let (mut second_device, second) = new_device(2, T0);
    let mut existing_device = existing(1);
    deliver_request(&mut existing_device, &first, T0);
    assert_eq!(
        existing_device.receive(&PairingMessage::Request(second.clone()), T0, T0),
        ExistingDeviceEvent::Requested {
            session_id: second.session_id,
            competing: true,
        }
    );
    assert!(existing_device.competing_requests(T0));
    for request in [&first, &second] {
        assert_eq!(
            existing_device.answer(&request.session_id, &published(), T0),
            Err(PairingError::CompetingRequests)
        );
    }

    // One side gives up, and the other can go ahead.
    let cancel = second_device.cancel().expect("cancel");
    existing_device.receive(&PairingMessage::Cancel(cancel), T0, T0);
    assert!(!existing_device.competing_requests(T0));
    assert!(
        existing_device
            .answer(&first.session_id, &published(), T0)
            .is_ok()
    );
}

#[test]
fn pairing_competing_request_during_a_comparison_blocks_the_link() {
    let mut pair = to_comparison(T0);
    let session_id = pair.session_id();
    assert!(pair.existing.can_offer_link(&session_id, T0));

    let (mut intruder, competing) = new_device(2, T0);
    assert_eq!(
        pair.existing
            .receive(&PairingMessage::Request(competing), T0, T0),
        ExistingDeviceEvent::Requested {
            session_id: *intruder.session_id(),
            competing: true,
        }
    );
    assert!(!pair.existing.can_offer_link(&session_id, T0));
    assert_eq!(
        pair.existing.confirm_link(&session_id, device_group(), T0),
        Err(PairingError::CompetingRequests)
    );
    assert!(
        pair.existing.code(&session_id, T0).is_some(),
        "still comparing"
    );

    let cancel = intruder.cancel().expect("cancel");
    pair.existing
        .receive(&PairingMessage::Cancel(cancel), T0, T0);
    assert!(pair.existing.can_offer_link(&session_id, T0));
    assert!(
        pair.existing
            .confirm_link(&session_id, device_group(), T0)
            .is_ok()
    );
}

#[test]
fn pairing_confirmations_go_in_a_fixed_order() {
    // The new device's user taps first: its confirmation waits for the
    // existing device's.
    let mut pair = to_comparison(T0);
    let session_id = pair.session_id();
    assert_eq!(
        pair.new.confirm_match(T0),
        Ok(NewDeviceConfirmation::Waiting)
    );
    assert_eq!(pair.new.code(T0), None, "the code is gone once decided");
    assert_eq!(pair.new.linked(), None, "nothing sent yet");
    let existing_confirm = pair
        .existing
        .confirm_link(&session_id, device_group(), T0)
        .expect("tap");
    assert_eq!(pair.existing.linked(&session_id), None);
    assert!(!pair.existing.can_offer_link(&session_id, T0), "decided");
    assert_eq!(
        pair.existing.code(&session_id, T0),
        None,
        "the code is gone once decided"
    );
    let NewDeviceEvent::Linked {
        confirm,
        link: new_link,
    } = pair
        .new
        .receive(&PairingMessage::Confirm(existing_confirm), T0)
    else {
        panic!("the new device links and sends its confirmation");
    };
    let ExistingDeviceEvent::Linked(existing_link) =
        pair.existing
            .receive(&PairingMessage::Confirm(confirm), T0, T0)
    else {
        panic!("existing device links");
    };
    assert_eq!(new_link, existing_link);
    assert_eq!(pair.existing.linked(&session_id), Some(&existing_link));
    assert_eq!(pair.new.linked(), Some(&new_link));

    // The existing device's user taps first.
    let mut pair = to_comparison(T0);
    let (_, confirm) = confirm_both(&mut pair, T0);
    assert!(pair.new.accepts_welcome_for(&device_group()));
    assert!(matches!(
        pair.existing
            .receive(&PairingMessage::Confirm(confirm.clone()), T0, T0),
        ExistingDeviceEvent::Linked(_)
    ));

    // A new device's confirmation that arrives before this device's user
    // confirmed is ignored, and counts once this device has confirmed. An
    // identical session supplies one, since an honest new device never
    // sends it early.
    let mut pair = to_comparison(T0);
    let session_id = pair.session_id();
    assert_eq!(
        pair.existing
            .receive(&PairingMessage::Confirm(confirm.clone()), T0, T0),
        ExistingDeviceEvent::Ignored(IgnoreReason::WrongStep)
    );
    assert_eq!(pair.existing.linked(&session_id), None);
    assert!(
        pair.existing.can_offer_link(&session_id, T0),
        "still undecided"
    );
    pair.existing
        .confirm_link(&session_id, device_group(), T0)
        .expect("tap");
    assert!(matches!(
        pair.existing
            .receive(&PairingMessage::Confirm(confirm), T0, T0),
        ExistingDeviceEvent::Linked(_)
    ));
}

#[test]
fn pairing_a_confirmed_link_never_times_out() {
    let mut pair = to_comparison(T0);
    let session_id = pair.session_id();
    let later = T0 + SESSION_TTL_SECS + REQUEST_TTL_SECS;
    let (_, confirm) = confirm_both(&mut pair, T0);
    let ExistingDeviceEvent::Linked(link) =
        pair.existing
            .receive(&PairingMessage::Confirm(confirm.clone()), T0, T0)
    else {
        panic!("existing device links");
    };

    // Neither side owes a timeout cancel for a confirmed link.
    assert_eq!(pair.new.expire(later), None);
    assert_eq!(pair.existing.expire(later), vec![]);
    assert_eq!(pair.new.linked(), Some(&link));
    assert!(pair.new.accepts_welcome_for(&device_group()));

    // The existing device forgets the session once it would have expired;
    // the host acts on the link `Linked` carried.
    assert_eq!(pair.existing.linked(&session_id), None);
    assert_eq!(pair.existing.end_reason(&session_id), None);
    assert_eq!(
        pair.existing
            .receive(&PairingMessage::Confirm(confirm), later, later),
        ExistingDeviceEvent::Ignored(IgnoreReason::OtherSession)
    );
}

#[test]
fn pairing_lost_existing_device_confirmation_adds_nothing() {
    let mut pair = to_comparison(T0);
    let session_id = pair.session_id();
    let deadline = T0 + SESSION_TTL_SECS;
    assert_eq!(
        pair.new.confirm_match(T0),
        Ok(NewDeviceConfirmation::Waiting)
    );
    // The existing device's confirmation never arrives.
    pair.existing
        .confirm_link(&session_id, device_group(), T0)
        .expect("tap");

    let timeout = PairingCancel {
        session_id,
        reason: CancelReason::Timeout,
    };
    assert_eq!(pair.new.expire(deadline), Some(timeout.clone()));
    assert_eq!(pair.new.linked(), None, "the new device never confirmed");
    assert_eq!(pair.existing.expire(deadline), vec![timeout]);
    assert_eq!(pair.existing.linked(&session_id), None, "nothing to add");
}

#[test]
fn pairing_lost_new_device_confirmation_adds_nothing_and_drops_the_link() {
    let mut pair = to_comparison(T0);
    let session_id = pair.session_id();
    let deadline = T0 + SESSION_TTL_SECS;
    // The new device links and confirms, but its confirmation never
    // arrives.
    let _lost = confirm_both(&mut pair, T0);
    assert!(pair.new.accepts_welcome_for(&device_group()));

    let cancels = pair.existing.expire(deadline);
    assert_eq!(
        cancels,
        vec![PairingCancel {
            session_id,
            reason: CancelReason::Timeout,
        }]
    );
    assert_eq!(pair.existing.linked(&session_id), None, "nothing to add");

    let [cancel] = <[PairingCancel; 1]>::try_from(cancels).expect("one cancel");
    assert_eq!(
        pair.new.receive(&PairingMessage::Cancel(cancel), deadline),
        NewDeviceEvent::Ended {
            reason: EndReason::Cancelled(CancelReason::Timeout),
            cancel: None,
        }
    );
    assert_eq!(pair.new.linked(), None);
    assert!(
        !pair.new.accepts_welcome_for(&device_group()),
        "no Welcome is coming"
    );
}

#[test]
fn pairing_each_side_ignores_its_own_messages() {
    let mut pair = to_comparison(T0);
    let session_id = pair.session_id();
    assert_eq!(
        pair.new
            .receive(&PairingMessage::Reveal(pair.reveal.clone()), T0),
        NewDeviceEvent::Ignored(IgnoreReason::OwnRole)
    );
    assert_eq!(
        pair.existing
            .receive(&PairingMessage::Answer(pair.answer.clone()), T0, T0),
        ExistingDeviceEvent::Ignored(IgnoreReason::OwnRole)
    );
    // An identical session supplies a new device's confirmation while this
    // one is still comparing.
    let mut twin = to_comparison(T0);
    let (_, new_confirm) = confirm_both(&mut twin, T0);
    assert_eq!(
        pair.new.receive(&PairingMessage::Confirm(new_confirm), T0),
        NewDeviceEvent::Ignored(IgnoreReason::OwnRole)
    );
    let existing_confirm = pair
        .existing
        .confirm_link(&session_id, device_group(), T0)
        .expect("tap");
    assert_eq!(
        pair.existing
            .receive(&PairingMessage::Confirm(existing_confirm), T0, T0),
        ExistingDeviceEvent::Ignored(IgnoreReason::OwnRole)
    );

    // Messages for another session change nothing.
    let other = PairingConfirm {
        session_id: marmot_pairing::SessionId::new([9; 32]),
        sender: ConfirmSender::NewDevice,
        mac: [0; 32],
    };
    assert_eq!(
        pair.new
            .receive(&PairingMessage::Confirm(other.clone()), T0),
        NewDeviceEvent::Ignored(IgnoreReason::OtherSession)
    );
    assert_eq!(
        pair.existing
            .receive(&PairingMessage::Confirm(other), T0, T0),
        ExistingDeviceEvent::Ignored(IgnoreReason::OtherSession)
    );
}

#[test]
fn pairing_cancel_ends_the_session_on_both_sides() {
    // The existing device's user cancels mid-comparison.
    let mut pair = to_comparison(T0);
    let session_id = pair.session_id();
    let cancel = pair
        .existing
        .cancel(&session_id)
        .expect("answered, so it tells");
    assert_eq!(cancel.reason, CancelReason::User);
    assert_eq!(pair.existing.code(&session_id, T0), None);
    assert_eq!(
        pair.new.receive(&PairingMessage::Cancel(cancel), T0),
        NewDeviceEvent::Ended {
            reason: EndReason::Cancelled(CancelReason::User),
            cancel: None,
        }
    );
    assert_eq!(pair.new.code(T0), None);
    assert_eq!(pair.new.confirm_match(T0), Err(PairingError::WrongStep));

    // The existing device's user says the codes differ.
    let mut pair = to_comparison(T0);
    let session_id = pair.session_id();
    let cancel = pair
        .existing
        .reject_link(&session_id, T0)
        .expect("mismatch");
    assert_eq!(cancel.reason, CancelReason::MismatchedCode);
    assert_eq!(
        pair.new.receive(&PairingMessage::Cancel(cancel), T0),
        NewDeviceEvent::Ended {
            reason: EndReason::Cancelled(CancelReason::MismatchedCode),
            cancel: None,
        }
    );

    // The new device gives up before any answer.
    let (mut new, request) = new_device(1, T0);
    let mut existing_device = existing(1);
    deliver_request(&mut existing_device, &request, T0);
    let cancel = new.cancel().expect("cancel");
    assert_eq!(new.cancel(), None, "once");
    assert_eq!(
        existing_device.receive(&PairingMessage::Cancel(cancel), T0, T0),
        ExistingDeviceEvent::Ended {
            session_id: request.session_id,
            reason: EndReason::Cancelled(CancelReason::User),
            cancel: None,
        }
    );
    assert!(existing_device.live_requests(T0).is_empty());

    // Dismissing a request this device never answered tells no one.
    let (_, request) = new_device(2, T0);
    deliver_request(&mut existing_device, &request, T0);
    assert_eq!(existing_device.cancel(&request.session_id), None);
    assert_eq!(
        existing_device.end_reason(&request.session_id),
        Some(&EndReason::UserCancelled)
    );
}

#[test]
fn pairing_tracks_a_bounded_number_of_requests() {
    let mut existing_device = existing(1);
    for session in 0..MAX_TRACKED_REQUESTS as u8 {
        let (_, request) = new_device(session, T0);
        deliver_request(&mut existing_device, &request, T0);
    }
    let (_, request) = new_device(MAX_TRACKED_REQUESTS as u8, T0);
    assert_eq!(
        existing_device.receive(&PairingMessage::Request(request), T0, T0),
        ExistingDeviceEvent::Ignored(IgnoreReason::Capacity)
    );
}

#[test]
fn pairing_a_request_beyond_capacity_still_blocks_the_link() {
    let mut existing_device = existing(1);
    for session in 10..10 + MAX_TRACKED_REQUESTS as u8 - 1 {
        let (_, request) = new_device(session, T0);
        deliver_request(&mut existing_device, &request, T0);
        assert_eq!(existing_device.cancel(&request.session_id), None);
    }
    let now = T0 + 100;
    let (mut new, request) = new_device(1, now);
    let session_id = request.session_id;
    deliver_request(&mut existing_device, &request, now);
    let answer = existing_device
        .answer_pinned(&session_id, &published(), [0x22; 32], now)
        .expect("the only live request");
    let NewDeviceEvent::Reveal(reveal) = new.receive(&PairingMessage::Answer(answer), now) else {
        panic!("expected a reveal");
    };
    existing_device.receive(&PairingMessage::Reveal(reveal), now, now);
    assert!(existing_device.can_offer_link(&session_id, now));

    // Sent at T0 + 50 and so live until T0 + 650, but the ended sessions
    // fill every slot.
    let (_, untracked) = new_device(2, T0 + 50);
    assert_eq!(
        existing_device.receive(&PairingMessage::Request(untracked), T0 + 50, now),
        ExistingDeviceEvent::Ignored(IgnoreReason::Capacity)
    );
    assert!(existing_device.competing_requests(now));
    assert!(!existing_device.can_offer_link(&session_id, now));
    assert_eq!(
        existing_device.confirm_link(&session_id, device_group(), now),
        Err(PairingError::CompetingRequests)
    );

    let expired = T0 + 50 + REQUEST_TTL_SECS;
    assert!(!existing_device.competing_requests(expired));
    assert!(existing_device.can_offer_link(&session_id, expired));
    assert!(
        existing_device
            .confirm_link(&session_id, device_group(), expired)
            .is_ok()
    );
}

#[test]
fn pairing_finished_sessions_are_forgotten_once_a_replay_is_stale() {
    let (mut new, request) = new_device(1, T0);
    let mut existing_device = existing(1);
    deliver_request(&mut existing_device, &request, T0);
    let cancel = new.cancel().expect("cancel");
    existing_device.receive(&PairingMessage::Cancel(cancel), T0, T0);

    let replay = PairingMessage::Request(request.clone());
    let last_fresh = T0 + REQUEST_TTL_SECS - 1;
    assert_eq!(
        existing_device.receive(&replay, T0, last_fresh),
        ExistingDeviceEvent::Ignored(IgnoreReason::Duplicate)
    );
    assert_eq!(
        existing_device.receive(&replay, T0, T0 + REQUEST_TTL_SECS),
        ExistingDeviceEvent::Ignored(IgnoreReason::Stale)
    );
    assert_eq!(
        existing_device.end_reason(&request.session_id),
        None,
        "forgotten"
    );
}
