//! A NULL out-pointer must be rejected *before* the wrapper does any work.
//!
//! Rejecting it afterwards makes a mutating command report failure after
//! its side effect landed (so a retry duplicates it) and makes a
//! subscription read consume an item it can no longer hand back.

use std::ffi::CString;
use std::time::Instant;

use marmot_c::commands::marmot_set_group_archived;
use marmot_c::subscriptions::{
    MarmotEventsSubscription, marmot_events_subscription_free, marmot_events_subscription_next,
    marmot_subscribe_events,
};
use marmot_c::{
    MarmotClient, MarmotStatus, marmot_client_free, marmot_client_new, marmot_client_shutdown,
};

/// Open a client rooted in a temp dir, or `None` on hosts without a
/// keystore (the same documented skip as `examples/smoke.c`).
fn client(root: &tempfile::TempDir) -> Option<*mut MarmotClient> {
    let root_path = CString::new(root.path().to_str().expect("utf-8 temp path")).unwrap();
    let relay = CString::new("wss://relay.example.org").unwrap();
    let relays = [relay.as_ptr()];
    let mut client: *mut MarmotClient = std::ptr::null_mut();

    match unsafe { marmot_client_new(root_path.as_ptr(), relays.as_ptr(), 1, &raw mut client) } {
        MarmotStatus::Ok => Some(client),
        MarmotStatus::KeystoreUnavailable => None,
        status => panic!("client_new failed: {status:?}"),
    }
}

#[test]
fn null_out_is_rejected_before_the_command_runs() {
    let root = tempfile::tempdir().expect("temp dir");
    let Some(client) = client(&root) else {
        return;
    };

    let account = CString::new("npub1nobody").unwrap();
    let group = CString::new("00ff").unwrap();

    // A mutating command: NULL out must fail as NULL_POINTER, not as the
    // runtime error it would report had the mutation been attempted.
    let status = unsafe {
        marmot_set_group_archived(
            client,
            account.as_ptr(),
            group.as_ptr(),
            1,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, MarmotStatus::NullPointer);

    unsafe { marmot_client_shutdown(client) };
    unsafe { marmot_client_free(client) };
}

#[test]
fn null_out_is_rejected_before_a_subscription_read_dequeues() {
    let root = tempfile::tempdir().expect("temp dir");
    let Some(client) = client(&root) else {
        return;
    };

    let mut sub: *mut MarmotEventsSubscription = std::ptr::null_mut();
    assert_eq!(
        unsafe { marmot_subscribe_events(client, &raw mut sub) },
        MarmotStatus::Ok
    );

    // With the check after the read, this would block for the full timeout
    // (and consume any item that arrived) before reporting NULL_POINTER.
    let started = Instant::now();
    let status = unsafe { marmot_events_subscription_next(sub, 5_000, std::ptr::null_mut()) };
    assert_eq!(status, MarmotStatus::NullPointer);
    assert!(
        started.elapsed().as_millis() < 1_000,
        "next() waited on the stream before validating its out-pointer"
    );

    unsafe { marmot_events_subscription_free(sub) };
    unsafe { marmot_client_shutdown(client) };
    unsafe { marmot_client_free(client) };
}
