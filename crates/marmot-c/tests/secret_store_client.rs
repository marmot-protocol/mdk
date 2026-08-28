//! A host-supplied secret store must be enough to open a client, with no
//! platform keychain involved, and must be released when the client is.

use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use marmot_c::secret_store::{MarmotSecretStore, MarmotSecretStoreStatus};
use marmot_c::{
    MarmotClient, MarmotStatus, marmot_client_free, marmot_client_new_with_secret_store,
    marmot_client_shutdown,
};

/// The host's vault, reached through `user_data`.
static ENTRIES: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
static DESTROYED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn has(_user_data: *mut c_void, key: *const c_char, out: *mut u8) -> u32 {
    let key = unsafe { CStr::from_ptr(key) }.to_str().unwrap().to_owned();
    let present = ENTRIES.lock().unwrap().iter().any(|(k, _)| *k == key);
    unsafe { out.write(u8::from(present)) };
    MarmotSecretStoreStatus::Ok as u32
}

unsafe extern "C" fn write_secret(
    _user_data: *mut c_void,
    label: *const c_char,
    _account: *const c_char,
    secret: *const c_char,
) -> u32 {
    let label = unsafe { CStr::from_ptr(label) }
        .to_str()
        .unwrap()
        .to_owned();
    let secret = unsafe { CStr::from_ptr(secret) }
        .to_str()
        .unwrap()
        .to_owned();
    ENTRIES.lock().unwrap().push((label, secret));
    MarmotSecretStoreStatus::Ok as u32
}

unsafe extern "C" fn load_secret(
    _user_data: *mut c_void,
    label: *const c_char,
    _account: *const c_char,
    out: *mut *mut c_char,
) -> u32 {
    let label = unsafe { CStr::from_ptr(label) }
        .to_str()
        .unwrap()
        .to_owned();
    let found = ENTRIES
        .lock()
        .unwrap()
        .iter()
        .find(|(k, _)| *k == label)
        .map(|(_, secret)| secret.clone());
    let Some(secret) = found else {
        return MarmotSecretStoreStatus::NotFound as u32;
    };
    unsafe { out.write(CString::new(secret).unwrap().into_raw()) };
    MarmotSecretStoreStatus::Ok as u32
}

unsafe extern "C" fn remove_secret(
    _user_data: *mut c_void,
    label: *const c_char,
    _account: *const c_char,
) -> u32 {
    let label = unsafe { CStr::from_ptr(label) }
        .to_str()
        .unwrap()
        .to_owned();
    ENTRIES.lock().unwrap().retain(|(k, _)| *k != label);
    MarmotSecretStoreStatus::Ok as u32
}

unsafe extern "C" fn free_secret(_user_data: *mut c_void, secret: *mut c_char) {
    drop(unsafe { CString::from_raw(secret) });
}

unsafe extern "C" fn destroy(_user_data: *mut c_void) {
    DESTROYED.store(true, Ordering::SeqCst);
}

#[test]
fn a_host_store_opens_a_client_without_the_platform_keychain() {
    let root = tempfile::tempdir().expect("temp dir");
    let root_path = CString::new(root.path().to_str().expect("utf-8 temp path")).unwrap();
    let relay = CString::new("wss://relay.example.org").unwrap();
    let relays = [relay.as_ptr()];

    let store = MarmotSecretStore {
        user_data: std::ptr::null_mut(),
        has_secret_for_label: Some(has),
        has_secret_for_account_id: Some(has),
        write_secret: Some(write_secret),
        load_secret: Some(load_secret),
        remove_secret: Some(remove_secret),
        free_secret: Some(free_secret),
        destroy: Some(destroy),
    };

    let mut client: *mut MarmotClient = std::ptr::null_mut();
    let status = unsafe {
        marmot_client_new_with_secret_store(
            root_path.as_ptr(),
            relays.as_ptr(),
            1,
            &raw const store,
            &raw mut client,
        )
    };
    assert_eq!(status, MarmotStatus::Ok, "host store must need no keystore");
    assert!(!client.is_null());

    unsafe { marmot_client_shutdown(client) };
    unsafe { marmot_client_free(client) };

    assert!(
        DESTROYED.load(Ordering::SeqCst),
        "destroy must fire once the client releases the store"
    );
}

/// Separate flag: the success-path `destroy` above fires in the same
/// process, so this test cannot share it.
static DESTROYED_AFTER_FAILURE: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn destroy_after_failure(_user_data: *mut c_void) {
    DESTROYED_AFTER_FAILURE.store(true, Ordering::SeqCst);
}

#[test]
fn a_failure_after_the_vtable_is_accepted_leaves_user_data_to_the_host() {
    let root = tempfile::tempdir().expect("temp dir");
    let root_path = CString::new(root.path().to_str().expect("utf-8 temp path")).unwrap();
    // Accepted vtable, then a bad relay array: the failure lands after the
    // store was taken but before any handle reached the caller.
    let relays = [std::ptr::null()];

    let store = MarmotSecretStore {
        user_data: std::ptr::null_mut(),
        has_secret_for_label: Some(has),
        has_secret_for_account_id: Some(has),
        write_secret: Some(write_secret),
        load_secret: Some(load_secret),
        remove_secret: Some(remove_secret),
        free_secret: Some(free_secret),
        destroy: Some(destroy_after_failure),
    };

    let mut client: *mut MarmotClient = std::ptr::dangling_mut();
    let status = unsafe {
        marmot_client_new_with_secret_store(
            root_path.as_ptr(),
            relays.as_ptr(),
            1,
            &raw const store,
            &raw mut client,
        )
    };

    assert_eq!(status, MarmotStatus::NullPointer);
    assert!(client.is_null());
    assert!(
        !DESTROYED_AFTER_FAILURE.load(Ordering::SeqCst),
        "a failed constructor must not destroy user_data the host still owns"
    );
}

#[test]
fn a_null_store_is_rejected_before_the_client_is_built() {
    let root = tempfile::tempdir().expect("temp dir");
    let root_path = CString::new(root.path().to_str().expect("utf-8 temp path")).unwrap();
    let mut client: *mut MarmotClient = std::ptr::dangling_mut();

    let status = unsafe {
        marmot_client_new_with_secret_store(
            root_path.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            &raw mut client,
        )
    };
    assert_eq!(status, MarmotStatus::NullPointer);
    assert!(client.is_null(), "out-pointer must be cleared at entry");
}
