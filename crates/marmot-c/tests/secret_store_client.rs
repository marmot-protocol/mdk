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
            marmot_c::deployment::OwnedDeployment::white_noise().as_ptr(),
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
            marmot_c::deployment::OwnedDeployment::white_noise().as_ptr(),
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
            marmot_c::deployment::OwnedDeployment::white_noise().as_ptr(),
            &raw mut client,
        )
    };
    assert_eq!(status, MarmotStatus::NullPointer);
    assert!(client.is_null(), "out-pointer must be cleared at entry");
}

#[test]
fn client_name_constructor_validates_arguments_without_taking_store_ownership() {
    let mut client: *mut MarmotClient = std::ptr::dangling_mut();
    let name = CString::new("whitenoise").unwrap();
    let status = unsafe {
        marmot_c::marmot_client_new_with_client_name(
            std::ptr::null(),
            std::ptr::null(),
            0,
            name.as_ptr(),
            u32::MAX,
            std::ptr::null(),
            marmot_c::deployment::OwnedDeployment::white_noise().as_ptr(),
            &raw mut client,
        )
    };
    assert_eq!(status, MarmotStatus::InvalidArgument);
    assert!(client.is_null());

    unsafe extern "C" fn count_destroy(data: *mut c_void) {
        unsafe { &*(data as *const std::sync::atomic::AtomicUsize) }.fetch_add(1, Ordering::SeqCst);
    }
    let destroyed = std::sync::atomic::AtomicUsize::new(0);
    let store = MarmotSecretStore {
        user_data: (&destroyed as *const std::sync::atomic::AtomicUsize)
            .cast_mut()
            .cast(),
        has_secret_for_label: Some(has),
        has_secret_for_account_id: Some(has),
        write_secret: Some(write_secret),
        load_secret: Some(load_secret),
        remove_secret: Some(remove_secret),
        free_secret: Some(free_secret),
        destroy: Some(count_destroy),
    };
    client = std::ptr::dangling_mut();
    let status = unsafe {
        marmot_c::marmot_client_new_with_client_name(
            std::ptr::null(),
            std::ptr::null(),
            0,
            name.as_ptr(),
            marmot_c::types::notification::MarmotCursorPersistence::Advance as u32,
            &store,
            marmot_c::deployment::OwnedDeployment::white_noise().as_ptr(),
            &raw mut client,
        )
    };
    assert_eq!(
        status,
        MarmotStatus::NullPointer,
        "valid cursor reaches the later required root guard"
    );
    assert!(client.is_null());
    assert_eq!(
        destroyed.load(Ordering::SeqCst),
        0,
        "accepted vtable remains host-owned after failure"
    );
}

#[test]
fn combined_options_validate_before_transferring_store_ownership() {
    unsafe extern "C" fn mark_destroyed(data: *mut c_void) {
        unsafe { &*(data as *const AtomicBool) }.store(true, Ordering::SeqCst);
    }
    let destroyed = AtomicBool::new(false);
    let store = MarmotSecretStore {
        user_data: (&destroyed as *const AtomicBool).cast_mut().cast(),
        has_secret_for_label: Some(has),
        has_secret_for_account_id: Some(has),
        write_secret: Some(write_secret),
        load_secret: Some(load_secret),
        remove_secret: Some(remove_secret),
        free_secret: Some(free_secret),
        destroy: Some(mark_destroyed),
    };
    let name = CString::new("whitenoise").unwrap();
    let root = tempfile::tempdir().unwrap();
    let path = CString::new(root.path().to_str().unwrap()).unwrap();
    let relay = CString::new("ws://127.0.0.1:1").unwrap();
    let relays = [relay.as_ptr()];
    let mut options = marmot_c::MarmotClientOptions {
        attachment_acquisition_mode: 0,
        relay_policy: 2,
        cursor_persistence: 1,
        client_name: name.as_ptr(),
        store: &store,
        device_platform: std::ptr::null(),
    };
    for (relay_policy, cursor_persistence) in [(u32::MAX, 1), (2, u32::MAX)] {
        options.relay_policy = relay_policy;
        options.cursor_persistence = cursor_persistence;
        let mut client = std::ptr::dangling_mut();
        let status = unsafe {
            marmot_c::marmot_client_new_with_configuration(
                path.as_ptr(),
                relays.as_ptr(),
                1,
                &options,
                marmot_c::deployment::OwnedDeployment::white_noise().as_ptr(),
                &raw mut client,
            )
        };
        assert_eq!(status, MarmotStatus::InvalidArgument);
        assert!(client.is_null());
        assert!(!destroyed.load(Ordering::SeqCst));
    }
    options.relay_policy = 2;
    options.cursor_persistence = 1;
    let mut client = std::ptr::dangling_mut();
    let status = unsafe {
        marmot_c::marmot_client_new_with_configuration(
            std::ptr::null(),
            relays.as_ptr(),
            1,
            &options,
            marmot_c::deployment::OwnedDeployment::white_noise().as_ptr(),
            &raw mut client,
        )
    };
    assert_eq!(status, MarmotStatus::NullPointer);
    assert!(client.is_null());
    assert!(
        !destroyed.load(Ordering::SeqCst),
        "failed construction leaves the store with its owner"
    );
    let mut client = std::ptr::null_mut();
    let status = unsafe {
        marmot_c::marmot_client_new_with_configuration(
            path.as_ptr(),
            relays.as_ptr(),
            1,
            &options,
            marmot_c::deployment::OwnedDeployment::white_noise().as_ptr(),
            &raw mut client,
        )
    };
    assert_eq!(status, MarmotStatus::Ok);
    assert!(!destroyed.load(Ordering::SeqCst));
    unsafe { marmot_client_free(client) };
    assert!(destroyed.load(Ordering::SeqCst));
}

#[test]
fn a_deployment_constructor_opens_with_a_host_store() {
    unsafe extern "C" fn mark_destroyed(data: *mut c_void) {
        unsafe { &*(data as *const AtomicBool) }.store(true, Ordering::SeqCst);
    }
    let destroyed = AtomicBool::new(false);
    let store = MarmotSecretStore {
        user_data: (&destroyed as *const AtomicBool).cast_mut().cast(),
        has_secret_for_label: Some(has),
        has_secret_for_account_id: Some(has),
        write_secret: Some(write_secret),
        load_secret: Some(load_secret),
        remove_secret: Some(remove_secret),
        free_secret: Some(free_secret),
        destroy: Some(mark_destroyed),
    };
    let root = tempfile::tempdir().unwrap();
    let path = CString::new(root.path().to_str().unwrap()).unwrap();
    let relay = CString::new("ws://127.0.0.1:1").unwrap();
    let relays = [relay.as_ptr()];
    let options = marmot_c::MarmotClientOptions {
        attachment_acquisition_mode: 0,
        relay_policy: 2,
        cursor_persistence: 0,
        client_name: std::ptr::null(),
        store: &store,
        device_platform: std::ptr::null(),
    };
    let mut deployment = std::ptr::null_mut();
    assert_eq!(
        unsafe { marmot_c::deployment::marmot_deployment_neutral(&raw mut deployment) },
        MarmotStatus::Ok
    );
    let mut client = std::ptr::null_mut();
    let status = unsafe {
        marmot_c::marmot_client_new_with_configuration(
            path.as_ptr(),
            relays.as_ptr(),
            1,
            &options,
            deployment,
            &raw mut client,
        )
    };
    // The client copied the deployment, so the host may free it at once.
    unsafe { marmot_c::deployment::marmot_deployment_free(deployment) };
    assert_eq!(status, MarmotStatus::Ok);
    unsafe { marmot_client_free(client) };
    assert!(destroyed.load(Ordering::SeqCst));
}

#[test]
fn a_null_deployment_is_rejected_before_the_store_is_taken() {
    unsafe extern "C" fn mark_destroyed(data: *mut c_void) {
        unsafe { &*(data as *const AtomicBool) }.store(true, Ordering::SeqCst);
    }
    let destroyed = AtomicBool::new(false);
    let store = MarmotSecretStore {
        user_data: (&destroyed as *const AtomicBool).cast_mut().cast(),
        has_secret_for_label: Some(has),
        has_secret_for_account_id: Some(has),
        write_secret: Some(write_secret),
        load_secret: Some(load_secret),
        remove_secret: Some(remove_secret),
        free_secret: Some(free_secret),
        destroy: Some(mark_destroyed),
    };
    let root = tempfile::tempdir().unwrap();
    let path = CString::new(root.path().to_str().unwrap()).unwrap();
    let relay = CString::new("ws://127.0.0.1:1").unwrap();
    let relays = [relay.as_ptr()];
    let mut client = std::ptr::dangling_mut();
    let status = unsafe {
        marmot_client_new_with_secret_store(
            path.as_ptr(),
            relays.as_ptr(),
            1,
            &store,
            std::ptr::null(),
            &raw mut client,
        )
    };
    assert_eq!(status, MarmotStatus::NullPointer);
    assert!(client.is_null());
    assert!(
        !destroyed.load(Ordering::SeqCst),
        "a refused construction leaves the store with its owner"
    );
    assert!(
        std::fs::read_dir(root.path()).unwrap().next().is_none(),
        "nothing opens without a deployment"
    );
}

/// These callbacks use each host's own vault rather than process-global state.
/// They also prove the experimental constructor preserves callback ownership.
mod experimental_host {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Vault {
        entries: Mutex<BTreeMap<String, String>>,
        destroyed: AtomicBool,
    }

    unsafe fn vault<'a>(data: *mut c_void) -> &'a Vault {
        unsafe { &*data.cast::<Vault>() }
    }

    unsafe extern "C" fn has(data: *mut c_void, key: *const c_char, out: *mut u8) -> u32 {
        let key = unsafe { CStr::from_ptr(key) }.to_str().unwrap();
        unsafe {
            out.write(u8::from(
                vault(data).entries.lock().unwrap().contains_key(key),
            ))
        };
        MarmotSecretStoreStatus::Ok as u32
    }

    unsafe extern "C" fn write(
        data: *mut c_void,
        _label: *const c_char,
        account: *const c_char,
        secret: *const c_char,
    ) -> u32 {
        let account = unsafe { CStr::from_ptr(account) }
            .to_str()
            .unwrap()
            .to_owned();
        let secret = unsafe { CStr::from_ptr(secret) }
            .to_str()
            .unwrap()
            .to_owned();
        unsafe { vault(data) }
            .entries
            .lock()
            .unwrap()
            .insert(account, secret);
        MarmotSecretStoreStatus::Ok as u32
    }

    unsafe extern "C" fn load(
        data: *mut c_void,
        _label: *const c_char,
        account: *const c_char,
        out: *mut *mut c_char,
    ) -> u32 {
        let account = unsafe { CStr::from_ptr(account) }.to_str().unwrap();
        let entry = unsafe { vault(data) }
            .entries
            .lock()
            .unwrap()
            .get(account)
            .cloned();
        let Some(secret) = entry else {
            return MarmotSecretStoreStatus::NotFound as u32;
        };
        unsafe { out.write(CString::new(secret).unwrap().into_raw()) };
        MarmotSecretStoreStatus::Ok as u32
    }

    unsafe extern "C" fn remove(
        data: *mut c_void,
        _label: *const c_char,
        account: *const c_char,
    ) -> u32 {
        let account = unsafe { CStr::from_ptr(account) }.to_str().unwrap();
        unsafe { vault(data) }
            .entries
            .lock()
            .unwrap()
            .remove(account);
        MarmotSecretStoreStatus::Ok as u32
    }

    unsafe extern "C" fn destroy(data: *mut c_void) {
        unsafe { vault(data) }
            .destroyed
            .store(true, Ordering::SeqCst);
    }

    fn store(vault: &Vault) -> MarmotSecretStore {
        MarmotSecretStore {
            user_data: (vault as *const Vault).cast_mut().cast(),
            has_secret_for_label: Some(has),
            has_secret_for_account_id: Some(has),
            write_secret: Some(write),
            load_secret: Some(load),
            remove_secret: Some(remove),
            free_secret: Some(super::free_secret),
            destroy: Some(destroy),
        }
    }

    fn options(store: &MarmotSecretStore) -> marmot_c::MarmotClientOptions {
        marmot_c::MarmotClientOptions {
            attachment_acquisition_mode: 0,
            relay_policy: 1,
            cursor_persistence: 0,
            client_name: c"experimental-host-test".as_ptr(),
            store,
            device_platform: c"desktop".as_ptr(),
        }
    }

    #[cfg(not(feature = "dev-device-groups"))]
    #[test]
    fn an_unavailable_experimental_constructor_has_no_root_or_callback_side_effects() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("unopened");
        let path = CString::new(root.to_str().unwrap()).unwrap();
        let vault = Vault::default();
        let store = store(&vault);
        let options = options(&store);
        let mut client = std::ptr::dangling_mut();
        // Required output preflight still wins before capability checks.
        assert_eq!(
            unsafe {
                marmot_c::marmot_client_new_with_experimental_device_groups(
                    path.as_ptr(),
                    std::ptr::null(),
                    0,
                    &options,
                    marmot_c::deployment::OwnedDeployment::white_noise().as_ptr(),
                    std::ptr::null_mut(),
                )
            },
            MarmotStatus::NullPointer
        );
        assert_eq!(
            unsafe {
                marmot_c::marmot_client_new_with_experimental_device_groups(
                    path.as_ptr(),
                    std::ptr::null(),
                    0,
                    &options,
                    marmot_c::deployment::OwnedDeployment::white_noise().as_ptr(),
                    &mut client,
                )
            },
            MarmotStatus::Runtime
        );
        assert!(client.is_null());
        let detail = marmot_c::marmot_last_error_message();
        assert!(
            unsafe { CStr::from_ptr(detail) }
                .to_str()
                .unwrap()
                .contains("experimental_device_groups_unavailable")
        );
        unsafe { marmot_c::marmot_string_free(detail) };
        assert!(!root.exists(), "an unavailable build never opens a root");
        assert!(!vault.destroyed.load(Ordering::SeqCst));
        assert!(vault.entries.lock().unwrap().is_empty());
    }

    #[cfg(feature = "dev-device-groups")]
    #[test]
    fn experimental_c_hosts_link_real_devices_while_ordinary_opens_stay_disabled() {
        // A composed host lifecycle uses its own 8 MiB caller and runtime
        // threads, matching the existing composed whole-app test budget.
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                use marmot_c::commands::*;
                use marmot_c::types::account::marmot_account_summary_free;
                use marmot_c::types::device_link::*;
                use nostr::prelude::{Keys, ToBech32};
                use std::time::{Duration, Instant};

                fn check(status: MarmotStatus) {
                    if status != MarmotStatus::Ok {
                        let detail = marmot_c::marmot_last_error_message();
                        let detail_text = unsafe { CStr::from_ptr(detail) }
                            .to_string_lossy()
                            .into_owned();
                        unsafe { marmot_c::marmot_string_free(detail) };
                        panic!("host call failed: {status:?}: {detail_text}");
                    }
                }
                fn snapshot(
                    client: *mut MarmotClient,
                    account: &CStr,
                ) -> *mut MarmotDeviceLinkSnapshot {
                    let mut value = std::ptr::null_mut();
                    check(unsafe {
                        marmot_device_link_snapshot(client, account.as_ptr(), &mut value)
                    });
                    value
                }
                fn wait<T>(mut read: impl FnMut() -> Option<T>) -> T {
                    let deadline = Instant::now() + Duration::from_secs(120);
                    loop {
                        if let Some(value) = read() {
                            return value;
                        }
                        assert!(
                            Instant::now() < deadline,
                            "device-link host state did not advance"
                        );
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .thread_stack_size(8 * 1024 * 1024)
                    .enable_all()
                    .build()
                    .unwrap();
                let relay = runtime
                    .block_on(nostr_relay_builder::MockRelay::run())
                    .unwrap();
                let relay_url = CString::new(runtime.block_on(relay.url()).to_string()).unwrap();
                let relays = [relay_url.as_ptr()];
                let roots: [_; 3] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
                let vaults: [_; 3] = std::array::from_fn(|_| Vault::default());
                let mut clients = [std::ptr::null_mut(); 3];
                let identity =
                    CString::new(Keys::generate().secret_key().to_bech32().unwrap()).unwrap();
                let mut account = None;
                let mut deployment = std::ptr::null_mut();
                check(unsafe { marmot_c::deployment::marmot_deployment_neutral(&mut deployment) });
                for index in 0..3 {
                    let path = CString::new(roots[index].path().to_str().unwrap()).unwrap();
                    let store = store(&vaults[index]);
                    let options = options(&store);
                    let constructor = if index == 0 {
                        marmot_c::marmot_client_new_with_configuration
                    } else {
                        marmot_c::marmot_client_new_with_experimental_device_groups
                    };
                    check(unsafe {
                        constructor(
                            path.as_ptr(),
                            relays.as_ptr(),
                            1,
                            &options,
                            deployment,
                            &mut clients[index],
                        )
                    });
                    check(unsafe { marmot_c::marmot_client_start(clients[index]) });
                    let mut summary = std::ptr::null_mut();
                    check(unsafe {
                        marmot_login(
                            clients[index],
                            identity.as_ptr(),
                            relays.as_ptr(),
                            1,
                            relays.as_ptr(),
                            1,
                            relays.as_ptr(),
                            1,
                            &mut summary,
                        )
                    });
                    let this_account =
                        unsafe { CStr::from_ptr((*summary).account_id_hex) }.to_owned();
                    if let Some(account) = account.as_ref() {
                        assert_eq!(account, &this_account);
                    }
                    account = Some(this_account);
                    unsafe { marmot_account_summary_free(summary) };
                    if index == 0 {
                        let mut refused = std::ptr::dangling_mut();
                        assert_ne!(
                            unsafe {
                                marmot_start_device_link(
                                    clients[0],
                                    account.as_ref().unwrap().as_ptr(),
                                    &mut refused,
                                )
                            },
                            MarmotStatus::Ok
                        );
                        assert!(
                            refused.is_null(),
                            "ordinary constructor does not activate the capability"
                        );
                        let detail = marmot_c::marmot_last_error_message();
                        assert!(
                            unsafe { CStr::from_ptr(detail) }
                                .to_str()
                                .unwrap()
                                .contains("pairing_unsupported")
                        );
                        unsafe { marmot_c::marmot_string_free(detail) };
                        refused = std::ptr::dangling_mut();
                        assert_ne!(
                            unsafe {
                                marmot_reset_device_group_for_repair(
                                    clients[0],
                                    account.as_ref().unwrap().as_ptr(),
                                    &mut refused,
                                )
                            },
                            MarmotStatus::Ok
                        );
                        assert!(
                            refused.is_null(),
                            "ordinary opens also refuse explicit reset"
                        );
                        let detail = marmot_c::marmot_last_error_message();
                        assert!(
                            unsafe { CStr::from_ptr(detail) }
                                .to_str()
                                .unwrap()
                                .contains("pairing_unsupported")
                        );
                        unsafe { marmot_c::marmot_string_free(detail) };
                        check(unsafe {
                            marmot_c::commands::marmot_client_shutdown_and_close(clients[0])
                        });
                        unsafe { marmot_client_free(clients[0]) };
                        clients[0] = std::ptr::null_mut();
                        assert!(vaults[0].destroyed.load(Ordering::SeqCst));
                    }
                }
                unsafe { marmot_c::deployment::marmot_deployment_free(deployment) };
                let account = account.unwrap();
                let mut started = std::ptr::null_mut();
                check(unsafe {
                    marmot_start_device_link(clients[2], account.as_ptr(), &mut started)
                });
                unsafe { marmot_device_link_snapshot_free(started) };
                let (prompt_id, existing_code) = wait(|| {
                    let value = snapshot(clients[1], &account);
                    let result = if unsafe { (*value).prompts_len } == 0 {
                        &[]
                    } else {
                        unsafe {
                            std::slice::from_raw_parts((*value).prompts, (*value).prompts_len)
                        }
                    }
                    .iter()
                    .find_map(|prompt| match &prompt.state {
                        MarmotDeviceLinkPromptState::Comparing { code, code_len } => Some((
                            unsafe { CStr::from_ptr(prompt.prompt_id) }.to_owned(),
                            unsafe { std::slice::from_raw_parts(*code, *code_len) }
                                .iter()
                                .map(|e| unsafe { CStr::from_ptr(e.emoji) }.to_owned())
                                .collect::<Vec<_>>(),
                        )),
                        _ => None,
                    });
                    unsafe { marmot_device_link_snapshot_free(value) };
                    result
                });
                let new_code = wait(|| {
                    let value = snapshot(clients[2], &account);
                    let result = match unsafe { (*value).new_device.as_ref() } {
                        Some(MarmotNewDeviceLinkState::Comparing { code, code_len }) => Some(
                            unsafe { std::slice::from_raw_parts(*code, *code_len) }
                                .iter()
                                .map(|e| unsafe { CStr::from_ptr(e.emoji) }.to_owned())
                                .collect::<Vec<_>>(),
                        ),
                        _ => None,
                    };
                    unsafe { marmot_device_link_snapshot_free(value) };
                    result
                });
                assert_eq!(existing_code.len(), 7);
                assert_eq!(
                    new_code, existing_code,
                    "both authenticated host screens agree"
                );
                let mut value = std::ptr::null_mut();
                check(unsafe {
                    marmot_confirm_device_link_match(clients[2], account.as_ptr(), &mut value)
                });
                unsafe { marmot_device_link_snapshot_free(value) };
                check(unsafe {
                    marmot_link_device(
                        clients[1],
                        account.as_ptr(),
                        prompt_id.as_ptr(),
                        c"linked host".as_ptr(),
                        1,
                        1,
                        &mut value,
                    )
                });
                unsafe { marmot_device_link_snapshot_free(value) };
                wait(|| {
                    let existing = snapshot(clients[1], &account);
                    let new = snapshot(clients[2], &account);
                    let existing_linked = if unsafe { (*existing).prompts_len } == 0 {
                        &[]
                    } else {
                        unsafe {
                            std::slice::from_raw_parts((*existing).prompts, (*existing).prompts_len)
                        }
                    }
                    .iter()
                    .any(|p| matches!(&p.state, MarmotDeviceLinkPromptState::Linked));
                    let new_linked = matches!(
                        unsafe { (*new).new_device.as_ref() },
                        Some(MarmotNewDeviceLinkState::Linked)
                    );
                    unsafe {
                        marmot_device_link_snapshot_free(existing);
                        marmot_device_link_snapshot_free(new);
                    }
                    (existing_linked && new_linked).then_some(())
                });
                let mut reset = std::ptr::null_mut();
                check(unsafe {
                    marmot_reset_device_group_for_repair(clients[2], account.as_ptr(), &mut reset)
                });
                assert!(!reset.is_null());
                assert!(unsafe { (*reset).new_device.is_null() });
                unsafe { marmot_device_link_snapshot_free(reset) };
                for (index, client) in clients.into_iter().enumerate().skip(1) {
                    check(unsafe { marmot_c::commands::marmot_client_shutdown_and_close(client) });
                    unsafe { marmot_client_free(client) };
                    assert!(vaults[index].destroyed.load(Ordering::SeqCst));
                    assert!(
                        !vaults[index].entries.lock().unwrap().is_empty(),
                        "real host signing callbacks were used"
                    );
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
