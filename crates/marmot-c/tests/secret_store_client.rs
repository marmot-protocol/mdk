//! A host-supplied secret store must be enough to open a client, with no
//! platform keychain involved, and must be released when the client is.

use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::atomic::{AtomicBool, Ordering};

use marmot_c::secret_store::MarmotSecretStore;
use marmot_c::{
    MarmotClient, MarmotClientOptions, MarmotIosOptions, MarmotStatus, marmot_client_free,
    marmot_client_new_with_secret_store, marmot_client_shutdown,
};

use marmot_c::secret_store as host_abi;
#[allow(dead_code)]
#[path = "support/owned_store.rs"]
mod owned_store;
use owned_store::MemoryVault;

static DESTROYED: AtomicBool = AtomicBool::new(false);
unsafe extern "C" fn destroy(_: *mut c_void) {
    DESTROYED.store(true, Ordering::SeqCst);
}

#[test]
fn a_host_store_opens_a_client_without_the_platform_keychain() {
    let root = tempfile::tempdir().expect("temp dir");
    let root_path = CString::new(root.path().to_str().expect("utf-8 temp path")).unwrap();
    let relay = CString::new("wss://relay.example.org").unwrap();
    let relays = [relay.as_ptr()];

    let mut store = MemoryVault::global().table();
    store.destroy = Some(destroy);

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

    let mut store = MemoryVault::global().table();
    store.destroy = Some(destroy_after_failure);

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

    let vault = MemoryVault::default();
    let destroyed = &vault.destroy_count;
    let mut store = vault.table();
    store.destroy = Some(MemoryVault::destroy_mark);
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
    let vault = MemoryVault::default();
    let destroyed = &vault.destroyed;
    let mut store = vault.table();
    store.destroy = Some(MemoryVault::destroy_mark);
    let name = CString::new("whitenoise").unwrap();
    let root = tempfile::tempdir().unwrap();
    let path = CString::new(root.path().to_str().unwrap()).unwrap();
    let relay = CString::new("ws://127.0.0.1:1").unwrap();
    let relays = [relay.as_ptr()];
    let mut options = MarmotClientOptions {
        attachment_acquisition_mode: 0,
        relay_policy: 2,
        cursor_persistence: 1,
        client_name: name.as_ptr(),
        store: &store,
        device_platform: std::ptr::null(),
        ios_options: std::ptr::null(),
    };
    let deployment = marmot_c::deployment::OwnedDeployment::white_noise();
    let open = |root_path, options: &MarmotClientOptions, client| unsafe {
        marmot_c::marmot_client_new_with_configuration(
            root_path,
            relays.as_ptr(),
            relays.len(),
            options,
            deployment.as_ptr(),
            client,
        )
    };
    let missing_array = MarmotIosOptions {
        app_group_identifiers: std::ptr::null(),
        app_group_identifiers_len: 1,
        keychain_access_group: std::ptr::null(),
    };
    let invalid_utf8 = [0xffu8, 0];
    let invalid_access_group = MarmotIosOptions {
        app_group_identifiers: std::ptr::null(),
        app_group_identifiers_len: 0,
        keychain_access_group: invalid_utf8.as_ptr().cast(),
    };
    for (policy, cursor, ios, expected) in [
        (u32::MAX, 1, std::ptr::null(), MarmotStatus::InvalidArgument),
        (2, u32::MAX, std::ptr::null(), MarmotStatus::InvalidArgument),
        (2, 1, &raw const missing_array, MarmotStatus::NullPointer),
        (
            2,
            1,
            &raw const invalid_access_group,
            MarmotStatus::InvalidUtf8,
        ),
    ] {
        options.relay_policy = policy;
        options.cursor_persistence = cursor;
        options.ios_options = ios;
        let mut client = std::ptr::dangling_mut();
        assert_eq!(open(path.as_ptr(), &options, &raw mut client), expected);
        assert!(client.is_null());
        assert!(!destroyed.load(Ordering::SeqCst));
    }
    options.relay_policy = 2;
    options.cursor_persistence = 1;
    options.ios_options = std::ptr::null();
    let mut client = std::ptr::dangling_mut();
    let status = open(std::ptr::null(), &options, &raw mut client);
    assert_eq!(status, MarmotStatus::NullPointer);
    assert!(client.is_null());
    assert!(
        !destroyed.load(Ordering::SeqCst),
        "failed construction leaves the store with its owner"
    );
    let mut client = std::ptr::null_mut();
    let status = open(path.as_ptr(), &options, &raw mut client);
    assert_eq!(status, MarmotStatus::Ok);
    assert!(!destroyed.load(Ordering::SeqCst));
    unsafe { marmot_client_free(client) };
    assert!(destroyed.load(Ordering::SeqCst));
}

#[test]
fn a_deployment_constructor_opens_with_a_host_store() {
    let vault = MemoryVault::default();
    let destroyed = &vault.destroyed;
    let mut store = vault.table();
    store.destroy = Some(MemoryVault::destroy_mark);
    let root = tempfile::tempdir().unwrap();
    let path = CString::new(root.path().to_str().unwrap()).unwrap();
    let relay = CString::new("ws://127.0.0.1:1").unwrap();
    let relays = [relay.as_ptr()];
    let options = MarmotClientOptions {
        attachment_acquisition_mode: 0,
        relay_policy: 2,
        cursor_persistence: 0,
        client_name: std::ptr::null(),
        store: &store,
        device_platform: std::ptr::null(),
        ios_options: std::ptr::null(),
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
    let vault = MemoryVault::default();
    let destroyed = &vault.destroyed;
    let mut store = vault.table();
    store.destroy = Some(MemoryVault::destroy_mark);
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

mod host_output_failures {
    use super::*;
    use host_abi::{MarmotSecretCredential, MarmotSecretStoreStatus as StoreStatus};
    use marmot_c::commands::{marmot_list_accounts, marmot_login, marmot_reveal_nsec};
    use marmot_c::types::account::{marmot_account_summary_free, marmot_account_summary_list_free};
    use nostr::prelude::{Keys, ToBech32};
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

    #[derive(Clone, Copy)]
    struct Failure {
        status: u32,
        invalid_utf8: bool,
        origin: u32,
        detail: &'static str,
    }

    #[repr(C)]
    struct Host {
        vault: MemoryVault,
        failure: Option<Failure>,
        fail_load: AtomicBool,
        secret: CString,
        outstanding: Mutex<Vec<usize>>,
        freed: AtomicUsize,
    }
    impl Host {
        fn new(keys: &Keys, failure: Option<Failure>) -> Self {
            Self {
                vault: MemoryVault::default(),
                failure,
                fail_load: AtomicBool::new(false),
                secret: CString::new(keys.secret_key().to_secret_hex()).unwrap(),
                outstanding: Mutex::default(),
                freed: AtomicUsize::new(0),
            }
        }
        fn table(&self) -> MarmotSecretStore {
            let mut table = self.vault.table();
            table.user_data = (self as *const Self).cast_mut().cast();
            table.acquire_secret = Some(Self::acquire);
            table.load_secret = Some(Self::load);
            table.free_secret = Some(Self::free);
            table
        }
        unsafe fn output(&self, invalid_utf8: bool, out: *mut *mut c_char) {
            let secret = if invalid_utf8 {
                CString::new(vec![0xff]).unwrap()
            } else {
                self.secret.clone()
            }
            .into_raw();
            self.outstanding.lock().unwrap().push(secret as usize);
            unsafe { out.write(secret) };
        }
        unsafe extern "C" fn acquire(
            data: *mut c_void,
            credential: *const MarmotSecretCredential,
            mode: u32,
            proposed: *const c_char,
            out: *mut *mut c_char,
            origin: *mut u32,
        ) -> u32 {
            let host = unsafe { &*data.cast::<Self>() };
            if let Some(failure) = host.failure {
                unsafe {
                    host.output(failure.invalid_utf8, out);
                    origin.write(failure.origin);
                }
                failure.status
            } else {
                let table = host.vault.table();
                unsafe {
                    table.acquire_secret.unwrap()(
                        table.user_data,
                        credential,
                        mode,
                        proposed,
                        out,
                        origin,
                    )
                }
            }
        }
        unsafe extern "C" fn load(
            data: *mut c_void,
            credential: *const MarmotSecretCredential,
            out: *mut *mut c_char,
        ) -> u32 {
            let host = unsafe { &*data.cast::<Self>() };
            if host.fail_load.load(Ordering::SeqCst) {
                unsafe { host.output(false, out) };
                StoreStatus::Failed as u32
            } else {
                let table = host.vault.table();
                unsafe { table.load_secret.unwrap()(table.user_data, credential, out) }
            }
        }
        unsafe extern "C" fn free(data: *mut c_void, value: *mut c_char) {
            let host = unsafe { &*data.cast::<Self>() };
            let mut outstanding = host.outstanding.lock().unwrap();
            if let Some(index) = outstanding
                .iter()
                .position(|pointer| *pointer == value as usize)
            {
                outstanding.swap_remove(index);
                host.freed.fetch_add(1, Ordering::SeqCst);
            }
            unsafe { MemoryVault::free(data, value) };
        }
    }

    struct Client(*mut MarmotClient);
    impl Client {
        fn open(root: &tempfile::TempDir, host: &Host, relay: &CStr, policy: u32) -> Self {
            let path = CString::new(root.path().to_str().unwrap()).unwrap();
            let relays = [relay.as_ptr()];
            let store = host.table();
            let deployment = marmot_c::deployment::OwnedDeployment::white_noise();
            assert_eq!(
                unsafe {
                    marmot_c::deployment::marmot_deployment_set_discovery_indexer_relays(
                        deployment.as_ptr().cast_mut(),
                        relays.as_ptr(),
                        relays.len(),
                    )
                },
                MarmotStatus::Ok
            );
            let mut client = std::ptr::null_mut();
            assert_eq!(
                unsafe {
                    marmot_c::marmot_client_new_with_options(
                        path.as_ptr(),
                        relays.as_ptr(),
                        1,
                        policy,
                        &store,
                        deployment.as_ptr(),
                        &mut client,
                    )
                },
                MarmotStatus::Ok
            );
            Self(client)
        }
        fn login(
            &self,
            keys: &Keys,
            relay: &CStr,
        ) -> (
            MarmotStatus,
            *mut marmot_c::types::account::MarmotAccountSummary,
        ) {
            let identity = CString::new(keys.secret_key().to_bech32().unwrap()).unwrap();
            let relays = [relay.as_ptr()];
            let mut summary = std::ptr::dangling_mut();
            let status = unsafe {
                marmot_login(
                    self.0,
                    identity.as_ptr(),
                    relays.as_ptr(),
                    1,
                    relays.as_ptr(),
                    1,
                    relays.as_ptr(),
                    1,
                    &mut summary,
                )
            };
            (status, summary)
        }
        fn account_ids(&self) -> Vec<String> {
            let mut accounts = std::ptr::null_mut();
            assert_eq!(
                unsafe { marmot_list_accounts(self.0, &mut accounts) },
                MarmotStatus::Ok
            );
            let list = unsafe { &*accounts };
            let ids = (0..list.len)
                .map(|index| unsafe {
                    CStr::from_ptr((*list.items.add(index)).account_id_hex)
                        .to_str()
                        .unwrap()
                        .to_owned()
                })
                .collect();
            unsafe { marmot_account_summary_list_free(accounts) };
            ids
        }
    }
    impl Drop for Client {
        fn drop(&mut self) {
            unsafe {
                marmot_client_shutdown(self.0);
                marmot_client_free(self.0);
            }
        }
    }
    fn last_error() -> String {
        let error = marmot_c::marmot_last_error_message();
        let text = unsafe { CStr::from_ptr(error) }
            .to_str()
            .unwrap()
            .to_owned();
        unsafe { marmot_c::marmot_string_free(error) };
        text
    }

    #[test]
    fn host_acquire_outputs_fail_without_admitting_an_account() {
        let cases = [
            Failure {
                status: StoreStatus::Failed as u32,
                invalid_utf8: false,
                origin: 0,
                detail: "host secret store failed (acquire_secret)",
            },
            Failure {
                status: StoreStatus::Unavailable as u32,
                invalid_utf8: false,
                origin: 0,
                detail: "host secret store unavailable (acquire_secret)",
            },
            Failure {
                status: u32::MAX,
                invalid_utf8: false,
                origin: 0,
                detail: "out of range (acquire_secret)",
            },
            Failure {
                status: StoreStatus::Ok as u32,
                invalid_utf8: true,
                origin: 0,
                detail: "host secret store returned non-UTF-8 hex",
            },
            Failure {
                status: StoreStatus::Ok as u32,
                invalid_utf8: false,
                origin: u32::MAX,
                detail: "host secret store returned an invalid origin tag",
            },
        ];
        for failure in cases {
            let keys = Keys::generate();
            let host = Host::new(&keys, Some(failure));
            let root = tempfile::tempdir().unwrap();
            let client = Client::open(&root, &host, c"wss://relay.example.org", 0);
            let (status, summary) = client.login(&keys, c"wss://relay.example.org");
            assert_eq!(status, MarmotStatus::KeystoreUnavailable);
            assert!(summary.is_null());
            assert!(last_error().contains(failure.detail));
            assert_eq!(host.freed.load(Ordering::SeqCst), 1);
            assert!(host.outstanding.lock().unwrap().is_empty());
            assert_eq!(client.account_ids(), Vec::<String>::new());
        }
    }

    #[test]
    fn host_load_failure_frees_output_without_replacing_account() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let relay = runtime
            .block_on(nostr_relay_builder::MockRelay::run())
            .unwrap();
        let relay_url = CString::new(runtime.block_on(relay.url()).to_string()).unwrap();
        let keys = Keys::generate();
        let host = Host::new(&keys, None);
        let root = tempfile::tempdir().unwrap();
        let client = Client::open(
            &root,
            &host,
            &relay_url,
            marmot_c::MarmotRelayPolicy::AllowLoopback as u32,
        );
        assert_eq!(
            unsafe { marmot_c::marmot_client_start(client.0) },
            MarmotStatus::Ok
        );
        let (status, summary) = client.login(&keys, &relay_url);
        assert_eq!(status, MarmotStatus::Ok);
        unsafe { marmot_account_summary_free(summary) };
        assert_eq!(client.account_ids(), vec![keys.public_key().to_hex()]);
        host.fail_load.store(true, Ordering::SeqCst);
        let account = CString::new(keys.public_key().to_hex()).unwrap();
        let mut output = std::ptr::dangling_mut();
        assert_eq!(
            unsafe { marmot_reveal_nsec(client.0, account.as_ptr(), &mut output) },
            MarmotStatus::KeystoreUnavailable
        );
        assert!(output.is_null());
        assert!(last_error().contains("host secret store failed (load_secret)"));
        assert_eq!(host.freed.load(Ordering::SeqCst), 1);
        assert!(host.outstanding.lock().unwrap().is_empty());
        assert_eq!(client.account_ids(), vec![keys.public_key().to_hex()]);
    }
}

/// These callbacks use each host's own vault rather than process-global state.
/// They also prove the experimental constructor preserves callback ownership.
mod experimental_host {
    use super::*;
    use owned_store::MemoryVault as Vault;

    fn store(vault: &Vault) -> MarmotSecretStore {
        let mut store = vault.table();
        store.destroy = Some(Vault::destroy_mark);
        store
    }

    fn options(store: &MarmotSecretStore) -> MarmotClientOptions {
        MarmotClientOptions {
            attachment_acquisition_mode: 0,
            relay_policy: 1,
            cursor_persistence: 0,
            client_name: c"experimental-host-test".as_ptr(),
            store,
            device_platform: c"desktop".as_ptr(),
            ios_options: std::ptr::null(),
        }
    }

    #[test]
    fn c_hosts_link_real_devices_through_either_constructor() {
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
                let roots: [_; 2] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
                let vaults: [_; 2] = std::array::from_fn(|_| Vault::default());
                let mut clients = [std::ptr::null_mut(); 2];
                let identity =
                    CString::new(Keys::generate().secret_key().to_bech32().unwrap()).unwrap();
                let mut account = None;
                let mut deployment = std::ptr::null_mut();
                check(unsafe { marmot_c::deployment::marmot_deployment_neutral(&mut deployment) });
                for index in 0..2 {
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
                }
                unsafe { marmot_c::deployment::marmot_deployment_free(deployment) };
                let account = account.unwrap();
                let mut started = std::ptr::null_mut();
                check(unsafe {
                    marmot_start_device_link(clients[1], account.as_ptr(), &mut started)
                });
                unsafe { marmot_device_link_snapshot_free(started) };
                let (prompt_id, existing_code) = wait(|| {
                    let value = snapshot(clients[0], &account);
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
                    let value = snapshot(clients[1], &account);
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
                    marmot_confirm_device_link_match(clients[1], account.as_ptr(), &mut value)
                });
                unsafe { marmot_device_link_snapshot_free(value) };
                check(unsafe {
                    marmot_link_device(
                        clients[0],
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
                    let existing = snapshot(clients[0], &account);
                    let new = snapshot(clients[1], &account);
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
                    marmot_reset_device_group_for_repair(clients[1], account.as_ptr(), &mut reset)
                });
                assert!(!reset.is_null());
                assert!(unsafe { (*reset).new_device.is_null() });
                unsafe { marmot_device_link_snapshot_free(reset) };
                for (index, client) in clients.into_iter().enumerate() {
                    check(unsafe { marmot_c::commands::marmot_client_shutdown_and_close(client) });
                    unsafe { marmot_client_free(client) };
                    assert!(vaults[index].destroyed.load(Ordering::SeqCst));
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
