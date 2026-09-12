//! Offline identity decode and profile-pseudonym ABI coverage using a
//! host secret store so the platform keychain is never required.

use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use marmot_c::commands::{
    marmot_account_id_hex, marmot_default_profile_pseudonym, marmot_normalize_member_ref,
    marmot_random_profile_pseudonym,
};
use marmot_c::secret_store::{MarmotSecretStore, MarmotSecretStoreStatus};
use marmot_c::types::group::{MarmotMemberRef, marmot_member_ref_free};
use marmot_c::{
    MarmotClient, MarmotStatus, marmot_client_free, marmot_client_new_with_secret_store,
    marmot_client_shutdown, marmot_string_free,
};

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../marmot-app/tests/support/identity_reference_vectors.rs"
));

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

fn host_store() -> MarmotSecretStore {
    MarmotSecretStore {
        user_data: ptr::null_mut(),
        has_secret_for_label: Some(has),
        has_secret_for_account_id: Some(has),
        write_secret: Some(write_secret),
        load_secret: Some(load_secret),
        remove_secret: Some(remove_secret),
        free_secret: Some(free_secret),
        destroy: Some(destroy),
    }
}

fn open_client(root: &tempfile::TempDir) -> *mut MarmotClient {
    let root_path = CString::new(root.path().to_str().expect("utf-8 temp path")).unwrap();
    let relay = CString::new("wss://relay.example.org").unwrap();
    let relays = [relay.as_ptr()];
    let store = host_store();
    let mut client: *mut MarmotClient = ptr::null_mut();
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
    client
}

fn take_string(ptr: *mut c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let value = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .expect("utf-8")
        .to_owned();
    unsafe { marmot_string_free(ptr) };
    Some(value)
}

#[test]
fn account_id_hex_and_pseudonyms_are_offline() {
    let root = tempfile::tempdir().expect("temp dir");
    let client = open_client(&root);
    for case in cases() {
        let input = CString::new(case.reference.clone())
            .unwrap_or_else(|_| panic!("case {} must be a C string", case.name));

        let mut hex_out: *mut c_char = 0x10 as *mut c_char;
        let hex_status = unsafe { marmot_account_id_hex(client, input.as_ptr(), &raw mut hex_out) };
        match case.ffi_account_id_hex {
            Some(expected) => {
                assert_eq!(hex_status, MarmotStatus::Ok, "case {}", case.name);
                assert_eq!(
                    take_string(hex_out).as_deref(),
                    Some(expected),
                    "case {}",
                    case.name
                );
            }
            None => {
                assert_eq!(hex_status, MarmotStatus::Ok, "case {}", case.name);
                assert!(
                    hex_out.is_null(),
                    "case {} optional decode stays OK plus NULL",
                    case.name
                );
            }
        }

        let mut typed_out: *mut MarmotMemberRef = 0x10 as *mut MarmotMemberRef;
        let typed_status =
            unsafe { marmot_normalize_member_ref(client, input.as_ptr(), &raw mut typed_out) };
        match case.ffi_account_id_hex {
            Some(expected) => {
                assert_eq!(typed_status, MarmotStatus::Ok, "case {}", case.name);
                assert!(!typed_out.is_null(), "case {}", case.name);
                let record = unsafe { &*typed_out };
                let member_ref = unsafe { CStr::from_ptr(record.member_ref) }
                    .to_str()
                    .expect("utf-8");
                let account_id = unsafe { CStr::from_ptr(record.account_id_hex) }
                    .to_str()
                    .expect("utf-8");
                let npub = unsafe { CStr::from_ptr(record.npub) }
                    .to_str()
                    .expect("utf-8");
                assert_eq!(member_ref, expected, "case {}", case.name);
                assert_eq!(account_id, expected, "case {}", case.name);
                assert_eq!(npub, NPUB, "case {}", case.name);
                unsafe { marmot_member_ref_free(typed_out) };
            }
            None => {
                assert_eq!(
                    typed_status,
                    MarmotStatus::InvalidIdentity,
                    "case {}",
                    case.name
                );
                assert!(
                    typed_out.is_null(),
                    "case {} typed normalize clears the output",
                    case.name
                );
            }
        }
    }

    let mut out: *mut c_char = 0x10 as *mut c_char;
    assert_eq!(
        unsafe { marmot_account_id_hex(client, ptr::null(), &raw mut out) },
        MarmotStatus::NullPointer
    );
    assert!(out.is_null());
    out = 0x10 as *mut c_char;
    assert_eq!(
        unsafe { marmot_default_profile_pseudonym(client, ptr::null(), &raw mut out) },
        MarmotStatus::NullPointer
    );
    assert!(out.is_null());

    let mut typed_null: *mut MarmotMemberRef = 0x10 as *mut MarmotMemberRef;
    assert_eq!(
        unsafe { marmot_normalize_member_ref(client, ptr::null(), &raw mut typed_null) },
        MarmotStatus::NullPointer
    );
    assert!(typed_null.is_null());

    let account = CString::new(ACCOUNT_ID).unwrap();
    let mut name_out: *mut c_char = 0x10 as *mut c_char;
    assert_eq!(
        unsafe { marmot_default_profile_pseudonym(client, account.as_ptr(), &raw mut name_out) },
        MarmotStatus::Ok
    );
    assert_eq!(take_string(name_out).as_deref(), Some("Loyal Crane"));

    let mut random_out: *mut c_char = 0x10 as *mut c_char;
    assert_eq!(
        unsafe { marmot_random_profile_pseudonym(client, &raw mut random_out) },
        MarmotStatus::Ok
    );
    let random = take_string(random_out).expect("random name");
    assert!(random.split_once(' ').is_some());

    unsafe { marmot_client_shutdown(client) };
    unsafe { marmot_client_free(client) };
    assert!(DESTROYED.load(Ordering::SeqCst));
}
