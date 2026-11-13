//! A NULL out-pointer must be rejected *before* the wrapper does any work.
//!
//! Rejecting it afterwards makes a mutating command report failure after
//! its side effect landed (so a retry duplicates it) and makes a
//! subscription read consume an item it can no longer hand back.

use std::ffi::CString;
use std::time::Instant;

use marmot_c::commands::{
    marmot_group_app_component, marmot_pending_welcome_deliveries,
    marmot_send_prepared_media_with_client_token, marmot_set_group_archived,
    marmot_update_app_component,
};
use marmot_c::subscriptions::{
    MarmotEventsSubscription, marmot_events_subscription_free, marmot_events_subscription_next,
    marmot_subscribe_events,
};
use marmot_c::{MarmotClient, MarmotStatus, marmot_client_free, marmot_client_shutdown};

use marmot_c::secret_store::MarmotSecretStoreStatus as StoreStatus;

// All ownership here is a private host fixture in the existing binary.
// No platform keystore and no assertion-skipping constructor path.
#[derive(Default)]
struct Vault(std::sync::Mutex<std::collections::HashMap<(String, String), String>>);
unsafe fn input_text(value: *const std::ffi::c_char) -> Result<String, u32> {
    if value.is_null() {
        return Err(marmot_c::secret_store::MarmotSecretStoreStatus::Failed as u32);
    }
    unsafe { std::ffi::CStr::from_ptr(value) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| marmot_c::secret_store::MarmotSecretStoreStatus::Failed as u32)
}
unsafe extern "C" fn has_label(
    data: *mut std::ffi::c_void,
    key: *const std::ffi::c_char,
    out: *mut u8,
) -> u32 {
    let Ok(key) = (unsafe { input_text(key) }) else {
        return StoreStatus::Failed as u32;
    };
    let vault = unsafe { &*(data as *const Vault) };
    let Ok(entries) = vault.0.lock() else {
        return StoreStatus::Failed as u32;
    };
    unsafe { out.write(u8::from(entries.keys().any(|(label, _)| label == &key))) };
    StoreStatus::Ok as u32
}
unsafe extern "C" fn has_account(
    data: *mut std::ffi::c_void,
    key: *const std::ffi::c_char,
    out: *mut u8,
) -> u32 {
    let Ok(key) = (unsafe { input_text(key) }) else {
        return StoreStatus::Failed as u32;
    };
    let vault = unsafe { &*(data as *const Vault) };
    let Ok(entries) = vault.0.lock() else {
        return StoreStatus::Failed as u32;
    };
    unsafe { out.write(u8::from(entries.keys().any(|(_, account)| account == &key))) };
    StoreStatus::Ok as u32
}
unsafe extern "C" fn store_write(
    data: *mut std::ffi::c_void,
    label: *const std::ffi::c_char,
    account: *const std::ffi::c_char,
    secret: *const std::ffi::c_char,
) -> u32 {
    let (Ok(label), Ok(account), Ok(secret)) = (
        unsafe { input_text(label) },
        unsafe { input_text(account) },
        unsafe { input_text(secret) },
    ) else {
        return StoreStatus::Failed as u32;
    };
    let vault = unsafe { &*(data as *const Vault) };
    let Ok(mut entries) = vault.0.lock() else {
        return StoreStatus::Failed as u32;
    };
    entries.insert((label, account), secret);
    StoreStatus::Ok as u32
}
unsafe extern "C" fn store_load(
    data: *mut std::ffi::c_void,
    label: *const std::ffi::c_char,
    account: *const std::ffi::c_char,
    out: *mut *mut std::ffi::c_char,
) -> u32 {
    let (Ok(label), Ok(account)) = (unsafe { input_text(label) }, unsafe { input_text(account) })
    else {
        return StoreStatus::Failed as u32;
    };
    let vault = unsafe { &*(data as *const Vault) };
    let Ok(entries) = vault.0.lock() else {
        return StoreStatus::Failed as u32;
    };
    let Some(secret) = entries.get(&(label, account)) else {
        return StoreStatus::NotFound as u32;
    };
    let Ok(secret) = CString::new(secret.as_str()) else {
        return StoreStatus::Failed as u32;
    };
    unsafe { out.write(secret.into_raw()) };
    StoreStatus::Ok as u32
}
unsafe extern "C" fn store_remove(
    data: *mut std::ffi::c_void,
    label: *const std::ffi::c_char,
    account: *const std::ffi::c_char,
) -> u32 {
    let (Ok(label), Ok(account)) = (unsafe { input_text(label) }, unsafe { input_text(account) })
    else {
        return StoreStatus::Failed as u32;
    };
    let vault = unsafe { &*(data as *const Vault) };
    let Ok(mut entries) = vault.0.lock() else {
        return StoreStatus::Failed as u32;
    };
    entries.remove(&(label, account));
    StoreStatus::Ok as u32
}
unsafe extern "C" fn store_free(_: *mut std::ffi::c_void, value: *mut std::ffi::c_char) {
    if !value.is_null() {
        drop(unsafe { CString::from_raw(value) });
    }
}
unsafe extern "C" fn store_destroy(data: *mut std::ffi::c_void) {
    drop(unsafe { Box::from_raw(data as *mut Vault) });
}

struct ClientFixture {
    client: *mut MarmotClient,
    account: CString,
    a: CString,
    b: CString,
    relay_url: CString,
    _home: tempfile::TempDir,
    _relay: nostr_relay_builder::MockRelay,
    _relay_runtime: tokio::runtime::Runtime,
}
impl ClientFixture {
    fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let relay = runtime
            .block_on(nostr_relay_builder::MockRelay::run())
            .unwrap();
        let relay_url = CString::new(runtime.block_on(relay.url()).to_string()).unwrap();
        let home = tempfile::tempdir().unwrap();
        let path = CString::new(home.path().to_str().unwrap()).unwrap();
        let data = Box::into_raw(Box::new(Vault::default()));
        let store = marmot_c::secret_store::MarmotSecretStore {
            user_data: data.cast(),
            has_secret_for_label: Some(has_label),
            has_secret_for_account_id: Some(has_account),
            write_secret: Some(store_write),
            load_secret: Some(store_load),
            remove_secret: Some(store_remove),
            free_secret: Some(store_free),
            destroy: Some(store_destroy),
        };
        let relays = [relay_url.as_ptr()];
        let mut client = std::ptr::null_mut();
        let status = unsafe {
            marmot_c::marmot_client_new_with_options(
                path.as_ptr(),
                relays.as_ptr(),
                1,
                marmot_c::MarmotRelayPolicy::AllowLoopback as u32,
                &store,
                marmot_c::deployment::OwnedDeployment::white_noise().as_ptr(),
                &mut client,
            )
        };
        if status != MarmotStatus::Ok {
            // Failed constructors explicitly leave this context with the host.
            unsafe { store_destroy(data.cast()) };
            panic!("host-memory constructor: {status:?}");
        }
        let fixture = Self {
            client,
            account: CString::default(),
            a: CString::default(),
            b: CString::default(),
            relay_url,
            _home: home,
            _relay: relay,
            _relay_runtime: runtime,
        };
        assert_eq!(
            unsafe { marmot_c::marmot_client_start(client) },
            MarmotStatus::Ok
        );
        fixture
    }
    fn populate(&mut self) {
        let relays = [self.relay_url.as_ptr()];
        let mut account = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                marmot_c::commands::marmot_create_identity(
                    self.client,
                    relays.as_ptr(),
                    1,
                    relays.as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    &mut account,
                )
            },
            MarmotStatus::Ok
        );
        self.account = unsafe { std::ffi::CStr::from_ptr((*account).account_id_hex) }.to_owned();
        unsafe { marmot_c::types::account::marmot_account_summary_free(account) };
        self.a = self.create_group(c"preflight A");
        self.b = self.create_group(c"preflight B");
        assert_ne!(self.a, self.b);
    }
    fn create_group(&self, name: &std::ffi::CStr) -> CString {
        let mut group = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                marmot_c::commands::marmot_create_group(
                    self.client,
                    self.account.as_ptr(),
                    name.as_ptr(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    &mut group,
                )
            },
            MarmotStatus::Ok
        );
        let owned = unsafe { std::ffi::CStr::from_ptr((*group).group_id_hex) }.to_owned();
        unsafe { marmot_c::types::group::marmot_group_creation_free(group) };
        owned
    }
    fn archive(&self, group: &std::ffi::CStr, archived: bool) {
        let mut result = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                marmot_set_group_archived(
                    self.client,
                    self.account.as_ptr(),
                    group.as_ptr(),
                    u8::from(archived),
                    &mut result,
                )
            },
            MarmotStatus::Ok
        );
        assert!(!result.is_null());
        assert_eq!(unsafe { (*result).archived }, archived);
        unsafe { marmot_c::types::group::marmot_app_group_record_free(result) };
    }
    fn archived(&self, group: &std::ffi::CStr) -> bool {
        let mut result = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                marmot_c::commands::marmot_chat_list_row(
                    self.client,
                    self.account.as_ptr(),
                    group.as_ptr(),
                    &mut result,
                )
            },
            MarmotStatus::Ok
        );
        assert!(!result.is_null());
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr((*result).group_id_hex) },
            group
        );
        let archived = unsafe { (*result).archived };
        unsafe { marmot_c::types::chat_list::marmot_chat_list_row_free(result) };
        archived
    }
}
impl Drop for ClientFixture {
    fn drop(&mut self) {
        unsafe {
            marmot_client_shutdown(self.client);
            marmot_client_free(self.client);
        }
    }
}

// Only queue position is compared for unrelated events. The explicit archive
// markers additionally pin known account/group/trigger/state independently of
// the reference stream. No raw struct padding or freed record is inspected.
#[derive(Debug, PartialEq, Eq)]
struct EventKey {
    tag: u32,
    account: Option<String>,
    group: Option<String>,
    archive: Option<bool>,
}
unsafe fn event_key(value: &marmot_c::types::event::MarmotEvent) -> EventKey {
    use marmot_c::types::event::MarmotEvent;
    let tag = unsafe { *(value as *const MarmotEvent as *const u32) };
    let mut key = EventKey {
        tag,
        account: None,
        group: None,
        archive: None,
    };
    match value {
        MarmotEvent::ProjectionUpdated { update }
            if update.update.chat_list_trigger
                == marmot_c::types::chat_list::MarmotChatListUpdateTrigger::ArchiveChanged =>
        {
            key.account = Some(
                unsafe { std::ffi::CStr::from_ptr(update.account_id_hex) }
                    .to_str()
                    .expect("runtime identifiers are UTF-8")
                    .to_owned(),
            );
            key.group = Some(
                unsafe { std::ffi::CStr::from_ptr(update.update.group_id_hex) }
                    .to_str()
                    .expect("runtime identifiers are UTF-8")
                    .to_owned(),
            );
            if !update.update.chat_list_row.is_null() {
                key.archive = Some(unsafe { (*update.update.chat_list_row).archived });
            }
        }
        MarmotEvent::GroupStateUpdated {
            account_id_hex,
            group_id_hex,
            ..
        }
        | MarmotEvent::GroupJoined {
            account_id_hex,
            group_id_hex,
            ..
        }
        | MarmotEvent::GroupEvent {
            account_id_hex,
            group_id_hex,
            ..
        } => {
            key.account = Some(
                unsafe { std::ffi::CStr::from_ptr(*account_id_hex) }
                    .to_str()
                    .expect("runtime identifiers are UTF-8")
                    .to_owned(),
            );
            key.group = Some(
                unsafe { std::ffi::CStr::from_ptr(*group_id_hex) }
                    .to_str()
                    .expect("runtime identifiers are UTF-8")
                    .to_owned(),
            );
        }
        _ => {}
    }
    key
}
impl EventKey {
    fn marker(&self, account: &std::ffi::CStr, group: &std::ffi::CStr, archived: bool) -> bool {
        self.account.as_deref() == Some(account.to_str().unwrap())
            && self.group.as_deref() == Some(group.to_str().unwrap())
            && self.archive == Some(archived)
    }
}
struct Events(*mut MarmotEventsSubscription);
impl Events {
    fn new(client: *mut MarmotClient) -> Self {
        let mut sub = std::ptr::null_mut();
        assert_eq!(
            unsafe { marmot_subscribe_events(client, &mut sub) },
            MarmotStatus::Ok
        );
        assert!(!sub.is_null());
        Self(sub)
    }
    fn through(
        &self,
        account: &std::ffi::CStr,
        group: &std::ffi::CStr,
        archived: bool,
    ) -> Vec<EventKey> {
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        let mut prefix = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "produced archive fence did not arrive");
            let mut event = std::ptr::null_mut();
            let millis = u32::try_from(left.as_millis()).unwrap_or(u32::MAX).max(1);
            assert_eq!(
                unsafe { marmot_events_subscription_next(self.0, millis, &mut event) },
                MarmotStatus::Ok
            );
            assert!(!event.is_null());
            let key = unsafe { event_key(&*event) };
            unsafe { marmot_c::types::event::marmot_event_free(event) };
            let marker = key.marker(account, group, archived);
            prefix.push(key);
            if marker {
                return prefix;
            }
            assert!(
                prefix.len() <= 256,
                "bounded fixture must not lag its event buffer"
            );
        }
    }
}
impl Drop for Events {
    fn drop(&mut self) {
        unsafe { marmot_events_subscription_free(self.0) };
    }
}

#[test]
fn null_out_is_rejected_before_the_command_runs() {
    let mut fixture = ClientFixture::new();
    let client = fixture.client;
    let account = CString::new("npub1nobody").unwrap();
    let group = CString::new("00ff").unwrap();
    // Retain original guard precedence before establishing valid mutation.
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

    fixture.populate();
    assert!(!fixture.archived(&fixture.a));
    let status = unsafe {
        marmot_set_group_archived(
            client,
            fixture.account.as_ptr(),
            fixture.a.as_ptr(),
            1,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, MarmotStatus::NullPointer);
    assert!(
        !fixture.archived(&fixture.a),
        "invalid output cannot archive a valid group"
    );
    fixture.archive(&fixture.a, true);
    assert!(
        fixture.archived(&fixture.a),
        "positive control reaches the same valid mutation"
    );
}

#[test]
fn group_output_preflight() {
    unsafe {
        assert_eq!(
            marmot_pending_welcome_deliveries(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut()
            ),
            MarmotStatus::NullPointer
        );
        let mut pending = std::ptr::dangling_mut();
        assert_eq!(
            marmot_pending_welcome_deliveries(std::ptr::null(), std::ptr::null(), &raw mut pending),
            MarmotStatus::NullPointer
        );
        assert!(
            pending.is_null(),
            "output must be cleared before reading the client or account"
        );
        assert_eq!(
            marmot_group_app_component(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                0xf301,
                std::ptr::null_mut()
            ),
            MarmotStatus::NullPointer
        );
        assert_eq!(
            marmot_update_app_component(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                0xf301,
                std::ptr::null(),
                1,
                std::ptr::null_mut()
            ),
            MarmotStatus::NullPointer
        );
        let mut out = std::ptr::dangling_mut();
        assert_eq!(
            marmot_update_app_component(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                0xf301,
                std::ptr::null(),
                0,
                &raw mut out
            ),
            MarmotStatus::NullPointer
        );
        assert!(out.is_null());
    }
}

#[test]
fn null_out_is_rejected_before_a_subscription_read_dequeues() {
    let mut fixture = ClientFixture::new();
    let subject = Events::new(fixture.client);
    // Keep the original prompt-refusal assertion on a real empty stream.
    let started = Instant::now();
    let status = unsafe { marmot_events_subscription_next(subject.0, 5_000, std::ptr::null_mut()) };
    assert_eq!(status, MarmotStatus::NullPointer);
    assert!(
        started.elapsed().as_millis() < 1_000,
        "next() waited on the stream before validating its out-pointer"
    );

    fixture.populate();
    let reference = Events::new(fixture.client);
    fixture.archive(&fixture.a, true);
    let subject_alignment = subject.through(&fixture.account, &fixture.a, true);
    let reference_alignment = reference.through(&fixture.account, &fixture.a, true);
    assert!(
        subject_alignment
            .last()
            .unwrap()
            .marker(&fixture.account, &fixture.a, true)
    );
    assert!(
        reference_alignment
            .last()
            .unwrap()
            .marker(&fixture.account, &fixture.a, true)
    );

    // Both receivers now name the same broadcast position. Real unrelated
    // events remain in their observed prefixes instead of being guessed away.
    fixture.archive(&fixture.a, false);
    assert!(!fixture.archived(&fixture.a));
    let queued = reference.through(&fixture.account, &fixture.a, false);
    assert!(
        queued
            .last()
            .unwrap()
            .marker(&fixture.account, &fixture.a, false)
    );
    let status = unsafe { marmot_events_subscription_next(subject.0, 5_000, std::ptr::null_mut()) };
    assert_eq!(status, MarmotStatus::NullPointer);

    // A distinct produced fence turns a dropped head into an observed prefix
    // mismatch, rather than relying only on waiting for a missing item.
    fixture.archive(&fixture.b, true);
    assert!(fixture.archived(&fixture.b));
    let mut expected = queued;
    expected.extend(reference.through(&fixture.account, &fixture.b, true));
    let actual = subject.through(&fixture.account, &fixture.b, true);
    assert!(
        actual
            .iter()
            .any(|key| key.marker(&fixture.account, &fixture.a, false))
    );
    assert!(
        actual
            .last()
            .unwrap()
            .marker(&fixture.account, &fixture.b, true)
    );
    assert_eq!(
        actual, expected,
        "NULL output preserves the entire queued prefix and order"
    );
}

#[test]
fn prepared_media_snapshot_output_is_preflighted_before_any_input_is_used() {
    unsafe {
        assert_eq!(
            marmot_send_prepared_media_with_client_token(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::dangling(),
                usize::MAX,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::dangling(),
                std::ptr::null_mut(),
            ),
            MarmotStatus::NullPointer
        );
        let mut out = std::ptr::dangling_mut();
        assert_eq!(
            marmot_send_prepared_media_with_client_token(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::dangling(),
                usize::MAX,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::dangling(),
                &raw mut out,
            ),
            MarmotStatus::NullPointer
        );
        assert!(out.is_null());
    }
}
