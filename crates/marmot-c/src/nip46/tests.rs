use super::*;
use futures::StreamExt;
use nostr::nips::{nip44, nip46::NostrConnectUri};
use nostr::prelude::*;
use nostr_sdk::prelude::ClientNotification;
use serde_json::{Value, json};
use std::sync::Mutex;
use std::time::Duration;
use transport_nostr_adapter::network_proxy as process_proxy;

fn keys(byte: u8) -> Keys {
    Keys::new(SecretKey::from_hex(&format!("{byte:02x}").repeat(32)).unwrap())
}
fn response_to(author: &Keys, client: PublicKey, payload: Value) -> Event {
    let encrypted = nip44::encrypt(
        author.secret_key(),
        &client,
        payload.to_string(),
        nip44::Version::V2,
    )
    .unwrap();
    EventBuilder::new(Kind::NostrConnect, encrypted)
        .tag(client)
        .finalize(author)
        .unwrap()
}
#[derive(Default)]
struct Store(Mutex<Vec<(String, String, String)>>);
impl Store {
    unsafe fn input(value: *const c_char) -> String {
        unsafe { std::ffi::CStr::from_ptr(value) }
            .to_string_lossy()
            .into_owned()
    }
    unsafe extern "C" fn has(data: *mut std::ffi::c_void, key: *const c_char, out: *mut u8) -> u32 {
        let store = unsafe { &*data.cast::<Store>() };
        let key = unsafe { Self::input(key) };
        let Ok(entries) = store.0.lock() else {
            return crate::secret_store::MarmotSecretStoreStatus::Failed as u32;
        };
        unsafe {
            out.write(u8::from(
                entries
                    .iter()
                    .any(|(label, account, _)| label == &key || account == &key),
            ))
        };
        crate::secret_store::MarmotSecretStoreStatus::Ok as u32
    }
    unsafe extern "C" fn write(
        data: *mut std::ffi::c_void,
        label: *const c_char,
        account: *const c_char,
        secret: *const c_char,
    ) -> u32 {
        let store = unsafe { &*data.cast::<Store>() };
        let (label, account, secret) = unsafe {
            (
                Self::input(label),
                Self::input(account),
                Self::input(secret),
            )
        };
        let Ok(mut entries) = store.0.lock() else {
            return crate::secret_store::MarmotSecretStoreStatus::Failed as u32;
        };
        entries
            .retain(|(old_label, old_account, _)| old_label != &label && old_account != &account);
        entries.push((label, account, secret));
        crate::secret_store::MarmotSecretStoreStatus::Ok as u32
    }
    unsafe extern "C" fn load(
        data: *mut std::ffi::c_void,
        label: *const c_char,
        account: *const c_char,
        out: *mut *mut c_char,
    ) -> u32 {
        let store = unsafe { &*data.cast::<Store>() };
        let (label, account) = unsafe { (Self::input(label), Self::input(account)) };
        let Ok(entries) = store.0.lock() else {
            return crate::secret_store::MarmotSecretStoreStatus::Failed as u32;
        };
        let Some((_, _, secret)) = entries
            .iter()
            .find(|(l, a, _)| l == &label || a == &account)
        else {
            return crate::secret_store::MarmotSecretStoreStatus::NotFound as u32;
        };
        let Ok(secret) = std::ffi::CString::new(secret.as_str()) else {
            return crate::secret_store::MarmotSecretStoreStatus::Failed as u32;
        };
        unsafe { out.write(secret.into_raw()) };
        crate::secret_store::MarmotSecretStoreStatus::Ok as u32
    }
    unsafe extern "C" fn remove(
        data: *mut std::ffi::c_void,
        label: *const c_char,
        account: *const c_char,
    ) -> u32 {
        let store = unsafe { &*data.cast::<Store>() };
        let (label, account) = unsafe { (Self::input(label), Self::input(account)) };
        let Ok(mut entries) = store.0.lock() else {
            return crate::secret_store::MarmotSecretStoreStatus::Failed as u32;
        };
        entries.retain(|(l, a, _)| l != &label && a != &account);
        crate::secret_store::MarmotSecretStoreStatus::Ok as u32
    }
    unsafe extern "C" fn free(_: *mut std::ffi::c_void, value: *mut c_char) {
        drop(unsafe { std::ffi::CString::from_raw(value) });
    }
    unsafe extern "C" fn destroy(data: *mut std::ffi::c_void) {
        drop(unsafe { Arc::from_raw(data.cast::<Store>()) });
    }
}

struct OwnedClient(*mut MarmotClient);
impl OwnedClient {
    fn open(root: &std::path::Path, relay: &str, store: Arc<Store>) -> Self {
        let root = std::ffi::CString::new(root.to_str().unwrap()).unwrap();
        let relay = std::ffi::CString::new(relay).unwrap();
        let relays = [relay.as_ptr()];
        let data = Arc::into_raw(store).cast_mut().cast();
        let store = crate::secret_store::MarmotSecretStore {
            user_data: data,
            has_secret_for_label: Some(Store::has),
            has_secret_for_account_id: Some(Store::has),
            write_secret: Some(Store::write),
            load_secret: Some(Store::load),
            remove_secret: Some(Store::remove),
            free_secret: Some(Store::free),
            destroy: Some(Store::destroy),
        };
        let mut deployment = std::ptr::null_mut();
        assert_eq!(
            unsafe { crate::deployment::marmot_deployment_neutral(&mut deployment) },
            MarmotStatus::Ok
        );
        let mut client = std::ptr::null_mut();
        let status = unsafe {
            crate::marmot_client_new_with_options(
                root.as_ptr(),
                relays.as_ptr(),
                1,
                crate::MarmotRelayPolicy::AllowLoopback as u32,
                &store,
                deployment,
                &mut client,
            )
        };
        unsafe { crate::deployment::marmot_deployment_free(deployment) };
        if status != MarmotStatus::Ok {
            // The public constructor takes no host-context ownership on failure.
            unsafe { Store::destroy(data) };
        }
        assert_eq!(status, MarmotStatus::Ok);
        assert!(!client.is_null());
        Self(client)
    }
}
impl Drop for OwnedClient {
    fn drop(&mut self) {
        unsafe {
            let _ = crate::commands::marmot_client_shutdown_and_close(self.0);
            crate::marmot_client_free(self.0);
        }
    }
}
type PeerSessions = Arc<Mutex<Vec<Weak<Nip46SessionFfi>>>>;
struct CancelOnPeerFailure(PeerSessions);
impl Drop for CancelOnPeerFailure {
    fn drop(&mut self) {
        // A failed fixture task must interrupt real blocking callers rather
        // than leave them waiting for the production 90-second RPC timeout.
        for session in self.0.lock().unwrap().iter().filter_map(Weak::upgrade) {
            session.cancel();
        }
    }
}
struct OwnedSession(*mut MarmotNip46Session);
impl OwnedSession {
    fn open(client: &OwnedClient, config: &Value, peers: &PeerSessions) -> Self {
        let config = std::ffi::CString::new(config.to_string()).unwrap();
        let mut session = std::ptr::null_mut();
        assert_eq!(
            unsafe { marmot_nip46_new(client.0, config.as_ptr(), &mut session) },
            MarmotStatus::Ok
        );
        assert!(!session.is_null());
        peers
            .lock()
            .unwrap()
            .push(Arc::downgrade(&unsafe { &*session }.inner));
        let session = Self(session);
        session.approve();
        session
    }
    fn resume(client: &OwnedClient, account: &std::ffi::CStr, peers: &PeerSessions) -> Self {
        let mut session = std::ptr::null_mut();
        assert_eq!(
            unsafe { marmot_nip46_resume(client.0, account.as_ptr(), &mut session) },
            MarmotStatus::Ok
        );
        assert!(!session.is_null());
        peers
            .lock()
            .unwrap()
            .push(Arc::downgrade(&unsafe { &*session }.inner));
        Self(session)
    }
    fn approve(&self) {
        let mut out = std::ptr::null_mut();
        assert_eq!(
            unsafe { marmot_nip46_review_grants(self.0, &mut out) },
            MarmotStatus::Ok
        );
        let reviewed: Value = serde_json::from_str(&unsafe { take_string(out) }).unwrap();
        let grants = reviewed["grants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|grant| std::ffi::CString::new(grant.as_str().unwrap()).unwrap())
            .collect::<Vec<_>>();
        let pointers = grants
            .iter()
            .map(|grant| grant.as_ptr())
            .collect::<Vec<_>>();
        assert_eq!(
            unsafe {
                marmot_nip46_approve_grants(
                    self.0,
                    reviewed["version"].as_u64().unwrap() as u32,
                    pointers.as_ptr(),
                    pointers.len(),
                )
            },
            MarmotStatus::Ok
        );
    }
    fn connect(&self) -> String {
        let mut output = std::ptr::null_mut();
        assert_eq!(
            unsafe { marmot_nip46_connect(self.0, &mut output) },
            MarmotStatus::Ok
        );
        unsafe { take_string(output) }
    }
}
impl Drop for OwnedSession {
    fn drop(&mut self) {
        unsafe { marmot_nip46_free(self.0) };
    }
}
unsafe fn take_string(value: *mut c_char) -> String {
    assert!(!value.is_null());
    let result = unsafe { std::ffi::CStr::from_ptr(value) }
        .to_str()
        .unwrap()
        .to_owned();
    unsafe { crate::marmot_string_free(value) };
    result
}
unsafe fn account_snapshot(client: &OwnedClient) -> (String, bool, bool) {
    let mut output = std::ptr::null_mut();
    assert_eq!(
        unsafe { crate::commands::marmot_list_accounts(client.0, &mut output) },
        MarmotStatus::Ok
    );
    let list = unsafe { &*output };
    assert_eq!(list.len, 1);
    let account = unsafe { &*list.items };
    let result = (
        unsafe { std::ffi::CStr::from_ptr(account.account_id_hex) }
            .to_str()
            .unwrap()
            .into(),
        account.running,
        account.signed_out,
    );
    assert!(account.external_signing);
    assert!(!account.local_signing);
    unsafe { crate::types::account::marmot_account_summary_list_free(output) };
    result
}

fn assert_profile_signed(
    client: &OwnedClient,
    account: &std::ffi::CStr,
    name: &str,
    signed: &Mutex<Vec<Event>>,
    user: PublicKey,
) {
    let name = std::ffi::CString::new(name).unwrap();
    let profile = crate::types::account::MarmotUserProfileMetadata {
        name: name.as_ptr().cast_mut(),
        display_name: std::ptr::null_mut(),
        about: std::ptr::null_mut(),
        picture: std::ptr::null_mut(),
        banner: std::ptr::null_mut(),
        nip05: std::ptr::null_mut(),
        lud16: std::ptr::null_mut(),
    };
    let mut output = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            crate::commands::marmot_publish_user_profile_using_account_relays(
                client.0,
                account.as_ptr(),
                &profile,
                &mut output,
            )
        },
        MarmotStatus::Ok,
        "{:?}",
        crate::status::take_last_error()
    );
    assert!(!output.is_null());
    assert!(!unsafe { &*output }.name.is_null());
    assert_eq!(
        unsafe { std::ffi::CStr::from_ptr((*output).name) },
        name.as_c_str()
    );
    unsafe { crate::types::account::marmot_user_profile_metadata_free(output) };
    let signed = signed.lock().unwrap();
    let event = signed
        .iter()
        .find(|event| {
            serde_json::from_str::<Value>(&event.content).unwrap()["name"] == name.to_str().unwrap()
        })
        .expect("account did not request the edited profile signature");
    event.verify().unwrap();
    assert_eq!(event.pubkey, user);
    assert_eq!(event.kind, Kind::Metadata);
}

#[test]
fn nip46_owner_and_review() {
    let _audit = crate::memory::audit::test_lock();
    let root = tempfile::tempdir().unwrap();
    let other_root = tempfile::tempdir().unwrap();
    let client = OwnedClient::open(root.path(), "ws://127.0.0.1:1", Arc::new(Store::default()));
    let other = OwnedClient::open(
        other_root.path(),
        "ws://127.0.0.1:1",
        Arc::new(Store::default()),
    );
    let config = std::ffi::CString::new(r#"{"relays":["ws://127.0.0.1:1"]}"#).unwrap();
    let mut raw = std::ptr::null_mut();
    assert_eq!(
        unsafe { marmot_nip46_new(client.0, config.as_ptr(), &mut raw) },
        MarmotStatus::Ok
    );
    let session = OwnedSession(raw);
    let mut uri = std::ptr::dangling_mut();
    assert_eq!(
        unsafe { marmot_nip46_uri(session.0, &mut uri) },
        MarmotStatus::ExternalSignerRejected
    );
    assert!(uri.is_null());
    assert_eq!(
        unsafe { marmot_nip46_review_grants(session.0, std::ptr::null_mut()) },
        MarmotStatus::NullPointer
    );
    let required = unsafe { &*session.0 }.inner.permissions();
    let strings = required
        .grants
        .iter()
        .map(|grant| std::ffi::CString::new(grant.as_str()).unwrap())
        .collect::<Vec<_>>();
    let pointers = strings
        .iter()
        .map(|grant| grant.as_ptr())
        .collect::<Vec<_>>();
    assert_eq!(
        unsafe {
            marmot_nip46_approve_grants(
                session.0,
                required.version,
                pointers.as_ptr(),
                pointers.len(),
            )
        },
        MarmotStatus::ExternalSignerRejected
    );
    session.approve();
    let mut summary = std::ptr::dangling_mut();
    assert_eq!(
        unsafe {
            marmot_nip46_login(
                other.0,
                session.0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                &mut summary,
            )
        },
        MarmotStatus::InvalidArgument
    );
    assert!(summary.is_null());
    let account = std::ffi::CString::new("unknown").unwrap();
    assert_eq!(
        unsafe { marmot_nip46_register(other.0, account.as_ptr(), session.0) },
        MarmotStatus::InvalidArgument
    );
    assert_eq!(
        unsafe { marmot_nip46_cancel_request(session.0, account.as_ptr()) },
        MarmotStatus::InvalidArgument
    );
    assert_eq!(
        unsafe { marmot_nip46_complete_auth(session.0, account.as_ptr()) },
        MarmotStatus::InvalidArgument
    );
    assert_eq!(
        unsafe { marmot_nip46_resume(client.0, account.as_ptr(), std::ptr::null_mut()) },
        MarmotStatus::NullPointer
    );
    unsafe { marmot_nip46_cancel(session.0) };
    let mut user = std::ptr::dangling_mut();
    assert_eq!(
        unsafe { marmot_nip46_connect(session.0, &mut user) },
        MarmotStatus::ExternalSignerRejected
    );
    assert!(user.is_null());
    let mut status = std::ptr::null_mut();
    assert_eq!(
        unsafe { marmot_nip46_status(session.0, &mut status) },
        MarmotStatus::Ok
    );
    assert_eq!(unsafe { &*status }.state, MarmotNip46State::Cancelled);
    assert!(unsafe { &*status }.has_last_error);
    assert_eq!(unsafe { &*status }.last_error, MarmotNip46Error::Cancelled);
    unsafe { marmot_nip46_status_free(status) };
}

#[cfg(feature = "alloc-audit")]
#[test]
fn nip46_status_deep_free() {
    let _audit = crate::memory::audit::test_lock();
    let before = crate::memory::audit::live_allocations();
    let auth = memory::boxed(MarmotNip46Status::from(Nip46StatusFfi {
        state: Nip46StateFfi::Approval,
        last_error: None,
        auth_url: Some("https://signer.example/approve".into()),
        request_id: Some("request-7".into()),
        generation: 7,
    }));
    unsafe {
        marmot_nip46_status_free(auth);
        marmot_nip46_status_free(std::ptr::null_mut());
    }
    assert_eq!(crate::memory::audit::live_allocations(), before);
}

#[test]
fn nip46_live_lifecycle() {
    let _audit = crate::memory::audit::test_lock();
    #[cfg(feature = "alloc-audit")]
    let before = crate::memory::audit::live_allocations();
    let peer_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let relay = nostr_relay_builder::LocalRelay::new(
        nostr_relay_builder::RelayBuilder::default().rate_limit(
            nostr_relay_builder::builder::RateLimit {
                notes_per_minute: 1_000,
                ..Default::default()
            },
        ),
    );
    peer_runtime.block_on(relay.run()).unwrap();
    let url = peer_runtime.block_on(relay.url()).to_string();
    let remote = keys(2);
    let user = keys(3);
    let client_a = keys(1);
    let client_b = keys(4);
    let peer = process_proxy::nostr_builder(Ok(None)).build();
    let mut notifications = peer.notifications();
    peer_runtime.block_on(async {
        peer.add_relay(url.as_str()).await.unwrap();
        peer.connect().and_wait(Duration::from_secs(5)).await;
        // This existing Nostr identity advertises both relay lists before
        // MDK logs it in; no directory/mock shortcut supplies them.
        for (kind, tag) in [(Kind::from(10_002), "r"), (Kind::from(10_050), "relay")] {
            let declaration = EventBuilder::new(kind, "")
                .tag(Tag::parse([tag, url.as_str()]).unwrap())
                .finalize(&user)
                .unwrap();
            assert!(
                !peer
                    .send_event(&declaration)
                    .await
                    .unwrap()
                    .success
                    .is_empty()
            );
        }
        peer.subscribe(
            Filter::new()
                .kind(Kind::NostrConnect)
                .pubkey(remote.public_key()),
        )
        .await
        .unwrap();
    });
    let observed = Arc::new(Mutex::new(Vec::<(PublicKey, String, Option<Kind>)>::new()));
    let signed_profiles = Arc::new(Mutex::new(Vec::<Event>::new()));
    let peers = PeerSessions::default();
    let peer_task = {
        let peer = peer.clone();
        let remote = remote.clone();
        let user = user.clone();
        let observed = observed.clone();
        let signed_profiles = signed_profiles.clone();
        let url = url.clone();
        let peers = peers.clone();
        peer_runtime.spawn(async move {
                let _cancel_on_failure = CancelOnPeerFailure(peers);
                let mut connected = std::collections::HashMap::<PublicKey, std::collections::HashSet<String>>::new();
                let mut used_secrets = std::collections::HashSet::new();
                while let Some(notification) = notifications.next().await {
                    let ClientNotification::Event { event, .. } = notification else { continue };
                    event.verify().unwrap();
                    let receiver = event.pubkey;
                    let plaintext = nip44::decrypt(remote.secret_key(), &receiver, &event.content).unwrap();
                    let request: Value = serde_json::from_str(&plaintext).unwrap();
                    let id = request["id"].as_str().unwrap();
                    let method = request["method"].as_str().unwrap();
                    let params = request["params"].as_array().unwrap();
                    let kind = if method == "sign_event" {
                        let unsigned: Value = serde_json::from_str(params[0].as_str().unwrap()).unwrap();
                        Some(serde_json::from_value::<Kind>(unsigned["kind"].clone()).unwrap())
                    } else { None };
                    observed.lock().unwrap().push((receiver, method.into(), kind));
                    let permission = match method {
                        "sign_event" => Some(format!("sign_event:{}", kind.unwrap().as_u16())),
                        "nip44_encrypt" | "nip44_decrypt" => Some(method.into()),
                        _ => None,
                    };
                    let authorized = if method == "connect" {
                        let secret = params.get(1).and_then(Value::as_str);
                        let permissions = params.get(2).and_then(Value::as_str);
                        if let (Some(secret), Some(permissions)) = (secret, permissions)
                            && params.first().and_then(Value::as_str) == Some(remote.public_key().to_hex().as_str())
                            && matches!(secret, "fixture-a" | "fixture-b" | "fixture-c")
                            && !connected.contains_key(&receiver)
                            && used_secrets.insert(secret.to_owned())
                        {
                            connected.insert(receiver, permissions.split(',').map(str::to_owned).collect());
                            true
                        } else { false }
                    } else {
                        connected.get(&receiver).is_some_and(|permissions| permission.as_ref().is_none_or(|permission| permissions.contains(permission)))
                    };
                    if !authorized {
                        let denied = response_to(&remote, receiver, json!({"id":id,"error":"unauthorized"}));
                        assert!(!peer.send_event(&denied).await.unwrap().success.is_empty());
                        continue;
                    }
                    let result = match method {
                        "connect" => json!("ack"),
                        "ping" => json!("pong"),
                        "get_public_key" => {
                            // A genuine encrypted but unrelated response must be
                            // ignored by the live RPC loop, not pinned as the user.
                            let unrelated = response_to(&remote, receiver, json!({"id":"unrelated-request", "result":keys(9).public_key().to_hex()}));
                            assert!(!peer.send_event(&unrelated).await.unwrap().success.is_empty());
                            json!(user.public_key().to_hex())
                        }
                        "switch_relays" => json!(json!([url]).to_string()),
                        "sign_event" => {
                            let value: Value = serde_json::from_str(params[0].as_str().unwrap()).unwrap();
                            let kind = serde_json::from_value::<Kind>(value["kind"].clone()).unwrap();
                            let tags = serde_json::from_value::<Tags>(value["tags"].clone()).unwrap();
                            let at = serde_json::from_value::<Timestamp>(value["created_at"].clone()).unwrap();
                            let signed = EventBuilder::new(kind, value["content"].as_str().unwrap()).tags(tags).custom_created_at(at).finalize(&user).unwrap();
                            let result = json!(signed.as_json());
                            if kind == Kind::Metadata {
                                signed_profiles.lock().unwrap().push(signed);
                            }
                            result
                        }
                        "nip44_encrypt" => {
                            let to = PublicKey::from_hex(params[0].as_str().unwrap()).unwrap();
                            json!(nip44::encrypt(user.secret_key(), &to, params[1].as_str().unwrap(), nip44::Version::V2).unwrap())
                        }
                        "nip44_decrypt" => {
                            let from = PublicKey::from_hex(params[0].as_str().unwrap()).unwrap();
                            json!(nip44::decrypt(user.secret_key(), &from, params[1].as_str().unwrap()).unwrap())
                        }
                        "logout" => { connected.remove(&receiver); json!("ack") },
                        other => panic!("unimplemented fixture RPC: {other}"),
                    };
                    let response = response_to(&remote, receiver, json!({"id":id,"result":result}));
                    assert!(!peer.send_event(&response).await.unwrap().success.is_empty());
                }
            })
    };
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::default());
    let client = OwnedClient::open(root.path(), &url, store.clone());
    let uri = |secret: &str| {
        NostrConnectUri::Bunker {
            remote_signer_public_key: remote.public_key(),
            relays: vec![RelayUrl::parse(&url).unwrap()],
            secret: Some(secret.into()),
        }
        .to_string()
    };
    let session = OwnedSession::open(
        &client,
        &json!({"uri":uri("fixture-a"),"client_secret":client_a.secret_key().to_secret_hex()}),
        &peers,
    );
    let independent = OwnedSession::open(
        &client,
        &json!({"uri":uri("fixture-b"),"client_secret":client_b.secret_key().to_secret_hex()}),
        &peers,
    );
    assert_eq!(session.connect(), user.public_key().to_hex());
    assert_eq!(independent.connect(), user.public_key().to_hex());
    let relay_text = std::ffi::CString::new(url.as_str()).unwrap();
    let relays = [relay_text.as_ptr()];
    let mut summary = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            marmot_nip46_login(
                client.0,
                session.0,
                relays.as_ptr(),
                1,
                relays.as_ptr(),
                1,
                relays.as_ptr(),
                1,
                &mut summary,
            )
        },
        MarmotStatus::Ok,
        "{:?}",
        crate::status::take_last_error()
    );
    let account = unsafe { &*summary };
    let account_ref =
        std::ffi::CString::new(unsafe { std::ffi::CStr::from_ptr(account.label) }.to_bytes())
            .unwrap();
    assert_eq!(
        unsafe { std::ffi::CStr::from_ptr(account.account_id_hex) }
            .to_str()
            .unwrap(),
        user.public_key().to_hex()
    );
    assert_eq!(
        (
            account.external_signing,
            account.local_signing,
            account.signed_out
        ),
        (true, false, false)
    );
    unsafe { crate::types::account::marmot_account_summary_free(summary) };
    assert_eq!(
        unsafe { account_snapshot(&client) },
        (user.public_key().to_hex(), true, false)
    );
    for expected in [450, 30_443] {
        assert!(
            observed
                .lock()
                .unwrap()
                .iter()
                .any(|(sender, method, kind)| *sender == client_a.public_key()
                    && method == "sign_event"
                    && kind.is_some_and(|kind| kind.as_u16() == expected)),
            "login did not request signed kind {expected}"
        );
    }
    let mut export = std::ptr::null_mut();
    assert_eq!(
        unsafe { marmot_nip46_export(session.0, &mut export) },
        MarmotStatus::Ok
    );
    let export = unsafe { take_string(export) };
    let saved: Value = serde_json::from_str(&export).unwrap();
    assert_eq!(
        saved["client_secret"],
        client_a.secret_key().to_secret_hex()
    );
    assert_eq!(saved["user_public_key"], user.public_key().to_hex());
    assert_eq!(
        saved["remote_signer_public_key"],
        remote.public_key().to_hex()
    );
    assert!(
        saved.get("uri").is_none()
            && !export.contains("fixture-a")
            && !export.contains("fixture-b")
    );
    drop(independent);
    let resumed = OwnedSession::resume(&client, &account_ref, &peers);
    drop(session);
    assert_profile_signed(
        &client,
        &account_ref,
        "after-original-free",
        &signed_profiles,
        user.public_key(),
    );
    assert_eq!(unsafe { marmot_nip46_ping(resumed.0) }, MarmotStatus::Ok);
    let retained = OwnedSession::resume(&client, &account_ref, &peers);
    drop(resumed);
    assert_profile_signed(
        &client,
        &account_ref,
        "after-resumed-free",
        &signed_profiles,
        user.public_key(),
    );
    assert_eq!(unsafe { marmot_nip46_ping(retained.0) }, MarmotStatus::Ok);
    drop(retained);
    assert_profile_signed(
        &client,
        &account_ref,
        "after-final-handle-free",
        &signed_profiles,
        user.public_key(),
    );
    drop(client);
    assert!(
        !observed
            .lock()
            .unwrap()
            .iter()
            .any(|(_, method, _)| method == "logout")
    );
    let client = OwnedClient::open(root.path(), &url, store);
    assert_eq!(
        unsafe { crate::marmot_client_start(client.0) },
        MarmotStatus::Ok
    );
    assert_eq!(
        unsafe { account_snapshot(&client) },
        (user.public_key().to_hex(), true, false)
    );
    let resumed = OwnedSession::resume(&client, &account_ref, &peers);
    assert_eq!(resumed.connect(), user.public_key().to_hex());
    let retained = OwnedSession::resume(&client, &account_ref, &peers);
    unsafe { marmot_nip46_cancel(resumed.0) };
    assert_eq!(
        unsafe { marmot_nip46_ping(retained.0) },
        MarmotStatus::ExternalSignerRejected
    );
    let mut status = std::ptr::null_mut();
    assert_eq!(
        unsafe { marmot_nip46_status(retained.0, &mut status) },
        MarmotStatus::Ok
    );
    assert!(unsafe { &*status }.has_last_error);
    assert_eq!(unsafe { &*status }.last_error, MarmotNip46Error::Cancelled);
    unsafe { marmot_nip46_status_free(status) };
    drop(retained);
    drop(resumed);
    assert_eq!(
        unsafe { marmot_nip46_remove(client.0, account_ref.as_ptr()) },
        MarmotStatus::Ok
    );
    let session = OwnedSession::open(&client, &saved, &peers);
    assert_eq!(session.connect(), user.public_key().to_hex());
    assert_eq!(
        unsafe { marmot_nip46_register(client.0, account_ref.as_ptr(), session.0) },
        MarmotStatus::Ok
    );
    assert_eq!(
        unsafe { account_snapshot(&client) },
        (user.public_key().to_hex(), true, false)
    );
    let courtesy_keys = keys(5);
    let courtesy = OwnedSession::open(
        &client,
        &json!({"uri":uri("fixture-c"),"client_secret":courtesy_keys.secret_key().to_secret_hex()}),
        &peers,
    );
    assert_eq!(courtesy.connect(), user.public_key().to_hex());
    assert_eq!(unsafe { marmot_nip46_logout(courtesy.0) }, MarmotStatus::Ok);
    drop(courtesy);
    let mut signed_out = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            crate::commands::marmot_sign_out(client.0, account_ref.as_ptr(), 0, &mut signed_out)
        },
        MarmotStatus::Ok
    );
    unsafe { crate::types::account::marmot_sign_out_outcome_free(signed_out) };
    assert_eq!(
        unsafe { account_snapshot(&client) },
        (user.public_key().to_hex(), false, true)
    );
    assert_eq!(
        unsafe { marmot_nip46_logout(session.0) },
        MarmotStatus::ExternalSignerUnavailable
    );
    let mut erased = std::ptr::dangling_mut();
    assert_eq!(
        unsafe { marmot_nip46_export(session.0, &mut erased) },
        MarmotStatus::ExternalSignerUnavailable
    );
    assert!(erased.is_null());
    let mut state = std::ptr::null_mut();
    assert_eq!(
        unsafe { marmot_nip46_state(session.0, &mut state) },
        MarmotStatus::Ok
    );
    let state: Value = serde_json::from_str(&unsafe { take_string(state) }).unwrap();
    assert_eq!(state["state"], "logged_out");
    drop(session);
    drop(client);
    let history = observed.lock().unwrap();
    assert!(
        history
            .iter()
            .any(|(sender, method, _)| *sender == client_a.public_key() && method == "sign_event")
    );
    assert_eq!(
        history
            .iter()
            .filter(|(_, method, _)| method == "connect")
            .count(),
        3
    );
    let logout_senders = history
        .iter()
        .filter(|(_, method, _)| method == "logout")
        .map(|(sender, _, _)| *sender)
        .collect::<Vec<_>>();
    assert_eq!(logout_senders, vec![courtesy_keys.public_key()]);
    drop(history);
    peer_task.abort();
    peer_runtime.block_on(async {
        assert!(peer_task.await.unwrap_err().is_cancelled());
        peer.disconnect().await;
    });
    #[cfg(feature = "alloc-audit")]
    assert_eq!(crate::memory::audit::live_allocations(), before);
}
