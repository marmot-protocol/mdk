//! Phase 1 verification smoke test.
//!
//! Opens a fresh Marmot kit in a tempdir, exercises the methods that don't
//! require an external relay (constructor, listAccounts, shutdown), and
//! confirms the empty case lifecycle behaves as expected.
//!
//! Full multi-device send/receive coverage lives in marmot-app's own
//! integration tests against a built-in nostr-relay-builder relay. The job
//! here is just to prove the FFI boundary itself is alive.

use std::sync::{Arc, Once};

use marmot_uniffi::{Marmot, MediaReferenceFfi, MediaUploadRequestFfi};

/// `Marmot::new` opens a Keychain-backed secret store, which on the real
/// targets (iOS/macOS) is always present but in headless CI (Linux Secret
/// Service, no D-Bus daemon) is not. Install an in-memory mock as the default
/// keyring store before constructing; `AccountHome` short-circuits its own
/// platform init when a default store already exists, so this exercises the
/// real constructor path on every platform without touching a real keychain.
fn install_mock_keyring() {
    static KEYRING_INIT: Once = Once::new();
    KEYRING_INIT.call_once(|| {
        if keyring_core::get_default_store().is_none() {
            let store = keyring_core::mock::Store::new().expect("create mock keyring store");
            keyring_core::set_default_store(store);
        }
    });
}

#[tokio::test]
async fn empty_kit_lifecycle() {
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kit: Arc<Marmot> = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");

    // Fresh kit should be openable and report no accounts.
    let accounts = kit.list_accounts().expect("list_accounts on empty kit");
    assert!(
        accounts.is_empty(),
        "expected no accounts on a brand-new root, got {:?}",
        accounts
    );

    // Shutdown must succeed even before start() — the constructor does no I/O
    // beyond opening the account-home dir, so there's nothing to tear down.
    kit.shutdown().await;
}

#[test]
fn display_name_is_none_for_unknown_account() {
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kit = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");

    // A hex string that doesn't match any known account should produce None.
    let name =
        kit.display_name("0000000000000000000000000000000000000000000000000000000000000000".into());
    assert!(
        name.is_none(),
        "expected None for unknown account, got {:?}",
        name
    );
}

#[tokio::test]
async fn media_binding_records_are_public_and_methods_validate_group_hex() {
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kit = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");

    let reference = MediaReferenceFfi {
        url: "https://blossom.example/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        file_hash_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        nonce_hex: "bbbbbbbbbbbbbbbbbbbbbbbb".into(),
        file_name: "note.txt".into(),
        media_type: "text/plain".into(),
        version: "mip04-v2".into(),
    };
    let request = MediaUploadRequestFfi {
        file_name: "note.txt".into(),
        media_type: "text/plain".into(),
        plaintext: b"note".to_vec(),
        caption: Some("caption".into()),
        send: true,
        blossom_server: Some("https://blossom.primal.net".into()),
    };

    let send_error = kit
        .send_media_reference("alice".into(), "not-hex".into(), reference, None)
        .await
        .expect_err("invalid group hex should fail before sending");
    assert!(format!("{send_error}").contains("invalid hex"));

    let upload_error = kit
        .upload_media("alice".into(), "not-hex".into(), request)
        .await
        .expect_err("invalid group hex should fail before upload");
    assert!(format!("{upload_error}").contains("invalid hex"));
}

#[tokio::test]
async fn relay_list_binding_methods_are_public() {
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kit = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");
    let relays = vec!["wss://relay.invalid.test".to_string()];

    assert!(kit.account_nip65_relays("missing".into()).is_err());
    assert!(kit.account_inbox_relays("missing".into()).is_err());
    assert!(kit.account_key_package_relays("missing".into()).is_err());
    assert!(
        kit.set_account_nip65_relays("missing".into(), relays.clone(), relays.clone())
            .await
            .is_err()
    );
    assert!(
        kit.set_account_inbox_relays("missing".into(), relays.clone(), relays.clone())
            .await
            .is_err()
    );
    assert!(
        kit.set_account_key_package_relays("missing".into(), relays.clone(), relays)
            .await
            .is_err()
    );
}
