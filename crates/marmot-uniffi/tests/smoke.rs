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

use marmot_account::AccountHome;
use marmot_uniffi::{
    AuditLogSettingsFfi, AuditLogTrackerConfigFfi, AuditLogUploadSourceFfi, Marmot, MarmotKitError,
    MediaAttachmentReferenceFfi, MediaLocatorFfi, MediaUploadAttachmentRequestFfi,
    MediaUploadRequestFfi, NotificationWakeSourceFfi, PushPlatformFfi, RelayTelemetrySettingsFfi,
    TimelineMessageQueryFfi,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

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

struct CapturedAuditUpload {
    method: String,
    path: String,
    authorization: Option<String>,
    content_type: Option<String>,
    account_label: Option<String>,
    device_label: Option<String>,
    platform: Option<String>,
    app_version: Option<String>,
    body: Vec<u8>,
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn header_value(headers: &str, name: &str) -> Option<String> {
    headers.lines().find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        candidate
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

async fn capture_audit_upload(listener: TcpListener, tx: oneshot::Sender<CapturedAuditUpload>) {
    let Ok((mut stream, _)) = listener.accept().await else {
        return;
    };
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        buf.extend_from_slice(&chunk[..read]);

        let Some(header_end) = find_subsequence(&buf, b"\r\n\r\n").map(|pos| pos + 4) else {
            continue;
        };
        let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|value| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        while buf.len() < header_end + content_length {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => buf.extend_from_slice(&chunk[..read]),
            }
        }

        let request_line = headers.lines().next().unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_owned();
        let path = parts.next().unwrap_or_default().to_owned();
        let authorization = header_value(&headers, "authorization");
        let content_type = header_value(&headers, "content-type");
        let account_label = header_value(&headers, "x-goggles-account-label");
        let device_label = header_value(&headers, "x-goggles-device-label");
        let platform = header_value(&headers, "x-goggles-platform");
        let app_version = header_value(&headers, "x-goggles-app-version");
        let body = buf[header_end..header_end + content_length].to_vec();

        let _ = stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await;
        let _ = stream.shutdown().await;
        let _ = tx.send(CapturedAuditUpload {
            method,
            path,
            authorization,
            content_type,
            account_label,
            device_label,
            platform,
            app_version,
            body,
        });
        return;
    }
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
    assert!(kit.is_stopping());
    assert!(matches!(
        kit.start()
            .await
            .expect_err("start after shutdown should be refused"),
        MarmotKitError::RuntimeStopping
    ));
}

#[tokio::test]
async fn remove_account_updates_list_accounts() {
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kit = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");
    let account = AccountHome::open_with_default_keychain(tmp.path())
        .expect("open account home")
        .create_nostr_account()
        .expect("create local account");
    assert_eq!(kit.list_accounts().expect("list accounts").len(), 1);

    kit.remove_account(account.label.clone())
        .await
        .expect("remove account");

    assert!(
        kit.list_accounts()
            .expect("list accounts after removal")
            .is_empty()
    );
    assert!(matches!(
        kit.remove_account(account.label)
            .await
            .expect_err("removed account should be unknown"),
        MarmotKitError::UnknownAccount { .. }
    ));
}

#[tokio::test]
async fn account_unread_summary_reports_local_accounts_without_session_load() {
    // darkmatter#461: the account-switcher badge query must work for accounts
    // that have never been started/loaded. A fresh local account with no
    // messages reports zero unread, and the call does not require start().
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kit = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");

    // Empty kit: no accounts, so no unread entries.
    assert!(
        kit.account_unread_summary()
            .expect("unread summary on empty kit")
            .is_empty()
    );

    let account = AccountHome::open_with_default_keychain(tmp.path())
        .expect("open account home")
        .create_nostr_account()
        .expect("create local account");

    // The account is not running (no start()/reconcile()), yet it is reported
    // with a zero unread count read from its on-disk projection.
    let summary = kit
        .account_unread_summary()
        .expect("unread summary with one account");
    assert_eq!(summary.len(), 1);
    let entry = &summary[0];
    assert_eq!(entry.account_id_hex, account.account_id_hex);
    assert_eq!(entry.unread_count, 0);
    assert_eq!(entry.unread_conversations, 0);
    assert!(!entry.has_unread);
}

#[tokio::test]
async fn login_existing_identity_returns_duplicate_identity_error() {
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";
    let existing = AccountHome::open(tmp.path())
        .import_nostr_account(nsec)
        .expect("seed existing account");
    let kit = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");

    assert!(matches!(
        kit.login(nsec.to_string(), Vec::new(), Vec::new())
            .await
            .expect_err("duplicate login should fail"),
        MarmotKitError::DuplicateIdentity { account } if account == existing.account_id_hex
    ));
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

#[test]
fn normalize_member_ref_accepts_profile_and_nostr_forms() {
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kit = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");
    let account_id = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
    let npub = "npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy";

    for reference in [
        account_id.to_string(),
        npub.to_string(),
        format!("nostr:{npub}"),
        format!("darkmatter://profile/{npub}?from=qr"),
    ] {
        let normalized = kit
            .normalize_member_ref(reference.clone())
            .expect("normalize member ref");
        assert_eq!(normalized.member_ref, account_id);
        assert_eq!(normalized.account_id_hex, account_id);
        assert_eq!(normalized.npub, npub);
        assert_eq!(
            kit.account_id_hex(reference),
            Some(account_id.to_string()),
            "legacy account_id_hex should accept the same references"
        );
    }

    assert!(matches!(
        kit.normalize_member_ref("not-a-member-ref".into())
            .expect_err("invalid member ref should fail"),
        MarmotKitError::InvalidIdentity { .. }
    ));
}

#[tokio::test]
async fn delete_group_local_binding_is_public_and_validates_group_hex() {
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kit = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");

    let error = kit
        .delete_group_local("alice".into(), "not-hex".into())
        .await
        .expect_err("invalid group hex should fail before local delete");
    assert!(format!("{error}").contains("invalid hex"));
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

    let reference = MediaAttachmentReferenceFfi {
        locators: vec![MediaLocatorFfi {
            kind: "blossom-v1".into(),
            value: "https://blossom.example/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        }],
        ciphertext_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        plaintext_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        nonce_hex: "bbbbbbbbbbbbbbbbbbbbbbbb".into(),
        file_name: "note.txt".into(),
        media_type: "text/plain".into(),
        version: "encrypted-media-v1".into(),
        source_epoch: 0,
        dim: None,
        thumbhash: None,
    };
    let request = MediaUploadRequestFfi {
        attachments: vec![MediaUploadAttachmentRequestFfi {
            file_name: "note.txt".into(),
            media_type: "text/plain".into(),
            plaintext: b"note".to_vec(),
            dim: None,
            thumbhash: None,
        }],
        caption: Some("caption".into()),
        send: true,
        blossom_server: Some("https://blossom.primal.net".into()),
    };

    let send_error = kit
        .send_media_attachments(
            "alice".into(),
            "not-hex".into(),
            vec![reference.clone()],
            None,
        )
        .await
        .expect_err("invalid group hex should fail before sending");
    assert!(format!("{send_error}").contains("invalid hex"));

    let singular_send_error = kit
        .send_media_reference("alice".into(), "not-hex".into(), reference, None)
        .await
        .expect_err("singular compatibility helper should validate group hex");
    assert!(format!("{singular_send_error}").contains("invalid hex"));

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
    assert!(
        kit.set_account_nip65_relays("missing".into(), relays.clone(), relays.clone())
            .await
            .is_err()
    );
    assert!(
        kit.set_account_inbox_relays("missing".into(), relays.clone(), relays)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn notification_binding_methods_are_public_and_validate_missing_accounts() {
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kit = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");

    assert!(kit.notification_settings("missing".into()).is_err());
    assert!(
        kit.set_local_notifications_enabled("missing".into(), true)
            .is_err()
    );
    assert!(
        kit.set_native_push_enabled("missing".into(), true)
            .await
            .is_err()
    );
    assert!(kit.push_registration("missing".into()).is_err());
    assert!(
        kit.upsert_push_registration(
            "missing".into(),
            PushPlatformFfi::Fcm,
            "opaque-token".into(),
            "00".repeat(32),
            None,
        )
        .await
        .is_err()
    );
    assert!(kit.clear_push_registration("missing".into()).await.is_err());
    assert!(
        kit.group_push_debug_info("missing".into(), "00".repeat(32))
            .await
            .is_err()
    );

    let collected = kit
        .collect_notifications_after_wake(1, NotificationWakeSourceFfi::ManualCatchUp)
        .await
        .expect("empty wake collection should be valid");
    assert!(collected.notifications.is_empty());
    let _subscription = kit
        .subscribe_notifications()
        .await
        .expect("empty notification subscription should be valid");
}

#[tokio::test]
async fn relay_telemetry_settings_binding_round_trips() {
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kit = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");

    let settings = kit
        .relay_telemetry_settings()
        .expect("default telemetry settings");
    assert!(!settings.export_enabled);
    assert_eq!(settings.export_interval_seconds, 60);

    let stored = kit
        .set_relay_telemetry_settings(RelayTelemetrySettingsFfi {
            export_enabled: true,
            export_interval_seconds: 30,
        })
        .await
        .expect("set telemetry settings");
    assert!(stored.export_enabled);
    assert_eq!(stored.export_interval_seconds, 30);

    let reopened = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("reopen marmot kit");
    assert_eq!(
        reopened
            .relay_telemetry_settings()
            .expect("persisted telemetry settings")
            .export_interval_seconds,
        stored.export_interval_seconds
    );
}

#[tokio::test]
async fn audit_log_settings_binding_round_trips() {
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kit = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");

    let settings = kit.audit_log_settings().expect("default audit settings");
    assert!(!settings.enabled);

    let stored = kit
        .set_audit_log_settings(AuditLogSettingsFfi { enabled: true })
        .await
        .expect("set audit settings");
    assert!(stored.enabled);

    let reopened = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("reopen marmot kit");
    assert!(
        reopened
            .audit_log_settings()
            .expect("persisted audit settings")
            .enabled
    );
}

#[test]
fn audit_log_binding_lists_local_jsonl_logs() {
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kit = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");
    let account = AccountHome::open_with_default_keychain(tmp.path())
        .expect("open account home")
        .create_nostr_account()
        .expect("create local account");
    let audit_path = AccountHome::open_with_default_keychain(tmp.path())
        .expect("reopen account home")
        .account_dir(&account.label)
        .join("audit-binding.jsonl");
    std::fs::write(&audit_path, b"{\"seq\":1}\n").expect("write audit log");

    let files = kit.audit_log_files().expect("list audit logs");

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, audit_path.to_string_lossy());
    assert_eq!(files[0].file_name, "audit-binding.jsonl");
    assert!(files[0].size_bytes > 0);
}

#[tokio::test]
async fn audit_log_binding_posts_jsonl_file() {
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kit = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");
    let account = AccountHome::open_with_default_keychain(tmp.path())
        .expect("open account home")
        .create_nostr_account()
        .expect("create local account");
    let audit_body = b"{\"seq\":1}\n{\"seq\":2}\n";
    let audit_path = AccountHome::open_with_default_keychain(tmp.path())
        .expect("reopen account home")
        .account_dir(&account.label)
        .join("audit-binding-upload.jsonl");
    std::fs::write(&audit_path, audit_body).expect("write audit log");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(capture_audit_upload(listener, tx));

    let result = kit
        .post_audit_log_file(
            audit_path.to_string_lossy().into_owned(),
            format!("http://{addr}/ingest"),
        )
        .await
        .expect("post audit log through binding");

    assert_eq!(
        std::fs::canonicalize(&result.path).expect("canonical result path"),
        std::fs::canonicalize(&audit_path).expect("canonical audit path")
    );
    assert_eq!(result.status, 204);
    assert_eq!(result.bytes_sent, audit_body.len() as u64);
    let captured = rx.await.expect("captured upload");
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path, "/ingest");
    assert_eq!(
        captured.content_type.as_deref(),
        Some("application/x-ndjson")
    );
    assert_eq!(captured.body, audit_body);

    server.await.unwrap();
}

#[tokio::test]
async fn audit_log_binding_posts_tracker_update() {
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kit = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");
    let account = AccountHome::open_with_default_keychain(tmp.path())
        .expect("open account home")
        .create_nostr_account()
        .expect("create local account");
    let audit_body = b"{\"seq\":1}\n{\"seq\":2}\n";
    let audit_path = AccountHome::open_with_default_keychain(tmp.path())
        .expect("reopen account home")
        .account_dir(&account.label)
        .join("audit-binding-tracker.jsonl");
    std::fs::write(&audit_path, audit_body).expect("write audit log");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(capture_audit_upload(listener, tx));

    kit.set_audit_log_settings(AuditLogSettingsFfi { enabled: true })
        .await
        .expect("enable audit logs");
    kit.set_audit_log_tracker_config(AuditLogTrackerConfigFfi {
        endpoint: Some(format!("http://{addr}/api/v1/audit-logs/")),
        authorization_bearer_token: Some("goggles_binding_secret".to_owned()),
        source: AuditLogUploadSourceFfi {
            account_label: Some("Alice".to_owned()),
            device_label: Some("Alice iPhone".to_owned()),
            platform: Some("ios".to_owned()),
            app_version: Some("2026.6.8".to_owned()),
        },
    })
    .expect("configure audit tracker");

    let result = kit
        .post_audit_log_tracker_update()
        .await
        .expect("post tracker update");

    assert!(result.enabled);
    assert_eq!(result.skipped_reason, None);
    assert_eq!(result.uploaded.len(), 1);
    assert_eq!(result.uploaded[0].status, 204);
    assert_eq!(result.uploaded[0].bytes_sent, audit_body.len() as u64);
    let captured = rx.await.expect("captured upload");
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path, "/api/v1/audit-logs/");
    assert_eq!(
        captured.authorization.as_deref(),
        Some("Bearer goggles_binding_secret")
    );
    assert_eq!(
        captured.content_type.as_deref(),
        Some("application/x-ndjson")
    );
    assert_eq!(captured.account_label.as_deref(), Some("Alice"));
    assert_eq!(captured.device_label.as_deref(), Some("Alice iPhone"));
    assert_eq!(captured.platform.as_deref(), Some("ios"));
    assert_eq!(captured.app_version.as_deref(), Some("2026.6.8"));
    assert_eq!(captured.body, audit_body);

    server.await.unwrap();
}

#[tokio::test]
async fn timeline_binding_methods_are_public_and_validate_inputs() {
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kit = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");

    let missing_account = kit
        .timeline_messages(
            "missing".into(),
            TimelineMessageQueryFfi {
                limit: Some(25),
                ..TimelineMessageQueryFfi::default()
            },
        )
        .expect_err("missing account should fail");
    assert!(format!("{missing_account}").contains("missing"));

    let invalid_group = kit
        .timeline_messages(
            "missing".into(),
            TimelineMessageQueryFfi {
                group_id_hex: Some("not-hex".into()),
                limit: Some(25),
                ..TimelineMessageQueryFfi::default()
            },
        )
        .expect_err("invalid group hex should fail before account lookup");
    assert!(format!("{invalid_group}").contains("invalid hex"));

    let invalid_cursor = kit
        .timeline_messages(
            "missing".into(),
            TimelineMessageQueryFfi {
                before: Some(1),
                before_message_id: Some("not-hex".into()),
                limit: Some(25),
                ..TimelineMessageQueryFfi::default()
            },
        )
        .expect_err("invalid cursor hex should fail before account lookup");
    assert!(format!("{invalid_cursor}").contains("invalid hex"));

    let subscribe_error = match kit
        .subscribe_timeline_messages("missing".into(), None, Some(25))
        .await
    {
        Ok(_) => panic!("missing account subscription should fail"),
        Err(err) => err,
    };
    assert!(format!("{subscribe_error}").contains("missing"));
}

#[tokio::test]
async fn chat_list_binding_methods_are_public_and_validate_inputs() {
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kit = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");

    let missing_account = kit
        .chat_list("missing".into(), false)
        .expect_err("missing account should fail");
    assert!(format!("{missing_account}").contains("missing"));

    let invalid_group = kit
        .initialize_chat_read_state("missing".into(), "not-hex".into())
        .expect_err("invalid group hex should fail before account lookup");
    assert!(format!("{invalid_group}").contains("invalid hex"));

    let invalid_message = kit
        .mark_timeline_message_read("missing".into(), "00".repeat(32), "not-hex".into())
        .expect_err("invalid message hex should fail before account lookup");
    assert!(format!("{invalid_message}").contains("invalid hex"));

    let subscribe_error = match kit.subscribe_chat_list("missing".into(), false).await {
        Ok(_) => panic!("missing account subscription should fail"),
        Err(err) => err,
    };
    assert!(format!("{subscribe_error}").contains("missing"));
}

#[tokio::test]
async fn message_history_binding_methods_validate_group_hex() {
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kit = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");

    // Invalid group hex must be rejected with InvalidHex before the account
    // lookup, matching every other group-scoped FFI method (regression for
    // darkmatter#204: messages() previously passed the host string straight
    // into the query, silently yielding empty history).
    let invalid_group = kit
        .messages("missing".into(), Some("not-hex".into()), Some(25))
        .expect_err("invalid group hex should fail before account lookup");
    assert!(format!("{invalid_group}").contains("invalid hex"));

    let invalid_subscribe = match kit
        .subscribe_messages("missing".into(), Some("not-hex".into()), Some(25))
        .await
    {
        Ok(_) => panic!("invalid group hex subscription should fail"),
        Err(err) => err,
    };
    assert!(format!("{invalid_subscribe}").contains("invalid hex"));

    // Valid hex (even uppercase/whitespace-padded) gets past validation and
    // then fails on the missing account, proving the value was canonicalized
    // rather than treated as an opaque host string.
    let missing_account = kit
        .messages(
            "missing".into(),
            Some(format!(" {} ", "AB".repeat(32))),
            Some(25),
        )
        .expect_err("missing account should fail after hex validation");
    assert!(format!("{missing_account}").contains("missing"));
}

#[tokio::test]
async fn retry_group_convergence_binding_is_public_and_validates_inputs() {
    install_mock_keyring();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kit = Marmot::new(
        tmp.path().to_string_lossy().into_owned(),
        vec!["wss://relay.invalid.test".to_string()],
    )
    .expect("open marmot kit");

    // The convergence-retry binding (darkmatter#472) must reject invalid group
    // hex with InvalidHex before any account/runtime work, matching every other
    // group-scoped FFI method.
    let invalid_group = kit
        .retry_group_convergence("missing".into(), "not-hex".into())
        .await
        .expect_err("invalid group hex should fail before account lookup");
    assert!(format!("{invalid_group}").contains("invalid hex"));

    // Valid hex gets past validation and then fails on the missing account,
    // proving the value was decoded rather than treated as an opaque string.
    let missing_account = kit
        .retry_group_convergence("missing".into(), "AB".repeat(32))
        .await
        .expect_err("missing account should fail after hex validation");
    assert!(format!("{missing_account}").contains("missing"));
}
