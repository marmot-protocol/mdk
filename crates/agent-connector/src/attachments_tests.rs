use super::*;
use agent_control::{AgentControlAttachmentState, AgentControlResponse};
use sha2::{Digest, Sha256};
use storage_sqlite::{StoredAccountGroup, StoredAccountState, StoredAppEvent};

const GROUP: &str = "abababababababababababababababab";

async fn request(
    connector: &AgentConnector,
    payload: agent_control::AgentControlRequest,
) -> AgentControlResponse {
    let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
    let exchange = async {
        agent_control::write_frame(
            &mut client,
            &agent_control::AgentControlEnvelope::new(Some("attachment-test".into()), payload),
        )
        .await
        .unwrap();
        let response: agent_control::AgentControlEnvelope<AgentControlResponse> =
            agent_control::read_envelope(&mut tokio::io::BufReader::new(client))
                .await
                .unwrap()
                .unwrap();
        assert!(
            agent_control::encode_frame(&response).unwrap().len()
                <= agent_control::MAX_AGENT_CONTROL_FRAME_BYTES
        );
        response.payload
    };
    let (served, response) = tokio::join!(connector.handle_connection(server), exchange);
    served.unwrap();
    response
}

fn seed(connector: &AgentConnector, tags: Vec<Vec<String>>) {
    seed_with(connector, tags, |_| {});
}

fn seed_with(
    connector: &AgentConnector,
    tags: Vec<Vec<String>>,
    change: impl FnOnce(&storage_sqlite::SqliteAppStorage),
) {
    seed_with_epoch(connector, tags, Some(7), change);
}

fn seed_with_epoch(
    connector: &AgentConnector,
    tags: Vec<Vec<String>>,
    epoch: Option<u64>,
    change: impl FnOnce(&storage_sqlite::SqliteAppStorage),
) {
    // Seed a historical encrypted database before the runtime opens it. The
    // supported legacy-key migration makes the fixture independent of private
    // app storage handles; never open a second connection to a live app store.
    let keys = connector.account_home.load_signing_keys("agent").unwrap();
    let mut digest = Sha256::new();
    digest.update(b"marmot-app-sqlcipher-key-v1");
    digest.update(b"agent");
    digest.update(keys.public_key().to_bytes());
    digest.update(zeroize::Zeroizing::new(keys.secret_key().to_secret_bytes()));
    let key = storage_sqlite::SqlCipherKey::new(hex::encode(digest.finalize())).unwrap();
    let handle = storage_sqlite::SqliteAccountStorage::open_encrypted(
        connector
            .account_home
            .account_dir("agent")
            .join("session.sqlite"),
        &key,
    )
    .unwrap();
    let storage = handle.app_storage();
    storage
        .save_account_projection_state(
            &StoredAccountState {
                label: "agent".into(),
                groups: vec![StoredAccountGroup {
                    group_id_hex: GROUP.into(),
                    endpoint: String::new(),
                    profile_name: String::new(),
                    profile_description: String::new(),
                    image_hash_hex: String::new(),
                    image_key_hex: String::new(),
                    image_nonce_hex: String::new(),
                    image_upload_key_hex: String::new(),
                    image_media_type: None,
                    admin_keys_hex: String::new(),
                    archived: false,
                    pending_confirmation: false,
                    member_count: None,
                    direct_member_ids_hex: None,
                    presentation_member_ids_hex: None,
                    welcomer_account_id_hex: None,
                    via_welcome_message_id_hex: None,
                    nostr_routing_last_epoch: 0,
                    prior_nostr_routes: vec![],
                    self_membership: Default::default(),
                    components: vec![],
                }],
                ..Default::default()
            },
            100,
            300,
        )
        .unwrap();
    storage
        .record_app_event(&StoredAppEvent {
            group_id_hex: GROUP.into(),
            message_id_hex: "aa".repeat(32),
            source_message_id_hex: Some("bb".repeat(32)),
            source_epoch: epoch,
            direction: "received".into(),
            sender: "cc".repeat(32),
            plaintext: String::new(),
            kind: 9,
            tags,
            recorded_at: 10,
            received_at: 10,
            origin_commit_id: None,
            moderation_grant: false,
        })
        .unwrap();
    change(&storage);
    handle.close().unwrap();
}

#[tokio::test]
async fn historical_attachment_missing_source_epoch_never_fabricates_epoch_zero() {
    let dir = tempfile::tempdir().unwrap();
    let connector = AgentConnector::open(crate::tests::test_config(
        dir.path(),
        dir.path().join("dev/agent.sock"),
        vec![],
        false,
        false,
    ))
    .unwrap();
    let account = connector.account_home.create_account("agent").unwrap();
    seed_with_epoch(&connector, vec![tag(b"body")], None, |_| {});
    let error = connector
        .attachment_response(&account.account_id_hex, GROUP, &"aa".repeat(32), 0, true)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "attachment_epoch_unavailable");
    assert!(error.client_message().contains("original source epoch"));
    connector.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn historical_attachment_missing_key_failure_is_actionable_and_not_retried() {
    let dir = tempfile::tempdir().unwrap();
    let connector = AgentConnector::open(crate::tests::test_config(
        dir.path(),
        dir.path().join("dev/agent.sock"),
        vec![],
        false,
        false,
    ))
    .unwrap();
    let account = connector.account_home.create_account("agent").unwrap();
    seed_with(&connector, vec![tag(b"body")], |storage| {
        let entry = storage
            .attachment_history_page(GROUP, 64, None)
            .unwrap()
            .entries
            .remove(0);
        let storage_sqlite::AttachmentDemand::Requested(reference) = storage
            .request_explicit_attachment(GROUP, &entry, Sha256::digest(b"body").into(), 100)
            .unwrap()
        else {
            panic!("demand")
        };
        // This is the native worker's durable outcome after the original epoch
        // decryption material stays unavailable through its bounded deferrals.
        for turn in 0..6 {
            assert_eq!(
                storage
                    .defer_attachment_preparation(&reference, 100 + turn * 1000)
                    .unwrap(),
                turn == 5
            );
        }
    });
    for _ in 0..2 {
        let response = connector
            .attachment_response(&account.account_id_hex, GROUP, &"aa".repeat(32), 0, true)
            .await
            .unwrap();
        let AgentControlResponse::Attachment {
            attachment: Some(attachment),
        } = response
        else {
            panic!("attachment missing")
        };
        assert_eq!(attachment.state, AgentControlAttachmentState::Failed);
        assert!(attachment.handoff.is_none());
        assert!(
            attachment
                .failure_hint
                .unwrap()
                .contains("original epoch key")
        );
    }
    connector.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn historical_attachment_restart_handoff_is_verified_private_and_released() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let config = crate::tests::test_config(
        dir.path(),
        dir.path().join("dev/agent.sock"),
        vec![],
        false,
        false,
    );
    let connector = AgentConnector::open(config.clone()).unwrap();
    let account = connector.account_home.create_account("agent").unwrap();
    let bytes = b"the second attachment, not the first";
    seed_with(&connector, vec![tag(b"first"), tag(bytes)], |storage| {
        let entries = storage
            .attachment_history_page(GROUP, 64, None)
            .unwrap()
            .entries;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for (index, bytes) in [(0, b"first".as_slice()), (1, bytes.as_slice())] {
            let entry = entries
                .iter()
                .find(|entry| entry.attachment_index == index)
                .unwrap();
            let storage_sqlite::AttachmentDemand::Requested(reference) = storage
                .request_attachment_acquisition(GROUP, entry, Sha256::digest(bytes).into(), now)
                .unwrap()
            else {
                panic!("demand")
            };
            let job = storage
                .claim_attachment_acquisition(&reference, now, now + 60)
                .unwrap()
                .unwrap();
            storage
                .complete_attachment_acquisition(&job, bytes, now, 10_000_000)
                .unwrap();
        }
    });
    // The recovery uses durable native state, not a saved live-event reference.
    connector.runtime.shutdown_and_close().await.unwrap();
    drop(connector);
    let connector = AgentConnector::open(config).unwrap();
    let other = connector.account_home.create_account("other").unwrap();
    for (account_id, group_id) in [
        (&other.account_id_hex, GROUP),
        (&account.account_id_hex, "cdcd"),
    ] {
        assert!(matches!(
            connector
                .attachment_response(account_id, group_id, &"aa".repeat(32), 1, true)
                .await
                .unwrap(),
            AgentControlResponse::Attachment { attachment: None }
        ));
    }
    // Both identically named bodies are retained: each source slot must return
    // its own bytes, not just whichever body happens to be locally available.
    let first = connector
        .attachment_response(&account.account_id_hex, GROUP, &"aa".repeat(32), 0, true)
        .await
        .unwrap();
    let AgentControlResponse::Attachment {
        attachment: Some(first),
    } = first
    else {
        panic!("first attachment missing")
    };
    let first_copy = first.handoff.unwrap();
    assert_eq!(std::fs::read(&first_copy.path).unwrap(), b"first");
    assert_eq!(
        first.plaintext_sha256,
        hex::encode(Sha256::digest(b"first"))
    );
    connector
        .runtime
        .release_attachment_handoff(&first_copy.lease)
        .await
        .unwrap();
    let response = request(
        &connector,
        agent_control::AgentControlRequest::DownloadAttachment {
            account_id_hex: account.account_id_hex.clone(),
            group_id_hex: GROUP.into(),
            message_id_hex: "aa".repeat(32),
            attachment_index: 1,
        },
    )
    .await;
    let AgentControlResponse::Attachment {
        attachment: Some(attachment),
    } = response
    else {
        panic!("attachment missing")
    };
    let copy = attachment.handoff.unwrap();
    let path = std::path::Path::new(&copy.path);
    let actual = std::fs::read(path).unwrap();
    assert_eq!(actual, bytes);
    assert_eq!(copy.size_bytes, bytes.len() as u64);
    assert_eq!(
        attachment.plaintext_sha256,
        hex::encode(Sha256::digest(&actual))
    );
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let directory = path.parent().unwrap();
    let held = directory.with_extension("held");
    std::fs::rename(directory, &held).unwrap();
    std::fs::write(directory, b"temporarily blocked").unwrap();
    let failed_release = request(
        &connector,
        agent_control::AgentControlRequest::ReleaseAttachment {
            lease: copy.lease.clone(),
        },
    )
    .await;
    assert!(matches!(
        failed_release,
        AgentControlResponse::Error {
            retryable: true,
            ..
        }
    ));
    std::fs::remove_file(directory).unwrap();
    std::fs::rename(&held, directory).unwrap();
    for _ in 0..2 {
        assert_eq!(
            request(
                &connector,
                agent_control::AgentControlRequest::ReleaseAttachment {
                    lease: copy.lease.clone()
                }
            )
            .await,
            AgentControlResponse::AttachmentReleased
        );
    }
    assert!(!path.exists());
    // A client that disappears after submitting its request must not leave an
    // unreachable plaintext copy behind when writing the reply fails.
    let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
    agent_control::write_frame(
        &mut client,
        &agent_control::AgentControlEnvelope::new(
            Some("abandoned".into()),
            agent_control::AgentControlRequest::DownloadAttachment {
                account_id_hex: account.account_id_hex,
                group_id_hex: GROUP.into(),
                message_id_hex: "aa".repeat(32),
                attachment_index: 1,
            },
        ),
    )
    .await
    .unwrap();
    drop(client);
    assert!(connector.handle_connection(server).await.is_err());
    let handoff_dir = connector.account_home.account_dir("agent").join("handoff");
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while std::fs::read_dir(&handoff_dir).unwrap().next().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    connector.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn historical_attachment_scope_and_invalidated_sources_are_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let connector = AgentConnector::open(crate::tests::test_config(
        dir.path(),
        dir.path().join("dev/agent.sock"),
        vec![],
        false,
        false,
    ))
    .unwrap();
    let account = connector.account_home.create_account("agent").unwrap();
    let other = connector.account_home.create_account("other").unwrap();
    seed_with(&connector, vec![tag(b"body")], |storage| {
        storage
            .invalidate_app_event_by_message_id(GROUP, &"aa".repeat(32), "LosingBranch")
            .unwrap();
    });
    for (account, group) in [
        (&account.account_id_hex, GROUP),
        (&other.account_id_hex, GROUP),
        (&account.account_id_hex, "cdcd"),
    ] {
        let response = connector
            .attachment_response(account, group, &"aa".repeat(32), 0, true)
            .await
            .unwrap();
        assert!(matches!(
            response,
            AgentControlResponse::Attachment { attachment: None }
        ));
    }
    connector.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn historical_attachment_deleted_and_expired_sources_are_unavailable() {
    for expired in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let connector = AgentConnector::open(crate::tests::test_config(
            dir.path(),
            dir.path().join("dev/agent.sock"),
            vec![],
            false,
            false,
        ))
        .unwrap();
        let account = connector.account_home.create_account("agent").unwrap();
        seed_with(&connector, vec![tag(b"body")], |storage| {
            if expired {
                storage
                    .finalize_app_event_source_retention(
                        GROUP,
                        &"aa".repeat(32),
                        Some(&"bb".repeat(32)),
                        7,
                        cgka_traits::app_event::AppMessageRetentionDecision::new(10, 1),
                    )
                    .unwrap();
            } else {
                storage
                    .record_app_event(&StoredAppEvent {
                        group_id_hex: GROUP.into(),
                        message_id_hex: "dd".repeat(32),
                        source_message_id_hex: Some("ee".repeat(32)),
                        source_epoch: Some(7),
                        direction: "received".into(),
                        sender: "cc".repeat(32),
                        plaintext: String::new(),
                        kind: 5,
                        tags: vec![vec!["e".into(), "aa".repeat(32)]],
                        recorded_at: 11,
                        received_at: 11,
                        origin_commit_id: None,
                        moderation_grant: false,
                    })
                    .unwrap();
            }
        });
        let response = connector
            .attachment_response(&account.account_id_hex, GROUP, &"aa".repeat(32), 0, true)
            .await
            .unwrap();
        assert!(
            matches!(
                response,
                AgentControlResponse::Attachment { attachment: None }
            ),
            "expired={expired}"
        );
        connector.runtime.shutdown_and_close().await.unwrap();
    }
}

fn tag(bytes: &[u8]) -> Vec<String> {
    vec![
        "imeta".into(),
        "m application/octet-stream".into(),
        "filename same.bin".into(),
        format!("plaintext_sha256 {}", hex::encode(Sha256::digest(bytes))),
        format!("ciphertext_sha256 {}", "dd".repeat(32)),
        format!("nonce {}", "ee".repeat(12)),
        "v encrypted-media-v1".into(),
        format!(
            "locator blossom-v1 https://blossom.example/{}",
            "dd".repeat(32)
        ),
    ]
}

#[tokio::test]
async fn historical_attachment_inspection_preserves_slots_and_creates_no_demand() {
    let dir = tempfile::tempdir().unwrap();
    let connector = AgentConnector::open(crate::tests::test_config(
        dir.path(),
        dir.path().join("dev/agent.sock"),
        vec![],
        false,
        false,
    ))
    .unwrap();
    let account = connector.account_home.create_account("agent").unwrap();
    let mut large = tag(b"first");
    large.push(format!(
        "dim {}",
        "1".repeat(agent_control::MAX_AGENT_CONTROL_FRAME_BYTES)
    ));
    let mut malformed = tag(b"bad locator");
    *malformed.last_mut().unwrap() = "locator blossom-v1 not-a-url".into();
    seed(
        &connector,
        vec![
            large,
            vec!["imeta".into(), "v future".into()],
            tag(b"second"),
            malformed,
        ],
    );
    for (index, bytes) in [(0, b"first".as_slice()), (2, b"second".as_slice())] {
        let response = connector
            .attachment_response(
                &account.account_id_hex,
                GROUP,
                &"aa".repeat(32),
                index,
                false,
            )
            .await
            .unwrap();
        let AgentControlResponse::Attachment {
            attachment: Some(attachment),
        } = response
        else {
            panic!("attachment missing")
        };
        assert_eq!(
            attachment.plaintext_sha256,
            hex::encode(Sha256::digest(bytes))
        );
        assert_eq!(attachment.attachment_index, index);
        assert_eq!(attachment.state, AgentControlAttachmentState::NotRequested);
        assert!(!attachment.locally_available);
        assert!(attachment.handoff.is_none());
        let wire = serde_json::to_string(&attachment).unwrap();
        assert!(
            wire.len() < 2048,
            "sender metadata must not enlarge the identity reply"
        );
        assert!(!wire.contains("blossom.example"));
        assert!(!wire.contains("nonce"));
    }
    let missing = connector
        .attachment_response(&account.account_id_hex, GROUP, &"aa".repeat(32), 4, true)
        .await
        .unwrap();
    assert!(matches!(
        missing,
        AgentControlResponse::Attachment { attachment: None }
    ));
    for index in [1, 3] {
        assert_eq!(
            connector
                .attachment_response(
                    &account.account_id_hex,
                    GROUP,
                    &"aa".repeat(32),
                    index,
                    true
                )
                .await
                .unwrap_err()
                .code(),
            "attachment_rejected"
        );
    }
    let refused = connector
        .attachment_response(&account.account_id_hex, GROUP, &"aa".repeat(32), 0, true)
        .await
        .unwrap();
    assert!(
        matches!(
            refused,
            AgentControlResponse::Attachment { attachment: None }
        ),
        "native admission refusal must not look like pending work"
    );
    let queued = request(
        &connector,
        agent_control::AgentControlRequest::DownloadAttachment {
            account_id_hex: account.account_id_hex,
            group_id_hex: GROUP.into(),
            message_id_hex: "aa".repeat(32),
            attachment_index: 2,
        },
    )
    .await;
    let AgentControlResponse::Attachment {
        attachment: Some(queued),
    } = queued
    else {
        panic!("queued attachment missing")
    };
    assert_eq!(queued.state, AgentControlAttachmentState::Queued);
    assert!(queued.handoff.is_none());
    connector.runtime.shutdown_and_close().await.unwrap();
}
