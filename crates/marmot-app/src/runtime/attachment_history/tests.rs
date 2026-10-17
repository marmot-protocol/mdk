use super::*;
use crate::MarmotApp;
use marmot_account::AccountHome;
use storage_sqlite::SqliteAppStorage;
use storage_sqlite::StoredAppEvent;

/// Warm a real account, then retain a synthetic first-open migration observation.
fn cached_diagnostic_runtime() -> (tempfile::TempDir, std::sync::Arc<MarmotAppRuntime>, String) {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relays(dir.path(), Vec::new());
    app.account_storage(&account.label).unwrap();
    app.set_startup_diagnostics_enabled(true);
    let first = app
        .startup_diagnostics
        .observe(crate::NativeStartupStage::MigrationApply);
    first.progress(crate::NativeStartupStage::MigrationApply, Some(105), true);
    first.finish(true);
    (dir, std::sync::Arc::new(app.runtime()), account.label)
}

/// Drive the same public policy boundary as startup, rather than only its nested storage cache.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cached_attachment_policy_reads_preserve_first_open_history() {
    let (_dir, runtime, account) = cached_diagnostic_runtime();
    let before = runtime.accounts.app.startup_diagnostics_snapshot();
    for _ in 0..128 {
        runtime.attachment_download_policy(&account).await.unwrap();
    }
    let after = runtime.accounts.app.startup_diagnostics_snapshot();
    runtime.shutdown_and_close().await.unwrap();
    assert_eq!(after.events, before.events);
    assert_eq!(after.dropped_events, 0);
    assert_eq!(after.dropped_scopes, 0);
    assert!(after.active.is_empty());
}

/// Concurrent cache-lock waits consume one scope each and remain snapshot-visible without evicting history.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::await_holding_lock,
    reason = "Exercise snapshotting while an independent native cache resource is held."
)]
async fn blocked_attachment_policy_reads_use_one_scope_each() {
    const READS: usize = 8;
    let (_dir, runtime, account) = cached_diagnostic_runtime();
    let before = runtime.accounts.app.startup_diagnostics_snapshot();
    let held = runtime.accounts.app.account_storages.lock().unwrap();
    let reads: Vec<_> = (0..READS)
        .map(|_| {
            let runtime = runtime.clone();
            let account = account.clone();
            tokio::spawn(async move { runtime.attachment_download_policy(&account).await })
        })
        .collect();
    let ready = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let snapshot = runtime.accounts.app.startup_diagnostics_snapshot();
            if snapshot.active.len() == READS
                && snapshot
                    .active
                    .iter()
                    .all(|scope| scope.stage == crate::NativeStartupStage::AccountStorageCache)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    let blocked = runtime.accounts.app.startup_diagnostics_snapshot();
    // Release the resource and join every reader before assertions, including on a regression failure.
    drop(held);
    for read in reads {
        tokio::time::timeout(std::time::Duration::from_secs(5), read)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    let after = runtime.accounts.app.startup_diagnostics_snapshot();
    runtime.shutdown_and_close().await.unwrap();
    assert!(
        ready.is_ok(),
        "each blocked policy read must have one observable cache-wait scope"
    );
    assert_eq!(blocked.active.len(), READS);
    assert_eq!(blocked.events, before.events);
    assert_eq!(blocked.dropped_scopes, 0);
    assert_eq!(after.events, before.events);
    assert_eq!(after.dropped_events, 0);
    assert!(after.active.is_empty());
}

/// Dropping the host future cannot hide a still-running blocking read; its last owner records abandonment.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::await_holding_lock,
    reason = "Exercise cancellation while an independent native read resource is held."
)]
async fn dropped_attachment_future_keeps_worker_observable_until_exit() {
    let (_dir, runtime, account) = cached_diagnostic_runtime();
    let before = runtime.accounts.app.startup_diagnostics_snapshot();
    let resource = std::sync::Arc::new(std::sync::Mutex::new(()));
    let held = resource.lock().unwrap();
    let read = {
        let runtime = runtime.clone();
        let resource = resource.clone();
        tokio::spawn(async move {
            runtime
                .attachment_read(&account, move |_, _| {
                    let _held = resource.lock().unwrap();
                    Ok(())
                })
                .await
        })
    };
    let ready = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if runtime
                .accounts
                .app
                .startup_diagnostics_snapshot()
                .active
                .iter()
                .any(|scope| scope.stage == crate::NativeStartupStage::AttachmentLocalRead)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    read.abort();
    let aborted = read.await;
    let blocked = runtime.accounts.app.startup_diagnostics_snapshot();
    drop(held);
    let drained = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if runtime
                .accounts
                .app
                .startup_diagnostics_snapshot()
                .active
                .is_empty()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    let after = runtime.accounts.app.startup_diagnostics_snapshot();
    runtime.shutdown_and_close().await.unwrap();
    assert!(ready.is_ok());
    assert!(aborted.unwrap_err().is_cancelled());
    assert_eq!(blocked.active.len(), 1);
    assert_eq!(blocked.events, before.events);
    assert!(drained.is_ok());
    assert_eq!(
        after.events.last().unwrap().outcome,
        crate::NativeStartupOutcome::Abandoned
    );
}

fn tag(mime: &str) -> Vec<String> {
    vec![
        "imeta".into(),
        "v encrypted-media-v2".into(),
        format!(
            "locator blossom-v1 https://media.example/{}.bin",
            "11".repeat(32)
        ),
        format!("ciphertext_sha256 {}", "11".repeat(32)),
        format!("plaintext_sha256 {}", "22".repeat(32)),
        "nonce 333333333333333333333333".into(),
        format!("m {mime}"),
        "filename test.bin".into(),
    ]
}
fn add(store: &SqliteAppStorage, i: usize) {
    store
        .record_app_event(&StoredAppEvent {
            group_id_hex: "ab".repeat(16),
            message_id_hex: format!("{i:064x}"),
            source_message_id_hex: Some(format!("{:064x}", i + 10000)),
            source_epoch: Some(1),
            direction: "received".into(),
            sender: "cd".repeat(32),
            plaintext: String::new(),
            kind: 9,
            tags: if i.is_multiple_of(7) {
                vec![
                    tag("image/png"),
                    vec!["imeta".into(), "v future".into()],
                    tag("audio/ogg"),
                ]
            } else {
                vec![]
            },
            recorded_at: 100 + i as u64,
            received_at: 9999 - i as u64,
            origin_commit_id: None,
            moderation_grant: false,
        })
        .unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attachment_discovery_traverses_sparse_albums_without_engine_or_network() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    for i in 0..350 {
        add(&store.app_storage(), i);
    }
    let runtime = app.runtime();
    let group = GroupId::new(vec![0xab; 16]);
    let mut cursor = None;
    let mut got = Vec::new();
    loop {
        let AttachmentPageRead::Page(page) = runtime
            .attachment_history_page(&account.label, &group, 1, cursor)
            .await
            .unwrap()
        else {
            panic!("page")
        };
        assert_eq!(page.entries.len(), 1);
        let entry = &page.entries[0];
        let index = match &entry.attachment {
            MediaAttachmentOutcome::Accepted {
                attachment_index, ..
            } => *attachment_index,
            MediaAttachmentOutcome::Rejected {
                attachment_index,
                rejection,
            } => {
                assert_eq!(
                    rejection.kind,
                    crate::MediaAttachmentRejectionKind::UnsupportedFormat
                );
                *attachment_index
            }
        };
        assert_eq!(
            entry.category,
            [
                AttachmentCategory::Image,
                AttachmentCategory::Rejected,
                AttachmentCategory::Audio
            ][index as usize]
        );
        got.push((entry.message_id_hex.clone(), index));
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
        assert!(got.len() <= 150);
    }
    let expected: Vec<_> = (0usize..350)
        .rev()
        .filter(|i| i.is_multiple_of(7))
        .flat_map(|i| (0..3).map(move |n| (format!("{i:064x}"), n)))
        .collect();
    assert_eq!(got, expected);
    assert!(runtime.accounts.workers.lock().await.is_empty());
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attachment_discovery_fences_changes_isolates_accounts_and_closes() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    add(&store.app_storage(), 0);
    add(&store.app_storage(), 7);
    let runtime = app.runtime();
    let group = GroupId::new(vec![0xab; 16]);
    let first = runtime
        .attachment_history_page(&alice.label, &group, 1, None)
        .await
        .unwrap();
    let AttachmentPageRead::Page(first) = first else {
        panic!("page")
    };
    let cursor = first.next_cursor.clone().unwrap();
    assert!(matches!(
        runtime
            .attachment_history_page(&bob.label, &group, 1, Some(cursor.clone()))
            .await
            .unwrap(),
        AttachmentPageRead::CursorMismatch
    ));
    assert!(matches!(
        runtime
            .attachment_history_page("alice", &GroupId::new(vec![1; 16]), 1, Some(cursor.clone()))
            .await
            .unwrap(),
        AttachmentPageRead::CursorMismatch
    ));
    for limit in [0, MAX_ATTACHMENT_HISTORY_PAGE + 1] {
        assert!(matches!(
            runtime
                .attachment_history_page("alice", &group, limit, None)
                .await
                .unwrap(),
            AttachmentPageRead::InvalidLimit
        ));
    }
    assert!(
        runtime
            .attachment_history_page("missing", &group, 1, None)
            .await
            .is_err()
    );
    add(&store.app_storage(), 14);
    let added = runtime
        .attachment_history_version("alice", &group)
        .await
        .unwrap();
    assert_ne!(added, first.version);
    assert!(!added.requires_restart_since(&first.version));
    assert!(matches!(
        runtime
            .attachment_history_page("alice", &group, 1, Some(cursor.clone()))
            .await
            .unwrap(),
        AttachmentPageRead::Page(_)
    ));
    store
        .app_storage()
        .record_app_event(&StoredAppEvent {
            group_id_hex: "ab".repeat(16),
            message_id_hex: "ee".repeat(32),
            source_message_id_hex: Some("ff".repeat(32)),
            source_epoch: Some(1),
            direction: "received".into(),
            sender: "cd".repeat(32),
            plaintext: String::new(),
            kind: 5,
            tags: vec![vec!["e".into(), format!("{:064x}", 7)]],
            recorded_at: 1000,
            received_at: 1000,
            origin_commit_id: None,
            moderation_grant: false,
        })
        .unwrap();
    let changed = runtime
        .attachment_history_version("alice", &group)
        .await
        .unwrap();
    assert!(changed.requires_restart_since(&first.version));
    assert!(matches!(
        runtime
            .attachment_history_page("alice", &group, 1, Some(cursor))
            .await
            .unwrap(),
        AttachmentPageRead::RestartRequired
    ));
    let AttachmentPageRead::Page(fresh) = runtime
        .attachment_history_page("alice", &group, 100, None)
        .await
        .unwrap()
    else {
        panic!("page")
    };
    assert!(
        fresh
            .entries
            .iter()
            .all(|e| e.message_id_hex != format!("{:064x}", 7))
    );
    store
        .app_storage()
        .invalidate_app_event_by_message_id(
            &"ab".repeat(16),
            &format!("{:064x}", 14),
            "branch_selection_withdrawn",
        )
        .unwrap();
    assert!(
        runtime
            .attachment_history_version("alice", &group)
            .await
            .unwrap()
            .requires_restart_since(&fresh.version)
    );
    let AttachmentPageRead::Page(after_invalidation) = runtime
        .attachment_history_page("alice", &group, 100, None)
        .await
        .unwrap()
    else {
        panic!("page")
    };
    assert_eq!(after_invalidation.entries.len(), fresh.entries.len() - 3);
    assert!(after_invalidation.entries.iter().all(|entry| {
        entry.message_id_hex != format!("{:064x}", 14)
            && entry.message_id_hex != format!("{:064x}", 7)
    }));
    runtime.shutdown_and_close().await.unwrap();
    assert!(matches!(
        runtime
            .attachment_history_page("alice", &group, 1, None)
            .await,
        Err(AppError::RuntimeStopping)
    ));
    assert!(
        runtime
            .attachment_history_version("alice", &group)
            .await
            .is_err()
    );
}

/// Legacy epoch absence and parser categories remain independent of the presentation role.
#[test]
fn attachment_discovery_legacy_epoch_and_categories_preserve_parser_verdicts() {
    for (mime, category) in [
        ("image/png", AttachmentCategory::Image),
        ("video/mp4", AttachmentCategory::Video),
        ("audio/ogg", AttachmentCategory::Audio),
        ("application/pdf", AttachmentCategory::File),
    ] {
        let raw = tag(mime);
        let entry = storage_sqlite::AttachmentHistoryEntry {
            message_id_hex: "private-message".into(),
            source_message_id_hex: "private-source".into(),
            attachment_index: 9,
            source_epoch: None,
            sender: "private-sender".into(),
            timeline_at: 1,
            received_at: 2,
            slot: serde_json::json!(raw),
            emoji_tags: vec![],
        };
        let projected = present(entry, false).unwrap();
        assert_eq!(projected.source_epoch, None);
        assert_eq!(projected.category, category);
        let MediaAttachmentOutcome::Accepted {
            attachment_index,
            reference,
        } = &projected.attachment
        else {
            panic!("accepted")
        };
        assert_eq!(*attachment_index, 9);
        // Storage classifies the raw m field; parser-based permission leases
        // must see that same verbatim MIME value.
        assert_eq!(reference.media_type, mime);
        assert_eq!(
            *reference,
            crate::parse_media_attachment(&raw, None, false).unwrap()
        );
        assert!(!format!("{projected:?}").contains("private"));
    }
}

/// Mixed and emoji-only messages remain pageable outside any conversation window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attachment_discovery_roles_preserve_slots_and_refresh() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    let emoji_url = format!("https://media.example/{}.bin", "11".repeat(32));
    let mut photo = tag("image/png");
    photo[2] = format!(
        "locator blossom-v1 https://media.example/{}.bin",
        "44".repeat(32)
    );
    photo[3] = format!("ciphertext_sha256 {}", "44".repeat(32));
    let mut event = StoredAppEvent {
        group_id_hex: "ab".repeat(16),
        message_id_hex: "01".repeat(32),
        source_message_id_hex: Some("02".repeat(32)),
        source_epoch: Some(1),
        direction: "received".into(),
        sender: "cd".repeat(32),
        plaintext: ":wave:".into(),
        kind: 9,
        tags: vec![
            photo,
            vec!["imeta".into(), "v future".into()],
            tag("image/png"),
            tag("image/png"),
            vec!["emoji".into(), "wave".into(), emoji_url.clone()],
            vec!["emoji".into(), "alias".into(), emoji_url.clone()],
        ],
        recorded_at: 1,
        received_at: 1,
        origin_commit_id: None,
        moderation_grant: false,
    };
    store.app_storage().record_app_event(&event).unwrap();
    // Newer ordinary chat pushes the album far outside a recent conversation window.
    for i in 1..350 {
        add(&store.app_storage(), i);
    }
    event.message_id_hex = "ff".repeat(32);
    event.source_message_id_hex = Some("fe".repeat(32));
    event.tags = vec![
        tag("image/png"),
        vec!["emoji".into(), "wave".into(), emoji_url],
    ];
    event.recorded_at = 10000;
    store.app_storage().record_app_event(&event).unwrap();
    let runtime = app.runtime();
    let group = GroupId::new(vec![0xab; 16]);
    let AttachmentPageRead::Page(first) = runtime
        .attachment_history_page("alice", &group, 1, None)
        .await
        .unwrap()
    else {
        panic!("page")
    };
    assert_eq!(first.entries[0].role, AttachmentRole::InlineEmoji);
    assert!(first.next_cursor.is_some());
    let mut cursor = first.next_cursor.clone();
    let mut album = Vec::new();
    while let Some(next) = cursor {
        let AttachmentPageRead::Page(page) = runtime
            .attachment_history_page("alice", &group, 1, Some(next))
            .await
            .unwrap()
        else {
            panic!("page")
        };
        assert_eq!(page.entries.len(), 1);
        album.extend(
            page.entries
                .into_iter()
                .filter(|e| e.message_id_hex == "01".repeat(32)),
        );
        cursor = page.next_cursor;
    }
    assert_eq!(
        album.iter().map(|e| e.role).collect::<Vec<_>>(),
        vec![
            AttachmentRole::Shared,
            AttachmentRole::Shared,
            AttachmentRole::InlineEmoji,
            AttachmentRole::InlineEmoji
        ]
    );
    assert!(matches!(
        album[1].attachment,
        MediaAttachmentOutcome::Rejected {
            attachment_index: 1,
            ..
        }
    ));
    assert!(matches!(
        album[2].attachment,
        MediaAttachmentOutcome::Accepted {
            attachment_index: 2,
            ..
        }
    ));
    assert!(matches!(
        album[3].attachment,
        MediaAttachmentOutcome::Accepted {
            attachment_index: 3,
            ..
        }
    ));
    // Removing the tag preserves the image's acquisition reference but changes its role.
    event.tags.pop();
    store.app_storage().record_app_event(&event).unwrap();
    let changed = runtime
        .attachment_history_version("alice", &group)
        .await
        .unwrap();
    assert!(changed.requires_restart_since(&first.version));
    let AttachmentPageRead::Page(fresh) = runtime
        .attachment_history_page("alice", &group, 1, None)
        .await
        .unwrap()
    else {
        panic!("page")
    };
    assert_eq!(fresh.entries[0].role, AttachmentRole::Shared);
    assert_eq!(fresh.entries[0].attachment, first.entries[0].attachment);
    assert!(runtime.accounts.workers.lock().await.is_empty());
    runtime.shutdown_and_close().await.unwrap();
}

/// Malformed tags, shadowed codes and non-image/rejected slots cannot hide shared content.
#[test]
fn attachment_roles_validate_definitions_without_changing_parser_outcomes() {
    let url = format!("https://media.example/{}.bin", "11".repeat(32));
    for (mime, tags, expected) in [
        (
            "image/png",
            vec![vec!["emoji", "wave", url.as_str()]],
            AttachmentRole::InlineEmoji,
        ),
        (
            "image/png",
            vec![vec!["emoji", "wave", url.as_str(), "30030:pubkey:set"]],
            AttachmentRole::InlineEmoji,
        ),
        (
            "image/png",
            vec![vec![
                "emoji",
                "wave",
                url.as_str(),
                "30030:pubkey:set",
                "extra",
            ]],
            AttachmentRole::Shared,
        ),
        (
            "image/png",
            vec![
                vec!["emoji", "wave", "https://absent.example", "", "extra"],
                vec!["emoji", "wave", url.as_str()],
            ],
            AttachmentRole::InlineEmoji,
        ),
        (
            "image/png",
            vec![vec!["emoji", "bad code", url.as_str()]],
            AttachmentRole::Shared,
        ),
        (
            "image/png",
            vec![
                vec!["emoji", "wave", "https://absent.example"],
                vec!["emoji", "wave", url.as_str()],
            ],
            AttachmentRole::Shared,
        ),
        (
            "image/png",
            vec![
                vec!["emoji", "wave", ""],
                vec!["emoji", "wave", url.as_str()],
            ],
            AttachmentRole::InlineEmoji,
        ),
        (
            "audio/ogg",
            vec![vec!["emoji", "wave", url.as_str()]],
            AttachmentRole::Shared,
        ),
    ] {
        let attachment = MediaAttachmentOutcome::Accepted {
            attachment_index: 4,
            reference: crate::parse_media_attachment(&tag(mime), Some(1), false).unwrap(),
        };
        let tags = tags
            .into_iter()
            .map(|t| t.into_iter().map(str::to_owned).collect())
            .collect::<Vec<_>>();
        assert_eq!(attachment_role(&attachment, &tags), expected);
    }
}
