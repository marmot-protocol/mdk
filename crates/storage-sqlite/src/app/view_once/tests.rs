use super::*;
use crate::{
    AttachmentDemand, AttachmentPublishResult, ImportedAppEvent, SqlCipherKey, SqliteAccountStorage,
};
use cgka_traits::storage::StorageError;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Barrier};

const GROUP: &str = "abababababababababababababababab";
const SENDER: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const RECIPIENT: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const FUTURE_CREATED_AT: u64 = 5 * 365 * 86_400;
fn event(deadline: u64) -> StoredAppEvent {
    let tags = vec![
        vec![
            "imeta".into(),
            "m image/png".into(),
            "v encrypted-media-view-once-v1".into(),
            format!("plaintext_sha256 {}", hex::encode(Sha256::digest(b"body"))),
            format!("ciphertext_sha256 {}", hex::encode([0x33; 32])),
            format!("nonce {}", hex::encode([0x44; 12])),
            "filename image.png".into(),
            format!(
                "locator blossom-v1 https://example.com/{}",
                hex::encode([0x33; 32])
            ),
        ],
        vec![
            "view-once".into(),
            "view-once-v1".into(),
            deadline.to_string(),
        ],
    ];
    let inner = MarmotAppEvent::new(SENDER, 10, 9, tags.clone(), String::new());
    StoredAppEvent {
        group_id_hex: GROUP.into(),
        message_id_hex: inner.id,
        source_message_id_hex: Some("source".into()),
        source_epoch: Some(3),
        direction: "received".into(),
        sender: SENDER.into(),
        plaintext: String::new(),
        kind: 9,
        tags,
        recorded_at: 10,
        received_at: 11,
        origin_commit_id: None,
        moderation_grant: false,
    }
}
fn future_event() -> StoredAppEvent {
    let mut once =
        event(FUTURE_CREATED_AT + cgka_traits::app_components::VIEW_ONCE_MAX_LIFETIME_SECONDS);
    once.recorded_at = FUTURE_CREATED_AT;
    once.message_id_hex = cgka_traits::app_event::canonical_event_id(
        SENDER,
        FUTURE_CREATED_AT,
        once.kind,
        &once.tags,
        &once.plaintext,
    );
    once
}

fn seed(store: &SqliteAccountStorage, event: &StoredAppEvent) {
    store.lock().unwrap().execute("INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES(?1,'',0) ON CONFLICT DO NOTHING",[GROUP]).unwrap();
    let inner = MarmotAppEvent::new(
        event.sender.clone(),
        event.recorded_at,
        event.kind,
        event.tags.clone(),
        event.plaintext.clone(),
    );
    store
        .app_storage()
        .record_app_event_with_retention(
            event,
            Some(AppMessageRetentionDecision {
                retention_seconds: 0,
                expires_at: None,
                view_once: inner.view_once_policy().ok().flatten(),
            }),
        )
        .unwrap();
}
fn claimed(result: ViewOnceClaim) {
    match result {
        ViewOnceClaim::Claimed {
            source_epoch,
            expires_at,
            imeta_tag,
        } => {
            assert_eq!(source_epoch, 3);
            assert_eq!(expires_at, 100);
            assert_eq!(imeta_tag[0], "imeta");
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn claim_races_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.sqlite");
    let key = SqlCipherKey::raw([0x61; 32]);
    let first = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let second = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let event = event(100);
    seed(&first, &event);
    assert_eq!(
        first
            .app_storage()
            .app_message(GROUP, &event.message_id_hex)
            .unwrap()
            .unwrap()
            .retention
            .unwrap()
            .view_once,
        Some(cgka_traits::app_event::ViewOncePolicy {
            unopened_expires_at: 100
        })
    );
    let barrier = Arc::new(Barrier::new(2));
    let id = event.message_id_hex.clone();
    let gate = barrier.clone();
    let runner = std::thread::spawn(move || {
        gate.wait();
        second
            .app_storage()
            .claim_view_once(&["image/png"], GROUP, &id, 0, RECIPIENT, 12)
            .unwrap()
    });
    barrier.wait();
    let local = first
        .app_storage()
        .claim_view_once(
            &["image/png"],
            GROUP,
            &event.message_id_hex,
            0,
            RECIPIENT,
            12,
        )
        .unwrap();
    let remote = runner.join().unwrap();
    assert_eq!(
        [&local, &remote]
            .iter()
            .filter(|r| matches!(r, ViewOnceClaim::Claimed { .. }))
            .count(),
        1
    );
    assert_eq!(
        [&local, &remote]
            .iter()
            .filter(|r| matches!(r, ViewOnceClaim::Consumed))
            .count(),
        1
    );
    assert!(
        first
            .app_storage()
            .view_once_access_valid(GROUP, &event.message_id_hex, 0, 12)
            .unwrap()
    );
    drop(first);
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert_eq!(
        reopened
            .app_storage()
            .claim_view_once(
                &["image/png"],
                GROUP,
                &event.message_id_hex,
                0,
                RECIPIENT,
                12
            )
            .unwrap(),
        ViewOnceClaim::Consumed
    );
    let tags: String = reopened
        .lock()
        .unwrap()
        .query_row(
            "SELECT tags_json FROM app_events WHERE group_id_hex=?1 AND message_id_hex=?2",
            params![GROUP, event.message_id_hex],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Vec<Vec<String>>>(&tags).unwrap(),
        vec![event.tags[1].clone()]
    );
}

#[test]
fn claim_erase_rolls_back() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let event = event(100);
    seed(&store, &event);
    store.lock().unwrap().execute_batch("CREATE TEMP TRIGGER refuse_once_erasure BEFORE UPDATE OF tags_json ON app_events BEGIN SELECT RAISE(ABORT,'once erasure fault'); END;").unwrap();
    match store.app_storage().claim_view_once(
        &["image/png"],
        GROUP,
        &event.message_id_hex,
        0,
        RECIPIENT,
        12,
    ) {
        Err(StorageError::Backend(message)) => assert!(message.contains("once erasure fault")),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(
        store
            .app_storage()
            .view_once_state(GROUP, &event.message_id_hex, 0, 11)
            .unwrap(),
        ViewOnceState::Unopened
    );
    store
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER refuse_once_erasure")
        .unwrap();
    claimed(
        store
            .app_storage()
            .claim_view_once(
                &["image/png"],
                GROUP,
                &event.message_id_hex,
                0,
                RECIPIENT,
                12,
            )
            .unwrap(),
    );
}

#[test]
fn future_time_keeps_receipt_cap() {
    let lifetime = cgka_traits::app_components::VIEW_ONCE_MAX_LIFETIME_SECONDS;
    for (high_water, expected) in [
        (1000, ViewOnceState::Unopened),
        (FUTURE_CREATED_AT, ViewOnceState::Expired),
    ] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let app = store.app_storage();
        app.view_once_state(GROUP, "unknown", 0, high_water)
            .unwrap();
        let event = future_event();
        seed(&store, &event);
        let expires = event.received_at + lifetime;
        let row = app
            .timeline_message(GROUP, &event.message_id_hex)
            .unwrap()
            .unwrap();
        assert_eq!(row.view_once.unwrap().unopened_expires_at, expires);
        assert_eq!(
            app.view_once_state(GROUP, &event.message_id_hex, 0, expires - 1)
                .unwrap(),
            expected
        );
        assert_eq!(
            app.claim_view_once(
                &["image/png"],
                GROUP,
                &event.message_id_hex,
                0,
                RECIPIENT,
                expires
            )
            .unwrap(),
            ViewOnceClaim::Expired
        );
        app.record_app_event(&event).unwrap();
        assert_eq!(
            app.view_once_state(GROUP, &event.message_id_hex, 0, 11)
                .unwrap(),
            ViewOnceState::Expired
        );
    }
}

#[test]
fn expiry_survives_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.sqlite");
    let key = SqlCipherKey::raw([0x62; 32]);
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let event = event(100);
    seed(&store, &event);
    let mut damaged_tags = event.tags.clone();
    damaged_tags.push(vec![
        "view-once".into(),
        "unknown".into(),
        "100".into(),
        "private-caption".into(),
    ]);
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE app_events SET tags_json=?1 WHERE group_id_hex=?2 AND message_id_hex=?3",
            params![
                serde_json::to_string(&damaged_tags).unwrap(),
                GROUP,
                event.message_id_hex
            ],
        )
        .unwrap();
    assert_eq!(
        store
            .app_storage()
            .claim_view_once(
                &["image/png"],
                GROUP,
                &event.message_id_hex,
                0,
                RECIPIENT,
                100
            )
            .unwrap(),
        ViewOnceClaim::Expired
    );
    let tags: String = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT tags_json FROM app_events WHERE group_id_hex=?1 AND message_id_hex=?2",
            params![GROUP, event.message_id_hex],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Vec<Vec<String>>>(&tags).unwrap(),
        vec![vec![
            "view-once".to_owned(),
            "view-once-v1".to_owned(),
            "100".to_owned()
        ]]
    );
    drop(store);
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert_eq!(
        store
            .app_storage()
            .claim_view_once(
                &["image/png"],
                GROUP,
                &event.message_id_hex,
                0,
                RECIPIENT,
                12
            )
            .unwrap(),
        ViewOnceClaim::Expired
    );
    assert!(
        !store
            .app_storage()
            .view_once_access_valid(GROUP, &event.message_id_hex, 0, 12)
            .unwrap()
    );
    store.app_storage().record_app_event(&event).unwrap();
    assert_eq!(
        store
            .app_storage()
            .view_once_state(GROUP, &event.message_id_hex, 0, 12)
            .unwrap(),
        ViewOnceState::Expired
    );
}

#[test]
fn claim_survives_history_clear() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let event = event(100);
    seed(&store, &event);
    let app = store.app_storage();
    assert!(
        !app.view_once_access_valid(GROUP, &event.message_id_hex, 0, 12)
            .unwrap()
    );
    assert_eq!(
        app.claim_view_once(&["image/png"], GROUP, &event.message_id_hex, 0, SENDER, 12)
            .unwrap(),
        ViewOnceClaim::Unavailable
    );
    assert_eq!(
        app.claim_view_once(
            &["image/png"],
            GROUP,
            &event.message_id_hex,
            1,
            RECIPIENT,
            12
        )
        .unwrap(),
        ViewOnceClaim::Unavailable
    );
    claimed(
        app.claim_view_once(
            &["image/png"],
            GROUP,
            &event.message_id_hex,
            0,
            RECIPIENT,
            12,
        )
        .unwrap(),
    );
    store
        .lock()
        .unwrap()
        .execute("DELETE FROM app_events WHERE group_id_hex=?1", [GROUP])
        .unwrap();
    app.record_app_event(&event).unwrap();
    app.rebuild_message_timeline_for_group(GROUP).unwrap();
    assert_eq!(
        app.claim_view_once(
            &["image/png"],
            GROUP,
            &event.message_id_hex,
            0,
            RECIPIENT,
            12
        )
        .unwrap(),
        ViewOnceClaim::Consumed
    );
    assert!(
        !app.view_once_access_valid(GROUP, &event.message_id_hex, 0, 12)
            .unwrap()
    );
    let timeline = app
        .timeline_message(GROUP, &event.message_id_hex)
        .unwrap()
        .unwrap();
    assert_eq!(timeline.view_once.unwrap().state, ViewOnceState::Consumed);
    assert!(timeline.plaintext.is_empty());
    assert!(timeline.media.is_none());
    assert_eq!(timeline.tags, vec![event.tags[1].clone()]);
    store.delete_local_group_data(GROUP).unwrap();
    seed(&store, &event);
    assert_eq!(
        app.claim_view_once(
            &["image/png"],
            GROUP,
            &event.message_id_hex,
            0,
            RECIPIENT,
            12
        )
        .unwrap(),
        ViewOnceClaim::Consumed
    );
}

#[test]
fn once_preserves_shared_media() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let once = event(100);
    seed(&store, &once);
    let app = store.app_storage();
    let mut ordinary = once.clone();
    ordinary.message_id_hex = "ordinary".into();
    ordinary.source_message_id_hex = Some("ordinary-source".into());
    ordinary.tags.truncate(1);
    ordinary.tags[0][2] = "v encrypted-media-v2".into();
    app.record_app_event(&ordinary).unwrap();
    let slot = app
        .attachment_control_entry(GROUP, "ordinary", "ordinary-source", 0, 12)
        .unwrap()
        .unwrap();
    let reference = match app
        .request_attachment_acquisition(GROUP, &slot, Sha256::digest(b"body").into(), 12)
        .unwrap()
    {
        AttachmentDemand::Requested(reference) => reference,
        other => panic!("unexpected {other:?}"),
    };
    let job = app
        .claim_attachment_acquisition(&reference, 12, 99)
        .unwrap()
        .unwrap();
    assert_eq!(
        app.complete_attachment_acquisition(&job, b"body", 12, 1024)
            .unwrap(),
        AttachmentPublishResult::Published
    );
    assert!(
        app.attachment_control_entry(GROUP, &once.message_id_hex, "source", 0, 12)
            .unwrap()
            .is_none()
    );
    assert!(
        app.retained_attachment_asset(GROUP, &once.message_id_hex, "source", 0, 12)
            .unwrap()
            .is_none()
    );
    assert!(
        app.retained_attachment_descriptor(GROUP, &once.message_id_hex, "source", 0, 12)
            .unwrap()
            .is_none()
    );
    let mut forged = slot.clone();
    forged.message_id_hex = once.message_id_hex.clone();
    forged.source_message_id_hex = "source".into();
    forged.slot = serde_json::json!(once.tags[0]);
    assert_eq!(
        app.request_attachment_acquisition(GROUP, &forged, Sha256::digest(b"body").into(), 12)
            .unwrap(),
        AttachmentDemand::Unavailable
    );
    claimed(
        app.claim_view_once(
            &["image/png"],
            GROUP,
            &once.message_id_hex,
            0,
            RECIPIENT,
            12,
        )
        .unwrap(),
    );
    assert_eq!(
        &*app
            .read_retained_attachment(&reference, 12, 0, 100)
            .unwrap()
            .unwrap(),
        b"body"
    );
    let page = app.attachment_history_page(GROUP, 100, None).unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].message_id_hex, "ordinary");
    let export = app.history_export_page(GROUP, None, 12, 100).unwrap();
    assert!(
        export
            .iter()
            .find(|r| r.message_id_hex == once.message_id_hex)
            .unwrap()
            .event
            .is_none()
    );
    let imported = ImportedAppEvent {
        message_id_hex: once.message_id_hex.clone(),
        source_epoch: 3,
        sender: once.sender,
        plaintext: once.plaintext,
        kind: 9,
        tags: once.tags,
        created_at: 10,
        retention: None,
        moderation_grant: None,
        file_keys: Vec::new(),
    };
    let other = SqliteAccountStorage::in_memory().unwrap();
    other
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES(?1,'',0)",
            [GROUP],
        )
        .unwrap();
    assert_eq!(
        other
            .app_storage()
            .import_app_events(GROUP, &[0x22; 32], &[imported], 12)
            .unwrap()
            .imported,
        0
    );
}

#[test]
fn once_keys_retire_after_prune() {
    let media = cgka_traits::app_components::GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID;
    for expired in [false, true] {
        for ordinary_first in [false, true] {
            let store = SqliteAccountStorage::in_memory().unwrap();
            let app = store.app_storage();
            app.ensure_account_projection_with_identity("local", RECIPIENT)
                .unwrap();
            let once = event(100);
            if expired {
                store.lock().unwrap().execute(
                    "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES(?1,'',0)",
                    [GROUP],
                ).unwrap();
                app.record_app_event(&once).unwrap();
            } else {
                seed(&store, &once);
            }
            let mut ordinary = once.clone();
            ordinary.message_id_hex = "ordinary".into();
            ordinary.source_message_id_hex = Some("ordinary-source".into());
            ordinary.recorded_at = if ordinary_first { 5 } else { 20 };
            ordinary.tags.truncate(1);
            ordinary.tags[0][2] = "v encrypted-media-v2".into();
            app.record_app_event(&ordinary).unwrap();
            app.remember_encrypted_media_epoch_secret(GROUP, media, 3, &[1, 2, 3])
                .unwrap();
            if expired {
                assert_eq!(
                    app.view_once_state(GROUP, &once.message_id_hex, 0, 100)
                        .unwrap(),
                    ViewOnceState::Expired
                );
                assert!(
                    app.finalize_app_event_source_retention(
                        GROUP,
                        &once.message_id_hex,
                        once.source_message_id_hex.as_deref(),
                        3,
                        AppMessageRetentionDecision {
                            retention_seconds: 0,
                            expires_at: None,
                            view_once: Some(ViewOncePolicy {
                                unopened_expires_at: 100
                            }),
                        },
                    )
                    .unwrap()
                    .is_some()
                );
            } else {
                claimed(
                    app.claim_view_once(
                        &["image/png"],
                        GROUP,
                        &once.message_id_hex,
                        0,
                        RECIPIENT,
                        12,
                    )
                    .unwrap(),
                );
            }
            assert_eq!(
                app.encrypted_media_epoch_secret(GROUP, media, 3).unwrap(),
                Some(vec![1, 2, 3])
            );
            app.record_app_event(&once).unwrap();
            assert_eq!(
                app.encrypted_media_epoch_secret(GROUP, media, 3).unwrap(),
                Some(vec![1, 2, 3])
            );
            let cutoff = if ordinary_first { 8 } else { 15 };
            let first = app
                .secure_prune_app_events_before(GROUP, cutoff, "local", &|_, _| false)
                .unwrap();
            assert_eq!(first.pruned_messages, 1);
            assert_eq!(first.pruned_media_epoch_secrets, 0);
            assert_eq!(
                app.encrypted_media_epoch_secret(GROUP, media, 3).unwrap(),
                Some(vec![1, 2, 3])
            );
            let last = app
                .secure_prune_app_events_before(GROUP, 30, "local", &|_, _| false)
                .unwrap();
            assert_eq!(last.pruned_messages, 1);
            assert_eq!(last.pruned_media_epoch_secrets, 1);
            assert_eq!(
                app.encrypted_media_epoch_secret(GROUP, media, 3).unwrap(),
                None
            );
            app.remember_encrypted_media_epoch_secret(GROUP, media, 3, &[4, 5, 6])
                .unwrap();
            assert_eq!(
                app.encrypted_media_epoch_secret(GROUP, media, 3).unwrap(),
                None
            );
        }
    }
}

#[test]
fn bad_marker_or_source_denied() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for mutate in 0..6 {
        let mut once = event(100);
        match mutate {
            0 => once.tags.push(once.tags[1].clone()),
            1 => once.tags[1][2] = "0100".into(),
            2 => once.tags[1][2] = "3888011".into(),
            3 => once.plaintext = "caption".into(),
            4 => once.tags[0].push("thumbhash forbidden".into()),
            _ => once.tags[0][1] = "m audio/ogg".into(),
        }
        once.message_id_hex = MarmotAppEvent::new(
            once.sender.clone(),
            10,
            9,
            once.tags.clone(),
            once.plaintext.clone(),
        )
        .id;
        once.source_message_id_hex = Some(format!("malformed-{mutate}"));
        seed(&store, &once);
        assert_eq!(
            store
                .app_storage()
                .claim_view_once(
                    &["image/png"],
                    GROUP,
                    &once.message_id_hex,
                    0,
                    RECIPIENT,
                    12
                )
                .unwrap(),
            ViewOnceClaim::Unavailable
        );
        let row = store
            .app_storage()
            .timeline_message(GROUP, &once.message_id_hex)
            .unwrap()
            .unwrap();
        assert!(row.plaintext.is_empty());
        assert!(row.media.is_none());
    }
    let once = event(100);
    seed(&store, &once);
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE app_events SET source_epoch=4 WHERE group_id_hex=?1 AND message_id_hex=?2",
            params![GROUP, once.message_id_hex],
        )
        .unwrap();
    assert_eq!(
        store
            .app_storage()
            .claim_view_once(
                &["image/png"],
                GROUP,
                &once.message_id_hex,
                0,
                RECIPIENT,
                12
            )
            .unwrap(),
        ViewOnceClaim::Unavailable
    );
}

#[test]
fn eligibility_requires_source() {
    for (source_epoch, deadline) in [(Some(3), None), (None, Some(100)), (Some(3), Some(99))] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES(?1,'',0)",
                [GROUP],
            )
            .unwrap();
        let mut once = event(100);
        once.source_epoch = source_epoch;
        let app = store.app_storage();
        app.record_app_event_with_retention(
            &once,
            Some(AppMessageRetentionDecision {
                retention_seconds: 0,
                expires_at: None,
                view_once: deadline.map(|unopened_expires_at| {
                    cgka_traits::app_event::ViewOncePolicy {
                        unopened_expires_at,
                    }
                }),
            }),
        )
        .unwrap();
        assert_eq!(
            app.view_once_state(GROUP, &once.message_id_hex, 0, 12)
                .unwrap(),
            ViewOnceState::Unavailable
        );
        assert_eq!(
            app.view_once_metadata(GROUP, &once.message_id_hex, 0, RECIPIENT, 12)
                .unwrap(),
            None
        );
        assert_eq!(
            app.claim_view_once(
                &["image/png"],
                GROUP,
                &once.message_id_hex,
                0,
                RECIPIENT,
                12
            )
            .unwrap(),
            ViewOnceClaim::Unavailable
        );
        let row = app
            .timeline_message(GROUP, &once.message_id_hex)
            .unwrap()
            .unwrap();
        assert!(row.plaintext.is_empty());
        assert!(row.media.is_none());
        assert_eq!(row.tags, vec![once.tags[1].clone()]);
        once.source_epoch = Some(3);
        once.received_at = 50;
        seed(&store, &once);
        assert_eq!(
            app.view_once_state(GROUP, &once.message_id_hex, 0, 50)
                .unwrap(),
            ViewOnceState::Unopened
        );
        assert_eq!(
            app.app_message(GROUP, &once.message_id_hex)
                .unwrap()
                .unwrap()
                .retention
                .unwrap()
                .view_once,
            Some(ViewOncePolicy {
                unopened_expires_at: 100
            })
        );
        claimed(
            app.claim_view_once(
                &["image/png"],
                GROUP,
                &once.message_id_hex,
                0,
                RECIPIENT,
                50,
            )
            .unwrap(),
        );
    }
}

#[test]
fn restored_sources_keep_cap() {
    for table in ["app_events", "account_groups"] {
        for prior in [
            ViewOnceState::Unopened,
            ViewOnceState::Consumed,
            ViewOnceState::Expired,
        ] {
            let store = SqliteAccountStorage::in_memory().unwrap();
            let mut once = future_event();
            let cap =
                once.received_at + cgka_traits::app_components::VIEW_ONCE_MAX_LIFETIME_SECONDS;
            seed(&store, &once);
            let app = store.app_storage();
            if prior == ViewOnceState::Consumed {
                assert!(matches!(
                    app.claim_view_once(
                        &["image/png"],
                        GROUP,
                        &once.message_id_hex,
                        0,
                        RECIPIENT,
                        12
                    )
                    .unwrap(),
                    ViewOnceClaim::Claimed { .. }
                ));
                assert!(
                    app.view_once_access_valid(GROUP, &once.message_id_hex, 0, 12)
                        .unwrap()
                );
            }
            if prior == ViewOnceState::Expired {
                assert_eq!(
                    app.view_once_state(GROUP, &once.message_id_hex, 0, cap)
                        .unwrap(),
                    ViewOnceState::Expired
                );
            }
            store
                .lock()
                .unwrap()
                .execute(
                    &format!("DELETE FROM {table} WHERE group_id_hex=?1"),
                    [GROUP],
                )
                .unwrap();
            assert_eq!(
                app.view_once_state(GROUP, &once.message_id_hex, 0, 12)
                    .unwrap(),
                if prior == ViewOnceState::Unopened {
                    ViewOnceState::Unavailable
                } else {
                    prior
                }
            );
            once.received_at = 50;
            seed(&store, &once);
            app.rebuild_message_timeline_for_group(GROUP).unwrap();
            assert_eq!(
                app.view_once_state(GROUP, &once.message_id_hex, 0, 50)
                    .unwrap(),
                prior
            );
            match prior {
                ViewOnceState::Unopened => {
                    let metadata = app
                        .view_once_metadata(GROUP, &once.message_id_hex, 0, RECIPIENT, 50)
                        .unwrap()
                        .unwrap();
                    assert_eq!(metadata.2, cap);
                    assert!(
                        matches!(app.claim_view_once(&["image/png"], GROUP, &once.message_id_hex, 0, RECIPIENT, 50).unwrap(), ViewOnceClaim::Claimed { expires_at, .. } if expires_at == cap)
                    );
                }
                ViewOnceState::Consumed => {
                    assert!(
                        !app.view_once_access_valid(GROUP, &once.message_id_hex, 0, 50)
                            .unwrap()
                    );
                    assert_eq!(
                        app.claim_view_once(
                            &["image/png"],
                            GROUP,
                            &once.message_id_hex,
                            0,
                            RECIPIENT,
                            50
                        )
                        .unwrap(),
                        ViewOnceClaim::Consumed
                    );
                }
                ViewOnceState::Expired => {
                    assert_eq!(
                        app.claim_view_once(
                            &["image/png"],
                            GROUP,
                            &once.message_id_hex,
                            0,
                            RECIPIENT,
                            50
                        )
                        .unwrap(),
                        ViewOnceClaim::Expired
                    );
                }
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn deletion_rollback_is_live() {
    for prior in [ViewOnceState::Unopened, ViewOnceState::Consumed] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let once = event(100);
        seed(&store, &once);
        let app = store.app_storage();
        if prior == ViewOnceState::Consumed {
            claimed(
                app.claim_view_once(
                    &["image/png"],
                    GROUP,
                    &once.message_id_hex,
                    0,
                    RECIPIENT,
                    12,
                )
                .unwrap(),
            );
            assert!(
                app.view_once_access_valid(GROUP, &once.message_id_hex, 0, 12)
                    .unwrap()
            );
        }
        let inner = MarmotAppEvent::new(
            SENDER,
            20,
            5,
            vec![vec!["e".into(), once.message_id_hex.clone()]],
            "",
        );
        let deletion = StoredAppEvent {
            message_id_hex: inner.id,
            source_message_id_hex: Some("deletion-source".into()),
            kind: inner.kind,
            tags: inner.tags,
            plaintext: inner.content,
            recorded_at: 20,
            received_at: 21,
            ..once.clone()
        };
        app.record_app_event(&deletion).unwrap();
        assert!(
            app.timeline_message(GROUP, &once.message_id_hex)
                .unwrap()
                .unwrap()
                .deleted
        );
        assert_eq!(
            app.view_once_state(GROUP, &once.message_id_hex, 0, 21)
                .unwrap(),
            if prior == ViewOnceState::Unopened {
                ViewOnceState::Unavailable
            } else {
                prior
            }
        );
        app.invalidate_app_event_by_message_id(
            GROUP,
            &deletion.message_id_hex,
            "SupersededByBranchSelection",
        )
        .unwrap();
        assert!(
            !app.timeline_message(GROUP, &once.message_id_hex)
                .unwrap()
                .unwrap()
                .deleted
        );
        assert_eq!(
            app.view_once_state(GROUP, &once.message_id_hex, 0, 22)
                .unwrap(),
            prior
        );
        if prior == ViewOnceState::Unopened {
            claimed(
                app.claim_view_once(
                    &["image/png"],
                    GROUP,
                    &once.message_id_hex,
                    0,
                    RECIPIENT,
                    22,
                )
                .unwrap(),
            );
        } else {
            assert!(
                !app.view_once_access_valid(GROUP, &once.message_id_hex, 0, 22)
                    .unwrap()
            );
            assert_eq!(
                app.claim_view_once(
                    &["image/png"],
                    GROUP,
                    &once.message_id_hex,
                    0,
                    RECIPIENT,
                    22
                )
                .unwrap(),
                ViewOnceClaim::Consumed
            );
        }
    }
}

#[test]
fn withdrawal_keeps_unclaimed() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut once = event(100);
    once.origin_commit_id = Some("origin".into());
    seed(&store, &once);
    let app = store.app_storage();
    for consumed in [false, true] {
        if consumed {
            claimed(
                app.claim_view_once(
                    &["image/png"],
                    GROUP,
                    &once.message_id_hex,
                    0,
                    RECIPIENT,
                    12,
                )
                .unwrap(),
            );
        }
        app.invalidate_app_events_by_origin_commit("origin", "SupersededByBranchSelection")
            .unwrap();
        assert!(
            !app.view_once_access_valid(GROUP, &once.message_id_hex, 0, 12)
                .unwrap()
        );
        assert_eq!(
            app.view_once_state(GROUP, &once.message_id_hex, 0, 12)
                .unwrap(),
            if consumed {
                ViewOnceState::Consumed
            } else {
                ViewOnceState::Unavailable
            }
        );
        app.clear_branch_selection_withdrawal_by_origin_commit("origin")
            .unwrap();
        assert_eq!(
            app.view_once_state(GROUP, &once.message_id_hex, 0, 12)
                .unwrap(),
            if consumed {
                ViewOnceState::Consumed
            } else {
                ViewOnceState::Unopened
            }
        );
        assert!(
            !app.view_once_access_valid(GROUP, &once.message_id_hex, 0, 12)
                .unwrap()
        );
        let cap: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT expires_at FROM view_once_consumption WHERE message_id_hex=?1",
                [&once.message_id_hex],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cap, 100);
    }
    assert_eq!(
        app.claim_view_once(
            &["image/png"],
            GROUP,
            &once.message_id_hex,
            0,
            RECIPIENT,
            12
        )
        .unwrap(),
        ViewOnceClaim::Consumed
    );
}

#[test]
fn pending_send_pins_admission() {
    for (deadline, now) in [(Some(100), 80), (None, 80), (Some(100), 100), (None, 100)] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES(?1,'',0)",
                [GROUP],
            )
            .unwrap();
        let mut once = event(100);
        once.direction = "sent".into();
        once.source_epoch = None;
        once.source_message_id_hex = None;
        let app = store.app_storage();
        app.record_app_event(&once).unwrap();
        app.invalidate_app_event_by_message_id(GROUP, &once.message_id_hex, "local_publish_failed")
            .unwrap();
        once.received_at = now;
        app.record_app_event(&once).unwrap();
        assert!(
            app.clear_local_publish_failure(GROUP, &once.message_id_hex)
                .unwrap()
                .is_some()
        );
        let retention = AppMessageRetentionDecision {
            retention_seconds: 0,
            expires_at: None,
            view_once: deadline.map(
                |unopened_expires_at| cgka_traits::app_event::ViewOncePolicy {
                    unopened_expires_at,
                },
            ),
        };
        assert!(
            app.finalize_app_event_source_retention(
                GROUP,
                &once.message_id_hex,
                Some("published"),
                3,
                retention
            )
            .unwrap()
            .is_some()
        );
        let stored = app
            .app_message(GROUP, &once.message_id_hex)
            .unwrap()
            .unwrap();
        assert_eq!(stored.retention.unwrap().view_once, retention.view_once);
        assert_eq!(stored.retention.unwrap().expires_at, Some(100));
        assert_eq!(
            app.view_once_state(GROUP, &once.message_id_hex, 0, now)
                .unwrap(),
            if now == 100 {
                ViewOnceState::Expired
            } else if deadline.is_some() {
                ViewOnceState::Sent
            } else {
                ViewOnceState::Unavailable
            }
        );
        assert_eq!(
            app.claim_view_once(
                &["image/png"],
                GROUP,
                &once.message_id_hex,
                0,
                RECIPIENT,
                now
            )
            .unwrap(),
            if now == 100 {
                ViewOnceClaim::Expired
            } else {
                ViewOnceClaim::Unavailable
            }
        );
        assert!(
            app.finalize_app_event_source_retention(
                GROUP,
                &once.message_id_hex,
                Some("different"),
                4,
                AppMessageRetentionDecision {
                    view_once: Some(cgka_traits::app_event::ViewOncePolicy {
                        unopened_expires_at: 100
                    }),
                    ..retention
                }
            )
            .unwrap()
            .is_none()
        );
    }
}

#[test]
fn membership_revokes_viewer() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let once = event(100);
    seed(&store, &once);
    let app = store.app_storage();
    for consumed in [false, true] {
        if consumed {
            claimed(
                app.claim_view_once(
                    &["image/png"],
                    GROUP,
                    &once.message_id_hex,
                    0,
                    RECIPIENT,
                    12,
                )
                .unwrap(),
            );
        }
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE account_groups SET self_membership='left' WHERE group_id_hex=?1",
                [GROUP],
            )
            .unwrap();
        assert_eq!(
            app.view_once_state(GROUP, &once.message_id_hex, 0, 12)
                .unwrap(),
            if consumed {
                ViewOnceState::Consumed
            } else {
                ViewOnceState::Unavailable
            }
        );
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE account_groups SET self_membership='member' WHERE group_id_hex=?1",
                [GROUP],
            )
            .unwrap();
        assert_eq!(
            app.view_once_state(GROUP, &once.message_id_hex, 0, 12)
                .unwrap(),
            if consumed {
                ViewOnceState::Consumed
            } else {
                ViewOnceState::Unopened
            }
        );
        assert!(
            !app.view_once_access_valid(GROUP, &once.message_id_hex, 0, 12)
                .unwrap()
        );
    }
}

#[test]
fn nested_claim_refuses_rollback() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let once = event(100);
    seed(&store, &once);
    let app = store.app_storage();
    let result: StorageResult<()> = store.connection.with_transaction(|| {
        match app.claim_view_once(
            &["image/png"],
            GROUP,
            &once.message_id_hex,
            0,
            RECIPIENT,
            12,
        ) {
            Err(StorageError::Backend(message)) => {
                assert_eq!(message, "view-once claim requires independent transaction")
            }
            other => panic!("unexpected {other:?}"),
        }
        Err(StorageError::Backend("outer rollback".into()))
    });
    assert!(matches!(result, Err(StorageError::Backend(message)) if message == "outer rollback"));
    claimed(
        app.claim_view_once(
            &["image/png"],
            GROUP,
            &once.message_id_hex,
            0,
            RECIPIENT,
            12,
        )
        .unwrap(),
    );
}

#[test]
fn unknown_profiles_are_redacted() {
    for (version, marker) in [
        ("encrypted-media-view-once-v2", None),
        ("encrypted-media-view-once", None),
        (
            "encrypted-media-view-once-v1",
            Some(vec!["view-once", "unknown", "100", "private-caption"]),
        ),
        (
            "encrypted-media-view-once-v1",
            Some(vec!["view-once", "view-once-v1", "100", "private-caption"]),
        ),
    ] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mut once = event(100);
        once.tags.truncate(1);
        once.tags[0][2] = format!("v {version}");
        if let Some(marker) = marker {
            once.tags
                .push(marker.into_iter().map(String::from).collect());
        }
        once.plaintext = "private caption".into();
        once.message_id_hex =
            MarmotAppEvent::new(SENDER, 10, 9, once.tags.clone(), once.plaintext.clone()).id;
        seed(&store, &once);
        let app = store.app_storage();
        let row = app
            .timeline_message(GROUP, &once.message_id_hex)
            .unwrap()
            .unwrap();
        assert!(row.plaintext.is_empty());
        assert_eq!(row.tags, vec![vec!["view-once".to_owned()]]);
        assert!(row.media.is_none());
        assert_eq!(row.view_once.unwrap().state, ViewOnceState::Unavailable);
        let mut reply = once.clone();
        reply.message_id_hex = "reply".into();
        reply.source_message_id_hex = Some("reply-source".into());
        reply.plaintext = "reply".into();
        reply.tags = vec![vec!["q".into(), once.message_id_hex.clone()]];
        app.record_app_event(&reply).unwrap();
        let preview = app
            .timeline_message(GROUP, &reply.message_id_hex)
            .unwrap()
            .unwrap()
            .reply_preview
            .unwrap();
        assert_eq!(preview.message_id_hex, once.message_id_hex);
        assert!(preview.plaintext.is_empty());
        assert_eq!(preview.tags, vec![vec!["view-once".to_owned()]]);
        assert!(preview.media.is_none());
        assert_eq!(preview.view_once.unwrap().state, ViewOnceState::Unavailable);
        for query in [
            "private caption",
            "private-caption",
            "image.png",
            "https://example.com",
        ] {
            assert!(
                app.message_timeline(crate::TimelineMessageQuery {
                    group_id_hex: Some(GROUP.into()),
                    search: Some(query.into()),
                    ..Default::default()
                })
                .unwrap()
                .messages
                .is_empty()
            );
        }
        assert!(
            app.attachment_history_page(GROUP, 100, None)
                .unwrap()
                .entries
                .is_empty()
        );
        assert!(
            app.attachment_control_entry(GROUP, &once.message_id_hex, "source", 0, 12)
                .unwrap()
                .is_none()
        );
        assert!(
            app.retained_attachment_descriptor(GROUP, &once.message_id_hex, "source", 0, 12)
                .unwrap()
                .is_none()
        );
        let export = app.history_export_page(GROUP, None, 12, 100).unwrap();
        assert!(
            export
                .iter()
                .find(|record| record.message_id_hex == once.message_id_hex)
                .unwrap()
                .event
                .is_none()
        );
        assert_eq!(
            app.claim_view_once(
                &["image/png"],
                GROUP,
                &once.message_id_hex,
                0,
                RECIPIENT,
                12
            )
            .unwrap(),
            ViewOnceClaim::Unavailable
        );
    }
}

#[test]
fn mime_refusal_preserves_claim() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut once = event(100);
    once.tags[0][1] = "m image/svg+xml".into();
    once.message_id_hex = MarmotAppEvent::new(SENDER, 10, 9, once.tags.clone(), String::new()).id;
    seed(&store, &once);
    let app = store.app_storage();
    for now in [12, 13] {
        assert_eq!(
            app.claim_view_once(
                &["image/png"],
                GROUP,
                &once.message_id_hex,
                0,
                RECIPIENT,
                now
            )
            .unwrap(),
            ViewOnceClaim::Unavailable,
        );
        assert_eq!(
            app.view_once_state(GROUP, &once.message_id_hex, 0, now)
                .unwrap(),
            ViewOnceState::Unopened,
        );
        let (tags, expires): (String, i64) = store.lock().unwrap().query_row(
            "SELECT a.tags_json,v.expires_at FROM app_events a JOIN view_once_consumption v USING(group_id_hex,message_id_hex) WHERE a.group_id_hex=?1 AND a.message_id_hex=?2",
            params![GROUP, once.message_id_hex], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<Vec<String>>>(&tags).unwrap(),
            once.tags
        );
        assert_eq!(expires, 100);
    }
    claimed(
        app.claim_view_once(
            &["image/svg+xml"],
            GROUP,
            &once.message_id_hex,
            0,
            RECIPIENT,
            14,
        )
        .unwrap(),
    );
    assert_eq!(
        app.claim_view_once(&[], GROUP, &once.message_id_hex, 0, RECIPIENT, 14)
            .unwrap(),
        ViewOnceClaim::Consumed,
    );
}

#[test]
fn live_access_checks_source() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let once = event(100);
    seed(&store, &once);
    let app = store.app_storage();
    let mut edit = once.clone();
    edit.kind = cgka_traits::app_event::MARMOT_APP_EVENT_KIND_EDIT;
    edit.message_id_hex = "edit".into();
    edit.source_message_id_hex = Some("edit-source".into());
    edit.tags = vec![vec!["e".into(), once.message_id_hex.clone()]];
    edit.plaintext = "forbidden caption".into();
    edit.recorded_at = 12;
    app.record_app_event(&edit).unwrap();
    assert!(
        app.message_edit_history(GROUP, &once.message_id_hex, None, 10)
            .unwrap()
            .versions
            .is_empty()
    );
    assert!(
        app.timeline_message(GROUP, &once.message_id_hex)
            .unwrap()
            .unwrap()
            .plaintext
            .is_empty()
    );
    claimed(
        app.claim_view_once(
            &["image/png"],
            GROUP,
            &once.message_id_hex,
            0,
            RECIPIENT,
            12,
        )
        .unwrap(),
    );
    assert!(
        app.view_once_access_valid(GROUP, &once.message_id_hex, 0, 12)
            .unwrap()
    );
    let mut deletion = edit;
    deletion.kind = 5;
    deletion.message_id_hex = "delete".into();
    deletion.source_message_id_hex = Some("delete-source".into());
    deletion.plaintext.clear();
    deletion.recorded_at = 13;
    app.record_app_event(&deletion).unwrap();
    assert!(
        !app.view_once_access_valid(GROUP, &once.message_id_hex, 0, 13)
            .unwrap()
    );
    app.record_app_event(&once).unwrap();
    assert!(
        !app.view_once_access_valid(GROUP, &once.message_id_hex, 0, 12)
            .unwrap()
    );
    assert_eq!(
        app.claim_view_once(
            &["image/png"],
            GROUP,
            &once.message_id_hex,
            0,
            RECIPIENT,
            12
        )
        .unwrap(),
        ViewOnceClaim::Consumed
    );

    let fresh = SqliteAccountStorage::in_memory().unwrap();
    fresh
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES(?1,'',0)",
            [GROUP],
        )
        .unwrap();
    fresh
        .app_storage()
        .record_app_event_with_retention(
            &once,
            Some(cgka_traits::app_event::AppMessageRetentionDecision {
                retention_seconds: 10,
                expires_at: Some(20),
                view_once: Some(cgka_traits::app_event::ViewOncePolicy {
                    unopened_expires_at: 100,
                }),
            }),
        )
        .unwrap();
    match fresh
        .app_storage()
        .claim_view_once(
            &["image/png"],
            GROUP,
            &once.message_id_hex,
            0,
            RECIPIENT,
            12,
        )
        .unwrap()
    {
        ViewOnceClaim::Claimed { expires_at, .. } => assert_eq!(expires_at, 20),
        other => panic!("unexpected {other:?}"),
    }
    assert!(
        !fresh
            .app_storage()
            .view_once_access_valid(GROUP, &once.message_id_hex, 0, 20)
            .unwrap()
    );
    assert!(
        !fresh
            .app_storage()
            .view_once_access_valid(GROUP, &once.message_id_hex, 0, 12)
            .unwrap()
    );
}
