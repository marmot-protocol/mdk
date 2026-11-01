//! A stored `app_events.tags_json` that no longer decodes is on-disk damage:
//! every writer serializes a typed tag list. These tests damage one row and run
//! each path that reads the blob, which must still complete.

use super::*;
use crate::{SqliteAccountStorage, StoredAppMessageQuery};
use cgka_traits::app_components::{
    ENCRYPTED_MEDIA_FORMAT_V1, GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID,
};

fn group() -> String {
    "11".repeat(32)
}

fn event(id: &str, kind: u64, tags: Vec<Vec<String>>, at: u64, plaintext: &str) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: group(),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: None,
        direction: "received".to_owned(),
        sender: "alice".to_owned(),
        plaintext: plaintext.to_owned(),
        kind,
        tags,
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
        moderation_grant: false,
    }
}

fn chat(id: &str, at: u64, plaintext: &str) -> StoredAppEvent {
    event(id, MARMOT_APP_EVENT_KIND_CHAT, Vec::new(), at, plaintext)
}

fn targeting(id: &str, kind: u64, target: &str, at: u64, plaintext: &str) -> StoredAppEvent {
    let tags = vec![vec![EVENT_REF_TAG.to_owned(), target.to_owned()]];
    event(id, kind, tags, at, plaintext)
}

fn damage_tags(app: &SqliteAppStorage, id: &str) {
    let damaged = app
        .lock()
        .unwrap()
        .execute(
            "UPDATE app_events SET tags_json = 'not-json'
             WHERE group_id_hex = ?1 AND message_id_hex = ?2",
            params![group(), id],
        )
        .unwrap();
    assert_eq!(damaged, 1);
}

fn no_mentions(_plaintext: &str, _tags: &[Vec<String>]) -> bool {
    false
}

fn stored_ids(app: &SqliteAppStorage, table: &str) -> Vec<String> {
    let conn = app.lock().unwrap();
    let mut stmt = conn
        .prepare(&format!(
            "SELECT message_id_hex FROM {table} WHERE group_id_hex = ?1 ORDER BY message_id_hex"
        ))
        .unwrap();
    stmt.query_map(params![group()], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// Whether `text` survives anywhere the prune must erase it from.
fn plaintext_survives(app: &SqliteAppStorage, text: &str) -> bool {
    app.lock()
        .unwrap()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM app_events WHERE instr(plaintext, ?1))
                 OR EXISTS(SELECT 1 FROM message_timeline WHERE instr(plaintext, ?1))
                 OR EXISTS(SELECT 1 FROM chat_list_rows WHERE instr(last_message_preview, ?1))",
            params![text],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn secure_prunes_erase_a_row_whose_tags_no_longer_decode() {
    // Both selections, by cutoff and by expiry, read the blob.
    for expiry in [false, true] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let app = store.app_storage();
        app.ensure_account_projection_with_identity("local", "alice")
            .unwrap();
        let retention = Some(AppMessageRetentionDecision::new(10, 10));
        for (id, at) in [("damaged", 10), ("healthy", 11)] {
            app.record_app_event_with_retention(&chat(id, at, &format!("{id} secret")), retention)
                .unwrap();
        }
        app.record_app_event(&chat("kept", 30, "kept")).unwrap();
        damage_tags(&app, "damaged");

        let outcome = if expiry {
            app.secure_prune_expired_app_events(&group(), 25, "local", &no_mentions)
        } else {
            app.secure_prune_app_events_before(&group(), 25, "local", &no_mentions)
        }
        .expect("a damaged tag blob must not block retention erasure");

        assert_eq!(outcome.pruned_messages, 2, "expiry mode: {expiry}");
        assert_eq!(stored_ids(&app, "app_events"), ["kept"]);
        assert_eq!(stored_ids(&app, "message_timeline"), ["kept"]);
        assert!(!plaintext_survives(&app, "damaged secret"));
    }
}

// A damaged chat's tags cannot say whether it carried encrypted media, so the
// prune asks the references they wrote while they still decoded: the media
// chat's epoch secret retires, and the plain chat's epoch stays open.
#[test]
fn secure_prune_retires_only_the_media_epochs_a_damaged_chat_referenced() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    app.ensure_account_projection_with_identity("local", "alice")
        .unwrap();
    let media = GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID;
    app.remember_encrypted_media_epoch_secret(&group(), media, 7, &[1, 2, 3])
        .unwrap();
    let mut with_media = chat("with-media", 10, "photo");
    with_media.source_epoch = Some(7);
    with_media.tags = vec![vec![
        "imeta".to_owned(),
        format!("v {ENCRYPTED_MEDIA_FORMAT_V1}"),
        format!("ciphertext_sha256 {}", "ab".repeat(32)),
    ]];
    let mut plain = chat("plain", 11, "text");
    plain.source_epoch = Some(8);
    for row in [&with_media, &plain] {
        let retention = AppMessageRetentionDecision::new(row.recorded_at, 10);
        app.record_app_event_with_retention(row, Some(retention))
            .unwrap();
        damage_tags(&app, &row.message_id_hex);
    }

    let outcome = app
        .secure_prune_expired_app_events(&group(), 25, "local", &no_mentions)
        .unwrap();

    assert_eq!(outcome.pruned_messages, 2);
    assert_eq!(outcome.pruned_media_epoch_secrets, 1);
    assert_eq!(
        app.encrypted_media_epoch_secret(&group(), media, 7)
            .unwrap(),
        None
    );
    // Retiring epoch 8 would refuse to cache a secret for it from now on.
    app.remember_encrypted_media_epoch_secret(&group(), media, 8, &[4])
        .unwrap();
    let cached = app
        .encrypted_media_epoch_secret(&group(), media, 8)
        .unwrap();
    assert_eq!(cached, Some(vec![4]));
}

/// Record each time the prune zeroes the target's timeline text or a chat-list
/// preview in place, which it does before rewriting an edited target.
fn record_in_place_scrubs(app: &SqliteAppStorage) {
    app.lock()
        .unwrap()
        .execute_batch(
            "CREATE TEMP TABLE scrubs(what TEXT NOT NULL);
             CREATE TEMP TRIGGER scrub_timeline AFTER UPDATE OF plaintext ON main.message_timeline
             WHEN NEW.message_id_hex = 'target' AND typeof(NEW.plaintext) = 'blob'
             BEGIN INSERT INTO scrubs VALUES ('timeline'); END;
             CREATE TEMP TRIGGER scrub_preview AFTER UPDATE OF last_message_preview
             ON main.chat_list_rows WHEN typeof(NEW.last_message_preview) = 'blob'
             BEGIN INSERT INTO scrubs VALUES ('preview'); END;",
        )
        .unwrap();
}

fn in_place_scrubs(app: &SqliteAppStorage) -> Vec<String> {
    let conn = app.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT DISTINCT what FROM temp.scrubs ORDER BY what")
        .unwrap();
    stmt.query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

// Only the damaged tags named the target an expired edit rewrote; the prune
// finds it through the edge recorded while they still decoded, and scrubs and
// reprojects it as it would for a healthy edit.
#[test]
fn secure_prune_of_a_damaged_edit_leaves_no_copy_on_its_target() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    app.ensure_account_projection_with_identity("local", "alice")
        .unwrap();
    app.record_app_event(&chat("target", 10, "original"))
        .unwrap();
    app.record_app_event_with_retention(
        &targeting(
            "edit",
            MARMOT_APP_EVENT_KIND_EDIT,
            "target",
            11,
            "edited secret",
        ),
        Some(AppMessageRetentionDecision::new(11, 10)),
    )
    .unwrap();
    let target = app.timeline_message(&group(), "target").unwrap().unwrap();
    assert_eq!(target.plaintext, "edited secret");
    app.lock()
        .unwrap()
        .execute(
            "INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES (?1, '', 0)",
            params![group()],
        )
        .unwrap();
    let row = app
        .refresh_chat_list_row("local", &group(), &no_mentions)
        .unwrap()
        .unwrap();
    let preview = row.last_message.unwrap();
    assert_eq!(
        (preview.message_id_hex.as_str(), preview.plaintext.as_str()),
        ("target", "edited secret")
    );
    damage_tags(&app, "edit");
    record_in_place_scrubs(&app);

    app.secure_prune_expired_app_events(&group(), 25, "local", &no_mentions)
        .unwrap();

    assert_eq!(stored_ids(&app, "app_events"), ["target"]);
    let target = app.timeline_message(&group(), "target").unwrap().unwrap();
    assert_eq!(target.plaintext, "original");
    assert_eq!(target.edit, None);
    assert!(!plaintext_survives(&app, "edited secret"));
    assert_eq!(in_place_scrubs(&app), ["preview", "timeline"]);
}

// An expired delete stays as a control with its content erased. The target's
// row reads the delete's recorded edge, not its tags, so it stays deleted.
#[test]
fn secure_prune_of_a_damaged_delete_keeps_its_target_deleted() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    app.ensure_account_projection_with_identity("local", "alice")
        .unwrap();
    app.record_app_event(&chat("target", 10, "original"))
        .unwrap();
    app.record_app_event_with_retention(
        &targeting("delete", MARMOT_APP_EVENT_KIND_DELETE, "target", 11, ""),
        Some(AppMessageRetentionDecision::new(11, 10)),
    )
    .unwrap();
    assert!(
        app.timeline_message(&group(), "target")
            .unwrap()
            .unwrap()
            .deleted
    );
    damage_tags(&app, "delete");

    app.secure_prune_expired_app_events(&group(), 25, "local", &no_mentions)
        .unwrap();

    assert_eq!(stored_ids(&app, "app_events"), ["delete", "target"]);
    let target = app.timeline_message(&group(), "target").unwrap().unwrap();
    assert!(target.deleted);
    assert_eq!(target.deleted_by_message_id_hex.as_deref(), Some("delete"));
}

#[test]
fn withdrawals_apply_to_a_row_whose_tags_no_longer_decode() {
    type Withdraw = fn(&SqliteAppStorage) -> StorageResult<Option<TimelineProjectionUpdate>>;
    let cases: [(&str, Withdraw, Option<&str>); 5] = [
        (
            "by source",
            |app| app.invalidate_app_event_by_source("source-damaged", "LosingBranch"),
            Some("LosingBranch"),
        ),
        (
            "by message id",
            |app| app.invalidate_app_event_by_message_id(&group(), "damaged", "LosingBranch"),
            Some("LosingBranch"),
        ),
        (
            "by origin commit",
            |app| app.invalidate_app_events_by_origin_commit("commit", "LosingBranch"),
            Some("LosingBranch"),
        ),
        (
            "branch-selection revival",
            |app| app.clear_branch_selection_withdrawal_by_origin_commit("commit"),
            None,
        ),
        (
            "terminal sweep",
            |app| {
                app.invalidate_pending_sent_app_events_for_group(
                    &group(),
                    LOCAL_PUBLISH_FAILED_REASON,
                )
            },
            Some(LOCAL_PUBLISH_FAILED_REASON),
        ),
    ];
    for (name, withdraw, reason) in cases {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let app = store.app_storage();
        for (id, at, text) in [("bystander", 9, "unrelated"), ("target", 10, "original")] {
            app.record_app_event(&chat(id, at, text)).unwrap();
        }
        let mut damaged = targeting(
            "damaged",
            MARMOT_APP_EVENT_KIND_EDIT,
            "target",
            11,
            "edited",
        );
        damaged.origin_commit_id = Some("commit".to_owned());
        if name == "terminal sweep" {
            damaged.direction = "sent".to_owned();
            damaged.source_message_id_hex = None;
        }
        app.record_app_event(&damaged).unwrap();
        if reason.is_none() {
            app.invalidate_app_events_by_origin_commit(
                "commit",
                BRANCH_SELECTION_WITHDRAWAL_REASON,
            )
            .unwrap();
        }
        damage_tags(&app, "damaged");

        let update = withdraw(&app)
            .unwrap_or_else(|error| panic!("{name}: {error}"))
            .unwrap_or_else(|| panic!("{name}: no row matched"));

        // The damaged tags no longer name the target, yet a withdrawal takes
        // the edit off it and live subscribers still hear of it. Nothing
        // changes on a revival: the edit applied neither before nor after.
        let upserts = update
            .changes
            .iter()
            .filter_map(|change| match change {
                TimelineMessageChange::Upsert { message, .. } => {
                    Some((message.message_id_hex.as_str(), message.plaintext.as_str()))
                }
                TimelineMessageChange::Remove { .. } => None,
            })
            .collect::<Vec<_>>();
        let messages = update
            .messages
            .iter()
            .map(|message| message.message_id_hex.as_str())
            .collect::<Vec<_>>();
        if reason.is_some() {
            assert_eq!(upserts, [("target", "original")], "{name}");
            assert_eq!(messages, ["target"], "{name}");
        } else {
            assert_eq!(upserts, [], "{name}");
            assert_eq!(messages, Vec::<&str>::new(), "{name}");
        }
        let stored: Option<String> = app
            .lock()
            .unwrap()
            .query_row(
                "SELECT invalidation_reason FROM app_events WHERE message_id_hex = 'damaged'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored.as_deref(), reason, "{name}");
    }
}

// Raw reads serve recovery and the app's delete path, which needs only the
// row's kind and sender.
#[test]
fn app_message_reads_return_a_row_whose_tags_no_longer_decode() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    for (id, at) in [("damaged", 10), ("healthy", 11)] {
        app.record_app_event(&chat(id, at, id)).unwrap();
    }
    damage_tags(&app, "damaged");

    let message = app
        .app_message(&group(), "damaged")
        .expect("a damaged tag blob must not block a raw read")
        .unwrap();
    assert_eq!(
        (message.kind, message.sender.as_str()),
        (MARMOT_APP_EVENT_KIND_CHAT, "alice")
    );
    assert!(message.tags.is_empty());
    let query = StoredAppMessageQuery {
        group_id_hex: Some(group()),
        ..Default::default()
    };
    for visible in [false, true] {
        let messages = if visible {
            app.visible_app_messages(query.clone())
        } else {
            app.app_messages(query.clone())
        }
        .expect("a damaged tag blob must not block a group's raw reads");
        let ids = messages
            .iter()
            .map(|message| message.message_id_hex.as_str());
        assert_eq!(ids.collect::<Vec<_>>(), ["damaged", "healthy"]);
    }
}

// A held send that publishes takes its retention deadline here; failing it
// would leave the row with no deadline, so it would never expire.
#[test]
fn source_retention_finalizes_a_row_whose_tags_no_longer_decode() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let mut sent = chat("damaged", 10, "held send");
    sent.direction = "sent".to_owned();
    sent.source_message_id_hex = None;
    app.record_app_event(&sent).unwrap();
    damage_tags(&app, "damaged");

    let update = app
        .finalize_app_event_source_retention(
            &group(),
            "damaged",
            Some("source-damaged"),
            1,
            AppMessageRetentionDecision::new(10, 10),
        )
        .unwrap();

    assert!(update.is_some());
    let message = app.timeline_message(&group(), "damaged").unwrap().unwrap();
    assert_eq!(message.retention_expires_at, Some(20));
}

// Deleting a reaction looks up the reaction's own target. A damaged reaction
// has none, so the delete still records.
#[test]
fn deleting_a_modifier_whose_tags_no_longer_decode_records_the_delete() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    app.record_app_event(&chat("target", 10, "target")).unwrap();
    app.record_app_event(&targeting(
        "reaction",
        MARMOT_APP_EVENT_KIND_REACTION,
        "target",
        11,
        "+",
    ))
    .unwrap();
    damage_tags(&app, "reaction");

    app.record_app_event(&targeting(
        "delete",
        MARMOT_APP_EVENT_KIND_DELETE,
        "reaction",
        12,
        "",
    ))
    .expect("a damaged delete target must not block the delete");

    assert_eq!(
        stored_ids(&app, "app_events"),
        ["delete", "reaction", "target"]
    );
}

// A response whose tags no longer decode names no poll, so it is skipped like
// any invalid response, and its voter falls back to their latest valid one.
#[test]
fn poll_tally_skips_a_response_whose_tags_no_longer_decode() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let poll_id = "22".repeat(32);
    let poll_tags = cgka_traits::poll_tags(
        100,
        "Drink?",
        &["Tea".to_owned(), "Coffee".to_owned()],
        cgka_traits::PollType::SingleChoice,
        Some(200),
    )
    .unwrap();
    app.record_app_event(&event(
        &poll_id,
        MARMOT_APP_EVENT_KIND_POLL,
        poll_tags,
        100,
        "Drink?",
    ))
    .unwrap();
    for (id, at, option) in [("older", 150, "0"), ("damaged", 160, "1")] {
        let tags = cgka_traits::poll_response_tags(&poll_id, &[option.to_owned()]).unwrap();
        let mut response = event(id, MARMOT_APP_EVENT_KIND_POLL_RESPONSE, tags, at, "");
        response.sender = "bob".to_owned();
        app.record_app_event(&response).unwrap();
    }
    damage_tags(&app, "damaged");

    let poll = app
        .timeline_message(&group(), &poll_id)
        .expect("a damaged poll response must not block the poll's read")
        .unwrap()
        .poll
        .unwrap();

    let votes = poll.options.iter().map(|option| option.votes);
    assert_eq!(votes.collect::<Vec<_>>(), [1, 0]);
}

// A row stays out of a history bundle when its content no longer hashes to its
// id; a damaged row decoded to no tags is one such row.
#[test]
fn history_export_leaves_out_a_row_whose_tags_no_longer_decode() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let sender = hex::encode([1; 32]);
    let rows = [("healthy", 10), ("damaged", 11)].map(|(text, at)| {
        let tags = vec![vec!["t".to_owned(), text.to_owned()]];
        let kind = MARMOT_APP_EVENT_KIND_CHAT;
        let signed = MarmotAppEvent::new(sender.clone(), at, kind, tags.clone(), text);
        let mut row = event(&signed.id, kind, tags, at, text);
        row.sender = sender.clone();
        row.source_epoch = Some(1);
        row
    });
    for row in &rows {
        app.record_app_event(row).unwrap();
    }
    damage_tags(&app, &rows[1].message_id_hex);

    let page = app
        .history_export_page(&group(), None, 100, 10)
        .expect("a damaged tag blob must not block the history export");

    let carried = page
        .iter()
        .map(|row| (row.message_id_hex.as_str(), row.event.is_some()))
        .collect::<Vec<_>>();
    assert_eq!(
        carried,
        [
            (rows[0].message_id_hex.as_str(), true),
            (rows[1].message_id_hex.as_str(), false),
        ]
    );
}
