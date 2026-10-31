use super::*;
use crate::{
    SelfMembership, SqliteAccountStorage, StoredAccountGroup, StoredAccountState, StoredAppEvent,
};
use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT;
use std::cell::Cell;

const LOCAL: &str = "aa";
const REMOTE: &str = "bb";
const MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;
/// A mute end far in the future, in seconds.
const MUTE_UNTIL: u64 = 4_000_000_000;

/// Highest version wins, then the lowest change id; the furthest read wins.
/// Change ids count up from 1, so a sibling's id can sort either side.
/// Pins go first unless `pin_last`.
struct TestRule {
    next: Cell<u8>,
    pin_last: bool,
}

impl TestRule {
    fn new() -> Self {
        Self {
            next: Cell::new(0),
            pin_last: false,
        }
    }
}

impl SmallStateRule for TestRule {
    fn wins(&self, incoming: &SmallStateItem, held: &SmallStateItem) -> bool {
        match (&incoming.value, &held.value, incoming.version, held.version) {
            (SmallStateValue::Read(incoming), SmallStateValue::Read(held), _, _) => incoming > held,
            (_, _, Some(incoming), Some(held)) => {
                (incoming.version, std::cmp::Reverse(incoming.change_id))
                    > (held.version, std::cmp::Reverse(held.change_id))
            }
            _ => false,
        }
    }

    fn new_change_id(&self) -> [u8; 16] {
        self.next.set(self.next.get() + 1);
        [self.next.get(); 16]
    }

    fn pin_index(&self, _pinned: &[String]) -> usize {
        if self.pin_last { usize::MAX } else { 0 }
    }
}

fn no_mentions(_plaintext: &str, _tags: &[Vec<String>]) -> bool {
    false
}

fn group(id: &str, archived: bool) -> StoredAccountGroup {
    StoredAccountGroup {
        group_id_hex: id.to_owned(),
        endpoint: "relay".to_owned(),
        profile_name: format!("Chat {id}"),
        profile_description: String::new(),
        image_hash_hex: String::new(),
        image_key_hex: String::new(),
        image_nonce_hex: String::new(),
        image_upload_key_hex: String::new(),
        image_media_type: None,
        admin_keys_hex: String::new(),
        archived,
        pending_confirmation: false,
        member_count: None,
        direct_member_ids_hex: None,
        presentation_member_ids_hex: None,
        welcomer_account_id_hex: None,
        via_welcome_message_id_hex: None,
        nostr_routing_last_epoch: 0,
        prior_nostr_routes: Vec::new(),
        self_membership: SelfMembership::Member,
        components: Vec::new(),
    }
}

fn save_groups(store: &SqliteAccountStorage, groups: &[(&str, bool)]) {
    store
        .app_storage()
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: groups
                    .iter()
                    .map(|(id, archived)| group(id, *archived))
                    .collect(),
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    store
        .app_storage()
        .refresh_chat_list_rows(LOCAL, &no_mentions)
        .unwrap();
}

fn started_store(groups: &[(&str, bool)]) -> SqliteAccountStorage {
    let store = SqliteAccountStorage::in_memory().unwrap();
    save_groups(&store, groups);
    assert!(store.app_storage().start_small_state().unwrap());
    store
}

fn sync(
    store: &SqliteAccountStorage,
    incoming: &[SmallStateItem],
    rule: &TestRule,
) -> SmallStateSync {
    store
        .app_storage()
        .sync_small_state(LOCAL, incoming, rule, &no_mentions)
        .unwrap()
}

fn pins(store: &SqliteAccountStorage) -> Vec<String> {
    pinned_chat_order_tx(&store.lock().unwrap()).unwrap()
}

fn versioned(group: &str, value: SmallStateValue, version: u64, id: u8) -> SmallStateItem {
    SmallStateItem {
        group_id_hex: group.to_owned(),
        value,
        version: Some(SmallStateVersion {
            version,
            change_id: [id; 16],
        }),
    }
}

/// A message id: 64 lowercase hex characters.
fn message(n: u8) -> String {
    format!("{n:064x}")
}

fn read(group: &str, epoch: u64, at: u64, id: u8) -> SmallStateItem {
    SmallStateItem {
        group_id_hex: group.to_owned(),
        value: SmallStateValue::Read(ReadPosition {
            epoch,
            at,
            message_id_hex: message(id),
        }),
        version: None,
    }
}

fn delivered_chat(group: &str, id: u8, epoch: u64, at: u64) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: group.to_owned(),
        message_id_hex: message(id),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: Some(epoch),
        direction: "received".to_owned(),
        sender: REMOTE.to_owned(),
        plaintext: format!("message {id}"),
        kind: MARMOT_APP_EVENT_KIND_CHAT,
        tags: Vec::new(),
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
        moderation_grant: false,
    }
}

#[test]
fn nothing_is_recorded_or_applied_before_small_state_starts() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    save_groups(&store, &[("11", false)]);
    let app = store.app_storage();
    app.set_chat_pinned("11", true).unwrap();
    let rule = TestRule::new();

    let incoming = versioned("11", SmallStateValue::Pin(false), 9, 1);
    assert_eq!(sync(&store, &[incoming], &rule), SmallStateSync::default());
    assert!(!app.small_state_started().unwrap());
    assert!(app.small_state_items().unwrap().is_empty());
    assert_eq!(pins(&store), vec!["11"]);

    assert_eq!(app.small_state_schedule().unwrap(), None);
    app.owe_small_state_broadcast_request().unwrap();
    app.owe_small_state_broadcast_answer().unwrap();
    app.begin_small_state_broadcast(100, 4).unwrap();
    assert_eq!(app.small_state_schedule().unwrap(), None);

    // Starting owes a broadcast request, and no broadcast has been made.
    assert!(app.start_small_state().unwrap());
    assert!(!app.start_small_state().unwrap());
    assert!(app.small_state_started().unwrap());
    assert_eq!(
        app.small_state_schedule().unwrap(),
        Some(SmallStateSchedule {
            last_broadcast: None,
            request_owed: true,
            answer_owed: false,
        })
    );
}

#[test]
fn starting_seeds_only_settings_that_differ_from_the_default() {
    let store = started_store(&[("11", false), ("22", true), ("33", false)]);
    let app = store.app_storage();
    app.set_chat_pinned("11", true).unwrap();
    app.set_chat_muted("33", None).unwrap();
    let rule = TestRule::new();

    let outcome = sync(&store, &[], &rule);
    assert_eq!(outcome.recorded, 3);
    assert!(outcome.applied.is_empty());
    assert!(outcome.archive_to_apply.is_empty());
    let owed = app.unsent_small_state_items().unwrap();
    assert_eq!(
        owed.iter()
            .map(|item| (item.group_id_hex.as_str(), item.value.clone()))
            .collect::<Vec<_>>(),
        vec![
            ("11", SmallStateValue::Pin(true)),
            ("22", SmallStateValue::Archive(true)),
            ("33", SmallStateValue::Mute(MuteSetting::Muted)),
        ]
    );
    assert!(
        owed.iter()
            .all(|item| item.version.is_some_and(|version| version.version == 1))
    );

    // Unchanged state records nothing more.
    assert_eq!(sync(&store, &[], &rule).recorded, 0);
}

#[test]
fn a_local_change_raises_the_version_and_stays_owed_until_sent() {
    let store = started_store(&[("11", false)]);
    let app = store.app_storage();
    let rule = TestRule::new();
    app.set_chat_pinned("11", true).unwrap();
    sync(&store, &[], &rule);
    let first = app.unsent_small_state_items().unwrap();
    assert_eq!(first.len(), 1);

    app.set_chat_pinned("11", false).unwrap();
    assert_eq!(sync(&store, &[], &rule).recorded, 1);
    // The first update reached the relays only after the second change: the
    // second stays owed.
    app.mark_small_state_sent(&first).unwrap();
    let second = app.unsent_small_state_items().unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].value, SmallStateValue::Pin(false));
    assert_eq!(second[0].version.unwrap().version, 2);

    app.mark_small_state_sent(&second).unwrap();
    assert!(app.unsent_small_state_items().unwrap().is_empty());
    assert_eq!(app.small_state_items().unwrap(), second);

    // After a small-state message is withdrawn, every item held is owed
    // again unchanged, a sibling's included.
    let sibling = versioned("22", SmallStateValue::Archive(true), 1, 9);
    sync(&store, std::slice::from_ref(&sibling), &rule);
    assert_eq!(app.owe_all_small_state_items().unwrap(), 2);
    assert_eq!(
        app.unsent_small_state_items().unwrap(),
        vec![second[0].clone(), sibling]
    );
    assert_eq!(app.owe_all_small_state_items().unwrap(), 0);
}

#[test]
fn an_item_at_the_highest_version_cannot_be_changed() {
    let store = started_store(&[("11", false)]);
    let app = store.app_storage();
    let rule = TestRule::new();
    let fixed = versioned("11", SmallStateValue::Pin(true), MAX_SMALL_STATE_NUMBER, 9);
    sync(&store, std::slice::from_ref(&fixed), &rule);
    assert_eq!(pins(&store), vec!["11"]);

    // The user's unpin is put back, and nothing is owed.
    app.set_chat_pinned("11", false).unwrap();
    let outcome = sync(&store, &[], &rule);
    assert_eq!(outcome.recorded, 0);
    assert_eq!(
        outcome.applied.get("11"),
        Some(&BTreeSet::from([SmallStateItemName::Pin]))
    );
    assert_eq!(pins(&store), vec!["11"]);
    assert_eq!(app.small_state_items().unwrap(), vec![fixed]);
    assert!(app.unsent_small_state_items().unwrap().is_empty());
    assert_eq!(sync(&store, &[], &rule), SmallStateSync::default());

    // Archiving unpins, and the pin is put back once the chat is unarchived.
    save_groups(&store, &[("11", true)]);
    sync(&store, &[], &rule);
    assert!(pins(&store).is_empty());
    save_groups(&store, &[("11", false)]);
    sync(&store, &[], &rule);
    assert_eq!(pins(&store), vec!["11"]);
    assert!(
        app.unsent_small_state_items()
            .unwrap()
            .iter()
            .all(|item| item.name() != SmallStateItemName::Pin)
    );
}

#[test]
fn a_broadcast_owes_every_item_and_answers_requests_read_before_it() {
    let store = started_store(&[("11", false), ("22", false)]);
    let app = store.app_storage();
    let rule = TestRule::new();
    app.set_chat_pinned("11", true).unwrap();
    app.set_chat_pinned("22", true).unwrap();
    sync(&store, &[], &rule);
    app.mark_small_state_sent(&app.unsent_small_state_items().unwrap())
        .unwrap();
    app.small_state_broadcast_request_sent().unwrap();
    app.owe_small_state_broadcast_answer().unwrap();
    assert_eq!(
        app.small_state_schedule().unwrap(),
        Some(SmallStateSchedule {
            last_broadcast: None,
            request_owed: false,
            answer_owed: true,
        })
    );

    // A broadcast owes every item held, keeps when and at which tip it
    // began, and answers the request.
    app.begin_small_state_broadcast(100, 4).unwrap();
    assert_eq!(app.unsent_small_state_items().unwrap().len(), 2);
    assert_eq!(
        app.small_state_schedule().unwrap(),
        Some(SmallStateSchedule {
            last_broadcast: Some(SmallStateBroadcast { at: 100, tip: 4 }),
            request_owed: false,
            answer_owed: false,
        })
    );

    // A withdrawn request is owed again; a later broadcast replaces the
    // earlier one.
    app.owe_small_state_broadcast_request().unwrap();
    app.begin_small_state_broadcast(200, 9).unwrap();
    assert_eq!(
        app.small_state_schedule().unwrap(),
        Some(SmallStateSchedule {
            last_broadcast: Some(SmallStateBroadcast { at: 200, tip: 9 }),
            request_owed: true,
            answer_owed: false,
        })
    );
}

#[test]
fn a_winning_pin_or_mute_is_applied_once_and_never_taken_for_a_local_change() {
    let store = started_store(&[("11", false), ("22", false)]);
    let app = store.app_storage();
    let rule = TestRule::new();
    app.set_chat_pinned("11", true).unwrap();
    sync(&store, &[], &rule);
    app.mark_small_state_sent(&app.unsent_small_state_items().unwrap())
        .unwrap();

    let outcome = sync(
        &store,
        &[
            versioned("22", SmallStateValue::Pin(true), 1, 9),
            versioned(
                "22",
                SmallStateValue::Mute(MuteSetting::MutedUntil(MUTE_UNTIL)),
                4,
                9,
            ),
        ],
        &rule,
    );
    assert_eq!(outcome.recorded, 0);
    assert_eq!(
        outcome.applied.get("22"),
        Some(&BTreeSet::from([
            SmallStateItemName::Pin,
            SmallStateItemName::Mute
        ]))
    );
    // A newly pinned chat goes first, as this device's own pins do.
    assert_eq!(pins(&store), vec!["22", "11"]);
    assert_eq!(
        app.chat_notification_settings("22").unwrap().muted_until_ms,
        Some(4_000_000_000_000)
    );
    assert!(app.unsent_small_state_items().unwrap().is_empty());
    assert_eq!(sync(&store, &[], &rule), SmallStateSync::default());

    // The same values again change nothing; an older version loses.
    let outcome = sync(
        &store,
        &[
            versioned("22", SmallStateValue::Pin(true), 1, 9),
            versioned("22", SmallStateValue::Mute(MuteSetting::Unmuted), 3, 1),
        ],
        &rule,
    );
    assert_eq!(outcome, SmallStateSync::default());
    assert!(app.chat_notification_settings("22").unwrap().muted);

    // The user unmutes here: a change one version above the winner.
    app.clear_chat_muted("22").unwrap();
    assert_eq!(sync(&store, &[], &rule).recorded, 1);
    let owed = app.unsent_small_state_items().unwrap();
    assert_eq!(owed.len(), 1);
    assert_eq!(owed[0].value, SmallStateValue::Mute(MuteSetting::Unmuted));
    assert_eq!(owed[0].version.unwrap().version, 5);
}

#[test]
fn a_concurrent_change_resolves_by_the_rule_on_both_sides() {
    let store = started_store(&[("11", false)]);
    let app = store.app_storage();
    let rule = TestRule::new();
    app.set_chat_pinned("11", true).unwrap();
    sync(&store, &[], &rule);
    let ours = app.unsent_small_state_items().unwrap();
    assert_eq!(ours[0].version.unwrap().change_id, [1; 16]);

    // A sibling's change at the same version with a higher change id loses.
    let losing = versioned("11", SmallStateValue::Pin(false), 1, 7);
    assert_eq!(sync(&store, &[losing], &rule).applied.len(), 0);
    assert_eq!(app.small_state_items().unwrap(), ours);
    assert_eq!(app.unsent_small_state_items().unwrap(), ours);

    // A lower one wins, is applied, and is not owed: its sender has it.
    let winning = SmallStateItem {
        version: Some(SmallStateVersion {
            version: 1,
            change_id: [0; 16],
        }),
        ..versioned("11", SmallStateValue::Pin(false), 1, 0)
    };
    sync(&store, std::slice::from_ref(&winning), &rule);
    assert!(pins(&store).is_empty());
    assert_eq!(app.small_state_items().unwrap(), vec![winning]);
    assert!(app.unsent_small_state_items().unwrap().is_empty());
}

#[test]
fn archive_winners_go_back_to_the_caller_and_settle_once_applied() {
    let store = started_store(&[("11", false)]);
    let app = store.app_storage();
    let rule = TestRule::new();
    app.set_chat_pinned("11", true).unwrap();
    sync(&store, &[], &rule);
    app.mark_small_state_sent(&app.unsent_small_state_items().unwrap())
        .unwrap();

    let archive = versioned("11", SmallStateValue::Archive(true), 1, 9);
    let outcome = sync(&store, std::slice::from_ref(&archive), &rule);
    assert_eq!(outcome.archive_to_apply, vec![("11".to_owned(), true)]);
    // Still owed to the caller until the chat is archived.
    assert_eq!(
        sync(&store, &[], &rule).archive_to_apply,
        vec![("11".to_owned(), true)]
    );

    // Archiving unpins: that unpin is this device's change, sent on.
    save_groups(&store, &[("11", true)]);
    let outcome = sync(&store, &[], &rule);
    assert!(outcome.archive_to_apply.is_empty());
    assert_eq!(outcome.recorded, 1);
    let owed = app.unsent_small_state_items().unwrap();
    assert_eq!(owed.len(), 1);
    assert_eq!(owed[0].value, SmallStateValue::Pin(false));
    assert_eq!(sync(&store, &[], &rule).recorded, 0);

    // A pin that wins while the chat is archived is not applied here.
    let pin = versioned("11", SmallStateValue::Pin(true), 5, 9);
    let outcome = sync(&store, &[pin], &rule);
    assert!(outcome.applied.is_empty());
    assert!(pins(&store).is_empty());
    assert_eq!(sync(&store, &[], &rule).recorded, 0);
}

#[test]
fn a_pin_for_an_archived_chat_waits_until_it_is_unarchived() {
    let store = started_store(&[("11", true), ("22", true)]);
    let rule = TestRule::new();
    sync(&store, &[], &rule);
    let unarchive = |chat: &str| versioned(chat, SmallStateValue::Archive(false), 2, 9);
    let pin = |chat: &str| versioned(chat, SmallStateValue::Pin(true), 1, 9);
    // One chat's pin comes with its unarchive, the other's before it.
    let outcome = sync(&store, &[unarchive("11"), pin("11"), pin("22")], &rule);
    assert_eq!(outcome.archive_to_apply, vec![("11".to_owned(), false)]);
    assert!(outcome.applied.is_empty());
    let outcome = sync(&store, &[unarchive("22")], &rule);
    assert_eq!(
        outcome.archive_to_apply,
        vec![("11".to_owned(), false), ("22".to_owned(), false)]
    );
    assert!(pins(&store).is_empty());

    // Once the caller unarchives, the pins go on, as no change of this
    // device's.
    save_groups(&store, &[("11", false), ("22", false)]);
    let outcome = sync(&store, &[], &rule);
    assert!(outcome.archive_to_apply.is_empty());
    assert_eq!(pins(&store).len(), 2);
    assert_eq!(outcome.recorded, 0);
    assert_eq!(sync(&store, &[], &rule).recorded, 0);
}

#[test]
fn items_for_a_chat_not_held_yet_apply_when_it_arrives() {
    let store = started_store(&[("11", false)]);
    let app = store.app_storage();
    let rule = TestRule::new();
    let incoming = [
        versioned("22", SmallStateValue::Pin(true), 2, 9),
        versioned("22", SmallStateValue::Mute(MuteSetting::Muted), 1, 9),
    ];
    assert!(sync(&store, &incoming, &rule).applied.is_empty());

    save_groups(&store, &[("11", false), ("22", false)]);
    let outcome = sync(&store, &[], &rule);
    assert_eq!(outcome.recorded, 0);
    assert_eq!(outcome.applied.len(), 1);
    assert_eq!(pins(&store), vec!["22"]);
    assert!(app.chat_notification_settings("22").unwrap().muted);

    // Leaving the chat is not a change to its settings, and coming back
    // applies them again.
    save_groups(&store, &[("11", false)]);
    assert_eq!(sync(&store, &[], &rule), SmallStateSync::default());
    assert_eq!(app.small_state_items().unwrap().len(), 2);
    app.clear_chat_muted("22").unwrap();
    save_groups(&store, &[("11", false), ("22", false)]);
    let outcome = sync(&store, &[], &rule);
    assert_eq!(outcome.recorded, 0);
    assert_eq!(outcome.applied.len(), 1);
    assert_eq!(pins(&store), vec!["22"]);
    assert!(app.chat_notification_settings("22").unwrap().muted);
    assert!(app.unsent_small_state_items().unwrap().is_empty());
}

#[test]
fn read_positions_only_move_forward() {
    let store = started_store(&[("11", false)]);
    let app = store.app_storage();
    let rule = TestRule::new();
    app.initialize_chat_read_state(LOCAL, "11", &no_mentions)
        .unwrap();
    for (id, epoch, at) in [(7, 7, 200), (8, 8, 150), (9, 8, 160)] {
        app.record_app_event(&delivered_chat("11", id, epoch, at))
            .unwrap();
    }
    app.refresh_chat_list_row(LOCAL, "11", &no_mentions)
        .unwrap();

    app.mark_timeline_message_read(LOCAL, "11", &message(7), &no_mentions)
        .unwrap();
    assert_eq!(sync(&store, &[], &rule).recorded, 1);
    assert_eq!(
        app.unsent_small_state_items().unwrap(),
        vec![read("11", 7, 200, 7)]
    );

    // A sibling read further: the marker follows, and nothing is owed back.
    let outcome = sync(&store, &[read("11", 8, 150, 8)], &rule);
    assert_eq!(
        outcome.applied.get("11"),
        Some(&BTreeSet::from([SmallStateItemName::Read]))
    );
    assert!(app.unsent_small_state_items().unwrap().is_empty());
    let row = app.chat_list_row("11").unwrap().unwrap();
    assert_eq!(row.last_read_message_id_hex, Some(message(8)));
    assert_eq!(row.unread_count, 1);

    // An older position, or the same one, changes nothing.
    let outcome = sync(
        &store,
        &[read("11", 7, 900, 7), read("11", 8, 150, 8)],
        &rule,
    );
    assert_eq!(outcome, SmallStateSync::default());
    assert_eq!(
        app.small_state_items().unwrap(),
        vec![read("11", 8, 150, 8)]
    );

    // A sibling's read keeps this device's manual-unread reminder.
    app.set_chat_manually_unread(LOCAL, "11", true, &no_mentions)
        .unwrap();
    sync(&store, &[read("11", 8, 160, 9)], &rule);
    let row = app.chat_list_row("11").unwrap().unwrap();
    assert_eq!(row.last_read_message_id_hex, Some(message(9)));
    assert_eq!(row.unread_count, 0);
    assert!(row.manually_marked_unread);
}

#[test]
fn a_read_marker_on_a_row_no_position_names_gives_the_message_before_it() {
    let store = started_store(&[("11", false)]);
    let app = store.app_storage();
    let rule = TestRule::new();
    app.initialize_chat_read_state(LOCAL, "11", &no_mentions)
        .unwrap();
    for (id, epoch, at) in [(7, 7, 200), (8, 8, 150)] {
        app.record_app_event(&delivered_chat("11", id, epoch, at))
            .unwrap();
    }
    // A send not delivered yet sorts after every delivered message.
    app.record_app_event(&StoredAppEvent {
        source_message_id_hex: None,
        source_epoch: None,
        direction: "sent".to_owned(),
        sender: LOCAL.to_owned(),
        ..delivered_chat("11", 10, 0, 300)
    })
    .unwrap();
    app.refresh_chat_list_row(LOCAL, "11", &no_mentions)
        .unwrap();

    app.mark_timeline_message_read(LOCAL, "11", &message(10), &no_mentions)
        .unwrap();
    assert_eq!(sync(&store, &[], &rule).recorded, 1);
    assert_eq!(
        app.unsent_small_state_items().unwrap(),
        vec![read("11", 8, 150, 8)]
    );

    // A delivered message whose time is out of range is not named either.
    app.mark_small_state_sent(&app.unsent_small_state_items().unwrap())
        .unwrap();
    app.record_app_event(&delivered_chat("11", 11, 9, MAX_SMALL_STATE_NUMBER + 1))
        .unwrap();
    app.mark_timeline_message_read(LOCAL, "11", &message(11), &no_mentions)
        .unwrap();
    assert_eq!(sync(&store, &[], &rule).recorded, 0);
    assert!(app.unsent_small_state_items().unwrap().is_empty());
}

#[test]
fn items_that_break_the_rules_are_skipped() {
    let long_chat = "11".repeat(257);
    let store = started_store(&[("11", false), (long_chat.as_str(), false)]);
    let app = store.app_storage();
    let rule = TestRule::new();
    // A chat whose MLS group id is longer than 256 bytes has no small state.
    app.set_chat_pinned(&long_chat, true).unwrap();
    assert_eq!(sync(&store, &[], &rule).recorded, 0);
    assert!(versioned(&"11".repeat(256), SmallStateValue::Pin(true), 1, 1).is_valid());
    let too_large = MAX_SMALL_STATE_NUMBER + 1;
    let invalid = [
        versioned(&long_chat, SmallStateValue::Pin(false), 9, 1),
        versioned("11", SmallStateValue::Pin(true), 0, 1),
        versioned("11", SmallStateValue::Pin(true), too_large, 1),
        versioned("1", SmallStateValue::Pin(true), 1, 1),
        versioned("AB", SmallStateValue::Pin(true), 1, 1),
        versioned(
            "11",
            SmallStateValue::Mute(MuteSetting::MutedUntil(too_large)),
            1,
            1,
        ),
        SmallStateItem {
            version: None,
            ..versioned("11", SmallStateValue::Archive(true), 1, 1)
        },
        read("11", too_large, 1, 1),
        SmallStateItem {
            value: SmallStateValue::Read(ReadPosition {
                epoch: 1,
                at: 1,
                message_id_hex: "m1".to_owned(),
            }),
            ..read("11", 1, 1, 1)
        },
        SmallStateItem {
            version: Some(SmallStateVersion {
                version: 1,
                change_id: [1; 16],
            }),
            ..read("11", 1, 1, 1)
        },
    ];
    assert!(invalid.iter().all(|item| !item.is_valid()));
    assert_eq!(sync(&store, &invalid, &rule), SmallStateSync::default());
    assert!(app.small_state_items().unwrap().is_empty());
    assert_eq!(pins(&store), vec![long_chat]);
}

#[test]
fn the_rule_places_a_pin_that_arrives_through_small_state() {
    let store = started_store(&[("11", false), ("22", false), ("33", false)]);
    let app = store.app_storage();
    let rule = TestRule {
        pin_last: true,
        ..TestRule::new()
    };
    app.set_chat_pinned("11", true).unwrap();
    app.set_chat_pinned("22", true).unwrap();
    sync(&store, &[], &rule);
    sync(
        &store,
        &[versioned("33", SmallStateValue::Pin(true), 1, 9)],
        &rule,
    );
    assert_eq!(pins(&store), vec!["22", "11", "33"]);
}

#[test]
fn mute_times_round_to_whole_seconds_without_a_spurious_change() {
    let store = started_store(&[("11", false)]);
    let app = store.app_storage();
    let rule = TestRule::new();
    app.set_chat_muted("11", Some(1_500)).unwrap();
    assert_eq!(sync(&store, &[], &rule).recorded, 1);
    assert_eq!(
        app.unsent_small_state_items().unwrap()[0].value,
        SmallStateValue::Mute(MuteSetting::MutedUntil(2))
    );
    assert_eq!(sync(&store, &[], &rule).recorded, 0);
}
