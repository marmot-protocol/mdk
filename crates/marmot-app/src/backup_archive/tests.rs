use std::collections::BTreeMap;

use cgka_engine::recovery_key::{
    RECOVERY_ENTROPY_LEN, derive_recovery_key_pair, open_with_recovery_key,
};
use cgka_traits::MarmotAppEvent;
use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT;
use openmls_rust_crypto::RustCrypto;
use storage_sqlite::{ReadPosition, SmallStateValue, SmallStateVersion};

use super::*;
use crate::history_bundle::BundledEvent;

const WORDS: [u8; RECOVERY_ENTROPY_LEN] = [7; RECOVERY_ENTROPY_LEN];
const OTHER_WORDS: [u8; RECOVERY_ENTROPY_LEN] = [8; RECOVERY_ENTROPY_LEN];
const WRITER: DeviceSlotId = [0x33; 32];
const SERVER: &str = "https://blossom.example/";
const BOOK_CLUB: [u8; 16] = [0x5a; 16];
const FAMILY: [u8; 16] = [0x6b; 16];

fn public_half(entropy: &[u8; RECOVERY_ENTROPY_LEN]) -> Vec<u8> {
    derive_recovery_key_pair(&RustCrypto::default(), entropy)
        .unwrap()
        .public
}

fn bundled(epoch: u64, at: u64, retention: Option<u64>) -> BundledEvent {
    BundledEvent {
        event: MarmotAppEvent::new(
            "bb".repeat(32),
            at,
            MARMOT_APP_EVENT_KIND_CHAT,
            Vec::new(),
            &format!("message {at}"),
        ),
        epoch,
        retention,
        grant: None,
        keys: None,
    }
}

fn bundle(chat: &[u8], events: Vec<BundledEvent>) -> HistoryBundle {
    let at = |event: &BundledEvent| ChatPosition::of(&event.event, event.epoch);
    let mut bundle = HistoryBundle::new(
        chat,
        at(events.first().unwrap()),
        at(events.last().unwrap()),
    );
    bundle.events = events;
    bundle
}

fn items() -> Vec<SmallStateItem> {
    vec![
        SmallStateItem {
            group_id_hex: hex::encode(BOOK_CLUB),
            value: SmallStateValue::Pin(true),
            version: Some(SmallStateVersion {
                version: 3,
                change_id: [9; 16],
            }),
        },
        SmallStateItem {
            group_id_hex: hex::encode(FAMILY),
            value: SmallStateValue::Read(ReadPosition {
                epoch: 2,
                at: 20,
                message_id_hex: "cc".repeat(32),
            }),
            version: None,
        },
    ]
}

/// A written backup: its head's bytes and its blobs by SHA-256.
struct Written {
    head: Vec<u8>,
    blobs: BTreeMap<String, Vec<u8>>,
}

impl Written {
    fn blob(&self, locator: &BlobLocator) -> &[u8] {
        &self.blobs[&locator.sha256]
    }
}

/// A backup of `chats`' bundles and `items`, sealed to `words`, as a writer
/// builds one.
fn write(
    words: &[u8; RECOVERY_ENTROPY_LEN],
    chats: &[(&[u8], Vec<HistoryBundle>)],
    items: &[SmallStateItem],
) -> Written {
    let archive_key = ArchiveKey::generate();
    let mut index = BackupIndex::new(1_700_000_000, &WRITER);
    let mut blobs = BTreeMap::new();
    for (chat, bundles) in chats {
        for bundle in bundles {
            let number = index.next_blob_number().unwrap();
            let sealed = seal_backup_bundle(&archive_key, number, bundle).unwrap();
            index
                .push_blob(chat, IndexBlob::new(bundle, &sealed, SERVER.into()))
                .unwrap();
            blobs.insert(hex::encode(sealed.sha256), sealed.ciphertext);
        }
    }
    if !items.is_empty() {
        let sealed = seal_backup_small_state(&archive_key, items).unwrap();
        index.small_state = Some(BlobLocator::new(&sealed, SERVER.into()));
        blobs.insert(hex::encode(sealed.sha256), sealed.ciphertext);
    }
    let head = BackupHead::seal(new_backup_id(), &archive_key, &public_half(words), &index)
        .unwrap()
        .encode();
    Written { head, blobs }
}

fn open_archive_key(head: &BackupHead, words: &[u8; RECOVERY_ENTROPY_LEN]) -> Option<ArchiveKey> {
    let (context, sealed) = head.sealed_archive_key();
    open_with_recovery_key(&RustCrypto::default(), words, &context, sealed)
        .unwrap()
        .and_then(|opened| ArchiveKey::from_opened(&opened))
}

fn refusal<T: fmt::Debug>(result: Result<T, AppError>) -> &'static str {
    match result {
        Err(AppError::DeviceGroupRefused(reason)) => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn book_club_history() -> Vec<HistoryBundle> {
    vec![
        bundle(&BOOK_CLUB, vec![bundled(1, 10, None), bundled(1, 11, None)]),
        bundle(&BOOK_CLUB, vec![bundled(2, 12, Some(60))]),
    ]
}

/// C1: what a writer wrote is what the words open, blob for blob.
#[test]
fn a_backup_opens_with_its_words_to_exactly_what_was_written() {
    let book_club = book_club_history();
    let family = vec![bundle(&FAMILY, vec![bundled(5, 50, Some(0))])];
    let written = write(
        &WORDS,
        &[(&BOOK_CLUB, book_club.clone()), (&FAMILY, family.clone())],
        &items(),
    );

    let head = BackupHead::decode(&written.head).unwrap();
    let index = head.open_index(&public_half(&WORDS)).unwrap();
    assert_eq!(index.written_at, 1_700_000_000);
    assert_eq!(index.writer, hex::encode(WRITER));
    let archive_key = open_archive_key(&head, &WORDS).expect("the words open the archive key");

    let mut opened = BTreeMap::<String, Vec<HistoryBundle>>::new();
    for (number, chat, blob) in index.blobs() {
        let bundle = open_backup_bundle(
            &archive_key,
            number,
            chat,
            blob,
            written.blob(&blob.locator()),
        )
        .unwrap();
        opened.entry(chat.chat.clone()).or_default().push(bundle);
    }
    assert_eq!(
        opened,
        BTreeMap::from([
            (hex::encode(BOOK_CLUB), book_club),
            (hex::encode(FAMILY), family),
        ])
    );
    let small_state = index.small_state.as_ref().unwrap();
    assert_eq!(
        open_backup_small_state(&archive_key, small_state, written.blob(small_state)).unwrap(),
        items()
    );
}

/// C1: the account's devices read what a backup holds with the public half
/// alone; only the words open its content.
#[test]
fn the_public_half_reads_the_index_but_only_the_words_open_the_archive_key() {
    let written = write(&WORDS, &[(&BOOK_CLUB, book_club_history())], &[]);
    let head = BackupHead::decode(&written.head).unwrap();

    let index = head.open_index(&public_half(&WORDS)).unwrap();
    let stretches = index
        .blobs()
        .map(|(number, chat, blob)| (number, chat.chat.clone(), blob.from.at, blob.to.at))
        .collect::<Vec<_>>();
    assert_eq!(
        stretches,
        vec![
            (0, hex::encode(BOOK_CLUB), 10, 11),
            (1, hex::encode(BOOK_CLUB), 12, 12),
        ]
    );
    assert_eq!(index.small_state, None);
    assert_eq!(
        refusal(head.open_index(&public_half(&OTHER_WORDS))),
        "backup_decrypt"
    );
    assert!(open_archive_key(&head, &OTHER_WORDS).is_none());
    assert!(open_archive_key(&head, &WORDS).is_some());
}

/// C2: a holder of the public half can write an index, but not one the
/// archive key opens with: the seal binds the index ciphertext and the id.
#[test]
fn an_altered_or_moved_index_leaves_the_archive_key_sealed() {
    let first =
        BackupHead::decode(&write(&WORDS, &[(&BOOK_CLUB, book_club_history())], &[]).head).unwrap();
    let mut altered_index = first.open_index(&public_half(&WORDS)).unwrap();
    altered_index.chats[0].blobs.pop();
    let altered = BackupHead {
        index: cipher(&index_key(&public_half(&WORDS), &first.id))
            .encrypt(
                &Nonce::default(),
                Payload {
                    msg: &altered_index.encode().unwrap(),
                    aad: INDEX_AAD,
                },
            )
            .unwrap(),
        ..first.clone()
    };
    assert_eq!(
        altered.open_index(&public_half(&WORDS)).unwrap(),
        altered_index
    );
    assert!(open_archive_key(&altered, &WORDS).is_none());

    let second =
        BackupHead::decode(&write(&WORDS, &[(&BOOK_CLUB, book_club_history())], &[]).head).unwrap();
    let moved = BackupHead {
        index: second.index.clone(),
        ..first.clone()
    };
    assert!(open_archive_key(&moved, &WORDS).is_none());
    let renamed = BackupHead {
        id: second.id,
        ..first
    };
    assert!(open_archive_key(&renamed, &WORDS).is_none());
}

/// C2: a blob opens only as the blob its index entry names: another blob,
/// the right blob under another number, or one of another backup is
/// refused, as is a bundle whose chat or stretch is not the entry's.
#[test]
fn a_blob_opens_only_as_the_blob_its_index_entry_names() {
    let written = write(&WORDS, &[(&BOOK_CLUB, book_club_history())], &items());
    let head = BackupHead::decode(&written.head).unwrap();
    let index = head.open_index(&public_half(&WORDS)).unwrap();
    let archive_key = open_archive_key(&head, &WORDS).unwrap();
    let chat = &index.chats[0];
    let (first, second) = (&chat.blobs[0], &chat.blobs[1]);
    let first_blob = written.blob(&first.locator());

    assert_eq!(
        refusal(open_backup_bundle(
            &archive_key,
            1,
            chat,
            second,
            first_blob
        )),
        "backup_blob_hash"
    );
    assert_eq!(
        refusal(open_backup_bundle(&archive_key, 1, chat, first, first_blob)),
        "history_bundle_decrypt"
    );
    let other = write(&WORDS, &[(&BOOK_CLUB, book_club_history())], &[]);
    let other_head = BackupHead::decode(&other.head).unwrap();
    let other_index = other_head.open_index(&public_half(&WORDS)).unwrap();
    let other_first = &other_index.chats[0].blobs[0];
    assert_eq!(
        refusal(open_backup_bundle(
            &archive_key,
            0,
            &other_index.chats[0],
            other_first,
            other.blob(&other_first.locator()),
        )),
        "history_bundle_decrypt"
    );

    let elsewhere = IndexChat {
        chat: hex::encode(FAMILY),
        blobs: chat.blobs.clone(),
    };
    assert_eq!(
        refusal(open_backup_bundle(
            &archive_key,
            0,
            &elsewhere,
            first,
            first_blob
        )),
        "backup_blob_mismatch"
    );
    let shorter = IndexBlob {
        to: first.from.clone(),
        ..first.clone()
    };
    assert_eq!(
        refusal(open_backup_bundle(
            &archive_key,
            0,
            chat,
            &shorter,
            first_blob
        )),
        "backup_blob_mismatch"
    );

    let small_state = index.small_state.as_ref().unwrap();
    assert_eq!(
        refusal(open_backup_small_state(
            &archive_key,
            small_state,
            first_blob
        )),
        "backup_blob_hash"
    );
    let other_key = ArchiveKey::generate();
    assert_eq!(
        refusal(open_backup_small_state(
            &other_key,
            small_state,
            written.blob(small_state)
        )),
        "backup_decrypt"
    );
}

/// C3: the derivations, as an independent HKDF-SHA256 computes them, shared
/// with the spec: archive key `01` × 32, backup id `02` × 16, and the
/// recovery public key of all-zero entropy.
#[test]
fn the_keys_derive_as_the_published_vectors() {
    let archive_key = ArchiveKey(Zeroizing::new([1; 32]));
    let public_key =
        hex::decode("aed5608fc1960f7992decafb36786d19508dce48e02288785cf24e557d58a368").unwrap();
    assert_eq!(public_key, public_half(&[0; RECOVERY_ENTROPY_LEN]));
    for (key, expected) in [
        (
            archive_key.blob_key(0),
            "b3491be68bcd1393f68892cf51e46650f231cd91bf118e0a62a7cfa974e51a73",
        ),
        (
            archive_key.blob_key(1),
            "7ffee8e8a3c2e1546c3a652dc8244be7410707500f706d808461372c2e51f0f7",
        ),
        (
            archive_key.small_state_key(),
            "3f775330af21efc398c027d0fbc8775c6a0d521293c1be67bd73e1febb9dfc54",
        ),
        (
            index_key(&public_key, &[2; BACKUP_ID_LEN]),
            "18da5e74bcd81f43d7e6639dfcc464515f380d6ce016496e07597f2a78ff6ffa",
        ),
    ] {
        assert_eq!(hex::encode(*key), expected);
    }
}

#[test]
fn a_head_is_written_compact_and_decodes_to_itself() {
    let head = BackupHead {
        id: [0xab; BACKUP_ID_LEN],
        sealed_key: vec![1, 2, 3],
        index: vec![4, 5],
    };
    let encoded = head.encode();
    assert_eq!(
        String::from_utf8(encoded.clone()).unwrap(),
        format!(
            r#"{{"v":1,"id":"{}","key":"AQID","index":"BAU="}}"#,
            "ab".repeat(16)
        )
    );
    assert_eq!(BackupHead::decode(&encoded).unwrap(), head);
}

#[test]
fn a_head_that_breaks_the_format_is_refused() {
    let id = "ab".repeat(16);
    for head in [
        format!(r#"{{"v":2,"id":"{id}","key":"AQID","index":"BAU="}}"#),
        format!(
            r#"{{"v":1,"id":"{}","key":"AQID","index":"BAU="}}"#,
            "AB".repeat(16)
        ),
        format!(
            r#"{{"v":1,"id":"{}","key":"AQID","index":"BAU="}}"#,
            "ab".repeat(15)
        ),
        format!(r#"{{"v":1,"id":"{id}","key":"","index":"BAU="}}"#),
        format!(r#"{{"v":1,"id":"{id}","key":"AQID","index":"not base64"}}"#),
        format!(r#"{{"v":1,"id":"{id}","key":"AQID"}}"#),
        format!(r#"{{"v":1,"id":"{id}","key":"AQID","index":"BAU=","extra":1}}"#),
        format!(r#"{{"v":1,"id":"{id}","key":"AQID","key":"AQID","index":"BAU="}}"#),
        format!(r#"{{"v":1,"id":"{id}","key":null,"index":"BAU="}}"#),
    ] {
        assert_eq!(
            refusal(BackupHead::decode(head.as_bytes())),
            "backup_format",
            "{head}"
        );
    }
    assert_eq!(
        refusal(BackupHead::decode(&vec![b' '; MAX_BACKUP_HEAD_BYTES + 1])),
        "backup_too_large"
    );
}

#[test]
fn an_index_that_breaks_the_format_is_refused_whole() {
    let mut index = BackupIndex::new(10, &WRITER);
    let book_club = book_club_history();
    for bundle in &book_club {
        let sealed = SealedBlob {
            ciphertext: vec![0; 32],
            sha256: [0x11; 32],
        };
        index
            .push_blob(&BOOK_CLUB, IndexBlob::new(bundle, &sealed, SERVER.into()))
            .unwrap();
    }
    assert_eq!(
        BackupIndex::decode(&index.encode().unwrap()).unwrap(),
        index
    );

    let broken: [(&str, fn(&mut BackupIndex)); 10] = [
        ("version", |index| index.v = 2),
        ("writer", |index| index.writer = "33".repeat(31)),
        ("chat named twice", |index| {
            let again = index.chats[0].clone();
            index.chats.push(again);
        }),
        ("chat with no blobs", |index| index.chats[0].blobs.clear()),
        ("chat not hex", |index| {
            index.chats[0].chat = "5A".repeat(16)
        }),
        ("stretch backwards", |index| {
            let blob = &mut index.chats[0].blobs[0];
            std::mem::swap(&mut blob.from, &mut blob.to);
        }),
        ("empty blob", |index| index.chats[0].blobs[0].size = 0),
        ("oversized blob", |index| {
            index.chats[0].blobs[0].size = MAX_BACKUP_BLOB_BYTES + 1
        }),
        ("server not normalized", |index| {
            index.chats[0].blobs[0].server = "https://Blossom.example/".into()
        }),
        ("small-state hash", |index| {
            index.small_state = Some(BlobLocator {
                sha256: "11".repeat(31),
                size: 1,
                server: SERVER.into(),
            })
        }),
    ];
    for (case, break_it) in broken {
        let mut broken = index.clone();
        break_it(&mut broken);
        assert_eq!(
            refusal(BackupIndex::decode(&broken.encode().unwrap())),
            "backup_format",
            "{case}"
        );
    }
    let null_expiry = String::from_utf8(index.encode().unwrap())
        .unwrap()
        .replacen(r#""sha256""#, r#""expires":null,"sha256""#, 1);
    assert_eq!(
        refusal(BackupIndex::decode(null_expiry.as_bytes())),
        "backup_format"
    );
}

#[test]
fn a_chats_blobs_are_numbered_in_index_order_and_added_together() {
    let mut index = BackupIndex::new(10, &WRITER);
    let blob = |bundle: &HistoryBundle| {
        IndexBlob::new(
            bundle,
            &SealedBlob {
                ciphertext: vec![0; 32],
                sha256: [0x11; 32],
            },
            SERVER.into(),
        )
    };
    let book_club = book_club_history();
    let family = bundle(&FAMILY, vec![bundled(5, 50, None)]);
    index.push_blob(&BOOK_CLUB, blob(&book_club[0])).unwrap();
    index.push_blob(&BOOK_CLUB, blob(&book_club[1])).unwrap();
    index.push_blob(&FAMILY, blob(&family)).unwrap();
    assert_eq!(index.next_blob_number().unwrap(), 3);
    assert_eq!(
        index
            .blobs()
            .map(|(number, chat, blob)| (number, chat.chat.clone(), blob.from.at))
            .collect::<Vec<_>>(),
        vec![
            (0, hex::encode(BOOK_CLUB), 10),
            (1, hex::encode(BOOK_CLUB), 12),
            (2, hex::encode(FAMILY), 50),
        ]
    );
    assert_eq!(
        refusal(index.push_blob(&BOOK_CLUB, blob(&book_club[1]))),
        "backup_chat_order"
    );
}

/// A blob expires when its last event does, never while one of its events
/// has no retention or a retention of 0.
#[test]
fn a_blob_expires_once_everything_in_it_has() {
    let expires = |events| bundle_expires(&bundle(&BOOK_CLUB, events));
    assert_eq!(
        expires(vec![bundled(1, 10, Some(60)), bundled(1, 20, Some(5))]),
        Some(70)
    );
    assert_eq!(
        expires(vec![bundled(1, 10, Some(60)), bundled(1, 20, None)]),
        None
    );
    assert_eq!(
        expires(vec![bundled(1, 10, Some(0)), bundled(1, 20, Some(5))]),
        None
    );
    assert_eq!(
        expires(vec![bundled(1, MAX_INTEGER, Some(MAX_INTEGER))]),
        Some(MAX_INTEGER)
    );
    let mut empty = bundle(&BOOK_CLUB, vec![bundled(1, 10, None)]);
    empty.events.clear();
    assert_eq!(bundle_expires(&empty), Some(0));
}
