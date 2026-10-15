//! Derived OpenMLS content columns and the filtered convergence listing
//! (mdk#2330).

use super::{
    OPENMLS_CONTENT_APPLICATION, OPENMLS_CONTENT_COMMIT, OPENMLS_CONTENT_NONE,
    OPENMLS_CONTENT_PENDING, OPENMLS_CONTENT_PROPOSAL, OPENMLS_CONTENT_UNCLASSIFIED,
    openmls_content_columns,
};
use crate::SqliteAccountStorage;
use crate::storage::test_support::{gid, sample_group};
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::storage::{GroupStorage, MessageStorage, OpenMlsContentFilter};
use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
use cgka_traits::types::{EpochId, MessageId};
use rusqlite::params;

const APPLICATION: u8 = 1;
const PROPOSAL: u8 = 2;
const COMMIT: u8 = 3;

/// A framed MLS `PrivateMessage` (RFC 9420 section 6.3). Classification
/// reads only its framing, so the encrypted fields are filler.
fn private_message(epoch: u64, content_type: u8) -> Vec<u8> {
    let mut bytes = vec![0x00, 0x01, 0x00, 0x02];
    bytes.extend([4, 1, 2, 3, 4]);
    bytes.extend(epoch.to_be_bytes());
    bytes.push(content_type);
    bytes.push(0);
    bytes.extend([4, 9, 9, 9, 9]);
    bytes.extend([4, 7, 7, 7, 7]);
    bytes
}

fn transport(id: u8, payload: Vec<u8>) -> TransportMessage {
    TransportMessage {
        id: MessageId::new(vec![id; 4]),
        payload,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("test".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: vec![1; 32],
        },
    }
}

fn wire_payload(mls: Vec<u8>) -> Vec<u8> {
    StoredMessagePayload::openmls_wire(transport(0, mls))
        .encode()
        .unwrap()
}

fn row(id: u8, epoch: u64, state: MessageState, payload: Vec<u8>) -> MessageRecord {
    MessageRecord {
        id: MessageId::new(vec![id; 4]),
        group_id: gid(1),
        epoch: EpochId(epoch),
        state,
        payload,
        deferred_peel: None,
    }
}

#[test]
fn content_columns_classify_only_framed_protocol_messages() {
    for (content_type, expected) in [
        (APPLICATION, OPENMLS_CONTENT_APPLICATION),
        (PROPOSAL, OPENMLS_CONTENT_PROPOSAL),
        (COMMIT, OPENMLS_CONTENT_COMMIT),
    ] {
        assert_eq!(
            openmls_content_columns(&wire_payload(private_message(7, content_type))),
            (expected, Some(7))
        );
    }
    let raw = StoredMessagePayload::raw_transport(transport(1, private_message(7, COMMIT)))
        .encode()
        .unwrap();
    assert_eq!(openmls_content_columns(&raw), (OPENMLS_CONTENT_NONE, None));
    for unclassified in [
        vec![0xAA, 0xBB],
        wire_payload(vec![0x00, 0x01, 0x00, 0x02, 0xFF]),
        wire_payload(private_message(u64::MAX, APPLICATION)),
    ] {
        assert_eq!(
            openmls_content_columns(&unclassified),
            (OPENMLS_CONTENT_UNCLASSIFIED, None)
        );
    }
}

/// Rows the listing must keep or may leave out, in insertion order.
fn seed_listing_rows(store: &SqliteAccountStorage) -> Vec<(u8, &'static str)> {
    store.put_group(&sample_group(gid(1), 6, 0)).unwrap();
    let raw = StoredMessagePayload::raw_transport(transport(1, vec![1]))
        .encode()
        .unwrap();
    let rows = [
        (
            1,
            1,
            MessageState::Processed,
            private_message(1, APPLICATION),
            "app@1",
        ),
        (
            2,
            2,
            MessageState::Processed,
            private_message(2, COMMIT),
            "commit@2",
        ),
        (
            3,
            2,
            MessageState::Processed,
            private_message(2, APPLICATION),
            "app@2",
        ),
        (
            4,
            3,
            MessageState::Processed,
            private_message(3, PROPOSAL),
            "proposal@3",
        ),
        (
            5,
            3,
            MessageState::Processed,
            private_message(3, APPLICATION),
            "app@3",
        ),
        (
            6,
            1,
            MessageState::Created,
            private_message(1, APPLICATION),
            "fresh app@1",
        ),
        (
            7,
            3,
            MessageState::Created,
            private_message(3, COMMIT),
            "fresh commit@3",
        ),
        (
            8,
            4,
            MessageState::Processed,
            private_message(4, APPLICATION),
            "app@4",
        ),
    ];
    let mut labels = Vec::new();
    for (id, epoch, state, mls, label) in rows {
        store
            .put_message(&row(id, epoch, state, wire_payload(mls)))
            .unwrap();
        labels.push((id, label));
    }
    store
        .put_message(&row(9, 3, MessageState::Sent, raw))
        .unwrap();
    labels.push((9, "own-echo marker"));
    store
        .put_message(&row(10, 2, MessageState::Processed, vec![0xAA]))
        .unwrap();
    labels.push((10, "unreadable"));
    // A row written before migration 0111 that promotion has not reached.
    store
        .put_message(&row(
            11,
            1,
            MessageState::Processed,
            wire_payload(private_message(1, APPLICATION)),
        ))
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE cgka_messages SET openmls_content = ?1, openmls_epoch = NULL WHERE id = ?2",
            params![OPENMLS_CONTENT_PENDING, vec![11_u8; 4]],
        )
        .unwrap();
    labels.push((11, "pending app@1"));
    labels
}

fn listed(
    store: &SqliteAccountStorage,
    labels: &[(u8, &'static str)],
    states: &[MessageState],
    at_or_after_epoch: u64,
    filter: OpenMlsContentFilter,
) -> Vec<&'static str> {
    store
        .list_openmls_messages_in_states(&gid(1), states, EpochId(at_or_after_epoch), filter)
        .unwrap()
        .into_iter()
        .map(|record| {
            labels
                .iter()
                .find(|(id, _)| record.id.as_slice() == [*id; 4])
                .unwrap()
                .1
        })
        .collect()
}

const GRAPH_STATES: [MessageState; 4] = [
    MessageState::Sent,
    MessageState::Created,
    MessageState::Processed,
    MessageState::ConvergenceDeferred,
];

#[test]
fn openmls_listing_leaves_out_only_rows_the_filter_excludes() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let labels = seed_listing_rows(&store);

    assert_eq!(
        listed(
            &store,
            &labels,
            &GRAPH_STATES,
            0,
            OpenMlsContentFilter::Commits
        ),
        ["commit@2", "fresh commit@3", "unreadable", "pending app@1"]
    );
    assert_eq!(
        listed(
            &store,
            &labels,
            &GRAPH_STATES,
            0,
            OpenMlsContentFilter::WithoutProcessedApplicationsThrough(EpochId(2)),
        ),
        [
            "commit@2",
            "proposal@3",
            "app@3",
            "fresh app@1",
            "fresh commit@3",
            "app@4",
            "unreadable",
            "pending app@1",
        ]
    );
    assert_eq!(
        listed(
            &store,
            &labels,
            &GRAPH_STATES,
            0,
            OpenMlsContentFilter::WithoutProcessedApplications,
        ),
        [
            "commit@2",
            "proposal@3",
            "fresh app@1",
            "fresh commit@3",
            "unreadable",
            "pending app@1",
        ]
    );
    // The row epoch floor and the state list still apply.
    assert_eq!(
        listed(
            &store,
            &labels,
            &[MessageState::Processed],
            3,
            OpenMlsContentFilter::WithoutProcessedApplicationsThrough(EpochId(0)),
        ),
        ["proposal@3", "app@3", "app@4"]
    );
    assert!(listed(&store, &labels, &[], 0, OpenMlsContentFilter::Commits).is_empty());
    assert_eq!(
        listed(
            &store,
            &labels,
            &GRAPH_STATES,
            0,
            OpenMlsContentFilter::ApplicationsAt(EpochId(3)),
        ),
        ["app@3", "unreadable", "pending app@1"]
    );
    assert_eq!(
        listed(
            &store,
            &labels,
            &GRAPH_STATES,
            0,
            OpenMlsContentFilter::ApplicationsAt(EpochId(1)),
        ),
        ["app@1", "fresh app@1", "unreadable", "pending app@1"]
    );
    // No classified application holds an epoch beyond SQLite's INTEGER range.
    assert_eq!(
        listed(
            &store,
            &labels,
            &GRAPH_STATES,
            0,
            OpenMlsContentFilter::ApplicationsAt(EpochId(u64::MAX)),
        ),
        ["unreadable", "pending app@1"]
    );
    // An epoch bound beyond SQLite's INTEGER range keeps no classified
    // delivered application, as every one of them holds a smaller epoch.
    assert_eq!(
        listed(
            &store,
            &labels,
            &[MessageState::Processed],
            0,
            OpenMlsContentFilter::WithoutProcessedApplicationsThrough(EpochId(u64::MAX)),
        ),
        ["commit@2", "proposal@3", "unreadable", "pending app@1"]
    );
}

#[test]
fn promotion_derives_content_for_rows_written_before_the_columns() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
    let payload = wire_payload(private_message(5, COMMIT));
    store
        .put_message(&row(1, 5, MessageState::Processed, payload.clone()))
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE cgka_messages SET openmls_content = ?1, openmls_epoch = NULL",
            params![OPENMLS_CONTENT_PENDING],
        )
        .unwrap();

    let progress = store.promote_legacy_message_rows(16).unwrap();
    assert_eq!(progress.promoted, 1);
    assert!(!progress.has_more);
    let (content, epoch, stored): (i64, Option<i64>, Vec<u8>) = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT openmls_content, openmls_epoch, payload FROM cgka_messages",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!((content, epoch), (OPENMLS_CONTENT_COMMIT, Some(5)));
    assert_eq!(stored, payload);
    assert_eq!(store.promote_legacy_message_rows(16).unwrap().promoted, 0);
}
