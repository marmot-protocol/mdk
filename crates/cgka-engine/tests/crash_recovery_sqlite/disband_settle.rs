//! Process death between a canonical apply that merges a peer's disband and
//! the settle that follows it keeps the disband's committed roster (mdk#3273 B).

use super::support::disband::{found_and_join, published_disband};
use super::*;
use cgka_engine::ManualConvergenceClock;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::storage::{
    CommittedMembers, CommittedRosterStorage, DisbandCandidateStorage, DisbandTombstoneStorage,
};
use openmls::prelude::MlsGroup;

/// Selects this module's child; the crash point alone is shared with other cases.
pub(super) const SCENARIO_ENV: &str = "MDK_CGKA_CRASH_DISBAND_SETTLE";
const POINT: &str = "convergence-pass-completed-durable";
const KEY: [u8; 32] = [0x3d; 32];
const ALICE: &[u8] = b"disband-settle-crash-alice";
const BOB: &[u8] = b"disband-settle-crash-bob";

fn build(seed: &[u8], storage: SqliteAccountStorage) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .identity(identity(seed))
        .account_identity_proof_signer(proof_signer(seed))
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build disband crash-test engine")
}

/// The apply writes the roster in its own transaction, from the members the
/// disband ended, so a settle that never runs leaves it correct: the merged
/// tree holds the committer alone. Where an older release's apply left no
/// roster, hydration records it from the disband's candidate. Realizing this
/// device's removal when a late message arrives before the settle keeps it,
/// and the settle that the reopened pass runs writes the same members from
/// the tombstone.
#[tokio::test]
async fn kill_between_a_disbands_apply_and_its_settle_keeps_the_disbands_roster() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("bob.sqlite");
    let (group, joined, late) = {
        let storage =
            SqliteAccountStorage::open_encrypted(&database, &SqlCipherKey::raw(KEY)).unwrap();
        let clock = ManualConvergenceClock::new(0, 10_000);
        let mut alice = EngineBuilder::new(SqliteAccountStorage::in_memory_for_test().unwrap())
            .identity(identity(ALICE))
            .account_identity_proof_signer(proof_signer(ALICE))
            .protocol_profile(ProtocolProfile::Current)
            .convergence_clock(std::sync::Arc::new(clock.clone()))
            .peeler(Box::new(MockPeeler))
            .build()
            .unwrap();
        let mut bob = build(BOB, storage.clone());
        let group = found_and_join(&mut alice, &mut bob).await;
        let joined = storage.committed_roster(&group).unwrap().unwrap();
        assert_eq!(joined.members.ids().len(), 2);
        let payload = app_payload_for(&alice, b"sent before the disband");
        let SendResult::ApplicationMessage { msg: late, .. } = alice
            .send(SendIntent::AppMessage {
                expected_epoch: None,
                only_to_members: None,
                group_id: group.clone(),
                payload,
            })
            .await
            .unwrap()
        else {
            panic!("application send")
        };
        let disband = published_disband(&mut alice, &clock, &group).await;
        bob.buffer_openmls_convergence_message_at(&group, disband, 1_000)
            .unwrap();
        let late = route(late, &group);
        (group, joined, late)
    };

    spawn_crash_child(&database, POINT, &[(SCENARIO_ENV, "1")]).kill_when_ready();
    let storage = SqliteAccountStorage::open_encrypted(&database, &SqlCipherKey::raw(KEY)).unwrap();
    let merged = MlsGroup::load(
        storage.mls_storage(),
        &openmls::group::GroupId::from_slice(group.as_slice()),
    )
    .unwrap()
    .unwrap();
    assert_eq!(merged.members().count(), 1, "the apply merged the disband");
    drop(merged);
    assert!(storage.disband_tombstone(&group).unwrap().is_none());
    assert!(!storage.list_disband_candidates(&group).unwrap().is_empty());
    assert_eq!(
        storage.committed_roster(&group).unwrap().as_ref(),
        Some(&joined),
        "the apply's roster holds the members the disband ended"
    );

    // What an apply on a release before committed rosters leaves.
    let raw = rusqlite::Connection::open(&database).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &raw,
        &SqlCipherKey::raw(KEY),
        storage_sqlite::SqlCipherHardening::live_cache(),
    )
    .unwrap();
    raw.execute(
        "DELETE FROM cgka_committed_rosters WHERE group_id = ?1",
        [group.as_slice()],
    )
    .unwrap();
    drop(raw);
    let mut bob = build(BOB, storage.clone());
    bob.hydrate_all_stored_groups().unwrap();
    assert!(bob.quarantined_groups().is_empty());
    assert_eq!(
        storage
            .committed_roster(&group)
            .unwrap()
            .map(|roster| roster.members),
        Some(joined.members.clone()),
        "hydration records an unsettled disband's roster from its candidate"
    );
    let joined = storage.committed_roster(&group).unwrap().unwrap();
    assert!(matches!(
        bob.ingest(late).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::LocalState {
            state: cgka_traits::ingest::LocalIngestState::Removed
        }
    ));
    assert_eq!(
        storage.committed_roster(&group).unwrap().as_ref(),
        Some(&joined),
        "realizing the removal a disband made keeps its roster"
    );
    bob.converge_stored_openmls_messages_at(&group, 2_000_000)
        .unwrap();
    // The completed pass has to reopen and cross its own collection cutoff.
    bob.converge_stored_openmls_messages_at(&group, 3_000_000)
        .unwrap();
    let tombstone = storage
        .disband_tombstone(&group)
        .unwrap()
        .expect("the reopened pass settles the disband");
    assert_eq!(
        CommittedMembers::of_members(&tombstone.former_members),
        joined.members
    );
    assert_eq!(storage.committed_roster(&group).unwrap(), Some(joined));
}

pub(super) async fn run_child(database: &Path) {
    let storage = SqliteAccountStorage::open_encrypted(database, &SqlCipherKey::raw(KEY)).unwrap();
    let group = storage.list_groups().unwrap().pop().expect("bob's group");
    let mut bob = build(BOB, storage.clone());
    bob.hydrate_all_stored_groups().unwrap();
    // Pauses after the apply's transaction commits, before the settle. The
    // reopened pass first collects the buffered disband, then freezes and
    // applies it on a later call.
    for now in [1_000_000, 2_000_000, 3_000_000] {
        let _ = bob.converge_stored_openmls_messages_at(&group, now);
    }
}
