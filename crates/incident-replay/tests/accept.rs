//! End-to-end accept path: a recovered metadata fork synthesizes a vector whose
//! scenario the simulator reproduces — the designated winner's branch survives
//! and the full `RecoverySummary` matches. `accept` returning `Ok` *is* that
//! proof (it run-and-compares internally).

use incident_replay::{accept, parse, recover_fork};

const PURE_METADATA_FORK: &str = r#"{
  "events": [
    { "kind": { "type": "fork_resolution", "source_epoch": 30, "invalidated_msg_id": "inv-1", "winner": "incumbent" } },
    { "account_ref": "alpha", "kind": { "type": "group_state_changed", "epoch": 31, "change_kind": "topic_changed", "actor_member_ref": "alpha" } },
    { "account_ref": "beta", "kind": { "type": "group_state_changed", "epoch": 31, "change_kind": "topic_changed", "actor_member_ref": "beta" } },
    { "account_ref": "beta", "kind": { "type": "publish_outcome", "msg_id": "inv-1" } }
  ]
}"#;

/// The real e1a04e82 shape: two committers race membership commits (one
/// `admin_added`, one `member_added`) at the same epoch.
const MEMBERSHIP_FORK: &str = r#"{
  "events": [
    { "kind": { "type": "fork_resolution", "source_epoch": 30, "invalidated_msg_id": "inv-1", "winner": "candidate" } },
    { "account_ref": "alpha", "kind": { "type": "group_state_changed", "epoch": 31, "change_kind": "admin_added", "actor_member_ref": "alpha" } },
    { "account_ref": "beta", "kind": { "type": "group_state_changed", "epoch": 31, "change_kind": "member_added", "actor_member_ref": "beta" } },
    { "account_ref": "beta", "kind": { "type": "publish_outcome", "msg_id": "inv-1" } }
  ]
}"#;

#[test]
fn metadata_fork_accepts_with_a_reproducible_vector() {
    let fork = recover_fork(&parse(PURE_METADATA_FORK).expect("parses")).expect("recovers");
    let vector =
        accept(&fork, "test-topic-fork/v1").expect("run-and-compare reproduces the fork winner");

    assert_eq!(vector.scenario_name, "test-topic-fork/v1");
    assert_eq!(vector.scenario.clients.len(), 2);
    // RecoverySummary + ClientsConverged.
    assert_eq!(vector.expected_outcomes.len(), 2);
}

#[test]
fn membership_fork_accepts_with_a_reproducible_vector() {
    let fork = recover_fork(&parse(MEMBERSHIP_FORK).expect("parses")).expect("recovers");
    let vector = accept(&fork, "test-membership-fork/v1")
        .expect("run-and-compare reproduces the membership fork recovery");

    assert_eq!(vector.scenario_name, "test-membership-fork/v1");
    // Two committers race competing invites; the two invitees round it out.
    assert_eq!(vector.scenario.clients.len(), 4);
    // RecoverySummary + ClientsConverged(member_count 3).
    assert_eq!(vector.expected_outcomes.len(), 2);
}
