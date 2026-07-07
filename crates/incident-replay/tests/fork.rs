//! `recover_fork` behaviour: rule 2 (racers at source_epoch+1), rule 3 tier-b
//! (invalidated commit's publisher is the loser), and the fail-closed gates.

use incident_replay::{ForkCommitKind, ForkRecoveryError, RecoveredFork, parse, recover_fork};

/// A pure two-committer group-metadata fork: alpha and beta both `topic_changed`
/// at epoch 31 (= source 30 + 1); the invalidated commit was published by beta.
fn pure_fork_json(winner_change: &str) -> String {
    format!(
        r#"{{
          "events": [
            {{ "kind": {{ "type": "fork_resolution", "source_epoch": 30,
                          "invalidated_msg_id": "inv-1", "winner": "incumbent" }} }},
            {{ "account_ref": "alpha",
               "kind": {{ "type": "group_state_changed", "epoch": 31, "change_kind": "{winner_change}",
                          "actor_member_ref": "alpha" }} }},
            {{ "account_ref": "beta",
               "kind": {{ "type": "group_state_changed", "epoch": 31, "change_kind": "topic_changed",
                          "actor_member_ref": "beta" }} }},
            {{ "account_ref": "beta",
               "kind": {{ "type": "publish_outcome", "msg_id": "inv-1" }} }}
          ]
        }}"#
    )
}

fn recover(json: &str) -> Result<RecoveredFork, ForkRecoveryError> {
    recover_fork(&parse(json).expect("parses"))
}

#[test]
fn recovers_a_pure_two_committer_metadata_fork() {
    assert_eq!(
        recover(&pure_fork_json("topic_changed")),
        Ok(RecoveredFork {
            source_epoch: 30,
            commit: ForkCommitKind::GroupData,
        })
    );
}

#[test]
fn missing_snapshot_winner_is_quarantined() {
    let json = r#"{ "events": [
        { "kind": { "type": "fork_resolution", "source_epoch": 30, "winner": "missing_snapshot" } }
    ] }"#;
    assert_eq!(recover(json), Err(ForkRecoveryError::MissingSnapshot));
}

#[test]
fn no_fork_resolution_is_quarantined() {
    let json = r#"{ "events": [ { "kind": { "type": "epoch_confirmed" } } ] }"#;
    assert_eq!(recover(json), Err(ForkRecoveryError::NoForkResolution));
}

#[test]
fn a_single_committer_at_the_tip_is_ambiguous() {
    let json = r#"{ "events": [
        { "kind": { "type": "fork_resolution", "source_epoch": 30, "invalidated_msg_id": "inv-1", "winner": "incumbent" } },
        { "account_ref": "alpha", "kind": { "type": "group_state_changed", "epoch": 31, "change_kind": "topic_changed", "actor_member_ref": "alpha" } }
    ] }"#;
    assert_eq!(
        recover(json),
        Err(ForkRecoveryError::AmbiguousCommitters(1))
    );
}

#[test]
fn an_unattributable_invalidated_commit_makes_the_winner_unrecoverable() {
    // No publish event ties `inv-1` to a committer.
    let json = r#"{ "events": [
        { "kind": { "type": "fork_resolution", "source_epoch": 30, "invalidated_msg_id": "inv-1", "winner": "incumbent" } },
        { "account_ref": "alpha", "kind": { "type": "group_state_changed", "epoch": 31, "change_kind": "topic_changed", "actor_member_ref": "alpha" } },
        { "account_ref": "beta", "kind": { "type": "group_state_changed", "epoch": 31, "change_kind": "topic_changed", "actor_member_ref": "beta" } }
    ] }"#;
    assert_eq!(recover(json), Err(ForkRecoveryError::UnrecoverableWinner));
}

#[test]
fn an_unmapped_commit_kind_is_quarantined() {
    // A membership fork (member_added) is not synthesizable yet.
    let json = r#"{ "events": [
        { "kind": { "type": "fork_resolution", "source_epoch": 30, "invalidated_msg_id": "inv-1", "winner": "incumbent" } },
        { "account_ref": "alpha", "kind": { "type": "group_state_changed", "epoch": 31, "change_kind": "member_added", "actor_member_ref": "alpha" } },
        { "account_ref": "beta", "kind": { "type": "group_state_changed", "epoch": 31, "change_kind": "member_added", "actor_member_ref": "beta" } },
        { "account_ref": "beta", "kind": { "type": "publish_outcome", "msg_id": "inv-1" } }
    ] }"#;
    assert_eq!(
        recover(json),
        Err(ForkRecoveryError::UnmappedCommitKind("member_added".into()))
    );
}
