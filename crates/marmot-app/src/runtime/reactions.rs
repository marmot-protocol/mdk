//! Complete, local reaction details for one materialized message.

use std::collections::BTreeMap;

use super::MarmotAppRuntime;
use crate::{AppError, TimelineUserReaction};

impl MarmotAppRuntime {
    /// Read every effective sender/emoji pair for one visible message.
    ///
    /// Uses the exact-message materialized read, including its block
    /// filtering. Missing, retention-pruned, deleted or invalidated targets have no
    /// participants. Repeated events for one sender/emoji select the latest
    /// `(reacted_at, reaction_message_id_hex)`, matching the distinct-sender
    /// chip tally. The result is a single local snapshot, ordered by timestamp,
    /// sender and emoji; re-read when the conversation changes. No network work
    /// or conversation-history scan is performed. Call off the UI thread.
    pub fn message_reactions(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        message_id_hex: &str,
    ) -> Result<Vec<TimelineUserReaction>, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let Some(message) = self.timeline_message(account_ref, group_id_hex, message_id_hex)?
        else {
            return Ok(Vec::new());
        };
        // Projection already clears deleted-message reactions; keep this explicit
        // guard so the details API preserves that policy if projection changes.
        if message.deleted || message.invalidation_status.is_some() {
            return Ok(Vec::new());
        }
        Ok(effective_participants(message.reactions.user_reactions))
    }
}

/// Select one deterministic effective event per user/emoji, as counted by chips.
fn effective_participants(reactions: Vec<TimelineUserReaction>) -> Vec<TimelineUserReaction> {
    let mut effective = BTreeMap::new();
    for reaction in reactions {
        let key = (reaction.sender.clone(), reaction.emoji.clone());
        let entry = effective.entry(key).or_insert_with(|| reaction.clone());
        if (reaction.reacted_at, &reaction.reaction_message_id_hex)
            > (entry.reacted_at, &entry.reaction_message_id_hex)
        {
            *entry = reaction;
        }
    }
    let mut participants: Vec<_> = effective.into_values().collect();
    participants.sort_by(|a, b| {
        (a.reacted_at, &a.sender, &a.emoji).cmp(&(b.reacted_at, &b.sender, &b.emoji))
    });
    participants
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one authenticated reaction without involving relay delivery.
    fn reaction(id: &str, sender: &str, emoji: &str, at: u64) -> TimelineUserReaction {
        TimelineUserReaction {
            reaction_message_id_hex: id.into(),
            target_message_id_hex: "target".into(),
            sender: sender.into(),
            emoji: emoji.into(),
            reacted_at: at,
        }
    }

    /// The two-person preview budget never limits complete mixed-emoji details.
    #[test]
    fn complete_details_include_three_identical_and_one_other_emoji() {
        let participants = effective_participants(vec![
            reaction("a", "alice", "👍", 1),
            reaction("b", "bob", "👍", 2),
            reaction("c", "carol", "👍", 3),
            reaction("d", "dave", "🔥", 4),
        ]);
        assert_eq!(participants.len(), 4);
        assert_eq!(participants.iter().filter(|r| r.emoji == "👍").count(), 3);
        assert_eq!(participants[2].sender, "carol");
    }

    /// Repeated events count once; timestamp ties use the event id, regardless of input order.
    #[test]
    fn duplicate_events_choose_latest_with_stable_tie_break() {
        let reactions = vec![
            reaction("z", "alice", "👍", 5),
            reaction("a", "alice", "👍", 5),
            reaction("old", "alice", "👍", 1),
            reaction("other", "alice", "🔥", 6),
        ];
        let expected = effective_participants(reactions.clone());
        assert_eq!(expected.len(), 2);
        assert_eq!(expected[0].reaction_message_id_hex, "z");
        assert_eq!(
            effective_participants(reactions.into_iter().rev().collect()),
            expected
        );
    }

    /// Exercise the actual account-scoped materialized read, additions, retractions and target guards.
    #[tokio::test]
    async fn complete_details_follow_materialized_changes_and_visibility() {
        use crate::MarmotApp;
        use storage_sqlite::StoredAppEvent;

        let root = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relays(root.path(), vec![]);
        let account = app.account_home().create_account("alice").unwrap();
        app.account_home().create_account("other").unwrap();
        let runtime = app.runtime();
        let group = "11".repeat(16);
        let target = "01".repeat(32);
        assert!(
            runtime
                .message_reactions("alice", &group, &target)
                .unwrap()
                .is_empty()
        );
        let storage = app.account_storage("alice").unwrap();
        let mut event = StoredAppEvent {
            group_id_hex: group.clone(),
            message_id_hex: target.clone(),
            source_message_id_hex: None,
            source_epoch: None,
            direction: "received".into(),
            sender: "ff".repeat(32),
            plaintext: "target".into(),
            kind: 9,
            tags: vec![],
            recorded_at: 1,
            received_at: 1,
            origin_commit_id: None,
            moderation_grant: false,
        };
        storage.record_app_event(&event).unwrap();
        event.kind = 7;
        event.tags = vec![vec!["e".into(), target.clone()]];
        for (index, emoji) in ["👍", "👍", "👍", "🔥"].into_iter().enumerate() {
            event.message_id_hex = format!("{:02x}", index + 2).repeat(32);
            event.sender = format!("{:02x}", index + 10).repeat(32);
            event.recorded_at = index as u64 + 2;
            event.plaintext = emoji.into();
            storage.record_app_event(&event).unwrap();
        }
        let participants = runtime.message_reactions("alice", &group, &target).unwrap();
        assert_eq!(participants.len(), 4);
        assert_eq!(participants.iter().filter(|r| r.emoji == "👍").count(), 3);
        assert!(
            runtime
                .message_reactions("alice", &"22".repeat(16), &target)
                .unwrap()
                .is_empty()
        );
        assert!(
            runtime
                .message_reactions("missing-account", &group, &target)
                .is_err()
        );
        // A repeat from the same sender does not create another sheet row.
        event.message_id_hex = "06".repeat(32);
        event.recorded_at = 6;
        storage.record_app_event(&event).unwrap();
        assert_eq!(
            runtime
                .message_reactions("alice", &group, &target)
                .unwrap()
                .len(),
            4
        );
        // Retract both copies; the other emoji and its three participants remain.
        event.kind = 5;
        event.message_id_hex = "07".repeat(32);
        event.tags = vec![
            vec!["e".into(), "05".repeat(32)],
            vec!["e".into(), "06".repeat(32)],
        ];
        storage.record_app_event(&event).unwrap();
        assert_eq!(
            runtime
                .message_reactions("alice", &group, &target)
                .unwrap()
                .len(),
            3
        );
        assert!(
            runtime
                .message_reactions("other", &group, &target)
                .unwrap()
                .is_empty()
        );
        // Block policy removes participants through the same materialized read as window tallies.
        let blocked_sender = participants[2].sender.clone();
        let mut block_list = storage_sqlite::StoredBlockList {
            event_id: "01".repeat(32),
            event_created_at: 1,
            ..Default::default()
        };
        storage
            .adopt_block_list(
                &block_list,
                &[(blocked_sender, true)],
                1,
                &account.account_id_hex,
                &|_, _| false,
            )
            .unwrap();
        assert_eq!(
            runtime
                .message_reactions("alice", &group, &target)
                .unwrap()
                .len(),
            2
        );
        block_list.event_id = "02".repeat(32);
        block_list.event_created_at = 2;
        storage
            .adopt_block_list(&block_list, &[], 2, &account.account_id_hex, &|_, _| false)
            .unwrap();
        assert_eq!(
            runtime
                .message_reactions("alice", &group, &target)
                .unwrap()
                .len(),
            3
        );
        storage
            .invalidate_app_event_by_message_id(&group, &target, "losing branch")
            .unwrap();
        assert!(
            runtime
                .message_reactions("alice", &group, &target)
                .unwrap()
                .is_empty()
        );
        // A separate deleted target and retention-pruned target cannot disclose reactors.
        for (message, prune) in [("08".repeat(32), false), ("09".repeat(32), true)] {
            event.kind = 9;
            event.message_id_hex = message.clone();
            event.tags.clear();
            event.plaintext = "visible target".into();
            storage.record_app_event(&event).unwrap();
            event.kind = 7;
            event.message_id_hex = "0a".repeat(32);
            event.tags = vec![vec!["e".into(), message.clone()]];
            event.plaintext = "👍".into();
            storage.record_app_event(&event).unwrap();
            assert_eq!(
                runtime
                    .message_reactions("alice", &group, &message)
                    .unwrap()
                    .len(),
                1
            );
            if prune {
                storage
                    .prune_app_events_before(&group, 100, &account.account_id_hex, &|_, _| false)
                    .unwrap();
            } else {
                event.kind = 5;
                event.message_id_hex = "0b".repeat(32);
                storage.record_app_event(&event).unwrap();
            }
            assert!(
                runtime
                    .message_reactions("alice", &group, &message)
                    .unwrap()
                    .is_empty()
            );
        }
        runtime.shutdown_and_close().await.unwrap();
    }
}
