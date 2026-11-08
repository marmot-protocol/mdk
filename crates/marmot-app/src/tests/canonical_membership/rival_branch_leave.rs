//! mdk#3226: a device that left on a branch that then loses to a longer rival
//! still reaches the winning branch. It holds its own SelfRemove as a pending
//! proposal sealed under the losing branch's state, and convergence must not
//! count that proposal against the rival.

use super::*;

/// alice and bob are admins, carol is not; all three start at the same epoch.
struct Fork {
    _app: MarmotApp,
    relay: Arc<ScriptedPushRelayClient>,
    clients: [AppClient; 3],
    cursors: [usize; 3],
    group: GroupId,
    _dir: tempfile::TempDir,
}

impl Fork {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let accounts = ["alice", "bob", "carol"].map(|label| home.create_account(label).unwrap());
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = app_at(&dir, relay.clone());
        for peer in &accounts {
            remember_test_member_inbox(&app, &peer.account_id_hex, "wss://relay.example");
        }
        let mut alice = app.client("alice").await.unwrap();
        let mut bob = app.client("bob").await.unwrap();
        let mut carol = app.client("carol").await.unwrap();
        bob.publish_key_package().await.unwrap();
        carol.publish_key_package().await.unwrap();
        let group = alice
            .create_group_with_options(
                "rival branch leave",
                &[&accounts[1].account_id_hex, &accounts[2].account_id_hex],
                crate::AppCreateGroupOptions {
                    initial_admins: vec![accounts[1].account_id_hex.clone()],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let mut cursors = [0; 3];
        deliver_new(&mut bob, &relay, &mut cursors[1]).await;
        deliver_new(&mut carol, &relay, &mut cursors[2]).await;
        bob.accept_group_invite(&group).unwrap();
        carol.accept_group_invite(&group).unwrap();
        let mut fork = Self {
            _app: app,
            relay,
            clients: [alice, bob, carol],
            cursors,
            group,
            _dir: dir,
        };
        // One more canonical advance, so the fork's source epoch keeps an anchor.
        fork.clients[0]
            .update_group_profile(&fork.group, Some("before the fork"), None)
            .await
            .unwrap();
        for index in 0..3 {
            let client = &mut fork.clients[index];
            deliver_new(client, &fork.relay, &mut fork.cursors[index]).await;
            fork.advance(index).await;
        }
        let epoch = fork.epoch(0);
        assert!((1..3).all(|index| fork.epoch(index) == epoch));
        fork
    }

    fn epoch(&self, index: usize) -> u64 {
        self.clients[index]
            .runtime
            .group_record(&self.group)
            .unwrap()
            .epoch
            .0
    }

    fn published_since(&self, start: usize) -> Vec<NostrTransportEvent> {
        self.relay.published_events.lock().unwrap()[start..].to_vec()
    }

    fn published(&self) -> usize {
        self.relay.published_events.lock().unwrap().len()
    }

    async fn advance(&mut self, index: usize) {
        let client = &mut self.clients[index];
        let effects = client
            .runtime
            .advance_convergence(&self.group)
            .await
            .unwrap();
        client
            .observe_drained_session_events(&effects)
            .await
            .unwrap();
        client.run_due_maintenance().await.unwrap();
    }

    /// Advance until no convergence input is pending, then a few more rounds
    /// for the deferred-peel sweeps that read the rival's later traffic.
    async fn settle(&mut self, indices: &[usize]) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                for &index in indices {
                    self.advance(index).await;
                }
                if indices.iter().all(|&index| {
                    !self.clients[index]
                        .runtime
                        .has_pending_convergence_inputs(&self.group)
                        .unwrap()
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("convergence settles");
        for _ in 0..4 {
            for &index in indices {
                self.advance(index).await;
            }
        }
    }

    /// alice publishes four commits from the fork's source epoch: a longer
    /// branch than the leaver's.
    async fn longer_rival(&mut self) -> Vec<NostrTransportEvent> {
        let start = self.published();
        for name in ["rival one", "rival two", "rival three", "rival four"] {
            self.clients[0]
                .update_group_profile(&self.group, Some(name), None)
                .await
                .unwrap();
        }
        self.published_since(start)
    }

    fn leaving(&self, index: usize) -> bool {
        self.clients[index]
            .runtime
            .leave_in_progress(&self.group)
            .unwrap()
    }
}

/// #3014's reproduction: bob steps down and leaves on his own branch while
/// alice extends a longer one. Before mdk#3226, bob's own SelfRemove made
/// alice's commit terminal on his device and he never left his branch. The
/// winning branch never held his step-down, so he is an admin there again;
/// finishing his leave from that state is #3014's re-drive, not this test's.
#[test]
fn an_admin_who_left_on_a_losing_branch_reaches_the_winning_branch() {
    run_composed_app_runtime_test("rival-branch-admin-leave", || async {
        let mut fork = Fork::new().await;
        let source = fork.epoch(1);
        let start = fork.published();
        fork.clients[1]
            .self_demote_admin(&fork.group)
            .await
            .unwrap();
        fork.clients[1].leave_group(&fork.group).await.unwrap();
        assert!(fork.leaving(1));
        assert_eq!(fork.epoch(1), source + 1);
        let leave = fork.published_since(start);

        let rival = fork.longer_rival().await;
        deliver_events(&mut fork.clients[1], &rival).await;
        deliver_events(&mut fork.clients[0], &leave).await;
        fork.settle(&[0, 1]).await;

        assert_eq!(fork.epoch(0), source + 4);
        assert_eq!(
            fork.epoch(1),
            fork.epoch(0),
            "the leaver adopts the longer branch"
        );
    });
}

/// The same fork for an ordinary member: carol adopts bob's commit, leaves on
/// that branch, then reaches alice's longer one and still leaves the group.
#[test]
fn a_member_who_left_on_a_losing_branch_reaches_the_winning_branch_and_leaves() {
    run_composed_app_runtime_test("rival-branch-member-leave", || async {
        let mut fork = Fork::new().await;
        let source = fork.epoch(2);
        let start = fork.published();
        fork.clients[1]
            .update_group_profile(&fork.group, Some("losing branch"), None)
            .await
            .unwrap();
        let losing = fork.published_since(start);
        deliver_events(&mut fork.clients[2], &losing).await;
        fork.advance(2).await;
        assert_eq!(fork.epoch(2), source + 1);
        fork.clients[2].leave_group(&fork.group).await.unwrap();
        assert!(fork.leaving(2));

        let rival = fork.longer_rival().await;
        deliver_events(&mut fork.clients[2], &rival).await;
        fork.settle(&[2]).await;
        assert_eq!(
            fork.epoch(2),
            fork.epoch(0),
            "the leaver adopts the longer branch"
        );

        // On the winning branch the leave goes ahead: alice commits carol's
        // SelfRemove and carol's copy reads removed. Alice stages that commit
        // only once its auto-commit delay has passed, which no convergence
        // input waits for.
        for _ in 0..4 {
            for index in [2, 0] {
                let client = &mut fork.clients[index];
                deliver_new(client, &fork.relay, &mut fork.cursors[index]).await;
            }
            if let Some(delay) = fork.clients[0]
                .runtime
                .scheduled_self_remove_auto_commit_delay_ms(&fork.group)
                .unwrap()
            {
                tokio::time::sleep(Duration::from_millis(delay + 1)).await;
            }
            fork.settle(&[2, 0]).await;
            if fork.clients[2]
                .runtime
                .group_record(&fork.group)
                .unwrap()
                .removed
            {
                break;
            }
        }
        assert!(
            fork.clients[2]
                .runtime
                .group_record(&fork.group)
                .unwrap()
                .removed,
            "the member's leave completes on the winning branch"
        );
    });
}
