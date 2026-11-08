//! A device that left on a branch that then loses to a longer rival still
//! reaches the winning branch and leaves. It holds its own SelfRemove as a
//! pending proposal sealed under the losing branch's state, and convergence
//! must not count that proposal against the rival (mdk#3226). An admin whose
//! step-down the winning branch never held steps down again first, and the
//! last admin's leave is blocked until it cancels (mdk#3014).

use super::*;

const LABELS: [&str; 3] = ["alice", "bob", "carol"];

/// alice and bob are admins, carol is not; all three start at the same epoch.
struct Fork {
    app: MarmotApp,
    relay: Arc<ScriptedPushRelayClient>,
    clients: Vec<AppClient>,
    cursors: [usize; 3],
    group: GroupId,
    accounts: [String; 3],
    _dir: tempfile::TempDir,
}

impl Fork {
    async fn new() -> Self {
        Self::with_device_groups(false).await
    }

    /// With device groups on, an admin's Leave steps its account down itself
    /// (D99).
    async fn with_device_groups(device_groups: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let accounts = LABELS.map(|label| home.create_account(label).unwrap());
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example",
            MarmotAppConfig::white_noise()
                .with_dev_settlement_quiescence_ms(0)
                .with_dev_scheduled_convergence_delay_ms(0)
                .with_dev_device_groups(device_groups),
        )
        .with_test_relay_client(relay.clone());
        assert_eq!(app.admin_leave_steps_down(), device_groups);
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
            app,
            relay,
            clients: vec![alice, bob, carol],
            cursors,
            group,
            accounts: accounts.map(|account| account.account_id_hex),
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

    fn name(&self, index: usize) -> String {
        self.clients[index]
            .runtime
            .group_record(&self.group)
            .unwrap()
            .name
    }

    fn record(&self, index: usize) -> crate::AppGroupRecord {
        self.app
            .group(LABELS[index], &hex::encode(self.group.as_slice()))
            .unwrap()
            .expect("the group record exists")
    }

    /// Close `index`'s client and open it again from its stored state.
    async fn restart(&mut self, index: usize) {
        drop(self.clients.remove(index));
        let client = self.app.client(LABELS[index]).await.unwrap();
        self.clients.insert(index, client);
    }

    fn published_since(&self, start: usize) -> Vec<NostrTransportEvent> {
        self.relay.published_events.lock().unwrap()[start..].to_vec()
    }

    fn published(&self) -> usize {
        self.relay.published_events.lock().unwrap().len()
    }

    /// One scheduler wake: advance convergence and observe its effects.
    async fn wake(&mut self, index: usize) {
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
    }

    async fn advance(&mut self, index: usize) {
        self.wake(index).await;
        self.clients[index].run_due_maintenance().await.unwrap();
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

    fn removed(&self, index: usize) -> bool {
        self.clients[index]
            .runtime
            .group_record(&self.group)
            .unwrap()
            .removed
    }

    fn admin(&self, viewer: usize, account: usize) -> bool {
        self.clients[viewer]
            .runtime
            .admin_pubkeys(&self.group)
            .unwrap()
            .iter()
            .any(|admin| hex::encode(admin) == self.accounts[account])
    }

    /// Exchange traffic among `members` until `leaver`'s copy reads removed.
    /// A member commits a SelfRemove only once its auto-commit delay has
    /// passed, which no convergence input waits for.
    async fn until_removed(&mut self, leaver: usize, members: &[usize]) {
        for _ in 0..8 {
            for &index in members {
                let client = &mut self.clients[index];
                deliver_new(client, &self.relay, &mut self.cursors[index]).await;
            }
            for &index in members {
                if let Some(delay) = self.clients[index]
                    .runtime
                    .scheduled_self_remove_auto_commit_delay_ms(&self.group)
                    .unwrap()
                {
                    tokio::time::sleep(Duration::from_millis(delay + 1)).await;
                }
            }
            self.settle(members).await;
            if self.removed(leaver) {
                return;
            }
        }
        panic!("the leave never completed");
    }
}

/// bob steps down and leaves on his own branch; alice's longer branch, which
/// never held his step-down, wins. Before mdk#3226 he never left his branch.
/// On the winning branch he is an admin again, so he steps down again and his
/// leave completes (mdk#3014).
async fn admin_leaves_across_a_lost_step_down(
    fork: &mut Fork,
    rival: Vec<NostrTransportEvent>,
    leave: Vec<NostrTransportEvent>,
) {
    deliver_events(&mut fork.clients[1], &rival).await;
    deliver_events(&mut fork.clients[0], &leave).await;
    deliver_events(&mut fork.clients[2], &leave).await;
    deliver_events(&mut fork.clients[2], &rival).await;
    // bob adopts the winning branch, where he is an admin again, and steps
    // down again in the same wake.
    for _ in 0..4 {
        fork.wake(1).await;
        if !fork.admin(1, 1) {
            break;
        }
    }
    assert!(
        !fork.admin(1, 1),
        "bob steps down again on the winning branch"
    );
    assert_eq!(
        fork.name(1),
        fork.name(0),
        "bob reaches the selected branch"
    );
    // Nothing but his leave request is left for bob, and only it keeps the
    // wake armed for the drain that sends his SelfRemove.
    assert_eq!(
        fork.clients[1]
            .convergence_schedule_state(&fork.group)
            .unwrap(),
        crate::client::ConvergenceScheduleState::PendingOutbound {
            retry_after_ms: None
        }
    );
    let published = fork.published();
    fork.wake(1).await;
    assert_eq!(
        fork.published(),
        published + 1,
        "the wake sends the SelfRemove"
    );
    assert_eq!(
        fork.clients[1]
            .convergence_schedule_state(&fork.group)
            .unwrap(),
        crate::client::ConvergenceScheduleState::Idle,
        "the leave now waits on the members"
    );
    assert!(
        fork.clients[1]
            .take_pending_superseded_change_events()
            .is_empty(),
        "the lost step-down is the leave's own work, not a change to report"
    );
    fork.settle(&[0, 1, 2]).await;
    fork.until_removed(1, &[0, 1, 2]).await;
    assert!(fork.removed(1), "the admin's leave completes");
    assert!(!fork.admin(0, 1), "the leaver is off the admin list");
    assert!(fork.admin(0, 0));
}

/// #3014's third acceptance case: the winning branch leaves the admin list
/// alone.
#[test]
fn an_admin_whose_step_down_lost_to_a_branch_that_left_admins_alone_steps_down_again_and_leaves() {
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
        admin_leaves_across_a_lost_step_down(&mut fork, rival, leave).await;
    });
}

/// #3014's second gap, with device groups on: bob's Leave records the leave
/// before anything is published, and the engine stages his step-down from
/// it. That step-down loses to alice's longer branch before his SelfRemove is
/// sent. The leave is already durable, so he steps down again on the winning
/// branch and leaves. Before, the app sent the step-down and the Leave as two
/// sends, and a step-down lost in between left the Leave refused with nothing
/// to retry it.
#[test]
fn an_admin_leave_whose_first_step_down_loses_steps_down_again_and_leaves() {
    run_composed_app_runtime_test("rival-branch-admin-leave-first-step-down", || async {
        let mut fork = Fork::with_device_groups(true).await;
        let source = fork.epoch(1);
        let start = fork.published();
        fork.clients[1].leave_group(&fork.group).await.unwrap();
        assert!(fork.leaving(1), "the leave is recorded");
        assert_eq!(fork.published(), start, "before anything is published");
        assert!(fork.admin(1, 1));
        fork.wake(1).await;
        assert!(!fork.admin(1, 1), "the engine stages the step-down");
        assert_eq!(fork.epoch(1), source + 1);
        let leave = fork.published_since(start);
        assert_eq!(leave.len(), 1, "the step-down alone, no SelfRemove yet");
        let rival = fork.longer_rival().await;
        admin_leaves_across_a_lost_step_down(&mut fork, rival, leave).await;
    });
}

/// #3014's second acceptance case: the winning branch promotes carol, so the
/// lost step-down's own bytes would now undo that promotion. bob steps down
/// from the winning branch's admin list instead, and carol stays an admin.
#[test]
fn an_admin_whose_step_down_lost_to_a_promotion_steps_down_again_and_leaves() {
    run_composed_app_runtime_test("rival-branch-admin-leave-promotion", || async {
        let mut fork = Fork::new().await;
        let start = fork.published();
        fork.clients[1]
            .self_demote_admin(&fork.group)
            .await
            .unwrap();
        fork.clients[1].leave_group(&fork.group).await.unwrap();
        let leave = fork.published_since(start);
        let start = fork.published();
        let carol = fork.accounts[2].clone();
        fork.clients[0]
            .promote_admin(&fork.group, &carol)
            .await
            .unwrap();
        for name in [
            "after promotion one",
            "after promotion two",
            "after promotion three",
        ] {
            fork.clients[0]
                .update_group_profile(&fork.group, Some(name), None)
                .await
                .unwrap();
        }
        let rival = fork.published_since(start);
        admin_leaves_across_a_lost_step_down(&mut fork, rival, leave).await;
        assert!(fork.admin(0, 2), "the winning branch's promotion stands");
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
        // SelfRemove and carol's copy reads removed.
        fork.until_removed(2, &[2, 0]).await;
    });
}

/// #3014's first acceptance case: alice and bob each step down and leave from
/// the same epoch. The selected branch keeps one step-down, so the other admin
/// is now the last one and its leave is blocked (D116): still shown as
/// leaving, never retried, and joined again only through its own Cancel. Its
/// SelfRemove, sealed at the same epoch number on the losing branch, does not
/// bring the leave back after a restart, and the other admin's leave completes.
#[test]
fn the_last_admin_after_a_rival_step_down_has_a_blocked_leave_until_it_cancels() {
    run_composed_app_runtime_test("rival-branch-admin-leave-blocked", || async {
        let mut fork = Fork::new().await;
        let source = fork.epoch(0);
        let mut leaves = Vec::new();
        for index in [0, 1] {
            let start = fork.published();
            fork.clients[index]
                .self_demote_admin(&fork.group)
                .await
                .unwrap();
            fork.clients[index].leave_group(&fork.group).await.unwrap();
            assert_eq!(fork.epoch(index), source + 1);
            leaves.push(fork.published_since(start));
        }
        deliver_events(&mut fork.clients[0], &leaves[1]).await;
        deliver_events(&mut fork.clients[1], &leaves[0]).await;
        fork.settle(&[0, 1]).await;
        let (blocked, other) = match (fork.admin(0, 0), fork.admin(0, 1)) {
            (true, false) => (0, 1),
            (false, true) => (1, 0),
            admins => panic!("exactly one step-down stands; admins {admins:?}"),
        };
        assert_eq!(fork.name(blocked), fork.name(other), "one selected branch");
        assert_eq!(fork.epoch(blocked), source + 1);
        assert!(fork.admin(blocked, blocked), "the last admin");

        let record = fork.record(blocked);
        assert!(record.leave_requested_at_ms.is_some(), "still leaving");
        assert!(record.leave_blocked);
        assert_eq!(
            fork.clients[blocked]
                .convergence_schedule_state(&fork.group)
                .unwrap(),
            crate::client::ConvergenceScheduleState::Idle,
            "no wake is armed"
        );
        let published = fork.published();
        fork.wake(blocked).await;
        assert_eq!(fork.published(), published, "nothing retries");
        assert!(fork.leaving(blocked));

        let refused = fork.clients[other].cancel_leave(&fork.group).unwrap_err();
        assert!(
            matches!(
                refused.as_engine_error(),
                Some(cgka_traits::error::EngineError::LeaveNotBlocked { .. })
            ),
            "a leave that can finish is not cancelled: {refused:?}"
        );

        fork.clients[blocked].cancel_leave(&fork.group).unwrap();
        assert!(!fork.leaving(blocked));
        let record = fork.record(blocked);
        assert_eq!(record.leave_requested_at_ms, None);
        assert!(!record.leave_blocked);
        assert_eq!(
            record.self_membership,
            SelfMembership::Member,
            "joined again"
        );
        assert!(
            fork.clients[blocked]
                .runtime
                .scheduled_self_remove_auto_commit_delay_ms(&fork.group)
                .unwrap()
                .is_some(),
            "the other admin's SelfRemove is scheduled for commit again"
        );
        fork.clients[blocked]
            .send(&fork.group, b"staying after all")
            .await
            .unwrap();

        fork.restart(blocked).await;
        fork.advance(blocked).await;
        assert!(
            !fork.leaving(blocked),
            "a restart does not restore the leave"
        );
        assert_eq!(fork.record(blocked).leave_requested_at_ms, None);

        fork.until_removed(other, &[blocked, other]).await;
        assert!(fork.admin(blocked, blocked));
    });
}
