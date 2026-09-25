use super::*;
use crate::{AppClient, AuditLogSettings, MarmotApp, MarmotAppConfig};
use marmot_account::AccountHome;
use nostr_relay_builder::MockRelay;
use std::{path::Path, time::Duration};

fn probe() -> WelcomeProbe {
    // Explicit synthetic source/build metadata, not an assertion of production
    // identity persistence or artifact provenance. All event facts come from
    // the instrumented app path below, not from hand-built event fixtures.
    WelcomeProbe::new(
        "11".repeat(16).try_into().unwrap(),
        "22".repeat(16).try_into().unwrap(),
        Producer {
            mdk_revision: "00".repeat(20).try_into().unwrap(),
            build_profile: BuildProfile::Debug,
            platform: Platform::Other,
            host_build: Some("unit-test-probe".to_owned().try_into().unwrap()),
        },
    )
}

fn app(path: &Path, relay: &str) -> MarmotApp {
    let app = MarmotApp::with_relay_and_config(
        path,
        relay.to_owned(),
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    // The existing recorder remains v4 even while the private probe is selected.
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    app
}

struct Scenario {
    _relay: MockRelay,
    _alice_dir: tempfile::TempDir,
    _bob_dir: tempfile::TempDir,
    alice: AppClient,
    bob: AppClient,
    bob_app: MarmotApp,
    bob_id: String,
}

impl Scenario {
    async fn new() -> Self {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let alice_dir = tempfile::tempdir().unwrap();
        let bob_dir = tempfile::tempdir().unwrap();
        AccountHome::open(alice_dir.path())
            .create_account("alice")
            .unwrap();
        let bob_id = AccountHome::open(bob_dir.path())
            .create_account("bob")
            .unwrap()
            .account_id_hex;
        let alice_app = app(alice_dir.path(), &url);
        let bob_app = app(bob_dir.path(), &url);
        let alice = alice_app.client("alice").await.unwrap();
        let mut bob = bob_app.client("bob").await.unwrap();
        bob.publish_key_package().await.unwrap();
        bob.audit_v5_probe = Some(probe());
        Self {
            _relay: relay,
            _alice_dir: alice_dir,
            _bob_dir: bob_dir,
            alice,
            bob,
            bob_app,
            bob_id,
        }
    }

    async fn create(&mut self) -> cgka_traits::GroupId {
        let group = self
            .alice
            .create_group("synthetic private group title", &[&self.bob_id])
            .await
            .unwrap();
        // Independent sender-side product oracle: enough actual relay ACKs
        // completed the retained delivery obligation. This is not a v5 ACK row.
        assert!(
            self.alice
                .runtime
                .outstanding_welcome_deliveries()
                .unwrap()
                .is_empty()
        );
        group
    }

    fn capture(&self) -> &WelcomeProbe {
        self.bob.audit_v5_probe.as_ref().unwrap()
    }

    fn updates(&self) -> Vec<&AppGroupUpdateFinished> {
        self.capture()
            .rows
            .iter()
            .filter_map(|r| match &r.fields().event {
                Event::AppGroupUpdateFinished(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    fn assert_clean(&self) {
        assert_eq!(self.capture().invalid, 0);
        assert_eq!(self.capture().dropped, 0);
        for (i, row) in self.capture().rows.iter().enumerate() {
            assert_eq!(row.fields().seq.get(), (i + 1) as u64);
            assert_eq!(Record::from_json(&row.to_json().unwrap()).unwrap(), *row);
        }
    }
}

#[tokio::test]
async fn real_welcome_pending_then_accepted_checkpoint_and_volume() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut scenario = Scenario::new().await;
        let group = scenario.create().await;
        let group_hex = hex::encode(group.as_slice());
        let joined = scenario.bob.sync().await.unwrap();
        assert!(joined.joined_groups.contains(&group));
        // Product assertions do not depend on audit output.
        let pending = scenario.bob_app.group("bob", &group_hex).unwrap().unwrap();
        assert!(pending.pending_confirmation);
        assert_eq!(scenario.bob.members(&group).unwrap().len(), 2);
        assert_eq!(scenario.alice.group_mls_state(&group).unwrap().epoch,
                   scenario.bob.group_mls_state(&group).unwrap().epoch);
        let observed = scenario.capture().rows.iter().find_map(|r| match &r.fields().event {
            Event::WelcomeObserved(e) => Some(e), _ => None,
        }).unwrap();
        let outer = observed.outer_event_ref.clone();
        assert_eq!(observed.acquisition, Acquisition::Unknown);
        assert_eq!(scenario.updates().len(), 1);
        assert_eq!(scenario.updates()[0].outer_event_ref, outer);
        assert_eq!(scenario.updates()[0].cause, UpdateCause::WelcomeJoin);
        assert_eq!(scenario.updates()[0].checkpoint, Checkpoint::Committed);
        assert_eq!(scenario.updates()[0].invite_state, InviteState::PendingConfirmation);

        scenario.bob.accept_group_invite(&group).unwrap();
        assert!(!scenario.bob_app.group("bob", &group_hex).unwrap().unwrap().pending_confirmation);
        assert_eq!(scenario.updates().len(), 2);
        assert_eq!(scenario.updates()[1].outer_event_ref, outer);
        assert_eq!(scenario.updates()[1].cause, UpdateCause::InviteConfirmation);
        assert_eq!(scenario.updates()[1].checkpoint, Checkpoint::Committed);
        assert_eq!(scenario.updates()[1].invite_state, InviteState::Accepted);
        assert_ne!(scenario.updates()[0].update_id, scenario.updates()[1].update_id);

        scenario.alice.send(&group, b"synthetic content must never enter probe").await.unwrap();
        let received = scenario.bob.sync().await.unwrap();
        assert_eq!(received.messages.len(), 1);
        assert_eq!(received.messages[0].plaintext, "synthetic content must never enter probe");
        assert_eq!(scenario.capture().rows.len(), 3, "ordinary message work adds no Welcome rows");
        scenario.assert_clean();
        let mut total = 0;
        let mut largest = 0;
        for row in &scenario.capture().rows {
            let body = row.to_json().unwrap();
            total += body.len(); largest = largest.max(body.len());
            let text = std::str::from_utf8(&body).unwrap();
            for forbidden in [&group_hex, &scenario.bob_id,
                "synthetic private group title", "synthetic content must never enter probe"] {
                assert!(!text.contains(forbidden));
            }
        }
        // A gross-regression bound for this THREE-ROW subset, not a bandwidth
        // target for the complete Welcome lifecycle or an upload measurement.
        assert!(total < 4096);
        println!("v5 recipient subset: rows=3 body_bytes={total} jsonl_bytes={} largest_body_bytes={largest}", total + 3);
        let files = scenario.bob_app.audit_log_files().unwrap();
        assert!(!files.is_empty());
        for file in files {
            for row in std::fs::read_to_string(file.path).unwrap().lines() {
                let v: serde_json::Value = serde_json::from_str(row).unwrap();
                assert_eq!(v["schema_version"], marmot_forensics::AUDIT_LOG_SCHEMA_VERSION);
            }
        }
    }).await.expect("bounded local Welcome scenario");
}

#[tokio::test]
async fn engine_join_survives_app_checkpoint_failure_without_false_success() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut scenario = Scenario::new().await;
        let group = scenario.create().await;
        scenario
            .bob
            .audit_v5_probe
            .as_mut()
            .unwrap()
            .reject_checkpoints = true;
        assert!(scenario.bob.sync().await.is_err());
        // Actual canonical MLS state already exists even though the pending
        // invitation has not crossed the app checkpoint transaction.
        assert_eq!(scenario.bob.members(&group).unwrap().len(), 2);
        assert!(
            scenario
                .bob_app
                .group("bob", &hex::encode(group.as_slice()))
                .unwrap()
                .is_none()
        );
        let failed_attempts = scenario.updates().len();
        assert!(failed_attempts > 0);
        assert!(
            scenario
                .updates()
                .iter()
                .all(|e| e.checkpoint == Checkpoint::FailedBeforeCommit
                    && e.invite_state == InviteState::Unknown)
        );
        let failed = scenario.updates()[0];
        assert_eq!(failed.compute, Compute::Completed);
        assert_eq!(failed.checkpoint, Checkpoint::FailedBeforeCommit);
        assert_eq!(failed.invite_state, InviteState::Unknown);
        assert!(failed.reason.is_some());
        let first_update = failed.update_id.clone();
        let outer = failed.outer_event_ref.clone();

        scenario
            .bob
            .audit_v5_probe
            .as_mut()
            .unwrap()
            .reject_checkpoints = false;
        scenario.bob.sync().await.unwrap();
        assert!(
            scenario
                .bob_app
                .group("bob", &hex::encode(group.as_slice()))
                .unwrap()
                .unwrap()
                .pending_confirmation
        );
        assert_eq!(scenario.updates().len(), failed_attempts + 1);
        let committed = scenario.updates()[failed_attempts];
        assert_eq!(committed.outer_event_ref, outer);
        assert_ne!(committed.update_id, first_update);
        assert_eq!(committed.checkpoint, Checkpoint::Committed);
        assert_eq!(committed.invite_state, InviteState::PendingConfirmation);
        scenario.assert_clean();
    })
    .await
    .expect("bounded failed-checkpoint scenario");
}

#[tokio::test]
async fn relay_ack_without_app_drain_is_not_recipient_success() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut scenario = Scenario::new().await;
        let group = scenario.create().await;
        // The relay may have delivered into a queue, but the app has not consumed
        // it. ACK alone cannot support a join or app-visible invitation claim.
        assert!(scenario.bob.runtime.group_record(&group).is_err());
        assert!(
            scenario
                .bob_app
                .group("bob", &hex::encode(group.as_slice()))
                .unwrap()
                .is_none()
        );
        assert!(scenario.capture().rows.is_empty());
        scenario.assert_clean();
    })
    .await
    .expect("bounded withheld-app-drain scenario");
}

#[test]
fn probe_bounds_and_unknown_checkpoint_do_not_fabricate_success() {
    let mut capture = probe();
    let update = || PendingUpdate {
        group: GroupRef::from_group_id(b"variable group id").unwrap(),
        outer: NostrEventRef::from_validated_event_id(&[3; 32]),
        cause: UpdateCause::WelcomeJoin,
        invite: InviteState::PendingConfirmation,
        projection_key: None,
    };
    capture.finish_checkpoint(vec![update()], false, false);
    let Event::AppGroupUpdateFinished(row) = &capture.rows[0].fields().event else {
        panic!()
    };
    assert_eq!(row.checkpoint, Checkpoint::Unknown);
    assert_eq!(row.invite_state, InviteState::Unknown);
    for _ in 0..MAX_ROWS + 1 {
        capture.finish_checkpoint(vec![update()], true, false);
    }
    assert_eq!(capture.rows.len(), MAX_ROWS);
    assert_eq!(capture.dropped, 2);
    assert!(capture.bytes <= MAX_BYTES);
    assert_eq!(capture.invalid, 0);
}
