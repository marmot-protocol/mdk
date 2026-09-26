use super::*;
use crate::{AppClient, AuditLogSettings, MarmotApp, MarmotAppConfig};
use cgka_traits::{group::ProtocolProfile, storage::GroupStorage};
use marmot_account::AccountHome;
use nostr_relay_builder::MockRelay;
use std::{path::Path, time::Duration};

fn actual_v5_rows(app: &MarmotApp, account: &str) -> Vec<Record> {
    let dir = app.account_dir(account);
    let paths = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .ends_with("-v5.jsonl")
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 1, "one active v5 recorder per account");
    let body = std::fs::read_to_string(&paths[0]).unwrap();
    assert!(body.len() < 256 * 1024, "bounded local scenario volume");
    assert!(!body.contains("wss://"));
    assert!(!body.contains("synthetic private group title"));
    body.lines()
        .map(|line| {
            assert!(line.len() < 65_535);
            Record::from_json(line.as_bytes()).unwrap()
        })
        .collect()
}

fn probe_with_ids(source: u8, session: u8) -> WelcomeProbe {
    // Explicit synthetic source/build metadata, not an assertion of production
    // identity persistence or artifact provenance. All event facts come from
    // the instrumented app path below, not from hand-built event fixtures.
    WelcomeProbe::new(
        format!("{source:02x}").repeat(16).try_into().unwrap(),
        format!("{session:02x}").repeat(16).try_into().unwrap(),
        Producer {
            mdk_revision: Some("00".repeat(20).try_into().unwrap()),
            build_profile: BuildProfile::Debug,
            platform: Platform::Other,
            host_build: Some("unit-test-probe".to_owned().try_into().unwrap()),
        },
    )
}

fn probe() -> WelcomeProbe {
    probe_with_ids(0x11, 0x22)
}

fn app(path: &Path, relay: &str) -> MarmotApp {
    let app = MarmotApp::with_relay_and_config(
        path,
        relay.to_owned(),
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    // Enable the same v5 recorder used by the live app path.
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    app
}

#[tokio::test]
async fn opened_inventory_selects_current_groups_before_the_64_group_cap() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let mut client = app.client("alice").await.unwrap();
    let mut ids = Vec::new();
    for index in 0..65 {
        ids.push(
            client
                .create_group(&format!("mixed profile group {index}"), &[])
                .await
                .unwrap(),
        );
    }
    ids.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    let current_id = ids.pop().unwrap();
    let storage = app.account_storage("alice").unwrap();
    for id in ids {
        let mut group = storage.get_group(&id).unwrap();
        group.protocol_profile = ProtocolProfile::Legacy;
        storage.put_group(&group).unwrap();
    }

    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    client.set_audit_recording(true);
    drop(client);
    let rows = actual_v5_rows(&app, "alice");
    let inventory = rows
        .iter()
        .find_map(|row| match &row.fields().event {
            Event::GroupBaselineInventory(event)
                if event.reason == BaselineReason::AuditEnabled =>
            {
                Some(event)
            }
            _ => None,
        })
        .expect("audit enable inventory");
    assert_eq!(inventory.eligible_group_count, Some(1));
    assert_eq!(inventory.selected_group_count, Some(1));
    assert_eq!(inventory.omitted_by_limit_count, Some(0));
    assert_eq!(inventory.failed_read_count, Some(0));
    let selected = rows
        .iter()
        .filter(|row| {
            matches!(
                &row.fields().event,
                Event::GroupBaseline(event) if event.reason == BaselineReason::AuditEnabled
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(selected.len(), 1);
    assert_eq!(
        selected[0].fields().group_ref.as_ref(),
        Some(&GroupRef::from_group_id(current_id.as_slice()).unwrap())
    );
}

#[tokio::test]
async fn normal_opt_in_records_real_welcome_and_operational_v5_rows() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await.to_string();
        let alice_dir = tempfile::tempdir().unwrap();
        let bob_dir = tempfile::tempdir().unwrap();
        AccountHome::open(alice_dir.path())
            .create_account("alice")
            .unwrap();
        let bob_id = AccountHome::open(bob_dir.path())
            .create_account("bob")
            .unwrap()
            .account_id_hex;
        let alice_app = app(alice_dir.path(), &relay_url);
        let bob_app = app(bob_dir.path(), &relay_url);
        let mut alice = alice_app.client("alice").await.unwrap();
        let mut bob = bob_app.client("bob").await.unwrap();
        bob.publish_key_package().await.unwrap();
        let group = alice
            .create_group_with_initial_source_and_optional_telemetry(
                "synthetic private group title",
                &[&bob_id],
                crate::AppCreateGroupOptions::default(),
                None,
                None,
            )
            .await
            .unwrap()
            .group_id;
        let retained = alice.runtime.outstanding_welcome_deliveries().unwrap();
        assert_eq!(retained.len(), 1);
        let outer_id = <[u8; 32]>::try_from(retained[0].1.id.as_slice()).unwrap();
        alice.drive_unpublished_welcome_delivery(None).await;
        assert!(
            alice
                .runtime
                .outstanding_welcome_deliveries()
                .unwrap()
                .is_empty()
        );
        assert!(bob.sync().await.unwrap().joined_groups.contains(&group));
        assert_eq!(bob.runtime.group_record(&group).unwrap().members.len(), 2);
        alice
            .send(&group, b"private audit integration message")
            .await
            .unwrap();

        let sender = actual_v5_rows(&alice_app, "alice");
        let recipient = actual_v5_rows(&bob_app, "bob");
        for rows in [&sender, &recipient] {
            let mut bytes_by_kind = std::collections::BTreeMap::<String, usize>::new();
            for row in rows {
                let kind = serde_json::to_value(&row.fields().event).unwrap()["type"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                *bytes_by_kind.entry(kind).or_default() += row.to_json().unwrap().len();
            }
            assert!(bytes_by_kind.values().all(|bytes| *bytes < 64 * 1024));
            let body = rows
                .iter()
                .flat_map(|row| row.to_json().unwrap())
                .collect::<Vec<_>>();
            let text = String::from_utf8(body).unwrap();
            assert!(!text.contains(&bob_id));
            assert!(!text.contains(&hex::encode(group.as_slice())));
            assert!(!text.contains(&hex::encode(outer_id)));
            assert!(!text.contains("private audit integration message"));
        }
        let sender_types = sender
            .iter()
            .map(|row| {
                serde_json::to_value(&row.fields().event).unwrap()["type"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect::<std::collections::BTreeSet<_>>();
        let recipient_types = recipient
            .iter()
            .map(|row| {
                serde_json::to_value(&row.fields().event).unwrap()["type"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect::<std::collections::BTreeSet<_>>();
        for kind in [
            "welcome_prepared",
            "welcome_publish_started",
            "welcome_publish_finished",
            "group_baseline",
            "publish_outcome",
        ] {
            assert!(
                sender_types.contains(kind),
                "missing sender {kind}: {sender_types:?}"
            );
        }
        for kind in [
            "welcome_observed",
            "welcome_unwrapped",
            "welcome_join_finished",
            "app_group_update_finished",
            "group_baseline",
        ] {
            assert!(
                recipient_types.contains(kind),
                "missing recipient {kind}: {recipient_types:?}"
            );
        }
        let outer = NostrEventRef::from_validated_event_id(&outer_id);
        let prepared = sender
            .iter()
            .find_map(|row| match &row.fields().event {
                Event::WelcomePrepared(event) => Some(event),
                _ => None,
            })
            .unwrap();
        let published = sender
            .iter()
            .find_map(|row| match &row.fields().event {
                Event::WelcomePublishFinished(event) => Some(event),
                _ => None,
            })
            .unwrap();
        let observed = recipient
            .iter()
            .find_map(|row| match &row.fields().event {
                Event::WelcomeObserved(event) => Some(event),
                _ => None,
            })
            .unwrap();
        assert_eq!(prepared.outer_event_ref.as_ref(), Some(&outer));
        assert_eq!(published.outer_event_ref, outer);
        assert_eq!(observed.outer_event_ref, outer);
        assert_eq!(published.policy, Policy::Met);
        assert_eq!(published.retained_state, RetainedState::Unknown);
        assert_eq!(
            prepared.op_id,
            sender
                .iter()
                .find_map(|row| match &row.fields().event {
                    Event::WelcomePublishStarted(event) => Some(event.op_id.clone()),
                    _ => None,
                })
                .unwrap()
        );
        assert_ne!(
            sender[0].fields().source_ref,
            recipient[0].fields().source_ref
        );
        assert_ne!(
            sender[0].fields().session_id,
            recipient[0].fields().session_id
        );
        drop(alice);
        let reopened = alice_app.client("alice").await.unwrap();
        assert_eq!(
            reopened.runtime.group_record(&group).unwrap().members.len(),
            2
        );
        assert!(
            actual_v5_rows(&alice_app, "alice")
                .iter()
                .any(|row| matches!(
                    &row.fields().event,
                    Event::GroupBaseline(baseline) if baseline.reason == BaselineReason::Opened
                ))
        );
    })
    .await
    .expect("bounded live v5 scenario");
}

struct Scenario {
    _relay: MockRelay,
    _alice_dir: tempfile::TempDir,
    _bob_dir: tempfile::TempDir,
    alice: AppClient,
    bob: AppClient,
    bob_app: MarmotApp,
    bob_id: String,
    key_package_event_id: [u8; 32],
    retained_welcome: Option<TransportMessage>,
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
        let mut bob_app = app(bob_dir.path(), &url);
        bob_app.audit_v5_peel_slot = Some((
            "bob".into(),
            std::sync::Arc::new(std::sync::Mutex::new(PeelSlot::default())),
        ));
        let mut alice = alice_app.client("alice").await.unwrap();
        let mut bob = bob_app.client("bob").await.unwrap();
        bob.publish_key_package().await.unwrap();
        let key_package_event_id: [u8; 32] = bob
            .runtime
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .authored_event_id
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        bob.audit_v5_probe = Some(probe());
        alice.audit_v5_probe = Some(probe_with_ids(0x33, 0x44));
        Self {
            _relay: relay,
            _alice_dir: alice_dir,
            _bob_dir: bob_dir,
            alice,
            bob,
            bob_app,
            bob_id,
            key_package_event_id,
            retained_welcome: None,
        }
    }

    async fn create(&mut self) -> cgka_traits::GroupId {
        let group = self
            .alice
            .create_group_with_initial_source_and_optional_telemetry(
                "synthetic private group title",
                &[&self.bob_id],
                crate::AppCreateGroupOptions::default(),
                None,
                None,
            )
            .await
            .unwrap()
            .group_id;
        // Independent product oracle at the post-canonical, pre-publish seam:
        // the engine retained the exact outbound artifact, not an app index.
        let retained = self.alice.runtime.outstanding_welcome_deliveries().unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].0, group);
        let stored = self
            .alice
            .runtime
            .session()
            .stored_sent_welcome(&retained[0].1.id)
            .unwrap();
        assert_eq!(stored, retained[0]);
        assert_eq!(
            self.sender_capture()
                .rows
                .iter()
                .filter(|row| matches!(row.fields().event, Event::WelcomePrepared(_)))
                .count(),
            1
        );
        self.retained_welcome = Some(retained[0].1.clone());
        self.alice.drive_unpublished_welcome_delivery(None).await;
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

    fn sender_capture(&self) -> &WelcomeProbe {
        self.alice.audit_v5_probe.as_ref().unwrap()
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

    fn joins(&self) -> Vec<(&Record, &WelcomeJoinFinished)> {
        self.capture()
            .rows
            .iter()
            .filter_map(|row| match &row.fields().event {
                Event::WelcomeJoinFinished(event) => Some((row, event)),
                _ => None,
            })
            .collect()
    }

    fn assert_clean(&self) {
        for capture in [self.sender_capture(), self.capture()] {
            assert_eq!(capture.invalid, 0);
            assert_eq!(capture.dropped, 0);
            for (i, row) in capture.rows.iter().enumerate() {
                assert_eq!(row.fields().seq.get(), (i + 1) as u64);
                assert_eq!(Record::from_json(&row.to_json().unwrap()).unwrap(), *row);
            }
        }
    }
}

#[tokio::test]
async fn duplicate_delivery_does_not_rejoin() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut scenario = Scenario::new().await;
        let group = scenario.create().await;
        scenario.bob.sync().await.unwrap();
        let original_join = scenario.joins()[0].1.clone();
        let original_epoch = scenario.bob.runtime.group_record(&group).unwrap().epoch;
        let delivery = cgka_traits::TransportDelivery {
            account_id: cgka_traits::MemberId::new(hex::decode(&scenario.bob_id).unwrap()),
            group_id_hint: None,
            message: scenario.retained_welcome.clone().unwrap(),
            received_at: cgka_traits::transport::Timestamp(1_700_000_002),
            source: cgka_traits::TransportDeliverySource {
                transport: cgka_traits::transport::TransportSource("nostr".into()),
                plane: cgka_traits::TransportDeliveryPlane::AccountInbox,
                endpoint: None,
                subscription_id: None,
                wire: None,
            },
        };
        let replay = scenario
            .bob
            .ingest_received_delivery(delivery)
            .await
            .unwrap();
        assert!(replay.joined_groups.is_empty());
        assert_eq!(
            scenario.bob.runtime.group_record(&group).unwrap().epoch,
            original_epoch
        );
        assert_eq!(scenario.joins().len(), 1);
        assert_eq!(scenario.joins()[0].1, &original_join);
        scenario.assert_clean();
    })
    .await
    .expect("bounded duplicate Welcome scenario");
}

#[tokio::test]
async fn join_row_uses_install_anchor_and_omits_ambiguous_replacement() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut scenario = Scenario::new().await;
        let group = scenario.create().await;
        scenario.bob.sync().await.unwrap();
        let observed = scenario
            .capture()
            .rows
            .iter()
            .find_map(|row| match &row.fields().event {
                Event::WelcomeObserved(event) => Some(event),
                _ => None,
            })
            .unwrap();
        let receive = (
            observed.receive_id.clone(),
            observed.outer_event_ref.clone(),
        );
        let mut later = scenario.bob.runtime.group_record(&group).unwrap();
        later.epoch.0 += 1;
        let mut capture = probe();
        capture.joined(receive.clone(), &later);
        let Event::WelcomeJoinFinished(join) = &capture.rows[0].fields().event else {
            panic!("expected join row")
        };
        assert_eq!(join.epoch, Some(later.local_copy_install_epoch.0.into()));
        assert_ne!(join.epoch, Some(later.epoch.0.into()));

        // A replacement resets this lower bound. Even if the current group
        // happens to be readable, this initial-join slice must omit it.
        later.join_epoch.0 = 0;
        let before = capture.rows.len();
        capture.joined(receive, &later);
        assert_eq!(capture.rows.len(), before);
        assert_eq!(capture.invalid, 0);
        assert_eq!(capture.dropped, 0);
        scenario.assert_clean();
    })
    .await
    .expect("bounded join-anchor scenario");
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
        assert_eq!(
            scenario.alice.group_mls_state(&group).unwrap().epoch,
            scenario.bob.group_mls_state(&group).unwrap().epoch
        );
        let observed = scenario
            .capture()
            .rows
            .iter()
            .find_map(|r| match &r.fields().event {
                Event::WelcomeObserved(e) => Some(e),
                _ => None,
            })
            .unwrap();
        let outer = observed.outer_event_ref.clone();
        let unwrapped = scenario
            .capture()
            .rows
            .iter()
            .find_map(|r| match &r.fields().event {
                Event::WelcomeUnwrapped(e) => Some(e),
                _ => None,
            })
            .unwrap();
        assert_eq!(unwrapped.receive_id, observed.receive_id);
        assert_eq!(unwrapped.outer_event_ref, outer);
        assert_eq!(unwrapped.result, UnwrapResult::Validated);
        assert_eq!(unwrapped.reason, None);
        assert!(unwrapped.rumor_event_ref.is_some());
        assert_ne!(unwrapped.rumor_event_ref.as_ref(), Some(&outer));
        assert_eq!(
            unwrapped.key_package_event_ref,
            Some(NostrEventRef::from_validated_event_id(
                &scenario.key_package_event_id
            ))
        );
        let joins = scenario.joins();
        let [(join_row, join)] = joins.as_slice() else {
            panic!("one actual engine join completion")
        };
        let committed_group = scenario.bob.runtime.group_record(&group).unwrap();
        assert_eq!(committed_group.members.len(), 2);
        assert_eq!(committed_group.protocol_profile, ProtocolProfile::Current);
        assert_eq!(
            committed_group.join_epoch,
            committed_group.local_copy_install_epoch
        );
        assert_eq!(
            join_row.fields().group_ref,
            Some(GroupRef::from_group_id(group.as_slice()).unwrap())
        );
        assert_eq!(join.receive_id, observed.receive_id);
        assert_eq!(join.outer_event_ref, outer);
        assert_eq!(join.result, JoinResult::Joined);
        assert_eq!(join.reason, None);
        assert_eq!(join.engine_commit, EngineCommit::Committed);
        assert_eq!(
            join.epoch,
            Some(committed_group.local_copy_install_epoch.0.into())
        );
        assert_eq!(join.elapsed_us, None);
        let prepared = scenario
            .sender_capture()
            .rows
            .iter()
            .find_map(|row| match &row.fields().event {
                Event::WelcomePrepared(event) => Some((row, event)),
                _ => None,
            })
            .unwrap();
        assert_ne!(
            prepared.0.fields().source_ref,
            scenario.capture().rows[0].fields().source_ref
        );
        assert_ne!(
            prepared.0.fields().session_id,
            scenario.capture().rows[0].fields().session_id
        );
        assert_eq!(
            prepared.0.fields().group_ref,
            Some(GroupRef::from_group_id(group.as_slice()).unwrap())
        );
        assert_eq!(
            prepared.1.recipient_ref,
            MemberRef::from_member_identity(&hex::decode(&scenario.bob_id).unwrap()).unwrap()
        );
        assert_eq!(prepared.1.mode, Mode::Founding);
        assert_eq!(prepared.1.basis, Basis::Founding {});
        assert_eq!(prepared.1.construction, Construction::Constructed);
        assert_eq!(prepared.1.retention, Retention::Committed);
        assert_eq!(prepared.1.failure_stage, None);
        assert_eq!(prepared.1.reason, None);
        assert_eq!(prepared.1.outer_event_ref, Some(outer.clone()));
        assert_eq!(
            prepared.1.key_package_event_ref,
            unwrapped.key_package_event_ref
        );
        assert_eq!(observed.acquisition, Acquisition::Unknown);
        assert!(
            join_row.fields().seq
                < scenario
                    .capture()
                    .rows
                    .iter()
                    .find(|r| matches!(r.fields().event, Event::AppGroupUpdateFinished(_)))
                    .unwrap()
                    .fields()
                    .seq
        );
        assert_eq!(scenario.updates().len(), 1);
        assert_eq!(scenario.updates()[0].outer_event_ref, outer);
        assert_eq!(scenario.updates()[0].cause, UpdateCause::WelcomeJoin);
        assert_eq!(scenario.updates()[0].checkpoint, Checkpoint::Committed);
        assert_eq!(
            scenario.updates()[0].invite_state,
            InviteState::PendingConfirmation
        );

        scenario.bob.accept_group_invite(&group).unwrap();
        assert!(
            !scenario
                .bob_app
                .group("bob", &group_hex)
                .unwrap()
                .unwrap()
                .pending_confirmation
        );
        assert_eq!(scenario.updates().len(), 2);
        assert_eq!(scenario.updates()[1].outer_event_ref, outer);
        assert_eq!(scenario.updates()[1].cause, UpdateCause::InviteConfirmation);
        assert_eq!(scenario.updates()[1].checkpoint, Checkpoint::Committed);
        assert_eq!(scenario.updates()[1].invite_state, InviteState::Accepted);
        assert_ne!(
            scenario.updates()[0].update_id,
            scenario.updates()[1].update_id
        );

        let before_message = scenario.capture().rows.len();
        scenario
            .alice
            .send(&group, b"synthetic content must never enter probe")
            .await
            .unwrap();
        let received = scenario.bob.sync().await.unwrap();
        assert_eq!(received.messages.len(), 1);
        assert_eq!(
            received.messages[0].plaintext,
            "synthetic content must never enter probe"
        );
        assert_eq!(
            scenario.capture().rows.len(),
            before_message,
            "ordinary message work adds no Welcome rows"
        );
        scenario.assert_clean();
        let mut total = 0;
        let mut largest = 0;
        let mut by_kind = std::collections::BTreeMap::<String, (usize, usize)>::new();
        for row in &scenario.capture().rows {
            let body = row.to_json().unwrap();
            total += body.len();
            largest = largest.max(body.len());
            let value = serde_json::to_value(&row.fields().event).unwrap();
            let kind = value["type"].as_str().unwrap().to_owned();
            let entry = by_kind.entry(kind).or_default();
            entry.0 += 1;
            entry.1 += body.len();
            let text = std::str::from_utf8(&body).unwrap();
            for forbidden in [
                &group_hex,
                &scenario.bob_id,
                &hex::encode(scenario.key_package_event_id),
                pending.via_welcome_message_id_hex.as_ref().unwrap(),
                "synthetic private group title",
                "synthetic content must never enter probe",
            ] {
                assert!(!text.contains(forbidden));
            }
        }
        // A gross-regression bound for this local subset, not a bandwidth
        // target for the complete Welcome lifecycle or an upload measurement.
        assert!(total < 7500);
        println!(
            "v5 recipient subset: rows={} body_bytes={total} \
             jsonl_bytes={} largest_body_bytes={largest} by_kind={by_kind:?}",
            scenario.capture().rows.len(),
            total + scenario.capture().rows.len()
        );
        let sender_rows = &scenario.sender_capture().rows;
        let sender_body: usize = sender_rows
            .iter()
            .map(|row| row.to_json().unwrap().len())
            .sum();
        let sender_largest = sender_rows
            .iter()
            .map(|row| row.to_json().unwrap().len())
            .max()
            .unwrap();
        let sender_by_kind = sender_rows
            .iter()
            .map(|row| {
                let body = row.to_json().unwrap();
                let kind = serde_json::to_value(&row.fields().event).unwrap()["type"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let text = std::str::from_utf8(&body).unwrap();
                for forbidden in [
                    &group_hex,
                    &scenario.bob_id,
                    &hex::encode(scenario.key_package_event_id),
                    pending.via_welcome_message_id_hex.as_ref().unwrap(),
                    "synthetic private group title",
                    "synthetic content must never enter probe",
                ] {
                    assert!(!text.contains(forbidden));
                }
                (kind, body.len())
            })
            .collect::<Vec<_>>();
        assert!(sender_body < 3000);
        assert!(
            sender_by_kind
                .iter()
                .any(|(kind, _)| kind == "welcome_prepared")
        );
        assert!(
            sender_by_kind
                .iter()
                .any(|(kind, _)| kind == "group_baseline")
        );
        println!(
            "v5 sender subset: rows={} body_bytes={sender_body} jsonl_bytes={} \
             largest_body_bytes={sender_largest} by_kind={sender_by_kind:?}",
            sender_rows.len(),
            sender_body + sender_rows.len()
        );
        for app in [&scenario.alice.app, &scenario.bob_app] {
            let files = app.audit_log_files().unwrap();
            assert!(!files.is_empty());
            for file in files {
                for row in std::fs::read_to_string(file.path).unwrap().lines() {
                    let v: serde_json::Value = serde_json::from_str(row).unwrap();
                    assert_eq!(v["schema_version"], marmot_forensics::v5::SCHEMA_VERSION);
                }
            }
        }
    })
    .await
    .expect("bounded local Welcome scenario");
}

#[tokio::test]
async fn founding_preparation_matches_two_recipients_without_order_inference() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut scenario = Scenario::new().await;
        let carol_dir = tempfile::tempdir().unwrap();
        let carol_id = AccountHome::open(carol_dir.path())
            .create_account("carol")
            .unwrap()
            .account_id_hex;
        let carol_app = app(carol_dir.path(), &scenario._relay.url().await.to_string());
        let mut carol = carol_app.client("carol").await.unwrap();
        carol.publish_key_package().await.unwrap();
        let carol_key_package_event_id: [u8; 32] = carol
            .runtime
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .authored_event_id
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();

        let group = scenario
            .alice
            .create_group_with_initial_source_and_optional_telemetry(
                "two recipient preparation",
                &[&scenario.bob_id, &carol_id],
                crate::AppCreateGroupOptions::default(),
                None,
                None,
            )
            .await
            .unwrap()
            .group_id;
        assert_eq!(scenario.alice.members(&group).unwrap().len(), 3);
        let retained = scenario
            .alice
            .runtime
            .outstanding_welcome_deliveries()
            .unwrap();
        assert_eq!(retained.len(), 2);
        for (retained_group, welcome) in &retained {
            assert_eq!(*retained_group, group);
            assert_eq!(
                scenario
                    .alice
                    .runtime
                    .session()
                    .stored_sent_welcome(&welcome.id)
                    .unwrap(),
                (retained_group.clone(), welcome.clone())
            );
        }
        let sender = scenario.sender_capture();
        assert_eq!(
            sender
                .rows
                .iter()
                .filter(|row| matches!(row.fields().event, Event::WelcomePrepared(_)))
                .count(),
            2
        );
        let expected = [
            (&scenario.bob_id, scenario.key_package_event_id),
            (&carol_id, carol_key_package_event_id),
        ];
        for (recipient_hex, key_package_event_id) in &expected {
            let recipient_bytes = hex::decode(recipient_hex).unwrap();
            let recipient_ref = MemberRef::from_member_identity(&recipient_bytes).unwrap();
            let row = sender
                .rows
                .iter()
                .find(|row| match &row.fields().event {
                    Event::WelcomePrepared(prepared) => prepared.recipient_ref == recipient_ref,
                    _ => false,
                })
                .unwrap();
            let Event::WelcomePrepared(prepared) = &row.fields().event else {
                unreachable!()
            };
            assert_eq!(
                row.fields().group_ref,
                Some(GroupRef::from_group_id(group.as_slice()).unwrap())
            );
            assert_eq!(
                prepared.key_package_event_ref,
                Some(NostrEventRef::from_validated_event_id(key_package_event_id))
            );
            let exact = retained
                .iter()
                .find(|(_, welcome)| match &welcome.envelope {
                    cgka_traits::transport::TransportEnvelope::Welcome { recipient } => {
                        recipient.as_slice() == recipient_bytes
                    }
                    _ => false,
                })
                .unwrap();
            let outer_id: [u8; 32] = exact.1.id.as_slice().try_into().unwrap();
            assert_eq!(
                prepared.outer_event_ref,
                Some(NostrEventRef::from_validated_event_id(&outer_id))
            );
            assert_eq!(prepared.retention, Retention::Committed);
        }
        assert_ne!(
            match &sender.rows[0].fields().event {
                Event::WelcomePrepared(e) => &e.outer_event_ref,
                _ => unreachable!(),
            },
            match &sender.rows[1].fields().event {
                Event::WelcomePrepared(e) => &e.outer_event_ref,
                _ => unreachable!(),
            }
        );
        scenario.assert_clean();

        // Reorder the same engine-retained artifacts when presenting them to
        // a separate bounded probe. Recipient identity, not vec index, binds K.
        let effects = SessionEffects {
            events: Vec::new(),
            publish: vec![PublishWork::FoundingGroupCreated {
                welcomes: retained
                    .iter()
                    .rev()
                    .map(|(_, welcome)| welcome.clone())
                    .collect(),
            }],
            queued: Vec::new(),
            pending_convergence: Vec::new(),
        };
        let selections = vec![
            FoundingSelection {
                recipient_hex: scenario.bob_id.clone(),
                key_package_event_id: Some(MessageId::new(scenario.key_package_event_id.to_vec())),
            },
            FoundingSelection {
                recipient_hex: carol_id.clone(),
                key_package_event_id: Some(MessageId::new(carol_key_package_event_id.to_vec())),
            },
        ];
        let mut reordered = probe_with_ids(0x55, 0x66);
        let pending = reordered.begin_founding(selections).unwrap();
        reordered.founding_prepared(pending, &group, &effects);
        assert_eq!(reordered.rows.len(), 2);
        assert_eq!(reordered.invalid, 0);
        for row in &reordered.rows {
            let Event::WelcomePrepared(prepared) = &row.fields().event else {
                unreachable!()
            };
            let (_, expected_id) = expected
                .iter()
                .find(|(recipient, _)| {
                    prepared.recipient_ref
                        == MemberRef::from_member_identity(&hex::decode(recipient).unwrap())
                            .unwrap()
                })
                .unwrap();
            assert_eq!(
                prepared.key_package_event_ref,
                Some(NostrEventRef::from_validated_event_id(expected_id))
            );
        }

        let mut mismatched = probe_with_ids(0x77, 0x88);
        let pending = mismatched
            .begin_founding(vec![FoundingSelection {
                recipient_hex: scenario.bob_id.clone(),
                key_package_event_id: Some(MessageId::new(scenario.key_package_event_id.to_vec())),
            }])
            .unwrap();
        mismatched.founding_prepared(pending, &group, &effects);
        assert!(mismatched.rows.is_empty());
        assert_eq!(mismatched.invalid, 1);

        let mut total = 0;
        let mut largest = 0;
        for row in &sender.rows {
            let body = row.to_json().unwrap();
            total += body.len();
            largest = largest.max(body.len());
            let text = std::str::from_utf8(&body).unwrap();
            for forbidden in [
                hex::encode(group.as_slice()),
                scenario.bob_id.clone(),
                carol_id.clone(),
                hex::encode(scenario.key_package_event_id),
                hex::encode(carol_key_package_event_id),
                "two recipient preparation".to_owned(),
            ] {
                assert!(!text.contains(&forbidden));
            }
        }
        assert!(total < 3200);
        println!(
            "v5 two-recipient sender: rows=2 body_bytes={total} jsonl_bytes={} \
             largest_body_bytes={largest} by_kind=[(welcome_prepared,2,{total})]",
            total + 2
        );
    })
    .await
    .expect("bounded two-recipient preparation");
}

#[tokio::test]
async fn hash_valid_unsigned_gift_wrap_is_observed_then_rejected_without_inner_refs() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut scenario = Scenario::new().await;
        let mut event = NostrTransportEvent {
            id: String::new(),
            pubkey: "44".repeat(32),
            created_at: 1_700_000_001,
            kind: transport_nostr_peeler::KIND_NIP59_GIFT_WRAP,
            tags: vec![vec!["p".into(), scenario.bob_id.clone()]],
            content: "synthetic invalid gift wrap".into(),
            sig: None,
        };
        event.id = event.computed_id();
        let message = event.to_transport_message().unwrap();
        let delivery = cgka_traits::TransportDelivery {
            account_id: cgka_traits::MemberId::new(hex::decode(&scenario.bob_id).unwrap()),
            group_id_hint: None,
            message,
            received_at: cgka_traits::transport::Timestamp(1_700_000_002),
            source: cgka_traits::TransportDeliverySource {
                transport: cgka_traits::transport::TransportSource("nostr".into()),
                plane: cgka_traits::TransportDeliveryPlane::AccountInbox,
                endpoint: None,
                subscription_id: None,
                wire: None,
            },
        };
        let summary = scenario
            .bob
            .ingest_received_delivery(delivery)
            .await
            .expect("terminal invalid-signature rejection is a handled ingest");
        assert!(summary.joined_groups.is_empty());
        assert!(summary.events.is_empty());
        assert!(scenario.bob_app.groups("bob").unwrap().is_empty());
        let rows = &scenario.capture().rows;
        let observed = rows
            .iter()
            .find_map(|r| match &r.fields().event {
                Event::WelcomeObserved(e) => Some(e),
                _ => None,
            })
            .unwrap();
        let rejected = rows
            .iter()
            .find_map(|r| match &r.fields().event {
                Event::WelcomeUnwrapped(e) => Some(e),
                _ => None,
            })
            .unwrap();
        assert_eq!(rejected.receive_id, observed.receive_id);
        assert_eq!(rejected.outer_event_ref, observed.outer_event_ref);
        assert_eq!(rejected.result, UnwrapResult::Rejected);
        assert_eq!(rejected.reason, Some(UnwrapReason::InvalidSignature));
        assert!(rejected.rumor_event_ref.is_none());
        assert!(rejected.key_package_event_ref.is_none());
        assert!(rows.iter().all(|r| r.fields().group_ref.is_none()));
        assert!(scenario.joins().is_empty());
        assert!(
            rows.iter()
                .all(|r| !matches!(r.fields().event, Event::AppGroupUpdateFinished(_)))
        );
        scenario.assert_clean();
        for row in rows {
            let text = String::from_utf8(row.to_json().unwrap()).unwrap();
            assert!(!text.contains(&scenario.bob_id));
            assert!(!text.contains(&event.id));
            assert!(!text.contains("synthetic invalid gift wrap"));
        }
        let body: usize = rows.iter().map(|r| r.to_json().unwrap().len()).sum();
        let largest = rows
            .iter()
            .map(|r| r.to_json().unwrap().len())
            .max()
            .unwrap();
        let by_kind = rows
            .iter()
            .map(|r| {
                let value = serde_json::to_value(&r.fields().event).unwrap();
                (
                    value["type"].as_str().unwrap().to_owned(),
                    r.to_json().unwrap().len(),
                )
            })
            .collect::<Vec<_>>();
        println!(
            "v5 rejected unwrap: rows={} body_bytes={body} jsonl_bytes={} \
             largest_body_bytes={largest} by_kind={by_kind:?}",
            rows.len(),
            body + rows.len()
        );
    })
    .await
    .expect("bounded invalid-signature scenario");
}

#[tokio::test]
async fn ambiguous_nip59_decrypt_error_is_failed_without_inner_refs() {
    let sender = nostr::prelude::Keys::generate();
    let recipient = nostr::prelude::Keys::generate();
    let wrong_key = nostr::prelude::Keys::generate();
    let message = NostrMlsPeeler::new()
        .with_welcome_signer(sender)
        .wrap_welcome_with_metadata(
            &EncryptedPayload {
                ciphertext: b"synthetic MLS bytes".to_vec(),
                aad: Vec::new(),
            },
            &MemberId::new(recipient.public_key().to_bytes().to_vec()),
            &WelcomeMetadata {
                key_package_event_id: cgka_traits::MessageId::new(vec![0x44; 32]),
                relays: vec![cgka_traits::TransportEndpoint("wss://group.example".into())],
            },
        )
        .await
        .unwrap();
    let slot = std::sync::Arc::new(std::sync::Mutex::new(PeelSlot::default()));
    let id: [u8; 32] = message.id.as_slice().try_into().unwrap();
    slot.lock().unwrap().arm(
        &message,
        (
            "33".repeat(16).try_into().unwrap(),
            NostrEventRef::from_validated_event_id(&id),
        ),
    );
    let peeler = ProbePeeler {
        inner: NostrMlsPeeler::new().with_welcome_signer(wrong_key),
        slot: slot.clone(),
    };
    assert!(matches!(
        peeler.peel_welcome(&message).await,
        Err(PeelerError::DecryptFailed)
    ));
    let completion = slot.lock().unwrap().take().unwrap();
    assert_eq!(completion.result, UnwrapResult::Failed);
    assert_eq!(completion.reason, Some(UnwrapReason::UnwrapFailed));
    assert!(completion.provenance.is_none());
    let mut capture = probe();
    capture.unwrapped(completion);
    assert_eq!(capture.invalid, 0);
    let Event::WelcomeUnwrapped(row) = &capture.rows[0].fields().event else {
        panic!("expected unwrap row")
    };
    assert!(row.rumor_event_ref.is_none());
    assert!(row.key_package_event_ref.is_none());
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
        let joins = scenario.joins();
        let [(join_row, join)] = joins.as_slice() else {
            panic!("engine commit survives app checkpoint failure")
        };
        assert_eq!(
            join_row.fields().group_ref,
            Some(GroupRef::from_group_id(group.as_slice()).unwrap())
        );
        assert_eq!(join.engine_commit, EngineCommit::Committed);
        assert_eq!(join.result, JoinResult::Joined);
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
        let failed_row = scenario
            .capture()
            .rows
            .iter()
            .find(|row| matches!(row.fields().event, Event::AppGroupUpdateFinished(_)))
            .unwrap();
        assert!(join_row.fields().seq < failed_row.fields().seq);
        assert_eq!(failed.compute, Compute::Completed);
        assert_eq!(failed.checkpoint, Checkpoint::FailedBeforeCommit);
        assert_eq!(failed.invite_state, InviteState::Unknown);
        assert!(failed.reason.is_some());
        assert!(actual_v5_rows(&scenario.bob_app, "bob").iter().any(|row| {
            matches!(
                &row.fields().event,
                Event::AppUpdateOutcome(outcome)
                    if outcome.transaction == marmot_forensics::v5::AppUpdateTransaction::NotCommitted
                        && outcome.failure_stage
                            == Some(marmot_forensics::v5::AppUpdateFailureStage::Transaction)
            )
        }));
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
async fn offworker_startup_receive_retains_join_after_checkpoint_failure() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut scenario = Scenario::new().await;
        let group = scenario.create().await;
        let delivery = cgka_traits::TransportDelivery {
            account_id: cgka_traits::MemberId::new(hex::decode(&scenario.bob_id).unwrap()),
            group_id_hint: None,
            message: scenario.retained_welcome.clone().unwrap(),
            received_at: cgka_traits::transport::Timestamp(1_700_000_002),
            source: cgka_traits::TransportDeliverySource {
                transport: cgka_traits::transport::TransportSource("nostr".into()),
                plane: cgka_traits::TransportDeliveryPlane::AccountInbox,
                endpoint: None,
                subscription_id: None,
                wire: None,
            },
        };
        scenario
            .bob
            .audit_v5_probe
            .as_mut()
            .unwrap()
            .reject_checkpoints = true;
        let failure = scenario
            .bob
            .ingest_received_delivery_with_partial(delivery)
            .await
            .expect_err("the post-ingest app checkpoint must fail");
        assert!(failure.partial_summary.joined_groups.is_empty());
        assert_eq!(scenario.bob.members(&group).unwrap().len(), 2);
        assert!(
            scenario
                .bob
                .pending_failed_sync_summary
                .joined_groups
                .contains(&group),
            "the applied join must wait for a successful checkpoint"
        );

        scenario
            .bob
            .audit_v5_probe
            .as_mut()
            .unwrap()
            .reject_checkpoints = false;
        let replay = scenario
            .bob
            .finish_deferred_comparison_sync()
            .await
            .unwrap();
        assert_eq!(replay.joined_groups, vec![group]);
        assert!(
            scenario
                .bob
                .pending_failed_sync_summary
                .joined_groups
                .is_empty()
        );
        let next = scenario
            .bob
            .finish_deferred_comparison_sync()
            .await
            .unwrap();
        assert!(
            next.joined_groups.is_empty(),
            "the join summary replays once"
        );
        scenario.assert_clean();
    })
    .await
    .expect("bounded startup receive checkpoint scenario");
}

#[tokio::test]
async fn no_op_welcome_replay_does_not_label_unrelated_checkpoint() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut scenario = Scenario::new().await;
        let group = scenario.create().await;
        let joined = scenario.bob.sync().await.unwrap();
        scenario.bob.accept_group_invite(&group).unwrap();
        let event = joined
            .events
            .into_iter()
            .find(|event| matches!(event, GroupEvent::GroupJoined { .. }))
            .expect("actual retained Welcome event");
        let before = scenario.capture().rows.len();
        assert_eq!(scenario.joins().len(), 1);
        scenario
            .bob
            .observe_drained_session_events(&marmot_account::AccountDeviceEffects {
                events: vec![event],
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(scenario.capture().projections.is_empty());
        scenario.bob.set_group_archived(&group, true).unwrap();
        assert!(
            scenario
                .bob_app
                .group("bob", &hex::encode(group.as_slice()))
                .unwrap()
                .unwrap()
                .archived
        );
        assert_eq!(scenario.capture().rows.len(), before);
        assert_eq!(scenario.joins().len(), 1);
        scenario.assert_clean();
    })
    .await
    .expect("bounded no-op replay scenario");
}

#[tokio::test]
async fn welcome_checkpoint_with_distinct_application_ack_keeps_generic_outcome() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut scenario = Scenario::new().await;
        let group = scenario.create().await;
        let joined = scenario.bob.sync().await.unwrap();
        let welcome_event = joined
            .events
            .iter()
            .find(|event| matches!(event, GroupEvent::GroupJoined { .. }))
            .unwrap()
            .clone();
        scenario
            .alice
            .send(&group, b"mixed checkpoint message")
            .await
            .unwrap();
        let received = scenario.bob.sync().await.unwrap();
        let message_id = received
            .events
            .iter()
            .find_map(|event| match event {
                GroupEvent::MessageReceived { message_id, .. } => Some(message_id.clone()),
                _ => None,
            })
            .expect("authenticated application event");
        // Recreate the pending mixed checkpoint using IDs observed from the
        // actual join and receive paths. A single non-Welcome ack must not be
        // mistaken for the Welcome's own ack merely because its count is one.
        scenario
            .bob
            .audit_v5_probe
            .as_mut()
            .unwrap()
            .projected(&welcome_event, UpdateCause::WelcomeJoin);
        scenario
            .bob
            .pending_application_event_acks
            .insert(message_id.clone());
        scenario
            .bob
            .pending_group_projection_updates
            .insert(hex::encode(group.as_slice()));
        scenario.bob.accept_group_invite(&group).unwrap();
        let message_ref = EngineMessageRef::from_message_id(message_id.as_slice()).unwrap();
        assert!(actual_v5_rows(&scenario.bob_app, "bob").iter().any(|row| {
            matches!(&row.fields().event, Event::AppUpdateOutcome(outcome)
                if outcome.category == AppUpdateCategory::AccountProjectionCheckpoint
                    && outcome.transaction == AppUpdateTransaction::Committed
                    && outcome.message_ref.as_ref() == Some(&message_ref))
        }));
        scenario.assert_clean();
    })
    .await
    .expect("bounded mixed Welcome and application checkpoint");
}

#[tokio::test]
async fn failed_acceptance_has_one_checkpoint_result_and_restores_origin() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut scenario = Scenario::new().await;
        let group = scenario.create().await;
        let joined = scenario.bob.sync().await.unwrap();
        let event = joined
            .events
            .iter()
            .find(|event| matches!(event, GroupEvent::GroupJoined { .. }))
            .unwrap();
        // Exercise an outstanding origin alongside a persisted pending row,
        // as may occur after an uncertain checkpoint result.
        let capture = scenario.bob.audit_v5_probe.as_mut().unwrap();
        capture.projected(event, UpdateCause::WelcomeJoin);
        capture.reject_checkpoints = true;
        let before = scenario.updates().len();
        assert!(scenario.bob.accept_group_invite(&group).is_err());
        assert!(
            scenario
                .bob_app
                .group("bob", &hex::encode(group.as_slice()))
                .unwrap()
                .unwrap()
                .pending_confirmation
        );
        assert_eq!(scenario.updates().len(), before + 1);
        let failed = scenario.updates()[before];
        assert_eq!(failed.cause, UpdateCause::InviteConfirmation);
        assert_eq!(failed.checkpoint, Checkpoint::FailedBeforeCommit);
        assert_eq!(failed.invite_state, InviteState::Unknown);
        assert_eq!(
            scenario
                .capture()
                .projections
                .values()
                .copied()
                .collect::<Vec<_>>(),
            vec![UpdateCause::WelcomeJoin]
        );
        scenario
            .bob
            .audit_v5_probe
            .as_mut()
            .unwrap()
            .reject_checkpoints = false;
        scenario.bob.accept_group_invite(&group).unwrap();
        assert_eq!(scenario.updates().len(), before + 2);
        let accepted = scenario.updates()[before + 1];
        assert_eq!(accepted.cause, UpdateCause::InviteConfirmation);
        assert_eq!(accepted.checkpoint, Checkpoint::Committed);
        assert_eq!(accepted.invite_state, InviteState::Accepted);
        assert!(scenario.capture().projections.is_empty());
        scenario.assert_clean();
    })
    .await
    .expect("bounded acceptance retry scenario");
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

#[tokio::test]
async fn baseline_marks_an_invalid_or_duplicate_member_identity_as_partial() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut scenario = Scenario::new().await;
        let group_id = scenario.create().await;
        let group = scenario.alice.runtime.group_record(&group_id).unwrap();
        let mut capture = probe();

        let mut invalid = group.clone();
        invalid.members[0].id = cgka_traits::types::MemberId::new(Vec::new());
        capture.baseline(&invalid, None, BaselineReason::Opened, None);
        let Event::GroupBaseline(row) = &capture.rows[0].fields().event else {
            panic!("expected baseline");
        };
        assert_eq!(row.capture, Capture::Partial);
        assert!(!row.members_complete);
        assert!(row.limitations.contains(&Limitation::MemberIdentityInvalid));

        let mut duplicate = group;
        duplicate.members[1].id = duplicate.members[0].id.clone();
        capture.baseline(&duplicate, None, BaselineReason::Opened, None);
        let Event::GroupBaseline(row) = &capture.rows[1].fields().event else {
            panic!("expected baseline");
        };
        assert_eq!(row.capture, Capture::Partial);
        assert!(!row.members_complete);
        assert!(row.limitations.contains(&Limitation::MemberIdentityInvalid));
    })
    .await
    .expect("bounded baseline identity scenario");
}
