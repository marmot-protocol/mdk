mod support;

use std::path::Path;

use cgka_engine::canonicalization::CanonicalizationPolicy;
use cgka_session::IngestEffects;
use cgka_session::PublishWork;
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::engine::{CreateGroupRequest, GroupEvent, KeyPackage, SendIntent};
use cgka_traits::ingest::{IngestOutcome, StaleReason};
use cgka_traits::{EpochId, GroupId, MemberId, MessageId, TransportEndpoint, TransportMessage};
use serde::Serialize;
use support::nostr_stack::{CreatedGroup, NostrStackHarness, StackClient};
use transport_nostr_peeler::NostrTransportEvent;

#[tokio::test]
async fn seeded_delivery_chaos_variants_preserve_stack_invariants() {
    for scenario in stack_chaos_scenarios() {
        let report = run_stack_chaos_scenario(&scenario).await;
        write_report(&report);
        assert!(
            report.failures.is_empty(),
            "scenario {} ({}) failed:\n{}\nreport: {}",
            report.name,
            report.seed,
            report.failures.join("\n"),
            serde_json::to_string_pretty(&report).unwrap()
        );
    }
}

#[tokio::test]
async fn invite_lifecycle_chaos_handles_wrong_routes_replays_and_welcome_before_commit() {
    let seed = 0x1FEC7_u64;
    let stack = NostrStackHarness::new();
    let mut alice = stack.client("alice").await;
    let mut bob = stack.client("bob").await;
    let mut carol = stack.client("carol").await;
    let created = create_group_for_bob(&mut alice, &mut bob, seed).await;
    let group_id = created.group_id.clone();
    publish_confirm_and_deliver_welcome(&stack, &mut alice, &mut bob, created).await;
    stack.sync_group(&bob, &group_id).await;

    let invite = invite_carol(&mut alice, &mut carol, &group_id).await;
    let commit_report = stack
        .publish_group(&alice, &group_id, invite.commit.clone(), 1)
        .await
        .unwrap();
    let welcome_report = stack
        .publish_welcome(&alice, &carol, invite.welcome.clone(), 1)
        .await
        .unwrap();
    assert!(commit_report.met_required_acks());
    assert!(welcome_report.met_required_acks());
    alice
        .session
        .confirm_published(invite.pending)
        .await
        .unwrap();
    bob.session.set_convergence_policy(CanonicalizationPolicy {
        settlement_quiescence_ms: 0,
        ..CanonicalizationPolicy::default()
    });

    let commit_event = stack.take_next_published();
    let welcome_event = stack.take_next_published();
    assert_eq!(commit_event.endpoints, vec![stack.group_endpoint()]);
    assert_eq!(welcome_event.endpoints, vec![carol.inbox_endpoint.clone()]);

    let wrong_commit = stack
        .deliver_event_to_session(
            &mut bob,
            TransportEndpoint("wss://wrong-group.example".into()),
            "wrong-commit",
            commit_event.event.clone(),
        )
        .await;
    assert!(wrong_commit.is_none());

    let carol_endpoint = carol.inbox_endpoint.clone();
    let wrong_welcome = stack
        .deliver_event_to_session(
            &mut carol,
            TransportEndpoint("wss://wrong-inbox.example".into()),
            "wrong-welcome",
            welcome_event.event.clone(),
        )
        .await;
    assert!(wrong_welcome.is_none());

    let carol_joined = stack
        .deliver_event_to_session(
            &mut carol,
            carol_endpoint.clone(),
            "carol-valid-welcome",
            welcome_event.event.clone(),
        )
        .await
        .expect("valid welcome should route to Carol");
    assert_eq!(carol_joined.outcome, IngestOutcome::Processed);
    assert_eq!(
        carol_joined.effects.events,
        vec![GroupEvent::GroupJoined {
            group_id: group_id.clone(),
            via_welcome: welcome_report.message_id,
            welcomer: Some(alice.account_id.clone()),
        }]
    );
    assert_eq!(carol.session.epoch(&group_id).unwrap(), EpochId(2));
    assert_eq!(carol.session.members(&group_id).unwrap().len(), 3);

    let carol_welcome_replay = stack
        .deliver_event_to_session(
            &mut carol,
            carol_endpoint,
            "carol-welcome-replay",
            welcome_event.event,
        )
        .await
        .expect("welcome replay should still route to Carol");
    assert!(matches!(
        carol_welcome_replay.outcome,
        IngestOutcome::Stale {
            reason: StaleReason::AlreadySeen
        }
    ));
    assert!(carol_welcome_replay.effects.events.is_empty());

    stack.sync_group(&carol, &group_id).await;
    let bob_account_id = bob.account_id.clone();
    let carol_account_id = carol.account_id.clone();
    let mut commit_deliveries = stack
        .deliver_event_to_sessions(
            &mut [&mut bob, &mut carol],
            stack.group_endpoint(),
            "shared-commit-delivery",
            commit_event.event.clone(),
        )
        .await;
    assert_eq!(commit_deliveries.len(), 2);

    let bob_commit = take_effect_for(&mut commit_deliveries, &bob_account_id);
    assert_invite_commit_processed(&bob_commit, &group_id, &carol_account_id);
    assert_eq!(bob.session.epoch(&group_id).unwrap(), EpochId(2));
    assert_eq!(bob.session.members(&group_id).unwrap().len(), 3);

    let carol_late_commit = take_effect_for(&mut commit_deliveries, &carol_account_id);
    assert_peel_failed(&carol_late_commit);

    let mut replay_deliveries = stack
        .deliver_event_to_sessions(
            &mut [&mut bob, &mut carol],
            stack.group_endpoint(),
            "shared-commit-replay",
            commit_event.event,
        )
        .await;
    assert_eq!(replay_deliveries.len(), 2);

    let bob_commit_replay = take_effect_for(&mut replay_deliveries, &bob_account_id);
    assert_already_seen(&bob_commit_replay);

    let carol_commit_replay = take_effect_for(&mut replay_deliveries, &carol_account_id);
    assert_already_seen(&carol_commit_replay);
}

#[tokio::test]
async fn invite_lifecycle_chaos_handles_commit_before_welcome_and_shared_replay() {
    let seed = 0xC01117_u64;
    let stack = NostrStackHarness::new();
    let mut alice = stack.client("alice").await;
    let mut bob = stack.client("bob").await;
    let mut carol = stack.client("carol").await;
    let created = create_group_for_bob(&mut alice, &mut bob, seed).await;
    let group_id = created.group_id.clone();
    publish_confirm_and_deliver_welcome(&stack, &mut alice, &mut bob, created).await;
    stack.sync_group(&bob, &group_id).await;
    bob.session.set_convergence_policy(CanonicalizationPolicy {
        settlement_quiescence_ms: 0,
        ..CanonicalizationPolicy::default()
    });

    let invite = invite_carol(&mut alice, &mut carol, &group_id).await;
    let commit_report = stack
        .publish_group(&alice, &group_id, invite.commit.clone(), 1)
        .await
        .unwrap();
    let welcome_report = stack
        .publish_welcome(&alice, &carol, invite.welcome.clone(), 1)
        .await
        .unwrap();
    assert!(commit_report.met_required_acks());
    assert!(welcome_report.met_required_acks());
    alice
        .session
        .confirm_published(invite.pending)
        .await
        .unwrap();

    let commit_event = stack.take_next_published();
    let welcome_event = stack.take_next_published();
    let bob_commit = stack
        .deliver_event_to_session(
            &mut bob,
            stack.group_endpoint(),
            "bob-commit-before-welcome",
            commit_event.event.clone(),
        )
        .await
        .expect("valid commit should route to Bob");
    assert_invite_commit_processed(&bob_commit, &group_id, &carol.account_id);
    assert_eq!(bob.session.epoch(&group_id).unwrap(), EpochId(2));

    let bob_replay = stack
        .deliver_event_to_session(
            &mut bob,
            stack.group_endpoint(),
            "bob-commit-before-welcome-replay",
            commit_event.event.clone(),
        )
        .await
        .expect("commit replay should route to Bob");
    assert_already_seen(&bob_replay);

    let carol_endpoint = carol.inbox_endpoint.clone();
    let carol_joined = stack
        .deliver_event_to_session(
            &mut carol,
            carol_endpoint,
            "carol-welcome-after-bob-commit",
            welcome_event.event,
        )
        .await
        .expect("valid welcome should route to Carol");
    assert_eq!(carol_joined.outcome, IngestOutcome::Processed);
    assert_eq!(
        carol_joined.effects.events,
        vec![GroupEvent::GroupJoined {
            group_id: group_id.clone(),
            via_welcome: welcome_report.message_id,
            welcomer: Some(alice.account_id.clone()),
        }]
    );
    assert_eq!(carol.session.epoch(&group_id).unwrap(), EpochId(2));

    stack.sync_group(&carol, &group_id).await;
    let bob_account_id = bob.account_id.clone();
    let carol_account_id = carol.account_id.clone();
    let mut shared_replay = stack
        .deliver_event_to_sessions(
            &mut [&mut bob, &mut carol],
            stack.group_endpoint(),
            "shared-commit-after-welcome",
            commit_event.event,
        )
        .await;
    assert_eq!(shared_replay.len(), 2);

    let bob_shared_replay = take_effect_for(&mut shared_replay, &bob_account_id);
    assert_already_seen(&bob_shared_replay);

    let carol_late_commit = take_effect_for(&mut shared_replay, &carol_account_id);
    assert_peel_failed(&carol_late_commit);
}

#[derive(Clone, Debug)]
struct StackChaosScenario {
    name: &'static str,
    seed: u64,
    message_count: usize,
    steps: Vec<DeliveryStep>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum DeliveryStep {
    Deliver { message_index: usize },
    Replay { message_index: usize },
    WrongEndpoint { message_index: usize },
    Drop { message_index: usize },
}

#[derive(Clone, Debug, Serialize)]
struct StackChaosReport {
    name: String,
    seed: u64,
    message_count: usize,
    steps: Vec<DeliveryStep>,
    observations: Vec<DeliveryObservation>,
    expected_payloads: Vec<String>,
    observed_payloads: Vec<String>,
    failures: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct DeliveryObservation {
    step_index: usize,
    step: DeliveryStep,
    outcome: String,
    payloads: Vec<String>,
}

struct ChaosRunState<'a> {
    scenario: &'a StackChaosScenario,
    seen: Vec<bool>,
    observations: Vec<DeliveryObservation>,
    expected_payloads: Vec<String>,
    observed_payloads: Vec<String>,
    failures: Vec<String>,
}

struct InvitePublish {
    pending: cgka_traits::PendingStateRef,
    commit: TransportMessage,
    welcome: TransportMessage,
}

fn stack_chaos_scenarios() -> Vec<StackChaosScenario> {
    let mut scenarios = vec![
        StackChaosScenario {
            name: "reorder_duplicate_wrong_endpoint_and_drop",
            seed: 0xC0FFEE,
            message_count: 4,
            steps: vec![
                DeliveryStep::Deliver { message_index: 2 },
                DeliveryStep::WrongEndpoint { message_index: 0 },
                DeliveryStep::Deliver { message_index: 0 },
                DeliveryStep::Replay { message_index: 2 },
                DeliveryStep::Drop { message_index: 1 },
                DeliveryStep::Deliver { message_index: 3 },
            ],
        },
        StackChaosScenario {
            name: "wrong_endpoint_then_late_valid_delivery",
            seed: 0xBAD5EED,
            message_count: 3,
            steps: vec![
                DeliveryStep::WrongEndpoint { message_index: 0 },
                DeliveryStep::Deliver { message_index: 1 },
                DeliveryStep::Deliver { message_index: 0 },
                DeliveryStep::Replay { message_index: 0 },
                DeliveryStep::Deliver { message_index: 2 },
            ],
        },
        StackChaosScenario {
            name: "reverse_delivery_with_replays",
            seed: 0x5157AC,
            message_count: 5,
            steps: vec![
                DeliveryStep::Deliver { message_index: 4 },
                DeliveryStep::Deliver { message_index: 3 },
                DeliveryStep::Replay { message_index: 4 },
                DeliveryStep::Deliver { message_index: 2 },
                DeliveryStep::Deliver { message_index: 1 },
                DeliveryStep::Replay { message_index: 2 },
                DeliveryStep::Deliver { message_index: 0 },
            ],
        },
    ];
    scenarios.extend([
        generated_stack_chaos_scenario("generated_delivery_weather_a", 0xC0DEC0DE, 3),
        generated_stack_chaos_scenario("generated_delivery_weather_b", 0xA11CE5, 3),
        generated_stack_chaos_scenario("generated_delivery_weather_c", 0xB0B5EED, 3),
    ]);
    scenarios
}

fn generated_stack_chaos_scenario(
    name: &'static str,
    seed: u64,
    message_count: usize,
) -> StackChaosScenario {
    let mut rng = ScriptRng::new(seed);
    let mut message_order = (0..message_count).collect::<Vec<_>>();
    for index in (1..message_order.len()).rev() {
        let swap_index = rng.next_usize(index + 1);
        message_order.swap(index, swap_index);
    }

    let mut steps = Vec::new();
    let mut has_wrong_endpoint = false;
    let mut has_drop = false;
    let mut has_replay = false;

    for message_index in message_order {
        if rng.one_in(4) {
            steps.push(DeliveryStep::WrongEndpoint { message_index });
            has_wrong_endpoint = true;
        }
        if rng.one_in(5) {
            steps.push(DeliveryStep::Drop { message_index });
            has_drop = true;
        }
        steps.push(DeliveryStep::Deliver { message_index });
        if rng.one_in(3) {
            steps.push(DeliveryStep::Replay { message_index });
            has_replay = true;
        }
    }

    if !has_wrong_endpoint {
        steps.insert(0, DeliveryStep::WrongEndpoint { message_index: 0 });
    }
    if !has_drop {
        steps.insert(1, DeliveryStep::Drop { message_index: 0 });
    }
    if !has_replay {
        steps.push(DeliveryStep::Replay {
            message_index: message_count.saturating_sub(1),
        });
    }

    StackChaosScenario {
        name,
        seed,
        message_count,
        steps,
    }
}

async fn run_stack_chaos_scenario(scenario: &StackChaosScenario) -> StackChaosReport {
    let stack = NostrStackHarness::new();
    let mut alice = stack.client("alice").await;
    let mut bob = stack.client("bob").await;
    let created = create_group_for_bob(&mut alice, &mut bob, scenario.seed).await;
    let group_id = created.group_id.clone();
    publish_confirm_and_deliver_welcome(&stack, &mut alice, &mut bob, created).await;
    stack.sync_group(&bob, &group_id).await;

    let events = publish_app_events(
        &stack,
        &mut alice,
        &group_id,
        scenario.seed,
        scenario.message_count,
    )
    .await;

    let mut run = ChaosRunState::new(scenario);

    for (step_index, step) in scenario.steps.iter().copied().enumerate() {
        if step.message_index() >= events.len() {
            run.observe_bad_reference(step_index, step, events.len());
            continue;
        }

        match step {
            DeliveryStep::Drop { message_index } => {
                run.observe_drop(step_index, step, message_index);
            }
            DeliveryStep::WrongEndpoint { message_index } => {
                let outcome = stack
                    .deliver_event_to_session(
                        &mut bob,
                        TransportEndpoint("wss://wrong-endpoint.example".into()),
                        format!("wrong-endpoint-{step_index}"),
                        events[message_index].clone(),
                    )
                    .await;
                run.observe_wrong_endpoint(step_index, step, outcome.is_some());
            }
            DeliveryStep::Deliver { message_index } => {
                let ingest = stack
                    .deliver_event_to_session(
                        &mut bob,
                        stack.group_endpoint(),
                        format!("deliver-{step_index}"),
                        events[message_index].clone(),
                    )
                    .await;
                run.observe_valid_delivery(step_index, step, message_index, ingest);
            }
            DeliveryStep::Replay { message_index } => {
                run.observe_replay_before_first_delivery(step_index, message_index);
                let ingest = stack
                    .deliver_event_to_session(
                        &mut bob,
                        stack.group_endpoint(),
                        format!("replay-{step_index}"),
                        events[message_index].clone(),
                    )
                    .await;
                run.observe_replay(step_index, step, message_index, ingest);
            }
        }
    }

    run.finalize()
}

impl ChaosRunState<'_> {
    fn new(scenario: &StackChaosScenario) -> ChaosRunState<'_> {
        ChaosRunState {
            scenario,
            seen: vec![false; scenario.message_count],
            observations: Vec::new(),
            expected_payloads: Vec::new(),
            observed_payloads: Vec::new(),
            failures: Vec::new(),
        }
    }

    fn observe_bad_reference(&mut self, step_index: usize, step: DeliveryStep, event_count: usize) {
        self.failures.push(format!(
            "step {step_index} references message {} but only {event_count} messages exist",
            step.message_index()
        ));
    }

    fn observe_drop(&mut self, step_index: usize, step: DeliveryStep, message_index: usize) {
        self.observations.push(DeliveryObservation {
            step_index,
            step,
            outcome: "dropped_before_adapter".into(),
            payloads: vec![payload_label(self.scenario.seed, message_index)],
        });
    }

    fn observe_wrong_endpoint(
        &mut self,
        step_index: usize,
        step: DeliveryStep,
        reached_session: bool,
    ) {
        if reached_session {
            self.failures.push(format!(
                "step {step_index} wrong-endpoint delivery unexpectedly reached session"
            ));
        }
        self.observations.push(DeliveryObservation {
            step_index,
            step,
            outcome: "not_routed".into(),
            payloads: vec![],
        });
    }

    fn observe_valid_delivery(
        &mut self,
        step_index: usize,
        step: DeliveryStep,
        message_index: usize,
        ingest: Option<IngestEffects>,
    ) {
        let Some(ingest) = ingest else {
            self.failures.push(format!(
                "step {step_index} valid delivery for message {message_index} did not route"
            ));
            self.observations.push(DeliveryObservation {
                step_index,
                step,
                outcome: "not_routed".into(),
                payloads: vec![],
            });
            return;
        };

        let payloads = message_payloads(&ingest);
        if self.seen[message_index] {
            if !matches!(
                ingest.outcome,
                IngestOutcome::Stale {
                    reason: StaleReason::AlreadySeen
                }
            ) {
                self.failures.push(format!(
                    "step {step_index} duplicate valid delivery for message {message_index} returned {:?}",
                    ingest.outcome
                ));
            }
            if !payloads.is_empty() {
                self.failures.push(format!(
                    "step {step_index} duplicate valid delivery emitted payloads {payloads:?}"
                ));
            }
            self.observations.push(DeliveryObservation {
                step_index,
                step,
                outcome: format!("{:?}", ingest.outcome),
                payloads,
            });
            return;
        }

        self.seen[message_index] = true;
        let expected = payload_label(self.scenario.seed, message_index);
        self.expected_payloads.push(expected.clone());
        self.observed_payloads.extend(payloads.clone());

        if ingest.outcome != IngestOutcome::Processed {
            self.failures.push(format!(
                "step {step_index} first valid delivery for message {message_index} returned {:?}",
                ingest.outcome
            ));
        }
        if payloads != vec![expected] {
            self.failures.push(format!(
                "step {step_index} first valid delivery for message {message_index} emitted {payloads:?}"
            ));
        }
        self.observations.push(DeliveryObservation {
            step_index,
            step,
            outcome: format!("{:?}", ingest.outcome),
            payloads,
        });
    }

    fn observe_replay_before_first_delivery(&mut self, step_index: usize, message_index: usize) {
        if !self.seen[message_index] {
            self.failures.push(format!(
                "step {step_index} replayed message {message_index} before first valid delivery"
            ));
        }
    }

    fn observe_replay(
        &mut self,
        step_index: usize,
        step: DeliveryStep,
        message_index: usize,
        ingest: Option<IngestEffects>,
    ) {
        let Some(ingest) = ingest else {
            self.failures.push(format!(
                "step {step_index} replay for message {message_index} did not route"
            ));
            self.observations.push(DeliveryObservation {
                step_index,
                step,
                outcome: "not_routed".into(),
                payloads: vec![],
            });
            return;
        };

        let payloads = message_payloads(&ingest);
        if !matches!(
            ingest.outcome,
            IngestOutcome::Stale {
                reason: StaleReason::AlreadySeen
            }
        ) {
            self.failures.push(format!(
                "step {step_index} replay for message {message_index} returned {:?}",
                ingest.outcome
            ));
        }
        if !payloads.is_empty() {
            self.failures.push(format!(
                "step {step_index} replay for message {message_index} emitted payloads {payloads:?}"
            ));
        }
        self.observations.push(DeliveryObservation {
            step_index,
            step,
            outcome: format!("{:?}", ingest.outcome),
            payloads,
        });
    }

    fn finalize(mut self) -> StackChaosReport {
        if self.expected_payloads != self.observed_payloads {
            self.failures.push(format!(
                "observed payloads did not match expected payloads: expected={:?} observed={:?}",
                self.expected_payloads, self.observed_payloads
            ));
        }

        StackChaosReport {
            name: self.scenario.name.into(),
            seed: self.scenario.seed,
            message_count: self.scenario.message_count,
            steps: self.scenario.steps.clone(),
            observations: self.observations,
            expected_payloads: self.expected_payloads,
            observed_payloads: self.observed_payloads,
            failures: self.failures,
        }
    }
}

async fn create_group_for_bob(
    alice: &mut StackClient,
    bob: &mut StackClient,
    seed: u64,
) -> CreatedGroup {
    let bob_key_package = key_package_with_event_id(
        bob.session.fresh_key_package().await.unwrap(),
        (seed & 0xff) as u8,
    );
    let created = alice
        .session
        .create_group(CreateGroupRequest {
            name: format!("stack-chaos-{seed:x}"),
            description: "seeded session stack chaos".into(),
            members: vec![bob_key_package],
            required_features: vec![],
            app_components: vec![support::nostr_stack::nostr_routing_component(
                format!("stack-chaos-{seed:x}").as_bytes(),
            )],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    CreatedGroup::from_effects(created)
}

async fn publish_confirm_and_deliver_welcome(
    stack: &NostrStackHarness,
    alice: &mut StackClient,
    bob: &mut StackClient,
    created: CreatedGroup,
) {
    let welcome_report = stack
        .publish_welcome(alice, bob, created.welcome, 1)
        .await
        .unwrap();
    assert!(welcome_report.met_required_acks());
    alice
        .session
        .confirm_published(created.pending)
        .await
        .unwrap();
    let joined = stack
        .deliver_next_to_inbox_session(bob)
        .await
        .expect("welcome delivery should route");
    assert_eq!(
        joined.effects.events,
        vec![GroupEvent::GroupJoined {
            group_id: created.group_id,
            via_welcome: welcome_report.message_id,
            welcomer: Some(alice.account_id.clone()),
        }]
    );
}

async fn publish_app_events(
    stack: &NostrStackHarness,
    sender: &mut StackClient,
    group_id: &GroupId,
    seed: u64,
    count: usize,
) -> Vec<NostrTransportEvent> {
    let mut events = Vec::new();
    for message_index in 0..count {
        let sent = sender
            .session
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: app_payload_for(sender, payload_label(seed, message_index).as_bytes()),
            })
            .await
            .unwrap();
        let message = match &sent.publish[0] {
            PublishWork::ApplicationMessage { msg } => msg.clone(),
            other => panic!("expected application message publish work, got {other:?}"),
        };
        let report = stack
            .publish_group(sender, group_id, message, 1)
            .await
            .unwrap();
        assert!(report.met_required_acks());
        events.push(stack.take_one_published().event);
    }
    events
}

async fn invite_carol(
    alice: &mut StackClient,
    carol: &mut StackClient,
    group_id: &GroupId,
) -> InvitePublish {
    let carol_key_package =
        key_package_with_event_id(carol.session.fresh_key_package().await.unwrap(), 0xC0);
    let invite = alice
        .session
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_key_package],
        })
        .await
        .unwrap();
    match &invite.publish[0] {
        PublishWork::GroupEvolution {
            msg,
            welcomes,
            pending,
        } => InvitePublish {
            pending: *pending,
            commit: msg.clone(),
            welcome: welcomes[0].clone(),
        },
        other => panic!("expected group evolution publish work, got {other:?}"),
    }
}

fn key_package_with_event_id(key_package: KeyPackage, marker: u8) -> KeyPackage {
    KeyPackage::with_source_event_id(
        key_package.bytes().to_vec(),
        MessageId::new(vec![marker; 32]),
    )
}

fn message_payloads(ingest: &IngestEffects) -> Vec<String> {
    ingest
        .effects
        .events
        .iter()
        .filter_map(|event| match event {
            GroupEvent::MessageReceived { payload, .. } => {
                let event = MarmotAppEvent::decode(payload).expect("chaos app event decodes");
                Some(event.content)
            }
            _ => None,
        })
        .collect()
}

fn app_payload_for(sender: &StackClient, payload: impl AsRef<[u8]>) -> Vec<u8> {
    let content = String::from_utf8(payload.as_ref().to_vec()).expect("chaos payloads are utf8");
    MarmotAppEvent::new(
        hex::encode(sender.session.self_id().as_slice()),
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        content,
    )
    .encode()
    .expect("chaos app event encodes")
}

fn take_effect_for(
    deliveries: &mut Vec<(MemberId, IngestEffects)>,
    account_id: &MemberId,
) -> IngestEffects {
    let position = deliveries
        .iter()
        .position(|(delivered, _)| delivered == account_id)
        .expect("expected delivery for account");
    deliveries.remove(position).1
}

fn assert_invite_commit_processed(
    effects: &IngestEffects,
    group_id: &GroupId,
    added_member: &MemberId,
) {
    assert_eq!(effects.outcome, IngestOutcome::Processed);
    assert!(effects.effects.events.iter().any(|event| matches!(
        event,
        GroupEvent::EpochChanged {
            group_id: changed_group,
            from: EpochId(1),
            to: EpochId(2),
        } if changed_group == group_id
    )));
    assert!(effects.effects.events.iter().any(|event| matches!(
        event,
        GroupEvent::GroupStateChanged {
            group_id: changed_group,
            change: cgka_traits::engine::GroupStateChange::MemberAdded { member },
            ..
        } if changed_group == group_id && member == added_member
    )));
}

fn assert_already_seen(effects: &IngestEffects) {
    assert!(
        matches!(
            effects.outcome,
            IngestOutcome::Stale {
                reason: StaleReason::AlreadySeen
                    | StaleReason::AlreadyAtEpoch { .. }
                    | StaleReason::PeelFailed
            }
        ),
        "expected duplicate/stale epoch outcome, got {:?}",
        effects.outcome
    );
    assert!(effects.effects.events.is_empty());
}

fn assert_peel_failed(effects: &IngestEffects) {
    assert!(
        matches!(
            effects.outcome,
            IngestOutcome::Stale {
                reason: StaleReason::PeelFailed
            }
        ),
        "unexpected peel failure outcome: {:?}",
        effects.outcome
    );
    assert!(effects.effects.events.is_empty());
}

fn payload_label(seed: u64, message_index: usize) -> String {
    format!("seed-{seed:x}-message-{message_index}")
}

impl DeliveryStep {
    fn message_index(self) -> usize {
        match self {
            Self::Deliver { message_index }
            | Self::Replay { message_index }
            | Self::WrongEndpoint { message_index }
            | Self::Drop { message_index } => message_index,
        }
    }
}

struct ScriptRng(u64);

impl ScriptRng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn next_usize(&mut self, upper_bound: usize) -> usize {
        (self.next() as usize) % upper_bound
    }

    fn one_in(&mut self, divisor: u64) -> bool {
        self.next().is_multiple_of(divisor)
    }
}

fn write_report(report: &StackChaosReport) {
    let target_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/session-stack-chaos")
        .canonicalize()
        .unwrap_or_else(|_| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/session-stack-chaos")
        });
    std::fs::create_dir_all(&target_dir).expect("create chaos report directory");
    let path = target_dir.join(format!("{}-{:x}.json", report.name, report.seed));
    std::fs::write(
        path,
        serde_json::to_vec_pretty(report).expect("serialize chaos report"),
    )
    .expect("write chaos report");
}
