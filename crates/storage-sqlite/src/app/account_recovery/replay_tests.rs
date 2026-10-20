//! Consumer-visible tests of the native goal's limited admission authority.
use super::*;

fn native(app: &SqliteAppStorage, generation: u8) -> RecoveryDemandTicket {
    app.request_recovery(
        RecoveryRequest::SubscriptionReplay {
            snapshot: &[generation; 32],
        },
        1_000,
    )
    .unwrap()
}

fn selected(app: &SqliteAppStorage, ticket: RecoveryDemandTicket) -> RecoveryRevisionFence {
    let mut fence = app.recovery_revision_fence().unwrap();
    fence.obligations.retain(|(id, _)| *id == ticket.id);
    fence
}

enum PeerAdmission {
    Granted,
    Refused,
}

fn scope(id: u64, since: u64, until: u64, admission: PeerAdmission) -> RecoveryScopePlan {
    RecoveryScopePlan {
        scope_id: id,
        route_kind: 0,
        route_role: 0,
        group_id: None,
        transport_group_id: None,
        since_seconds: Some(since),
        until_seconds: until,
        known_event_id: None,
        inventory_floor: None,
        required_endpoints: vec!["issued".into(), "unavailable".into()],
        admitted_endpoints: if matches!(admission, PeerAdmission::Granted) {
            vec!["issued".into()]
        } else {
            vec![]
        },
    }
}

fn admission(token: &RecoveryScopeToken) -> RecoveryScopeCheckpoint {
    RecoveryScopeCheckpoint {
        token: token.clone(),
        endpoints: vec![],
        retained_known_event: false,
        replay_admitted: true,
    }
}

fn prepare(
    app: &SqliteAppStorage,
    ticket: RecoveryDemandTicket,
    plans: &[RecoveryScopePlan],
) -> (RecoveryRevisionFence, Vec<RecoveryScopeToken>) {
    let fence = selected(app, ticket);
    let tokens = app
        .install_recovery_scope_plan(&fence, 0, ticket.id, plans)
        .unwrap()
        .unwrap();
    (fence, tokens)
}

#[test]
fn native_plan_issued_sources() {
    let app = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let ticket = native(&app, 1);
    assert!(app.recovery_scope_snapshots(ticket.id).unwrap().is_empty());
    let plans = [
        scope(41, 0, 10, PeerAdmission::Granted),
        scope(77, 3, 20, PeerAdmission::Granted),
    ];
    let (fence, tokens) = prepare(&app, ticket, &plans);
    let stored = app.recovery_scope_snapshots(ticket.id).unwrap();
    assert!(stored.iter().map(|scope| &scope.plan).eq(plans.iter()));
    assert!(native(&app, 1) == ticket);
    assert!(
        app.checkpoint_replay_admission(
            &fence,
            ticket,
            RecoveryReplayPlacement::Placed,
            &[admission(&tokens[0]), admission(&tokens[1])]
        )
        .unwrap()
    );
    assert!(
        app.recovery_obligation_is_satisfied(ticket.id, ticket.revision)
            .unwrap()
    );
    assert_eq!(app.recovery_retry_state().unwrap().attempt_serial, 0);
}

#[test]
fn native_global_placement_fence() {
    let app = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let ticket = native(&app, 1);
    let (fence, tokens) = prepare(&app, ticket, &[scope(41, 0, 20, PeerAdmission::Granted)]);
    let cost = app.recovery_retry_state().unwrap();
    assert!(
        !app.checkpoint_replay_admission(
            &fence,
            ticket,
            RecoveryReplayPlacement::Pending,
            &[admission(&tokens[0])]
        )
        .unwrap()
    );
    assert!(
        app.recovery_scope_snapshots(ticket.id).unwrap()[0].replay_admitted,
        "the source-local proof survives unrelated account-wide pending input"
    );
    assert_eq!(
        app.recovery_obligation_status(ticket.id)
            .unwrap()
            .unwrap()
            .state,
        RecoveryObligationState::Pending
    );
    assert!(
        !app.recovery_obligation_is_satisfied(ticket.id, ticket.revision)
            .unwrap()
    );
    assert!(
        app.checkpoint_replay_admission(&fence, ticket, RecoveryReplayPlacement::Placed, &[])
            .unwrap()
    );
    assert!(
        app.recovery_obligation_is_satisfied(ticket.id, ticket.revision)
            .unwrap()
    );
    assert_eq!(app.recovery_retry_state().unwrap(), cost);
}

#[test]
fn native_retire_fences_tokens() {
    let app = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let ticket = native(&app, 1);
    let mut unfloored = scope(41, 0, 20, PeerAdmission::Granted);
    unfloored.since_seconds = None;
    let kept = scope(77, 3, 20, PeerAdmission::Granted);
    let (fence, tokens) = prepare(&app, ticket, &[unfloored.clone(), kept.clone()]);
    let retry = app.recovery_retry_state().unwrap();
    assert!(
        app.retire_native_replay_scopes(&fence, ticket, &tokens[..1])
            .unwrap()
    );
    let successor = native(&app, 1);
    assert!(successor.revision > tokens.iter().map(|token| token.revision).max().unwrap());
    let stored = app.recovery_scope_snapshots(ticket.id).unwrap();
    assert_eq!(stored.len(), 1);
    assert!(stored[0].plan == kept);
    assert!(
        !app.retire_native_replay_scopes(&fence, ticket, &tokens[1..])
            .unwrap()
    );
    let (current, new_tokens) = prepare(&app, successor, &[unfloored, kept]);
    assert!(
        new_tokens
            .iter()
            .all(|token| token.revision > tokens[0].revision)
    );
    assert!(
        !app.checkpoint_replay_admission(
            &current,
            successor,
            RecoveryReplayPlacement::Placed,
            &[admission(&tokens[0])]
        )
        .unwrap()
    );
    assert!(
        app.retire_native_replay_scopes(&current, successor, &new_tokens)
            .unwrap()
    );
    let retired = app.recovery_obligation_status(ticket.id).unwrap().unwrap();
    assert_eq!(retired.state, RecoveryObligationState::Retired);
    assert!(
        !app.recovery_obligation_is_satisfied(ticket.id, retired.revision)
            .unwrap()
    );
    assert!(app.recovery_scope_snapshots(ticket.id).unwrap().is_empty());
    assert_eq!(app.recovery_retry_state().unwrap(), retry);
}

#[test]
fn native_unserved_park_resumes() {
    let app = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let ticket = native(&app, 1);
    let mut goal = scope(41, 0, 20, PeerAdmission::Refused);
    goal.since_seconds = None;
    let (fence, tokens) = prepare(&app, ticket, &[goal.clone()]);
    let retry = app.recovery_retry_state().unwrap();
    assert!(
        app.park_unserved_native_replay(&fence, ticket, &tokens)
            .unwrap()
    );
    let parked = app.parked_recovery_obligations().unwrap();
    assert_eq!(parked.len(), 1);
    assert!(parked[0].ticket == ticket);
    assert!(parked[0].parked_at_ms.is_some());
    assert!(
        app.recovery_eligible_revision_fence(false)
            .unwrap()
            .obligations
            .is_empty()
    );
    assert!(
        app.recovery_scope_snapshots(ticket.id).unwrap()[0]
            .plan
            .since_seconds
            .is_none()
    );
    let successor = native(&app, 2);
    assert!(app.parked_recovery_obligations().unwrap().is_empty());
    assert!(
        !app.park_unserved_native_replay(&fence, ticket, &tokens)
            .unwrap()
    );
    goal.admitted_endpoints = vec!["issued".into()];
    let (current, tokens) = prepare(&app, successor, &[goal]);
    assert!(
        app.checkpoint_replay_admission(
            &current,
            successor,
            RecoveryReplayPlacement::Placed,
            &[admission(&tokens[0])]
        )
        .unwrap()
    );
    assert_eq!(app.recovery_retry_state().unwrap(), retry);
    for cause in [
        RecoveryLossCause::Queue,
        RecoveryLossCause::NotificationConsumer,
    ] {
        assert!(
            app.recovery_loss_watermarks("alice", cause)
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn stale_native_cas_keeps_debt() {
    let app = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let ticket = native(&app, 1);
    let plans = [
        scope(41, 0, 20, PeerAdmission::Granted),
        scope(77, 3, 20, PeerAdmission::Granted),
    ];
    let (fence, old) = prepare(&app, ticket, &plans);
    let (_, current) = prepare(&app, ticket, &plans);
    let mixed = [current[0].clone(), old[1].clone()];
    assert!(
        !app.retire_native_replay_scopes(&fence, ticket, &mixed)
            .unwrap()
    );
    assert!(
        !app.park_unserved_native_replay(&fence, ticket, &mixed)
            .unwrap()
    );
    app.observe_recovery_route_snapshot([8; 32]).unwrap();
    assert!(
        !app.retire_native_replay_scopes(&fence, ticket, &current)
            .unwrap()
    );
    assert!(
        !app.park_unserved_native_replay(&fence, ticket, &current)
            .unwrap()
    );
    assert_eq!(app.recovery_scope_snapshots(ticket.id).unwrap().len(), 2);
    assert!(app.parked_recovery_obligations().unwrap().is_empty());
    assert_eq!(
        app.recovery_obligation_status(ticket.id)
            .unwrap()
            .unwrap()
            .revision,
        ticket.revision
    );
}

struct MixedComparison {
    app: SqliteAppStorage,
    native: RecoveryDemandTicket,
    auxiliary: RecoveryDemandTicket,
    native_token: RecoveryScopeToken,
    auxiliary_token: RecoveryScopeToken,
    fence: RecoveryRevisionFence,
    revision: u64,
    attempt: u64,
}

fn mixed_comparison() -> MixedComparison {
    let app = SqliteAccountStorage::in_memory().unwrap().app_storage();
    app.ensure_account_projection("alice").unwrap();
    let native = native(&app, 1);
    let auxiliary = app
        .request_recovery(
            RecoveryRequest::ExplicitHistory {
                operation_id: &[1; 16],
            },
            1_000,
        )
        .unwrap();
    let mut route = scope(0, 0, 20, PeerAdmission::Granted);
    route.required_endpoints = vec!["issued".into()];
    let revision = app
        .join_recovery_comparison(&[1; 16], 1_000, &[route.clone()])
        .unwrap();
    let (_, mut tokens) = prepare(&app, native, &[scope(41, 0, 20, PeerAdmission::Granted)]);
    let native_token = tokens.remove(0);
    let fence = app.recovery_revision_fence().unwrap();
    app.reserve_recovery_attempt(&fence, 1_000, 100, false)
        .unwrap()
        .unwrap();
    let attempt = app
        .reserve_recovery_attempt(&fence, 1_100, 100, false)
        .unwrap()
        .unwrap()
        .attempt_serial;
    let auxiliary_token = app
        .install_recovery_scope_plan(&fence, attempt, auxiliary.id, &[route.clone()])
        .unwrap()
        .unwrap()
        .remove(0);
    assert!(
        app.install_recovery_comparison_plan(
            revision,
            attempt,
            &RecoveryComparisonPlan {
                fence: fence.clone(),
                live_since_seconds: None,
                routes: vec![route],
                retry_routes: vec![0],
            }
        )
        .unwrap()
    );
    MixedComparison {
        app,
        native,
        auxiliary,
        native_token,
        auxiliary_token,
        fence,
        revision,
        attempt,
    }
}

#[test]
fn native_mixed_grant_settles() {
    for comparison_progress in [false, true] {
        let grant = mixed_comparison();
        let app = &grant.app;
        let cost = app.recovery_retry_state().unwrap();
        assert!(
            app.checkpoint_replay_admission(
                &grant.fence,
                grant.native,
                RecoveryReplayPlacement::Placed,
                &[admission(&grant.native_token)]
            )
            .unwrap()
        );
        assert_eq!(
            app.recovery_retry_state().unwrap(),
            cost,
            "passive admission cannot forgive retry cost"
        );
        let current = app.recovery_revision_fence().unwrap();
        assert!(
            !current
                .obligations
                .contains(&(grant.native.id, grant.native.revision))
        );
        let progress = if comparison_progress {
            app.checkpoint_recovery_comparison_progress(
                grant.revision,
                grant.attempt,
                &grant.fence,
                1_300,
                25,
            )
        } else {
            app.checkpoint_recovery_progress(&grant.fence, grant.attempt, 1_300, 25)
        };
        assert!(
            progress.unwrap(),
            "newly retained input still advances its exact mixed grant"
        );
        assert_eq!(app.recovery_retry_state().unwrap().ordinal, 1);
        assert!(
            app.settle_recovery_comparison(
                grant.revision,
                grant.attempt,
                &[(0, RecoveryComparisonOutcome::ServicedUnknown)],
                None
            )
            .unwrap()
        );
        assert!(!app.recovery_comparison().unwrap().pending());
        assert!(
            !app.recovery_obligation_is_satisfied(grant.auxiliary.id, grant.auxiliary.revision)
                .unwrap()
        );
        assert!(
            app.pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|demand| demand.cause == RecoveryCause::IncrementalHistory)
        );
    }
}

#[test]
fn native_mixed_fence_is_exact() {
    for invalidation in [
        "native successor",
        "route",
        "loss",
        "unimported loss",
        "other completion",
    ] {
        let grant = mixed_comparison();
        let app = &grant.app;
        assert!(
            app.checkpoint_replay_admission(
                &grant.fence,
                grant.native,
                RecoveryReplayPlacement::Placed,
                &[admission(&grant.native_token)]
            )
            .unwrap()
        );
        let cost = app.recovery_retry_state().unwrap();
        match invalidation {
            "native successor" => {
                native(app, 2);
            }
            "route" => {
                app.observe_recovery_route_snapshot([1; 32]).unwrap();
            }
            "loss" => {
                app.mark_account_delivery_recovery("alice", 7, 1).unwrap();
            }
            "unimported loss" => {
                app.record_account_recovery_loss("alice", RecoveryLossCause::Queue, 7, 1, 1)
                    .unwrap();
            }
            "other completion" => {
                assert!(
                    app.checkpoint_recovery_obligation(
                        &grant.fence,
                        grant.attempt,
                        grant.auxiliary.id,
                        &[RecoveryScopeCheckpoint {
                            token: grant.auxiliary_token.clone(),
                            endpoints: vec![RecoveryEndpointCheckpoint {
                                endpoint: "issued".into(),
                                outcome: RecoveryScopeOutcome::Covered,
                                exhaustive: true,
                                admission_complete: true,
                                first_boundary: false,
                            }],
                            retained_known_event: false,
                            replay_admitted: false,
                        }],
                        RecoveryEligibility::Retry
                    )
                    .unwrap()
                );
            }
            _ => unreachable!(),
        }
        assert!(
            !app.checkpoint_recovery_progress(&grant.fence, grant.attempt, 1_300, 25)
                .unwrap(),
            "{invalidation}"
        );
        assert!(
            !app.checkpoint_recovery_comparison_progress(
                grant.revision,
                grant.attempt,
                &grant.fence,
                1_300,
                25
            )
            .unwrap(),
            "{invalidation}"
        );
        assert!(
            !app.settle_recovery_comparison(
                grant.revision,
                grant.attempt,
                &[(0, RecoveryComparisonOutcome::ServicedUnknown)],
                None
            )
            .unwrap(),
            "{invalidation}"
        );
        assert!(app.recovery_comparison().unwrap().pending());
        assert_eq!(app.recovery_retry_state().unwrap(), cost);
    }
}

#[test]
fn native_successor_keeps_debt() {
    let app = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let first = native(&app, 1);
    let fence = selected(&app, first);
    let reservation = app
        .reserve_recovery_attempt(&fence, 1_000, 15_000, false)
        .unwrap()
        .unwrap();
    let plans = [
        scope(0, 0, 10, PeerAdmission::Granted),
        scope(7, 3, 20, PeerAdmission::Granted),
    ];
    let tokens = app
        .install_recovery_scope_plan(&fence, reservation.attempt_serial, first.id, &plans)
        .unwrap()
        .unwrap();
    assert!(
        !app.checkpoint_recovery_obligation(
            &fence,
            reservation.attempt_serial,
            first.id,
            &[RecoveryScopeCheckpoint {
                replay_admitted: false,
                ..admission(&tokens[0])
            }],
            RecoveryEligibility::NeedsDeepRepair,
        )
        .unwrap()
    );
    let (duplicate, transition) = app
        .request_recovery_observed(
            RecoveryRequest::SubscriptionReplay { snapshot: &[1; 32] },
            50_000,
        )
        .unwrap();
    assert!(duplicate == first);
    assert_eq!(transition, RecoveryDemandTransition::Unchanged);
    assert_eq!(
        app.recovery_obligation_status(first.id)
            .unwrap()
            .unwrap()
            .eligibility,
        RecoveryEligibility::NeedsDeepRepair
    );

    let successor = native(&app, 2);
    assert_eq!(successor.id, first.id);
    assert!(successor.revision > first.revision);
    let pending = app.pending_recovery_demands().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].cause, RecoveryCause::SubscriptionReplay);
    assert_eq!(pending[0].predicate, RecoveryPredicate::ReplayAdmission);
    assert_eq!(pending[0].eligibility, RecoveryEligibility::Ready);
    let preserved = app.recovery_scope_snapshots(successor.id).unwrap();
    assert!(preserved.iter().map(|stored| &stored.plan).eq(plans.iter()));
    assert_eq!(app.recovery_retry_state().unwrap(), reservation);
    assert!(
        app.reserve_recovery_attempt(&selected(&app, successor), 1_001, 15_000, false)
            .unwrap()
            .is_none()
    );
    assert!(
        !app.checkpoint_replay_admission(
            &fence,
            first,
            RecoveryReplayPlacement::Placed,
            &[admission(&tokens[0]), admission(&tokens[1])]
        )
        .unwrap()
    );

    let (fence, tokens) = prepare(&app, successor, &plans);
    // The zero-attempt scope cannot be checkpointed by that old network grant.
    assert!(
        !app.checkpoint_recovery_obligation(
            &fence,
            reservation.attempt_serial,
            successor.id,
            &[admission(&tokens[0])],
            RecoveryEligibility::NeedsDeepRepair,
        )
        .unwrap()
    );
    let cost = app
        .reserve_recovery_attempt(&fence, 16_000, 30_000, false)
        .unwrap()
        .unwrap();
    app.install_recovery_scope_plan(&fence, cost.attempt_serial, successor.id, &plans)
        .unwrap()
        .unwrap();
    // A normal owner-granted failure may park native debt without declaring loss.
    assert!(
        !app.checkpoint_recovery_obligation(
            &fence,
            cost.attempt_serial,
            successor.id,
            &[],
            RecoveryEligibility::NeedsDeepRepair,
        )
        .unwrap()
    );
    assert!(
        app.retire_parked_recovery_obligation(successor.id, successor.revision, 17_000)
            .unwrap()
    );
    let retired = native(&app, 2);
    assert_eq!(
        app.recovery_obligation_status(retired.id)
            .unwrap()
            .unwrap()
            .state,
        RecoveryObligationState::Retired
    );
    let fresh = native(&app, 3);
    assert_eq!(fresh.id, first.id);
    assert!(fresh.revision > retired.revision);
    assert!(
        app.recovery_scope_snapshots(fresh.id).unwrap().is_empty(),
        "retired windows are not inherited"
    );
    let new_plan = scope(0, 100, 200, PeerAdmission::Granted);
    let (fence, tokens) = prepare(&app, fresh, &[new_plan]);
    assert!(
        app.checkpoint_replay_admission(
            &fence,
            fresh,
            RecoveryReplayPlacement::Placed,
            &[admission(&tokens[0])]
        )
        .unwrap()
    );
    assert!(native(&app, 3) == fresh, "satisfied snapshots never rearm");
    assert!(
        app.recovery_obligation_is_satisfied(fresh.id, fresh.revision)
            .unwrap()
    );
    let newest = native(&app, 4);
    assert_eq!(newest.id, first.id);
    assert!(
        app.recovery_scope_snapshots(newest.id).unwrap().is_empty(),
        "satisfied windows are not inherited"
    );
    assert_eq!(app.recovery_retry_state().unwrap(), cost);
}

#[test]
fn native_all_scopes_need_a_peer() {
    let app = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let ticket = native(&app, 1);
    let cost = app.recovery_retry_state().unwrap();
    let plans = [
        scope(0, 0, 10, PeerAdmission::Granted),
        scope(1, 1, 20, PeerAdmission::Refused),
    ];
    let (fence, tokens) = prepare(&app, ticket, &plans);
    assert!(
        !app.checkpoint_replay_admission(
            &fence,
            ticket,
            RecoveryReplayPlacement::Placed,
            &[admission(&tokens[0])]
        )
        .unwrap()
    );
    assert!(
        !app.checkpoint_replay_admission(
            &fence,
            ticket,
            RecoveryReplayPlacement::Placed,
            &[admission(&tokens[1])]
        )
        .unwrap(),
        "an empty admitted endpoint set is not evidence"
    );
    let stored = app.recovery_scope_snapshots(ticket.id).unwrap();
    assert!(stored.iter().all(|scope| scope.replay_admitted));
    assert!(
        stored
            .iter()
            .all(|scope| scope.checkpoints.is_empty() && !scope.retained_known_event)
    );
    let new_plans = [plans[0].clone(), scope(1, 1, 20, PeerAdmission::Granted)];
    let (fence, tokens) = prepare(&app, ticket, &new_plans);
    assert!(
        !app.recovery_scope_snapshots(ticket.id).unwrap()[1].replay_admitted,
        "endpoint changes invalidate the old native fact"
    );
    assert!(
        app.checkpoint_replay_admission(
            &fence,
            ticket,
            RecoveryReplayPlacement::Placed,
            &[admission(&tokens[1])]
        )
        .unwrap()
    );
    assert_eq!(app.recovery_retry_state().unwrap(), cost);
    assert!(
        app.recovery_obligation_is_satisfied(ticket.id, ticket.revision)
            .unwrap()
    );
}

#[test]
fn native_observation_is_fenced() {
    let app = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let ticket = native(&app, 1);
    let plans = [
        scope(0, 0, 10, PeerAdmission::Granted),
        scope(1, 1, 20, PeerAdmission::Granted),
    ];
    let (fence, old) = prepare(&app, ticket, &plans);
    let (_, current) = prepare(&app, ticket, &plans);
    assert!(
        !app.checkpoint_replay_admission(
            &fence,
            ticket,
            RecoveryReplayPlacement::Placed,
            &[admission(&current[0]), admission(&old[1])]
        )
        .unwrap()
    );
    assert!(
        app.recovery_scope_snapshots(ticket.id)
            .unwrap()
            .iter()
            .all(|scope| !scope.replay_admitted)
    );
    app.observe_recovery_route_snapshot([1; 32]).unwrap();
    assert!(
        !app.checkpoint_replay_admission(
            &fence,
            ticket,
            RecoveryReplayPlacement::Placed,
            &[admission(&current[0]), admission(&current[1])]
        )
        .unwrap()
    );
    let (route_fence, tokens) = prepare(&app, ticket, &plans);
    let successor = native(&app, 2);
    assert!(
        !app.checkpoint_replay_admission(
            &route_fence,
            ticket,
            RecoveryReplayPlacement::Placed,
            &[admission(&tokens[0]), admission(&tokens[1])]
        )
        .unwrap()
    );
    assert!(
        !app.checkpoint_replay_admission(
            &selected(&app, successor),
            successor,
            RecoveryReplayPlacement::Placed,
            &[admission(&tokens[0]), admission(&tokens[1])]
        )
        .unwrap()
    );
    assert!(
        app.recovery_scope_snapshots(successor.id)
            .unwrap()
            .iter()
            .all(|scope| !scope.replay_admitted)
    );
}

#[test]
fn native_is_not_history_proof() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    app.ensure_account_projection("alice").unwrap();
    app.mark_account_delivery_recovery("alice", 1, 1).unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO cgka_groups(id,epoch,record) VALUES (?1,0,x'00')",
            [b"group".as_slice()],
        )
        .unwrap();
    let history = app
        .request_recovery(RecoveryRequest::IncrementalHistory, 1)
        .unwrap();
    let known = app
        .request_recovery(
            RecoveryRequest::KnownEvent {
                group_id: b"group",
                event_id: &[7; 32],
            },
            1,
        )
        .unwrap();
    let maintenance = app
        .request_recovery(
            RecoveryRequest::MaintenanceBoundary {
                job_id: b"job",
                group_id: b"group",
            },
            1,
        )
        .unwrap();
    let native = native(&app, 1);
    let fence = app.recovery_revision_fence().unwrap();
    let cost = app
        .reserve_recovery_attempt(&fence, 1_000, 15_000, false)
        .unwrap()
        .unwrap();
    let loss = app
        .pending_recovery_demands()
        .unwrap()
        .into_iter()
        .find(|demand| demand.cause == RecoveryCause::QueueLoss)
        .unwrap()
        .ticket;
    for ticket in [history, known, maintenance, loss] {
        let mut plan = scope(0, 0, 20, PeerAdmission::Granted);
        if ticket == known {
            plan.known_event_id = Some([7; 32]);
        }
        let tokens = app
            .install_recovery_scope_plan(&fence, cost.attempt_serial, ticket.id, &[plan])
            .unwrap()
            .unwrap();
        assert!(
            !app.checkpoint_replay_admission(
                &fence,
                ticket,
                RecoveryReplayPlacement::Placed,
                &[admission(&tokens[0])]
            )
            .unwrap()
        );
        assert!(
            !app.checkpoint_recovery_obligation(
                &fence,
                cost.attempt_serial,
                ticket.id,
                &[admission(&tokens[0])],
                RecoveryEligibility::Retry,
            )
            .unwrap()
        );
        assert!(
            !app.recovery_obligation_is_satisfied(ticket.id, ticket.revision)
                .unwrap()
        );
        assert!(
            app.install_recovery_scope_plan(
                &fence,
                0,
                ticket.id,
                &[scope(0, 0, 20, PeerAdmission::Granted)]
            )
            .is_err()
        );
    }
    let tokens = app
        .install_recovery_scope_plan(
            &fence,
            cost.attempt_serial,
            native.id,
            &[scope(0, 0, 20, PeerAdmission::Granted)],
        )
        .unwrap()
        .unwrap();
    assert!(
        app.checkpoint_replay_admission(
            &fence,
            native,
            RecoveryReplayPlacement::Placed,
            &[admission(&tokens[0])]
        )
        .unwrap()
    );
    let loss_watermarks = app
        .recovery_loss_watermarks("alice", RecoveryLossCause::Queue)
        .unwrap();
    assert!(
        !app.acknowledge_recovery_loss(&fence, native.id, &loss_watermarks)
            .unwrap()
    );
    assert!(
        !app.acknowledge_recovery_loss(&fence, loss.id, &loss_watermarks)
            .unwrap()
    );
    assert_eq!(
        app.recovery_loss_watermarks("alice", RecoveryLossCause::Queue)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(app.recovery_retry_state().unwrap(), cost);
}

#[test]
fn native_admission_rolls_back() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let ticket = native(&app, 1);
    let (fence, tokens) = prepare(&app, ticket, &[scope(0, 0, 10, PeerAdmission::Granted)]);
    let cost = app.recovery_retry_state().unwrap();
    store
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_native_completion BEFORE UPDATE ON account_recovery_obligations
         WHEN NEW.state=1 BEGIN SELECT RAISE(ABORT,'injected'); END",
        )
        .unwrap();
    assert!(
        app.checkpoint_replay_admission(
            &fence,
            ticket,
            RecoveryReplayPlacement::Placed,
            &[admission(&tokens[0])]
        )
        .is_err()
    );
    assert!(!app.recovery_scope_snapshots(ticket.id).unwrap()[0].replay_admitted);
    assert!(
        !app.recovery_obligation_is_satisfied(ticket.id, ticket.revision)
            .unwrap()
    );
    assert_eq!(app.recovery_retry_state().unwrap(), cost);
}

#[test]
fn native_scope_tokens_stay_stale() {
    for complete in [false, true] {
        let app = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let ticket = native(&app, 1);
        let mut plans = vec![scope(0, 0, 10, PeerAdmission::Granted)];
        if !complete {
            plans.push(scope(1, 1, 20, PeerAdmission::Granted));
        }
        // Several observations make the scope token exceed the obligation's
        // revision before its row is removed at the source-generation change.
        for _ in 0..3 {
            prepare(&app, ticket, &plans);
        }
        let (fence, old) = prepare(&app, ticket, &plans);
        assert_eq!(
            app.checkpoint_replay_admission(
                &fence,
                ticket,
                RecoveryReplayPlacement::Placed,
                &[admission(&old[0])]
            )
            .unwrap(),
            complete
        );
        let successor = native(&app, 2);
        let (fence, current) = prepare(&app, successor, &plans);
        assert!(current[0].revision > old[0].revision);
        assert!(
            !app.checkpoint_replay_admission(
                &fence,
                successor,
                RecoveryReplayPlacement::Placed,
                &[admission(&old[0])]
            )
            .unwrap()
        );
        assert!(
            app.recovery_scope_snapshots(successor.id)
                .unwrap()
                .iter()
                .all(|scope| !scope.replay_admitted)
        );
        assert_eq!(app.recovery_retry_state().unwrap().attempt_serial, 0);
    }
}

#[test]
fn native_grant_is_limited() {
    let app = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let ticket = native(&app, 1);
    let fence = selected(&app, ticket);
    let cost = app
        .reserve_recovery_attempt(&fence, 1_000, 15_000, false)
        .unwrap()
        .unwrap();
    let tokens = app
        .install_recovery_scope_plan(
            &fence,
            cost.attempt_serial,
            ticket.id,
            &[scope(0, 0, 20, PeerAdmission::Granted)],
        )
        .unwrap()
        .unwrap();
    assert!(
        app.checkpoint_recovery_obligation(
            &fence,
            cost.attempt_serial,
            ticket.id,
            &[admission(&tokens[0])],
            RecoveryEligibility::Retry,
        )
        .unwrap()
    );
    let stored = app.recovery_scope_snapshots(ticket.id).unwrap();
    assert!(stored[0].replay_admitted);
    assert!(stored[0].checkpoints.is_empty());
    assert!(!stored[0].retained_known_event);
    assert_eq!(app.recovery_retry_state().unwrap(), cost);
}

#[test]
fn native_reopen_keeps_floor() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("native-recovery.sqlite");
    let key = crate::SqlCipherKey::new("native recovery reopen").unwrap();
    let plans = [
        scope(0, 3, 10, PeerAdmission::Granted),
        scope(1, 0, 20, PeerAdmission::Granted),
    ];
    let (ticket, cost) = {
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let app = store.app_storage();
        let ticket = native(&app, 1);
        let cost = app
            .reserve_recovery_attempt(&selected(&app, ticket), 1_000, 15_000, false)
            .unwrap()
            .unwrap();
        let (fence, tokens) = prepare(&app, ticket, &plans);
        assert!(
            !app.checkpoint_replay_admission(
                &fence,
                ticket,
                RecoveryReplayPlacement::Placed,
                &[admission(&tokens[0])]
            )
            .unwrap()
        );
        store.close().unwrap();
        (ticket, cost)
    };
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let app = store.app_storage();
    assert!(native(&app, 1) == ticket);
    let stored = app.recovery_scope_snapshots(ticket.id).unwrap();
    assert!(stored.iter().map(|scope| &scope.plan).eq(plans.iter()));
    assert!(stored[0].replay_admitted);
    assert!(
        !stored[1].replay_admitted,
        "omitted historical format-1 facts default false"
    );
    assert!(
        stored
            .iter()
            .all(|scope| scope.checkpoints.is_empty() && !scope.retained_known_event)
    );
    let successor = native(&app, 2);
    let stored = app.recovery_scope_snapshots(successor.id).unwrap();
    assert_eq!(
        stored.len(),
        1,
        "admitted scope zero is not inherited or reseeded"
    );
    assert_eq!(stored[0].plan.scope_id, 1);
    assert_eq!(stored[0].plan.since_seconds, Some(0));
    assert_eq!(
        stored[0].plan.until_seconds, 20,
        "unresolved original window survives the successor"
    );
    assert!(native(&app, 2) == successor);
    assert_eq!(
        app.recovery_scope_snapshots(successor.id).unwrap().len(),
        1,
        "duplicate snapshot cannot restore an admitted scope"
    );
    let merged = stored
        .into_iter()
        .map(|mut stored| {
            stored.plan.until_seconds = 30;
            stored.plan
        })
        .collect::<Vec<_>>();
    prepare(&app, successor, &merged);
    assert_eq!(app.recovery_retry_state().unwrap(), cost);
    store.close().unwrap();
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let app = reopened.app_storage();
    let stored = app.recovery_scope_snapshots(successor.id).unwrap();
    assert!(stored.iter().map(|scope| &scope.plan).eq(merged.iter()));
    assert!(
        stored.iter().all(|scope| !scope.replay_admitted),
        "old source generation proofs cannot qualify a successor"
    );
    assert_eq!(app.recovery_retry_state().unwrap(), cost);
    reopened.close().unwrap();
}
