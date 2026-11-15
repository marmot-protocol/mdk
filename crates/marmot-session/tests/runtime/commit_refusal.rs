// mdk#2333: a group relay's refusal of a confirmed commit.
//
// A relay that refuses a confirmed commit for good will never carry it, so
// members who read only that relay may not have it. The refusal is kept in a
// per-commit record that outlives the commit's fanout, and is reported until
// the user acknowledges it. A size answer ends a target a relay may already
// hold once the commit is confirmed: a confirmed commit cannot roll back, and
// these bytes can never be published there. Any other answer after earlier
// ambiguity leaves the relay owed.

type FloorRuntime = AccountDeviceRuntime<RecordingAdapter, StaticTransportRouting, RecordingKeyPackages>;
/// One scripted relay answer for an endpoint.
type RelayAnswer = fn(&TransportEndpoint) -> TransportEndpointFailure;

const HOUR: u64 = 60 * 60;

/// A relay's answer as the adapter reports it, sent to the relay.
fn relay_answer(
    endpoint: &TransportEndpoint,
    kind: TransportEndpointFailureKind,
    category: Option<TransportEndpointRejectionCategory>,
) -> TransportEndpointFailure {
    TransportEndpointFailure {
        endpoint: endpoint.clone(),
        reason: "scripted".into(),
        kind,
        rejection_category: category,
        size_class: None,
        pre_send: false,
    }
}

/// strfry's size answer: definitive, with the event's size class.
fn strfry_too_large(endpoint: &TransportEndpoint) -> TransportEndpointFailure {
    TransportEndpointFailure {
        size_class: Some(cgka_traits::EventSizeClass::of_bytes(70_000)),
        ..relay_answer(
            endpoint,
            TransportEndpointFailureKind::TerminalRejected,
            Some(TransportEndpointRejectionCategory::TooLarge),
        )
    }
}

/// The adapter's rewrite of a size answer after an earlier ambiguous attempt
/// in the same call: possibly exposed, category kept, size class withheld.
fn too_large_after_ambiguity(endpoint: &TransportEndpoint) -> TransportEndpointFailure {
    relay_answer(
        endpoint,
        TransportEndpointFailureKind::PossiblyExposed,
        Some(TransportEndpointRejectionCategory::TooLarge),
    )
}

fn blocked(endpoint: &TransportEndpoint) -> TransportEndpointFailure {
    relay_answer(
        endpoint,
        TransportEndpointFailureKind::TerminalRejected,
        Some(TransportEndpointRejectionCategory::Blocked),
    )
}

fn timed_out(endpoint: &TransportEndpoint) -> TransportEndpointFailure {
    relay_answer(endpoint, TransportEndpointFailureKind::PossiblyExposed, None)
}

fn rate_limited(endpoint: &TransportEndpoint) -> TransportEndpointFailure {
    relay_answer(
        endpoint,
        TransportEndpointFailureKind::RetryableUnavailable,
        Some(TransportEndpointRejectionCategory::RateLimited),
    )
}

/// A connection never made: nothing was sent.
fn unreachable(endpoint: &TransportEndpoint) -> TransportEndpointFailure {
    TransportEndpointFailure {
        pre_send: true,
        ..relay_answer(endpoint, TransportEndpointFailureKind::RetryableUnavailable, None)
    }
}

/// The host-safety rule's refusal: the endpoint is never contacted.
fn refused_by_safety_rule(endpoint: &TransportEndpoint) -> TransportEndpointFailure {
    relay_answer(endpoint, TransportEndpointFailureKind::NotExposed, None)
}

fn refused(endpoint: &TransportEndpoint, cause: CommitRefusalCause) -> RefusedTarget {
    RefusedTarget {
        endpoint: endpoint.clone(),
        cause,
    }
}

fn too_large(size_class: Option<cgka_traits::EventSizeClass>) -> CommitRefusalCause {
    CommitRefusalCause::TooLarge { size_class }
}

fn publishes_to(adapter: &RecordingAdapter, endpoint: &TransportEndpoint) -> usize {
    adapter
        .publishes()
        .iter()
        .filter(|publish| publish.target.endpoints() == std::slice::from_ref(endpoint))
        .count()
}

/// The group's one stored fanout and `endpoint`'s index in it.
fn stored_fanout(runtime: &FloorRuntime, endpoint: &TransportEndpoint) -> (OutboundFanout, usize) {
    let mut stored = runtime.session().outbound_fanouts().unwrap();
    assert_eq!(stored.len(), 1, "{stored:?}");
    let fanout = stored.remove(0);
    let index = fanout
        .request()
        .target
        .endpoints()
        .iter()
        .position(|target| target == endpoint)
        .unwrap();
    (fanout, index)
}

fn stored_status(runtime: &FloorRuntime, endpoint: &TransportEndpoint) -> Option<FanoutTargetStatus> {
    let (fanout, index) = stored_fanout(runtime, endpoint);
    fanout.target_status(index)
}

fn undelivered(runtime: &FloorRuntime, fixture: &FloorFixture) -> Option<marmot_session::UndeliveredCommit> {
    runtime.undelivered_commit(&fixture.group_id).unwrap()
}

/// The refused relays the group's delivery answer names.
fn reported_refusals(runtime: &FloorRuntime, fixture: &FloorFixture) -> Vec<RefusedTarget> {
    undelivered(runtime, fixture).map_or_else(Vec::new, |commit| commit.refused_endpoints)
}

/// Save `failure` as the result of a new attempt at `endpoint` on the group's
/// one fanout, as the pass that received it does, and stop there: the process
/// dies before that pass merges any refusal.
fn save_attempt_result_and_crash(
    runtime: FloorRuntime,
    fixture: &FloorFixture,
    endpoint: &TransportEndpoint,
    failure: TransportEndpointFailure,
) {
    let (mut fanout, index) = stored_fanout(&runtime, endpoint);
    let now_ms = fixture.wall.now().0 * 1_000;
    assert!(fanout.mark_attempt_started_at(index, now_ms).unwrap());
    runtime.session().put_outbound_fanout(&fanout).unwrap();
    assert!(fanout.record_target_failure(index, failure).unwrap());
    runtime.session().put_outbound_fanout(&fanout).unwrap();
}

/// Store relay B's size answer after an ambiguous attempt as a release before
/// the successor edge left it on a confirmed commit: possibly exposed and
/// still retried, so no refusal is merged. Then the process dies.
fn store_legacy_exposed_size_answer_and_crash(
    runtime: FloorRuntime,
    fixture: &FloorFixture,
    endpoint: &TransportEndpoint,
) {
    let (mut fanout, index) = stored_fanout(&runtime, endpoint);
    assert_eq!(fanout.mls_state(), FanoutMlsState::Confirmed);
    let now_ms = fixture.wall.now().0 * 1_000;
    assert!(fanout.mark_attempt_started_at(index, now_ms).unwrap());
    runtime.session().put_outbound_fanout(&fanout).unwrap();
    let mut legacy = serde_json::to_value(&fanout).unwrap();
    legacy["target_statuses"][index] =
        serde_json::to_value(FanoutTargetStatus::PossiblyExposed).unwrap();
    legacy["target_failures"][index] =
        serde_json::to_value(too_large_after_ambiguity(endpoint)).unwrap();
    let legacy: OutboundFanout = serde_json::from_value(legacy).unwrap();
    runtime.session().put_outbound_fanout(&legacy).unwrap();
}

/// P1–P4: relay A accepts and relay B refuses the commit, by strfry's size
/// answer, by its known limit before anything is sent, by `blocked:`, or by
/// the host-safety rule. The first three are reported with their cause after
/// the fanout is gone and across a restart, until acknowledged; the
/// acknowledgement deletes the record for good. A host-safety refusal is
/// standing configuration, not a refusal of this commit: never reported.
#[tokio::test]
async fn a_relay_refusal_of_a_confirmed_commit_is_reported_until_acknowledged() {
    let class = Some(cgka_traits::EventSizeClass::of_bytes(70_000));
    let cases: [(&'static str, Option<CommitRefusalCause>); 4] = [
        ("refusal-strfry", Some(too_large(class))),
        ("refusal-known-limit", Some(too_large(class))),
        ("refusal-blocked", Some(CommitRefusalCause::Rejected)),
        ("refusal-host-safety", None),
    ];
    for (name, cause) in cases {
        let accepting = TransportEndpoint(format!("wss://{name}-a.example"));
        let refusing = TransportEndpoint(format!("wss://{name}-b.example"));
        let (fixture, alice) = FloorFixture::new(name, &[&accepting, &refusing]).await;
        let adapter = RecordingAdapter::default();
        match name {
            "refusal-strfry" => adapter.script_failures(refusing.clone(), vec![strfry_too_large(&refusing)]),
            "refusal-known-limit" => adapter.refuse_commits_as_too_large(vec![refusing.clone()]),
            "refusal-blocked" => adapter.script_failures(refusing.clone(), vec![blocked(&refusing)]),
            _ => adapter.script_failures(refusing.clone(), vec![refused_by_safety_rule(&refusing)]),
        }
        let mut runtime = fixture.runtime(alice, &adapter);

        let effects = runtime.send(fixture.rename()).await.unwrap();

        assert!(
            matches!(effects.pending.as_slice(), [PendingResolution::Confirmed { .. }]),
            "{name}: {:?}",
            effects.pending
        );
        assert!(runtime.session().outbound_fanouts().unwrap().is_empty(), "{name}");
        if name == "refusal-known-limit" {
            assert_eq!(publishes_to(&adapter, &refusing), 0, "{name}: refused unsent");
        }
        let Some(cause) = cause else {
            assert_eq!(undelivered(&runtime, &fixture), None, "{name}");
            assert!(runtime.session().commit_refusals().unwrap().is_empty(), "{name}");
            continue;
        };
        let expected = vec![refused(&refusing, cause)];
        let report = undelivered(&runtime, &fixture).expect("the refusal is reported");
        assert_eq!(report.refused_endpoints, expected, "{name}");
        assert!(report.owed_endpoints.is_empty(), "{name}");
        assert_eq!(report.endpoint_count, 2, "{name}");

        drop(runtime);
        let runtime = fixture.runtime(fixture.reopen(), &adapter);
        assert_eq!(reported_refusals(&runtime, &fixture), expected, "{name}: after a restart");

        runtime.acknowledge_commit_refusals(&fixture.group_id).unwrap();
        assert_eq!(undelivered(&runtime, &fixture), None, "{name}");
        assert!(runtime.session().commit_refusals().unwrap().is_empty(), "{name}");
        drop(runtime);
        let runtime = fixture.runtime(fixture.reopen(), &adapter);
        assert_eq!(undelivered(&runtime, &fixture), None, "{name}: after a restart");
    }
}

/// P5, one call: the adapter's rewritten size answer after earlier ambiguity
/// ends the relay refused on a confirmed commit, size class withheld. On a
/// pending commit the relay stays possibly exposed and is retried. Any other
/// answer after ambiguity leaves a confirmed commit's relay owed.
#[tokio::test]
async fn a_size_answer_after_ambiguity_refuses_only_a_confirmed_commit() {
    let accepting = TransportEndpoint("wss://ambiguity-a.example".into());
    let refusing = TransportEndpoint("wss://ambiguity-b.example".into());
    let (fixture, alice) = FloorFixture::new("ambiguity-confirmed", &[&accepting, &refusing]).await;
    let adapter = RecordingAdapter::default();
    adapter.script_failures(refusing.clone(), vec![too_large_after_ambiguity(&refusing)]);
    let mut runtime = fixture.runtime(alice, &adapter);
    runtime.send(fixture.rename()).await.unwrap();
    assert!(runtime.session().outbound_fanouts().unwrap().is_empty(), "no retry is left");
    assert_eq!(reported_refusals(&runtime, &fixture), vec![refused(&refusing, too_large(None))]);

    // A pending commit: the only relay may hold it, so it is retried.
    let only = TransportEndpoint("wss://ambiguity-only.example".into());
    let (fixture, alice) = FloorFixture::new("ambiguity-pending", &[&only]).await;
    let adapter = RecordingAdapter::default();
    adapter.script_failures(only.clone(), vec![too_large_after_ambiguity(&only)]);
    let mut runtime = fixture.runtime(alice, &adapter);
    let effects = runtime.send(fixture.rename()).await.unwrap();
    assert!(effects.pending.is_empty(), "{:?}", effects.pending);
    assert_eq!(stored_status(&runtime, &only), Some(FanoutTargetStatus::PossiblyExposed));
    fixture.wall.set(100_000 + HOUR);
    let effects = runtime.resume_outbound_fanouts().await.unwrap();
    assert_eq!(publishes_to(&adapter, &only), 2, "the relay was retried");
    assert!(matches!(effects.pending.as_slice(), [PendingResolution::Confirmed { .. }]));

    // `blocked:` after a timeout: a policy answer, so the relay stays owed.
    let (fixture, alice) = FloorFixture::new("ambiguity-blocked", &[&accepting, &refusing]).await;
    let adapter = RecordingAdapter::default();
    adapter.script_failures(refusing.clone(), vec![timed_out(&refusing), blocked(&refusing)]);
    let mut runtime = fixture.runtime(alice, &adapter);
    runtime.send(fixture.rename()).await.unwrap();
    fixture.wall.set(100_000 + HOUR);
    runtime.resume_outbound_fanouts().await.unwrap();
    assert_eq!(publishes_to(&adapter, &refusing), 2);
    assert_eq!(stored_status(&runtime, &refusing), Some(FanoutTargetStatus::PossiblyExposed));
    let report = undelivered(&runtime, &fixture).unwrap();
    assert_eq!(report.owed_endpoints, vec![refusing.clone()]);
    assert!(report.refused_endpoints.is_empty());
}

/// P5, two calls, the production path: the relay's first call only times out,
/// or answers `rate-limited:`, and its next gets a clean size answer with no
/// ambiguity in that call. The stored exposure makes the answer post-ambiguity:
/// on a confirmed commit the relay ends refused at once, size class withheld;
/// on a pending commit it stays possibly exposed and is retried.
#[tokio::test]
async fn a_clean_size_answer_after_an_earlier_call_refuses_only_a_confirmed_commit() {
    let first_answers: [(&'static str, RelayAnswer); 2] =
        [("two-calls-timeout", timed_out), ("two-calls-rate-limited", rate_limited)];
    for (name, first) in first_answers {
        let accepting = TransportEndpoint(format!("wss://{name}-a.example"));
        let refusing = TransportEndpoint(format!("wss://{name}-b.example"));
        let (fixture, alice) = FloorFixture::new(name, &[&accepting, &refusing]).await;
        let adapter = RecordingAdapter::default();
        adapter.script_failures(refusing.clone(), vec![first(&refusing), strfry_too_large(&refusing)]);
        let mut runtime = fixture.runtime(alice, &adapter);
        let effects = runtime.send(fixture.rename()).await.unwrap();
        assert!(matches!(effects.pending.as_slice(), [PendingResolution::Confirmed { .. }]), "{name}");
        assert_eq!(
            undelivered(&runtime, &fixture).unwrap().owed_endpoints,
            vec![refusing.clone()],
            "{name}"
        );

        fixture.wall.set(100_000 + HOUR);
        runtime.resume_outbound_fanouts().await.unwrap();
        assert_eq!(publishes_to(&adapter, &refusing), 2, "{name}");
        assert!(
            runtime.session().outbound_fanouts().unwrap().is_empty(),
            "{name}: the size answer ended the relay's retries"
        );
        assert_eq!(
            reported_refusals(&runtime, &fixture),
            vec![refused(&refusing, too_large(None))],
            "{name}: the size class is withheld after earlier exposure"
        );
    }

    // A pending commit: the clean size answer leaves the relay owed.
    let only = TransportEndpoint("wss://two-calls-pending.example".into());
    let (fixture, alice) = FloorFixture::new("two-calls-pending", &[&only]).await;
    let adapter = RecordingAdapter::default();
    adapter.script_failures(only.clone(), vec![timed_out(&only), strfry_too_large(&only)]);
    let mut runtime = fixture.runtime(alice, &adapter);
    runtime.send(fixture.rename()).await.unwrap();
    fixture.wall.set(100_000 + HOUR);
    let effects = runtime.resume_outbound_fanouts().await.unwrap();
    assert!(effects.pending.is_empty(), "{:?}", effects.pending);
    assert_eq!(stored_status(&runtime, &only), Some(FanoutTargetStatus::PossiblyExposed));
    fixture.wall.set(100_000 + 2 * HOUR);
    let effects = runtime.resume_outbound_fanouts().await.unwrap();
    assert_eq!(publishes_to(&adapter, &only), 3, "the relay was retried");
    assert!(matches!(effects.pending.as_slice(), [PendingResolution::Confirmed { .. }]));
}

/// P5, the size check before resending (mdk#2332): the relay's first call
/// timed out, and its limit now refuses the commit before anything is sent.
/// The refusal replaces the stored failure. On a confirmed commit the relay
/// ends refused, may not have it, size class withheld, and nothing is sent.
/// A known limit and the commit floor reach the session as the same refusal;
/// the pending case is `a_size_refusal_after_an_interrupted_send_keeps_the_commit_pending`.
#[tokio::test]
async fn a_size_check_after_an_earlier_timeout_refuses_a_confirmed_commit_unsent() {
    let accepting = TransportEndpoint("wss://exposed-check-a.example".into());
    let refusing = TransportEndpoint("wss://exposed-check-b.example".into());
    let (fixture, alice) = FloorFixture::new("exposed-check", &[&accepting, &refusing]).await;
    let adapter = RecordingAdapter::default();
    adapter.script_failures(refusing.clone(), vec![timed_out(&refusing)]);
    let mut runtime = fixture.runtime(alice, &adapter);
    runtime.send(fixture.rename()).await.unwrap();
    assert_eq!(stored_status(&runtime, &refusing), Some(FanoutTargetStatus::PossiblyExposed));

    adapter.refuse_commits_as_too_large(vec![refusing.clone()]);
    fixture.wall.set(100_000 + HOUR);
    runtime.resume_outbound_fanouts().await.unwrap();

    assert_eq!(publishes_to(&adapter, &refusing), 1, "the refusal sent nothing");
    assert!(runtime.session().outbound_fanouts().unwrap().is_empty());
    assert_eq!(reported_refusals(&runtime, &fixture), vec![refused(&refusing, too_large(None))]);
}

/// P5, confirmation reclassifies, and the reclassification is stored: relay
/// B's size answer after ambiguity is saved while the commit is pending, and
/// relay C times out. Relay A then accepts and confirms the commit. B ends
/// refused with no new attempt, C stays owed and is retried, and no resume
/// fails, with or without a restart between the two passes.
#[tokio::test]
async fn confirmation_ends_a_size_refused_relay_and_keeps_the_others_owed() {
    for restart in [false, true] {
        let name = if restart { "reclassify-restart" } else { "reclassify" };
        let confirming = TransportEndpoint(format!("wss://{name}-a.example"));
        let refusing = TransportEndpoint(format!("wss://{name}-b.example"));
        let owed = TransportEndpoint(format!("wss://{name}-c.example"));
        let (fixture, alice) = FloorFixture::new(name, &[&confirming, &refusing, &owed]).await;
        let adapter = RecordingAdapter::default();
        // A's connection fails before sending, so it is due again in seconds;
        // B and C may hold the commit, so they back off for longer.
        adapter.script_failures(confirming.clone(), vec![unreachable(&confirming)]);
        adapter.script_failures(refusing.clone(), vec![too_large_after_ambiguity(&refusing)]);
        adapter.script_failures(owed.clone(), vec![timed_out(&owed)]);
        let mut runtime = fixture.runtime(alice, &adapter);
        let effects = runtime.send(fixture.rename()).await.unwrap();
        assert!(effects.pending.is_empty(), "{name}: {:?}", effects.pending);
        assert_eq!(
            stored_status(&runtime, &refusing),
            Some(FanoutTargetStatus::PossiblyExposed),
            "{name}: a pending commit keeps the relay owed"
        );
        if restart {
            drop(runtime);
            runtime = fixture.runtime(fixture.reopen(), &adapter);
        }

        fixture.wall.set(100_000 + 10);
        let effects = runtime.resume_outbound_fanouts().await.unwrap();
        assert!(
            matches!(effects.pending.as_slice(), [PendingResolution::Confirmed { .. }]),
            "{name}: {:?}",
            effects.pending
        );
        assert_eq!(publishes_to(&adapter, &refusing), 1, "{name}: no new attempt at B");
        assert_eq!(publishes_to(&adapter, &owed), 1, "{name}: C is not due yet");
        assert_eq!(stored_status(&runtime, &refusing), Some(FanoutTargetStatus::Failed), "{name}");
        assert_eq!(stored_status(&runtime, &owed), Some(FanoutTargetStatus::PossiblyExposed), "{name}");
        let report = undelivered(&runtime, &fixture).unwrap();
        assert_eq!(report.refused_endpoints, vec![refused(&refusing, too_large(None))], "{name}");
        assert_eq!(report.owed_endpoints, vec![owed.clone()], "{name}");

        drop(runtime);
        let mut runtime = fixture.runtime(fixture.reopen(), &adapter);
        fixture.wall.set(100_000 + HOUR);
        let effects = runtime.resume_outbound_fanouts().await.unwrap();
        assert!(effects.failures.is_empty(), "{name}: {:?}", effects.failures);
        assert_eq!(publishes_to(&adapter, &owed), 2, "{name}: C is retried");
        assert_eq!(publishes_to(&adapter, &refusing), 1, "{name}: B is not");
        assert!(runtime.session().outbound_fanouts().unwrap().is_empty(), "{name}");
        assert_eq!(
            reported_refusals(&runtime, &fixture),
            vec![refused(&refusing, too_large(None))],
            "{name}"
        );
    }
}

/// Proof 6: convergence withdraws the refused commit from the selected
/// branch. The refusal no longer warns, and the next maintenance pass drops
/// its record.
#[tokio::test]
async fn a_withdrawn_commit_stops_warning_and_its_refusal_is_dropped() {
    use cgka_traits::MessageStorage;

    let accepting = TransportEndpoint("wss://withdrawn-a.example".into());
    let refusing = TransportEndpoint("wss://withdrawn-b.example".into());
    let (fixture, alice) = FloorFixture::new("withdrawn-refusal", &[&accepting, &refusing]).await;
    let adapter = RecordingAdapter::default();
    adapter.script_failures(refusing.clone(), vec![blocked(&refusing)]);
    let mut runtime = fixture.runtime(alice, &adapter);
    runtime.send(fixture.rename()).await.unwrap();
    let commit_id = undelivered(&runtime, &fixture).expect("the refusal is reported").message_id;
    drop(runtime);

    SqliteAccountStorage::open_encrypted(&fixture.alice_path, &SqlCipherKey::new(FLOOR_KEY).unwrap())
        .unwrap()
        .update_message_state(&commit_id, cgka_traits::MessageState::ConvergenceDeferred)
        .unwrap();
    let mut runtime = fixture.runtime(fixture.reopen(), &adapter);
    assert_eq!(undelivered(&runtime, &fixture), None);
    runtime.run_due_maintenance().await.unwrap();
    assert!(runtime.session().commit_refusals().unwrap().is_empty());
}

/// Proof 7, both crash windows. A pass saved relay B's refusal and died
/// before merging it: the next resume finds the fanout complete, merges the
/// refusal, then deletes the fanout, and reports no failure for a commit that
/// confirmed. A pass merged B's refusal while relay C was still owed and died:
/// the resume that completes the fanout leaves one record.
#[tokio::test]
async fn a_refusal_a_crash_left_unmerged_is_recorded_by_the_next_resume() {
    let accepting = TransportEndpoint("wss://crash-merge-a.example".into());
    let refusing = TransportEndpoint("wss://crash-merge-b.example".into());
    let (fixture, alice) = FloorFixture::new("crash-before-merge", &[&accepting, &refusing]).await;
    let adapter = RecordingAdapter::default();
    adapter.script_failures(refusing.clone(), vec![unreachable(&refusing)]);
    let mut runtime = fixture.runtime(alice, &adapter);
    runtime.send(fixture.rename()).await.unwrap();
    save_attempt_result_and_crash(runtime, &fixture, &refusing, blocked(&refusing));

    let mut runtime = fixture.runtime(fixture.reopen(), &adapter);
    let effects = runtime.resume_outbound_fanouts().await.unwrap();
    assert!(effects.failures.is_empty(), "{:?}", effects.failures);
    assert!(runtime.session().outbound_fanouts().unwrap().is_empty());
    let expected = vec![refused(&refusing, CommitRefusalCause::Rejected)];
    assert_eq!(reported_refusals(&runtime, &fixture), expected);

    // Merged, not yet deleted: C still owed.
    let owed = TransportEndpoint("wss://crash-merge-c.example".into());
    let (fixture, alice) = FloorFixture::new("crash-after-merge", &[&accepting, &refusing, &owed]).await;
    let adapter = RecordingAdapter::default();
    adapter.script_failures(refusing.clone(), vec![blocked(&refusing)]);
    adapter.script_failures(owed.clone(), vec![timed_out(&owed)]);
    let mut runtime = fixture.runtime(alice, &adapter);
    runtime.send(fixture.rename()).await.unwrap();
    assert_eq!(runtime.session().commit_refusals().unwrap().len(), 1);
    drop(runtime);

    let mut runtime = fixture.runtime(fixture.reopen(), &adapter);
    fixture.wall.set(100_000 + HOUR);
    runtime.resume_outbound_fanouts().await.unwrap();
    assert!(runtime.session().outbound_fanouts().unwrap().is_empty());
    let records = runtime.session().commit_refusals().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].refused, expected);
    assert_eq!(records[0].relay_count, 3);
    assert_eq!(reported_refusals(&runtime, &fixture), expected);
}

/// Proof 8: a refusal that arrives after a newer commit confirmed is still
/// reported. Once acknowledged it does not warn again: not when another relay
/// refuses the same commit, nor once its fanout completes and the device
/// restarts. The acknowledged record goes with the fanout.
#[tokio::test]
async fn a_late_refusal_warns_and_an_acknowledged_one_never_returns() {
    let accepting = TransportEndpoint("wss://late-refusal-a.example".into());
    let first = TransportEndpoint("wss://late-refusal-b.example".into());
    let second = TransportEndpoint("wss://late-refusal-c.example".into());
    let (fixture, alice) = FloorFixture::new("late-refusal", &[&accepting, &first, &second]).await;
    let adapter = RecordingAdapter::default();
    adapter.script_failures(first.clone(), vec![timed_out(&first)]);
    adapter.script_failures(second.clone(), vec![timed_out(&second)]);
    let mut runtime = fixture.runtime(alice, &adapter);
    runtime.send(fixture.rename()).await.unwrap();
    let refused_commit = undelivered(&runtime, &fixture).unwrap().message_id;
    runtime
        .send(SendIntent::UpdateGroupData {
            group_id: fixture.group_id.clone(),
            name: Some("renamed again".into()),
            description: None,
        })
        .await
        .unwrap();
    assert_eq!(runtime.session().outbound_fanouts().unwrap().len(), 1, "the newer commit is delivered");

    adapter.script_failures(first.clone(), vec![strfry_too_large(&first)]);
    adapter.script_failures(second.clone(), vec![timed_out(&second), strfry_too_large(&second)]);
    fixture.wall.set(100_000 + HOUR);
    runtime.resume_outbound_fanouts().await.unwrap();
    let report = undelivered(&runtime, &fixture).unwrap();
    assert_eq!(report.message_id, refused_commit);
    assert_eq!(report.refused_endpoints, vec![refused(&first, too_large(None))]);
    assert_eq!(report.owed_endpoints, vec![second.clone()]);

    runtime.acknowledge_commit_refusals(&fixture.group_id).unwrap();
    let report = undelivered(&runtime, &fixture).unwrap();
    assert!(report.refused_endpoints.is_empty());
    assert_eq!(report.owed_endpoints, vec![second.clone()]);

    fixture.wall.set(100_000 + 2 * HOUR);
    runtime.resume_outbound_fanouts().await.unwrap();
    assert!(runtime.session().outbound_fanouts().unwrap().is_empty());
    assert_eq!(undelivered(&runtime, &fixture), None, "C's refusal does not warn again");
    assert!(runtime.session().commit_refusals().unwrap().is_empty());
    drop(runtime);
    let runtime = fixture.runtime(fixture.reopen(), &adapter);
    assert_eq!(undelivered(&runtime, &fixture), None);
}

/// A size answer after an ambiguous attempt that a release before the
/// successor edge left possibly exposed on a confirmed commit is a refusal
/// before any drive ends it: reported at once. Acknowledged first, it does not
/// warn again once the fanout retires. Resumed first, past the relay's
/// backoff, the drive ends it before choosing retries and it still warns until
/// acknowledged. Either way nothing more is sent to the relay.
#[tokio::test]
async fn a_legacy_exposed_size_answer_is_a_refusal_before_any_drive() {
    for acknowledge_first in [true, false] {
        let name = if acknowledge_first { "legacy-size-ack" } else { "legacy-size-resume" };
        let accepting = TransportEndpoint(format!("wss://{name}-a.example"));
        let refusing = TransportEndpoint(format!("wss://{name}-b.example"));
        let (fixture, alice) = FloorFixture::new(name, &[&accepting, &refusing]).await;
        let adapter = RecordingAdapter::default();
        adapter.script_failures(refusing.clone(), vec![unreachable(&refusing)]);
        let mut runtime = fixture.runtime(alice, &adapter);
        runtime.send(fixture.rename()).await.unwrap();
        store_legacy_exposed_size_answer_and_crash(runtime, &fixture, &refusing);

        let mut runtime = fixture.runtime(fixture.reopen(), &adapter);
        let report = undelivered(&runtime, &fixture).unwrap();
        assert!(report.owed_endpoints.is_empty(), "{name}");
        assert_eq!(report.refused_endpoints, vec![refused(&refusing, too_large(None))], "{name}");
        if acknowledge_first {
            runtime.acknowledge_commit_refusals(&fixture.group_id).unwrap();
            assert_eq!(undelivered(&runtime, &fixture), None, "{name}");
        }

        let sent = publishes_to(&adapter, &refusing);
        fixture.wall.set(fixture.wall.now().0 + 2 * HOUR);
        runtime.resume_outbound_fanouts().await.unwrap();
        assert!(runtime.session().outbound_fanouts().unwrap().is_empty(), "{name}");
        assert_eq!(publishes_to(&adapter, &refusing), sent, "{name}: not retried");
        if !acknowledge_first {
            assert_eq!(
                reported_refusals(&runtime, &fixture),
                vec![refused(&refusing, too_large(None))],
                "{name}: still warns once the fanout is gone"
            );
            runtime.acknowledge_commit_refusals(&fixture.group_id).unwrap();
        }
        assert_eq!(undelivered(&runtime, &fixture), None, "{name}");
        assert!(runtime.session().commit_refusals().unwrap().is_empty(), "{name}");
    }
}

/// Proof 10: no later commit ends a refusal. After the refusal, the
/// self-update the hold delays goes through after an hour and another own
/// commit confirms; the refusal is still reported. The hold waits on each
/// gating commit's own time: an hour-old refusal does not let a self-update
/// build at once on a commit that is newly owed.
#[tokio::test]
async fn a_refusal_outlives_later_commits_and_the_hold_waits_on_the_newest() {
    let accepting = TransportEndpoint("wss://outlives-a.example".into());
    let refusing = TransportEndpoint("wss://outlives-b.example".into());
    let (fixture, alice) = FloorFixture::new("refusal-outlives", &[&accepting, &refusing]).await;
    let adapter = RecordingAdapter::default();
    adapter.script_failures(refusing.clone(), vec![blocked(&refusing)]);
    let mut runtime = fixture
        .runtime(alice, &adapter)
        .with_maintenance_timing(MaintenanceTiming::immediate());
    runtime.send(fixture.rename()).await.unwrap();
    let refused_commit = undelivered(&runtime, &fixture).unwrap().message_id;
    let phase = |runtime: &FloorRuntime, id| runtime.session().maintenance_obligation(id).unwrap().unwrap();

    let held = runtime.schedule_manual_self_update(&fixture.group_id).unwrap();
    runtime.run_due_maintenance().await.unwrap();
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(phase(&runtime, &held).last_failure_code.as_deref(), Some("commit_delivery_hold"));
    fixture.wall.set(100_000 + HOUR);
    runtime.run_due_maintenance().await.unwrap();
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(phase(&runtime, &held).phase, cgka_traits::MaintenancePhase::Complete);
    runtime
        .send(SendIntent::UpdateGroupData {
            group_id: fixture.group_id.clone(),
            name: Some("renamed again".into()),
            description: None,
        })
        .await
        .unwrap();
    let report = undelivered(&runtime, &fixture).unwrap();
    assert_eq!(report.message_id, refused_commit);
    assert_eq!(report.refused_endpoints, vec![refused(&refusing, CommitRefusalCause::Rejected)]);

    // A newly owed commit holds the next self-update, though the refusal the
    // report names is an hour old.
    adapter.script_failures(refusing.clone(), vec![timed_out(&refusing)]);
    runtime
        .send(SendIntent::UpdateGroupData {
            group_id: fixture.group_id.clone(),
            name: Some("renamed once more".into()),
            description: None,
        })
        .await
        .unwrap();
    let next = runtime.schedule_manual_self_update(&fixture.group_id).unwrap();
    runtime.run_due_maintenance().await.unwrap();
    runtime.run_due_maintenance().await.unwrap();
    let next = phase(&runtime, &next);
    assert_eq!(next.phase, cgka_traits::MaintenancePhase::Retry);
    assert_eq!(next.last_failure_code.as_deref(), Some("commit_delivery_hold"));
}

/// Proof 11: a disband request deletes the group's fanouts, so it records
/// their refusals first. A pass saved relay B's refusal and died before
/// merging it, or a release before the successor edge left B's size answer
/// after an ambiguous attempt possibly exposed; the request comes next. The
/// refusal is still reported while the request waits, and would be if it
/// failed. Once the disband settles, the group's refusals no longer warn.
#[tokio::test]
async fn a_disband_request_records_refusals_first_and_a_settled_disband_ends_them() {
    type CrashAfter = fn(FloorRuntime, &FloorFixture, &TransportEndpoint);
    let cases: [(&'static str, CrashAfter, CommitRefusalCause); 2] = [
        ("disband-legacy", store_legacy_exposed_size_answer_and_crash, too_large(None)),
        (
            "disband-refusal",
            |runtime, fixture, endpoint| {
                save_attempt_result_and_crash(runtime, fixture, endpoint, blocked(endpoint))
            },
            CommitRefusalCause::Rejected,
        ),
    ];
    let mut last = None;
    for (name, crash, cause) in cases {
        let accepting = TransportEndpoint(format!("wss://{name}-a.example"));
        let refusing = TransportEndpoint(format!("wss://{name}-b.example"));
        let (fixture, alice) = FloorFixture::new(name, &[&accepting, &refusing]).await;
        let adapter = RecordingAdapter::default();
        adapter.script_failures(refusing.clone(), vec![unreachable(&refusing)]);
        let mut runtime = fixture.runtime(alice, &adapter);
        runtime.send(fixture.rename()).await.unwrap();
        crash(runtime, &fixture, &refusing);

        let mut runtime = fixture.runtime(fixture.reopen(), &adapter);
        runtime
            .send(SendIntent::Disband {
                group_id: fixture.group_id.clone(),
            })
            .await
            .unwrap();
        assert!(runtime.session().disbanding_in_progress(&fixture.group_id).unwrap());
        assert!(runtime.session().outbound_fanouts().unwrap().is_empty());
        assert_eq!(
            reported_refusals(&runtime, &fixture),
            vec![refused(&refusing, cause)],
            "{name}"
        );
        drop(runtime);
        last = Some((fixture, adapter));
    }
    let (fixture, adapter) = last.unwrap();

    // The settle's stored outcome, as the engine's settle transaction writes
    // it: the terminal guard, the group record marked disbanded, the request
    // cleared. The settle itself is the engine's (its own tests drive it).
    {
        use cgka_traits::storage::{
            CommittedMembers, DisbandRequestStorage, DisbandTombstoneStorage, GroupStorage,
        };
        let storage = SqliteAccountStorage::open_encrypted(
            &fixture.alice_path,
            &SqlCipherKey::new(FLOOR_KEY).unwrap(),
        )
        .unwrap();
        let mut group = storage.get_group(&fixture.group_id).unwrap();
        let tombstone = cgka_traits::DisbandTombstone {
            epoch: group.epoch,
            actor: group.members[0].id.clone(),
            origin_commit_id: None,
            commit_digest: [0; 32],
            local_was_committer_leaf: true,
            former_members: group.members.clone(),
            announced: false,
        };
        storage.put_disband_tombstone(&fixture.group_id, &tombstone).unwrap();
        group.disbanded = Some(tombstone.clone());
        storage
            .put_group_with_roster(&group, &CommittedMembers::of_members(&tombstone.former_members))
            .unwrap();
        storage.clear_disband_request(&fixture.group_id).unwrap();
    }
    let runtime = fixture.runtime(fixture.reopen(), &adapter);
    assert!(runtime.session().group_record(&fixture.group_id).unwrap().disbanded.is_some());
    assert_eq!(undelivered(&runtime, &fixture), None);
    assert!(
        runtime.undelivered_commits_in(&fixture.group_id, None).unwrap().0.is_empty(),
        "nothing gates"
    );
    assert_eq!(runtime.session().commit_refusals().unwrap().len(), 1, "inert until forgotten");
}
