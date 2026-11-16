// mdk#2332: a host's group change that a later pass rolls back is recorded.
//
// The call that stages a change gets its rollback as the call's own result.
// A later pass (a wake, a retry, a resume after a restart) has no caller to
// tell, so the rollback writes a not-delivered record in its own transaction
// and announces `GroupChangeNotDelivered`. The record outlives the events,
// later commits and restarts until the host acknowledges it. An automatic
// commit has no caller waiting and records nothing.

/// The host's (or the runtime's own) rename, staged with one relay refusing
/// it and one never reached, then given up past the read-back bound once the
/// refusing relay's read shows the device online.
async fn given_up_change(
    name: &'static str,
    intent: impl FnOnce(&FloorFixture) -> SendIntent,
    host: bool,
) -> (FloorFixture, RecordingAdapter, FloorRuntime, AccountDeviceEffects, MessageId) {
    let refusing = TransportEndpoint(format!("wss://{name}-refusing.example"));
    let dead = TransportEndpoint(format!("wss://{name}-dead.example"));
    let (fixture, alice) = FloorFixture::new(name, &[&refusing, &dead]).await;
    let adapter = RecordingAdapter::default();
    adapter.script_failures(refusing.clone(), vec![blocked(&refusing)]);
    adapter.fail_endpoints_as(
        vec![dead.clone()],
        TransportEndpointFailureKind::RetryableUnavailable,
    );
    adapter.answer_read_backs(refusing.clone(), TransportReadBack::NotFound);
    let mut runtime = fixture.runtime(alice, &adapter);
    let start = fixture.wall.now().0;
    let intent = intent(&fixture);
    let sent = if host {
        runtime
            .send_host_change_with_audit_context(intent, Default::default())
            .await
    } else {
        runtime.send(intent).await
    }
    .unwrap();
    assert!(sent.pending.is_empty(), "{:?}", sent.pending);
    let commit = adapter.publishes().last().unwrap().message.id.clone();
    assert!(
        runtime
            .group_changes_not_delivered(&fixture.group_id)
            .unwrap()
            .is_empty(),
        "a commit still pending is not recorded"
    );

    fixture.wall.set(start + READ_BACK_BOUND_SECS);
    let effects = runtime.resume_outbound_fanouts().await.unwrap();
    assert!(
        matches!(effects.pending.as_slice(), [PendingResolution::RolledBack { .. }]),
        "{:?}",
        effects.pending
    );
    (fixture, adapter, runtime, effects, commit)
}

fn announced_not_delivered(effects: &AccountDeviceEffects) -> Vec<&GroupEvent> {
    effects
        .events
        .iter()
        .filter(|event| matches!(event, GroupEvent::GroupChangeNotDelivered { .. }))
        .collect()
}

/// Proof 8: a host's change given up on a later pass is recorded with the
/// rollback and announced. The record outlives a crash before the host saw
/// the event, a restart and a later commit, and goes once acknowledged.
#[tokio::test]
async fn a_host_change_given_up_later_is_recorded_until_acknowledged() {
    let (fixture, adapter, runtime, effects, commit) =
        given_up_change("not-delivered-host", FloorFixture::rename, true).await;
    let group_id = fixture.group_id.clone();
    assert!(
        matches!(
            announced_not_delivered(&effects).as_slice(),
            [GroupEvent::GroupChangeNotDelivered {
                group_id: announced,
                commit_id,
                intent_kind,
                reason,
            }] if *announced == group_id
                && *commit_id == commit
                && intent_kind == "update_group_data"
                && reason == "not_delivered"
        ),
        "{:?}",
        effects.events
    );
    let records = runtime.group_changes_not_delivered(&group_id).unwrap();
    assert!(
        matches!(
            records.as_slice(),
            [cgka_traits::storage::ChangeNotDelivered {
                group_id: recorded,
                commit_id,
                origin: cgka_traits::storage::ChangeOrigin::Direct,
                intent_kind,
                reason,
                at_ms,
            }] if *recorded == group_id
                && *commit_id == commit
                && intent_kind == "update_group_data"
                && reason == "not_delivered"
                && *at_ms > 0
        ),
        "{records:?}"
    );

    // The host never drained those events: the process stops here.
    drop(runtime);
    let mut restarted = fixture.runtime(fixture.reopen(), &adapter);
    restarted.resume_outbound_fanouts().await.unwrap();
    assert_eq!(
        restarted.group_changes_not_delivered(&group_id).unwrap(),
        records
    );

    // The refusing relay takes the next commit, which confirms.
    let next = restarted
        .send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    assert!(
        matches!(next.pending.as_slice(), [PendingResolution::Confirmed { .. }]),
        "{:?}",
        next.pending
    );
    assert_eq!(
        restarted.group_changes_not_delivered(&group_id).unwrap(),
        records,
        "a later commit leaves the record for the host"
    );

    assert!(
        restarted
            .acknowledge_change_not_delivered(&group_id, &commit)
            .unwrap()
    );
    assert!(
        restarted
            .group_changes_not_delivered(&group_id)
            .unwrap()
            .is_empty()
    );
    assert!(
        !restarted
            .acknowledge_change_not_delivered(&group_id, &commit)
            .unwrap(),
        "acknowledging twice finds nothing"
    );
}

/// An automatic commit given up the same way has no caller waiting for it:
/// nothing is recorded or announced.
#[tokio::test]
async fn an_automatic_commit_given_up_later_records_nothing() {
    let (fixture, _adapter, runtime, effects, _commit) = given_up_change(
        "not-delivered-automatic",
        |fixture| SendIntent::SelfUpdate {
            group_id: fixture.group_id.clone(),
        },
        false,
    )
    .await;
    assert!(
        announced_not_delivered(&effects).is_empty(),
        "{:?}",
        effects.events
    );
    assert!(
        runtime
            .group_changes_not_delivered(&fixture.group_id)
            .unwrap()
            .is_empty()
    );
}

/// Proof 19: a host's change refused for its size inside the call that
/// staged it is that call's result and records nothing. The same refusal on
/// a later pass, after a first attempt that never connected, has no caller:
/// it is recorded `event_too_large`, and the record is read after a restart.
#[tokio::test]
async fn a_host_change_refused_for_size_on_a_later_pass_is_recorded() {
    let relay = TransportEndpoint("wss://not-delivered-floor.example".into());
    let (fixture, alice) = FloorFixture::new("not-delivered-floor", &[&relay]).await;
    let group_id = fixture.group_id.clone();
    let adapter = RecordingAdapter::default();
    let mut runtime = fixture.runtime(alice, &adapter);

    adapter.refuse_commits_as_too_large(vec![relay.clone()]);
    let staged = runtime
        .send_host_change_with_audit_context(fixture.rename(), Default::default())
        .await
        .unwrap();
    assert!(
        matches!(staged.pending.as_slice(), [PendingResolution::RolledBack { .. }]),
        "{:?}",
        staged.pending
    );
    assert!(announced_not_delivered(&staged).is_empty());
    assert!(
        runtime
            .group_changes_not_delivered(&group_id)
            .unwrap()
            .is_empty(),
        "the staging call's own refusal is its result"
    );

    adapter.refuse_commits_as_too_large(vec![]);
    adapter.script_failures(relay.clone(), vec![unreachable(&relay)]);
    let start = fixture.wall.now().0;
    let sent = runtime
        .send_host_change_with_audit_context(fixture.rename(), Default::default())
        .await
        .unwrap();
    assert!(sent.pending.is_empty(), "{:?}", sent.pending);
    let commit = adapter.publishes().last().unwrap().message.id.clone();

    adapter.refuse_commits_as_too_large(vec![relay.clone()]);
    fixture.wall.set(start + HOUR);
    let effects = runtime.resume_outbound_fanouts().await.unwrap();
    assert!(
        matches!(effects.pending.as_slice(), [PendingResolution::RolledBack { .. }]),
        "{:?}",
        effects.pending
    );
    assert!(
        matches!(
            announced_not_delivered(&effects).as_slice(),
            [GroupEvent::GroupChangeNotDelivered { commit_id, reason, .. }]
                if *commit_id == commit && reason == "event_too_large"
        ),
        "{:?}",
        effects.events
    );

    drop(runtime);
    let restarted = fixture.runtime(fixture.reopen(), &adapter);
    let records = restarted.group_changes_not_delivered(&group_id).unwrap();
    assert!(
        matches!(
            records.as_slice(),
            [cgka_traits::storage::ChangeNotDelivered {
                commit_id,
                origin: cgka_traits::storage::ChangeOrigin::Direct,
                intent_kind,
                reason,
                ..
            }] if *commit_id == commit
                && intent_kind == "update_group_data"
                && reason == "event_too_large"
        ),
        "{records:?}"
    );
}
