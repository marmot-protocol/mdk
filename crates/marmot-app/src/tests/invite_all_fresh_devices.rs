use super::*;
use crate::key_package_records::{
    MAX_KEY_PACKAGES_PER_MEMBER, MEMBER_KEY_PACKAGE_FRESHNESS_WINDOW,
};

pub(super) fn device_event(
    account: &AccountSummary,
    package: KeyPackage,
    slot: usize,
    created_at: u64,
) -> NostrTransportEvent {
    let mut event = member_resolution_key_package_event(account, package);
    event.tags.iter_mut().find(|tag| tag[0] == "d").unwrap()[1] = format!("device-{slot}");
    NostrTransportEvent::new_unsigned_at(
        event.pubkey,
        event.kind,
        event.tags,
        event.content,
        created_at,
    )
}

#[tokio::test]
async fn invite_all_fresh_devices_caps_newest_slots_and_deduplicates_refs() {
    let (_directory, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let now = unix_now_seconds();
    let mut events = Vec::new();
    for slot in 0..31 {
        events.push(device_event(
            account,
            fresh_key_package_for_account(&app, account, false).await,
            slot,
            now - slot as u64,
        ));
    }
    let mut duplicate = events[0].clone();
    duplicate.tags.iter_mut().find(|tag| tag[0] == "d").unwrap()[1] = "duplicate-ref".into();
    duplicate = NostrTransportEvent::new_unsigned_at(
        duplicate.pubkey,
        duplicate.kind,
        duplicate.tags,
        duplicate.content,
        now,
    );
    events.push(duplicate);
    assert_eq!(events.len(), 32, "exactly one saturated per-author prefix");
    let mut expected = events.clone();
    expected.sort_by(|a, b| (b.created_at, &b.id).cmp(&(a.created_at, &a.id)));
    let mut refs = HashSet::new();
    expected.retain(|event| refs.insert(event.tag_value("i").unwrap().to_owned()));
    expected.truncate(MAX_KEY_PACKAGES_PER_MEMBER);
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    fetcher.events.lock().unwrap().extend(events.clone());
    for reverse in [false, true] {
        if reverse {
            fetcher.events.lock().unwrap().reverse();
        }
        let packages = app
            .resolve_member_key_packages(&[&account.account_id_hex])
            .await
            .unwrap();
        assert_eq!(packages.len(), 10);
        assert_eq!(
            packages
                .iter()
                .map(|kp| hex::encode(kp.source.as_ref().unwrap().event_id.as_slice()))
                .collect::<Vec<_>>(),
            expected.iter().map(|e| e.id.clone()).collect::<Vec<_>>()
        );
    }
    // Recovery accepts this deliberate 32-event prefix too, but still requires
    // completed transport reads and deletion absence coverage.
    let exclusions = crate::key_package_records::MemberKeyPackageExclusions {
        obligations: Some(std::collections::BTreeMap::from([(
            account.account_id_hex.clone(),
            vec!["missing-leaf".into(); 10],
        )])),
        ..Default::default()
    };
    let recovered = app
        .resolve_member_key_packages_with_exclusions(
            vec![account.account_id_hex.clone()],
            crate::directory::MemberResolutionPurpose::CommitFresh,
            None,
            &exclusions,
        )
        .await
        .unwrap();
    assert_eq!(recovered.key_packages.len(), 10);
}

#[tokio::test]
async fn invite_all_fresh_devices_publication_age_includes_exact_freshness_boundary() {
    let (_directory, app, accounts, _) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let now = 1_700_000_000;
    let window = MEMBER_KEY_PACKAGE_FRESHNESS_WINDOW.as_secs();
    let mut records = Vec::new();
    for (slot, age) in [window - 1, window, window + 1].into_iter().enumerate() {
        records.push(RelayEventRecord {
            event: device_event(
                account,
                fresh_key_package_for_account(&app, account, false).await,
                slot,
                now - age,
            ),
            endpoints: vec![],
        });
    }
    // MLS lifetime validation remains independent of publication age. Only the
    // selection clock is fixed so the exact second boundary cannot drift.
    let mut candidates = crate::key_package_records::validate_member_key_package_candidates(
        &account.account_id_hex,
        &records,
        DirectoryFreshness {
            max_created_at: now,
        },
        None,
    );
    let selected = candidates
        .select_at(
            now,
            |_| true,
            &crate::key_package_records::MemberKeyPackageExclusions::default(),
        )
        .unwrap()
        .value;
    assert_eq!(
        selected
            .iter()
            .map(|package| package.key_package_event_id.clone())
            .collect::<Vec<_>>(),
        vec![records[0].event.id.clone(), records[1].event.id.clone()],
        "include ages window - 1 and window; exclude window + 1 seconds",
    );
}

#[tokio::test]
async fn invite_all_fresh_devices_publication_age_and_single_stale_fallback() {
    let (_directory, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let now = unix_now_seconds();
    let day = 24 * 60 * 60;
    let window = MEMBER_KEY_PACKAGE_FRESHNESS_WINDOW.as_secs();
    let mut events = Vec::new();
    // Multiple fresh devices make this fail on the former single selection.
    for (slot, age) in [window + day, window - day, window - 2 * day]
        .into_iter()
        .enumerate()
    {
        events.push(device_event(
            account,
            fresh_key_package_for_account(&app, account, false).await,
            slot,
            now - age,
        ));
    }
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    fetcher.events.lock().unwrap().extend(events.clone());
    let resolved = app
        .resolve_member_key_packages_with_stats(vec![account.account_id_hex.clone()])
        .await
        .unwrap();
    assert_eq!(resolved.key_packages.len(), 2);
    assert_eq!(resolved.stats.stale_fallback_members, 0);
    assert_eq!(
        resolved
            .key_packages
            .iter()
            .map(|package| hex::encode(package.source.as_ref().unwrap().event_id.as_slice()))
            .collect::<Vec<_>>(),
        vec![events[2].id.clone(), events[1].id.clone()],
        "the 29-day slot is included and the 31-day slot is excluded",
    );
    // KeyPackage lifetimes are independent of these publication timestamps.
    for event in &mut events {
        event.created_at -= 3 * day;
    }
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    fetcher.events.lock().unwrap().extend(events.clone());
    let resolved = app
        .resolve_member_key_packages_with_stats(vec![account.account_id_hex.clone()])
        .await
        .unwrap();
    assert_eq!(resolved.key_packages.len(), 1);
    assert_eq!(resolved.stats.stale_fallback_members, 1);
    assert_eq!(
        hex::encode(
            resolved.key_packages[0]
                .source
                .as_ref()
                .unwrap()
                .event_id
                .as_slice()
        ),
        events[2].id
    );
}

#[tokio::test]
async fn invite_all_fresh_devices_create_and_invite_include_both_siblings() {
    let (_directory, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let peer = &accounts[0];
    let now = unix_now_seconds();
    let mut events = Vec::new();
    for slot in 0..2 {
        events.push(device_event(
            peer,
            fresh_key_package_for_account(&app, peer, false).await,
            slot,
            now - slot as u64,
        ));
    }
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    fetcher.events.lock().unwrap().extend(events);
    app.account_home().create_account("alice").unwrap();
    let summary = app
        .prewarm_group_member_key_packages(&[&peer.account_id_hex])
        .await
        .unwrap();
    assert_eq!(summary.unique_members, 1);
    assert_eq!(summary.network_resolved_members, 1);
    let mut alice = client_on_app_relay_plane(&app, "alice").await;
    let direct = alice
        .create_group("", &[&peer.account_id_hex])
        .await
        .unwrap();
    assert_eq!(alice.group_mls_state(&direct).unwrap().member_count, 3);
    let empty = alice.create_group("", &[]).await.unwrap();
    alice
        .invite_members(&empty, &[&peer.account_id_hex])
        .await
        .unwrap();
    assert_eq!(alice.group_mls_state(&empty).unwrap().member_count, 3);
}

#[tokio::test]
async fn invite_all_fresh_devices_app_recovery_refetches_multiple_packages_for_one_account() {
    staggered_device_recovery(false).await;
}

#[tokio::test]
async fn invite_all_fresh_devices_deduplicates_signing_keys_with_distinct_refs() {
    let (_directory, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let peer = &accounts[0];
    let mut device = client_on_app_relay_plane(&app, &peer.label).await;
    let older = device
        .runtime
        .session_mut()
        .fresh_key_package()
        .await
        .unwrap();
    let newer = device
        .runtime
        .session_mut()
        .fresh_key_package()
        .await
        .unwrap();
    let old_meta = cgka_engine::key_package::key_package_metadata(&older).unwrap();
    let new_meta = cgka_engine::key_package::key_package_metadata(&newer).unwrap();
    assert_ne!(old_meta.key_package_ref_hex, new_meta.key_package_ref_hex);
    assert_eq!(old_meta.signature_key_hex, new_meta.signature_key_hex);
    let healthy = fresh_key_package_for_account(&app, peer, false).await;
    let events = vec![
        device_event(peer, newer, 1, unix_now_seconds()),
        device_event(peer, older, 2, unix_now_seconds() - 1),
        device_event(peer, healthy, 3, unix_now_seconds() - 2),
    ];
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    fetcher.events.lock().unwrap().extend(events.clone());
    for reverse in [false, true] {
        if reverse {
            fetcher.events.lock().unwrap().reverse();
        }
        let packages = app
            .resolve_member_key_packages(&[&peer.account_id_hex])
            .await
            .unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(
            cgka_engine::key_package::key_package_metadata(&packages[0])
                .unwrap()
                .key_package_ref_hex,
            new_meta.key_package_ref_hex
        );
    }
}

#[tokio::test]
async fn invite_all_fresh_devices_recovery_skips_consumed_sibling_until_replenished() {
    staggered_device_recovery(true).await;
}

async fn staggered_device_recovery(partial: bool) {
    use cgka_traits::storage::{
        OutboundIntentStorage, OwnCommitBaseline, OwnCommitIntent, ReinviteRetry,
    };
    let (_directory, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let peer = &accounts[0];
    app.account_home().create_account("alice").unwrap();
    let mut alice = client_on_app_relay_plane(&app, "alice").await;
    // An already-present sibling must not satisfy a lost Add for another leaf.
    let group = alice
        .create_group("recovery", &[&peer.account_id_hex])
        .await
        .unwrap();
    let active = fetcher
        .events
        .lock()
        .unwrap()
        .iter()
        .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
        .unwrap()
        .clone();
    let mut old = Vec::new();
    let mut fresh = Vec::new();
    let mut consumed_sibling = None;
    for slot in 1..3 {
        let package = fresh_key_package_for_account(&app, peer, false).await;
        if slot == 2 {
            consumed_sibling = Some(device_event(
                peer,
                package.clone(),
                slot,
                unix_now_seconds(),
            ));
        }
        old.push(package);
        fresh.push(device_event(
            peer,
            fresh_key_package_for_account(&app, peer, false).await,
            slot,
            unix_now_seconds(),
        ));
    }
    let commit_id = MessageId::new(vec![0xee; 32]);
    let storage = app.account_storage("alice").unwrap();
    storage
        .put_own_commit_intent(&OwnCommitIntent {
            commit_id: commit_id.clone(),
            group_id: group.clone(),
            source_epoch: cgka_traits::EpochId(0),
            intent: cgka_traits::engine::SendIntent::Invite {
                group_id: group.clone(),
                key_packages: old.clone(),
                initial_admins: vec![],
            },
            baseline: OwnCommitBaseline::None,
            reinvite: Some(ReinviteRetry::default()),
            reissue_attempts: 0,
            created_at_ms: 0,
        })
        .unwrap();
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    fetcher.events.lock().unwrap().extend([active]);
    fetcher.events.lock().unwrap().extend(if partial {
        vec![fresh[0].clone(), consumed_sibling.unwrap()]
    } else {
        fresh.clone()
    });
    alice.recover_superseded_invites().await.unwrap();
    let queued = storage.list_queued_outbound_intents(&group).unwrap();
    assert_eq!(queued.len(), 1);
    let cgka_traits::engine::SendIntent::Invite { key_packages, .. } = &queued[0].intent else {
        panic!("queued reinvitation");
    };
    assert_eq!(
        key_packages.len(),
        if partial { 1 } else { 2 },
        "usable replenishment is queued independently"
    );
    if partial {
        let remaining = storage.own_commit_intent(&commit_id).unwrap().unwrap();
        let cgka_traits::engine::SendIntent::Invite { key_packages, .. } = &remaining.intent else {
            panic!("remaining invite");
        };
        assert_eq!(key_packages, &vec![old[1].clone()]);
        // A's consumed original remains visible in an independent replaceable
        // slot while its replacement is queued. It must never discharge B.
        let mut retry = remaining.clone();
        retry.reinvite.as_mut().unwrap().next_attempt_at_ms = 0;
        storage.put_own_commit_intent(&retry).unwrap();
        fetcher.events.lock().unwrap().push(device_event(
            peer,
            old[0].clone(),
            99,
            unix_now_seconds(),
        ));
        alice.recover_superseded_invites().await.unwrap();
        assert_eq!(
            storage.list_queued_outbound_intents(&group).unwrap().len(),
            1
        );
        assert!(storage.own_commit_intent(&commit_id).unwrap().is_some());
        // Only B replenishes on the next attempt; A's new intent is already queued.
        let mut remaining = remaining;
        remaining.reinvite.as_mut().unwrap().next_attempt_at_ms = 0;
        storage.put_own_commit_intent(&remaining).unwrap();
        fetcher
            .events
            .lock()
            .unwrap()
            .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        fetcher
            .events
            .lock()
            .unwrap()
            .extend([fresh[0].clone(), fresh[1].clone()]);
        alice.recover_superseded_invites().await.unwrap();
        assert_eq!(
            storage.list_queued_outbound_intents(&group).unwrap().len(),
            2
        );
    }
    assert!(storage.own_commit_intent(&commit_id).unwrap().is_none());
}

#[tokio::test]
async fn invite_all_fresh_devices_deletion_proofs_validate_candidates_once_and_bound_fetch_round_count()
 {
    use crate::key_package_records::MEMBER_CANDIDATE_VALIDATIONS;
    let (_directory, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let peer = &accounts[0];
    let mut events = vec![];
    for slot in 0..10 {
        events.push(device_event(
            peer,
            fresh_key_package_for_account(&app, peer, false).await,
            slot,
            unix_now_seconds() - slot as u64,
        ));
    }
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    fetcher.events.lock().unwrap().extend(events);
    MEMBER_CANDIDATE_VALIDATIONS.with(|count| count.set(0));
    assert_eq!(
        app.resolve_member_key_packages(&[&peer.account_id_hex])
            .await
            .unwrap()
            .len(),
        10
    );
    let requests = fetcher.requests.lock().unwrap();
    let mut proof_rounds = std::collections::BTreeMap::new();
    for request in requests
        .iter()
        .filter(|request| request.queries.iter().any(|query| query.kind == 5))
    {
        assert!(request.queries.len() <= 10, "bounded relay filter list");
        *proof_rounds.entry(request.endpoints.clone()).or_insert(0) += 1;
    }
    assert!(!proof_rounds.is_empty());
    for rounds in proof_rounds.values() {
        assert!(
            *rounds <= 2,
            "ten candidates need at most two bounded proof fetch rounds per route chunk, got {rounds}"
        );
    }
    eprintln!(
        "ten-candidate proof rounds per route chunk: {:?}",
        proof_rounds.values().collect::<Vec<_>>()
    );
    drop(requests);
    let work = MEMBER_CANDIDATE_VALIDATIONS.with(|count| count.get());
    assert!(
        work <= 20,
        "ten immutable candidates need one recovery validation plus final lifetime revalidation, got {work}"
    );
}

#[tokio::test]
async fn invite_all_fresh_devices_recovery_matches_original_leaf_before_cap() {
    use cgka_traits::storage::{
        OutboundIntentStorage, OwnCommitBaseline, OwnCommitIntent, ReinviteRetry,
    };
    let (_directory, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let peer = &accounts[0];
    app.account_home().create_account("alice").unwrap();
    let mut alice = client_on_app_relay_plane(&app, "alice").await;
    let group = alice.create_group("recovery", &[]).await.unwrap();
    let mut device = client_on_app_relay_plane(&app, &peer.label).await;
    let original = device
        .runtime
        .session_mut()
        .fresh_key_package()
        .await
        .unwrap();
    let replacement = device
        .runtime
        .session_mut()
        .fresh_key_package()
        .await
        .unwrap();
    let commit_id = MessageId::new(vec![0xea; 32]);
    let storage = app.account_storage("alice").unwrap();
    storage
        .put_own_commit_intent(&OwnCommitIntent {
            commit_id: commit_id.clone(),
            group_id: group.clone(),
            source_epoch: cgka_traits::EpochId(0),
            intent: cgka_traits::engine::SendIntent::Invite {
                group_id: group.clone(),
                key_packages: vec![original],
                initial_admins: vec![],
            },
            baseline: OwnCommitBaseline::None,
            reinvite: Some(ReinviteRetry::default()),
            reissue_attempts: 0,
            created_at_ms: 0,
        })
        .unwrap();
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    let now = unix_now_seconds();
    // New devices are newer than A and would fill the outbound cap first.
    for slot in 0..11 {
        let package = fresh_key_package_for_account(&app, peer, false).await;
        fetcher
            .events
            .lock()
            .unwrap()
            .push(device_event(peer, package, slot, now));
    }
    fetcher
        .events
        .lock()
        .unwrap()
        .push(device_event(peer, replacement.clone(), 12, now - 1));
    alice.recover_superseded_invites().await.unwrap();
    let queued = storage.list_queued_outbound_intents(&group).unwrap();
    assert_eq!(queued.len(), 1);
    let cgka_traits::engine::SendIntent::Invite { key_packages, .. } = &queued[0].intent else {
        panic!("invite");
    };
    assert_eq!(key_packages.len(), 1);
    assert_eq!(key_packages[0].bytes, replacement.bytes);
    assert!(storage.own_commit_intent(&commit_id).unwrap().is_none());
}

#[tokio::test]
async fn invite_all_fresh_devices_normal_invite_excludes_active_sibling() {
    let (_directory, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let peer = &accounts[0];
    let mut active = client_on_app_relay_plane(&app, &peer.label).await;
    let original = active
        .runtime
        .session_mut()
        .fresh_key_package()
        .await
        .unwrap();
    let replenished = active
        .runtime
        .session_mut()
        .fresh_key_package()
        .await
        .unwrap();
    let now = unix_now_seconds();
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    fetcher
        .events
        .lock()
        .unwrap()
        .push(device_event(peer, original, 0, now - 2));
    app.account_home().create_account("alice").unwrap();
    let mut alice = client_on_app_relay_plane(&app, "alice").await;
    let group = alice
        .create_group("siblings", &[&peer.account_id_hex])
        .await
        .unwrap();
    assert_eq!(alice.group_mls_state(&group).unwrap().member_count, 2);
    let sibling = fresh_key_package_for_account(&app, peer, false).await;
    let sibling_key = cgka_engine::key_package::key_package_metadata(&sibling)
        .unwrap()
        .signature_key_hex;
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    fetcher.events.lock().unwrap().extend([
        device_event(peer, replenished, 0, now - 1),
        device_event(peer, sibling, 1, now),
    ]);
    alice
        .invite_members(&group, &[&peer.account_id_hex])
        .await
        .unwrap();
    assert_eq!(alice.group_mls_state(&group).unwrap().member_count, 3);
    let roster = alice.runtime.group_record(&group).unwrap();
    assert!(
        roster
            .members
            .iter()
            .any(|member| hex::encode(&member.credential) == sibling_key)
    );
}

#[tokio::test]
async fn invite_all_fresh_devices_multi_author_fetch_bounds_prolific_account() {
    use crate::key_package_records::MEMBER_CANDIDATE_VALIDATIONS;
    let (_directory, app, accounts, fetcher) = member_resolution_fixture(2, false).await;
    let peer = &accounts[0];
    let package = fresh_key_package_for_account(&app, peer, false).await;
    fetcher.events.lock().unwrap().retain(|event| {
        event.kind != KIND_MARMOT_KEY_PACKAGE || event.pubkey != peer.account_id_hex
    });
    // One author dominates the batch. Distinct replaceable slots ensure the
    // excess cannot disappear merely through slot winner deduplication.
    let now = unix_now_seconds();
    for slot in 0..64 {
        fetcher.events.lock().unwrap().push(device_event(
            peer,
            package.clone(),
            slot,
            now - slot as u64,
        ));
    }
    MEMBER_CANDIDATE_VALIDATIONS.with(|count| count.set(0));
    let members = accounts
        .iter()
        .map(|account| account.account_id_hex.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        app.resolve_member_key_packages(&members)
            .await
            .unwrap()
            .len(),
        2
    );
    let work = MEMBER_CANDIDATE_VALIDATIONS.with(|count| count.get());
    // Recovery validates the retained prefix, then final selection revalidates
    // it: at most 32 prolific-author slots plus the other author, twice.
    assert!(
        work <= 2 * (32 + 1),
        "prolific author exceeded bounded candidate validation: {work}"
    );
    for request in fetcher.requests.lock().unwrap().iter() {
        for query in request
            .queries
            .iter()
            .filter(|query| query.kind == KIND_MARMOT_KEY_PACKAGE)
        {
            assert_eq!(query.authors.len(), 1);
            assert_eq!(query.limit, 32);
        }
    }
}
