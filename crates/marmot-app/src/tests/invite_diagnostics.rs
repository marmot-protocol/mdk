use super::*;
use crate::key_package_records::preferred_member_key_package_from_records;

#[tokio::test]
async fn legacy_only_member_lookup_reports_obsolete_without_extra_queries() {
    let (_dir, app, accounts, fetcher) = member_resolution_fixture(2, false).await;
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    for account in &accounts {
        let package = fresh_key_package_for_account(&app, account, true).await;
        fetcher
            .events
            .lock()
            .unwrap()
            .push(member_resolution_key_package_event(account, package));
    }
    // Both batch and single-author fallback classify the first requested member.
    for targets in [
        vec![accounts[0].account_id_hex.as_str()],
        vec![
            accounts[1].account_id_hex.as_str(),
            accounts[0].account_id_hex.as_str(),
        ],
    ] {
        fetcher.requests.lock().unwrap().clear();
        let error = app.resolve_member_key_packages(&targets).await.unwrap_err();
        assert!(
            matches!(error, AppError::ObsoleteKeyPackage(ref account) if account == targets[0])
        );
        let requests = fetcher.requests.lock().unwrap();
        let queries = requests
            .iter()
            .flat_map(|request| &request.queries)
            .collect::<Vec<_>>();
        assert!(queries.iter().all(|query| matches!(
            query.kind,
            KIND_NIP65_RELAY_LIST | KIND_MARMOT_INBOX_RELAY_LIST | KIND_MARMOT_KEY_PACKAGE
        )));
        assert_eq!(
            queries
                .iter()
                .filter(|query| query.kind == KIND_MARMOT_KEY_PACKAGE)
                .count(),
            1 + targets.len()
        );
    }
}

#[tokio::test]
async fn incomplete_lookup_cannot_claim_obsolete_or_missing_but_can_use_current_package() {
    let (_dir, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let current = fresh_key_package_for_account(&app, account, false).await;
    let legacy = fresh_key_package_for_account(&app, account, true).await;
    *fetcher.incomplete_endpoint.lock().unwrap() = Some("wss://shared.example".into());
    for package in [None, Some(legacy)] {
        fetcher
            .events
            .lock()
            .unwrap()
            .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        if let Some(package) = package {
            fetcher
                .events
                .lock()
                .unwrap()
                .push(member_resolution_key_package_event(account, package));
        }
        let error = app
            .resolve_member_key_packages(&[account.account_id_hex.as_str()])
            .await
            .unwrap_err();
        assert!(
            matches!(error, AppError::MemberDiscoveryIncomplete(ref id) if id == &account.account_id_hex)
        );
    }
    // Keep current and legacy in distinct addressable slots: same-second
    // events in one slot would make the event-id tie break choose the winner.
    let mut current_event = member_resolution_key_package_event(account, current);
    current_event
        .tags
        .iter_mut()
        .find(|tag| tag[0] == "d")
        .unwrap()[1] = "current-fixture-slot".into();
    fetcher.events.lock().unwrap().push(current_event);
    app.resolve_member_key_packages(&[account.account_id_hex.as_str()])
        .await
        .unwrap();
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    *fetcher.incomplete_endpoint.lock().unwrap() = None;
    let error = app
        .resolve_member_key_packages(&[account.account_id_hex.as_str()])
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::MissingKeyPackage(_)));
}

#[tokio::test]
async fn member_diagnosis_preserves_current_selection_and_newest_slot_validation() {
    let (_dir, app, accounts, _) = member_resolution_fixture(2, false).await;
    let account = &accounts[0];
    let legacy = fresh_key_package_for_account(&app, account, true).await;
    let current = fresh_key_package_for_account(&app, account, false).await;
    let make = |package, slot: &str, timestamp| {
        let mut event = member_resolution_key_package_event(account, package);
        event.tags.iter_mut().find(|tag| tag[0] == "d").unwrap()[1] = slot.into();
        event.created_at = timestamp;
        event
    };
    let now = unix_now_seconds();
    let old = make(legacy, "legacy", now - 10);
    let current_event = make(current, "current", now - 20);
    let select = |events: Vec<NostrTransportEvent>| {
        let records = events
            .into_iter()
            .map(|event| RelayEventRecord {
                event,
                endpoints: vec![],
            })
            .collect::<Vec<_>>();
        preferred_member_key_package_from_records(
            &account.account_id_hex,
            &records,
            app.directory_freshness(),
            None,
        )
    };
    assert!(matches!(
        select(vec![old.clone()]),
        Err(AppError::ObsoleteKeyPackage(_))
    ));
    assert_eq!(
        select(vec![old.clone(), current_event.clone()])
            .unwrap()
            .value
            .unwrap()
            .fetched
            .key_package_event_id,
        current_event.id
    );
    let mut malformed = old.clone();
    malformed.created_at = now;
    malformed.content = "not base64".into();
    assert!(matches!(
        select(vec![old.clone(), malformed]),
        Err(AppError::InvalidKeyPackageEvent(_))
    ));
    let mut wrong_identity = old.clone();
    wrong_identity.content = member_resolution_key_package_event(
        &accounts[1],
        fresh_key_package_for_account(&app, &accounts[1], true).await,
    )
    .content;
    assert!(matches!(
        select(vec![wrong_identity]),
        Err(AppError::InvalidKeyPackageEvent(_))
    ));
    let mut future = current_event;
    future.created_at = u64::MAX;
    assert!(!matches!(
        select(vec![old.clone(), future]),
        Err(AppError::ObsoleteKeyPackage(_))
    ));
    let mut legacy_kind = old;
    legacy_kind.kind = 443;
    assert!(select(vec![legacy_kind]).unwrap().value.is_none());
}
