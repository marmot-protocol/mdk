use super::*;
use crate::key_package_records::preferred_fresh_key_package_from_records;

fn candidate(
    account: &AccountSummary,
    package: KeyPackage,
    slot: &str,
    client: Option<&str>,
    timestamp: u64,
) -> NostrTransportEvent {
    let event = member_resolution_key_package_event(account, package);
    let mut tags = event.tags;
    tags.iter_mut().find(|tag| tag[0] == "d").unwrap()[1] = slot.into();
    if let Some(client) = client {
        tags.push(vec!["client".into(), client.into()]);
    }
    NostrTransportEvent::new_unsigned_at(event.pubkey, event.kind, tags, event.content, timestamp)
}

#[tokio::test]
async fn client_preference_ranks_only_valid_current_slots_and_preserves_recency() {
    let (_dir, app, accounts, _) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let package = fresh_key_package_for_account(&app, account, false).await;
    let now = unix_now_seconds();
    let amethyst = candidate(
        account,
        package.clone(),
        "amethyst",
        Some("  AmEtHySt\t"),
        now,
    );
    let untagged = candidate(account, package.clone(), "untagged", None, now - 10);
    let other = candidate(account, package.clone(), "other", Some("other"), now - 20);
    let white = candidate(
        account,
        package.clone(),
        "white",
        Some("  WHITEnoise "),
        now - 30,
    );
    let newest_white = candidate(
        account,
        package.clone(),
        "white-two",
        Some("whitenoise"),
        now - 5,
    );
    let select = |events: Vec<NostrTransportEvent>| {
        preferred_fresh_key_package_from_records(
            &account.account_id_hex,
            events
                .into_iter()
                .map(|event| RelayEventRecord {
                    event,
                    endpoints: vec![],
                })
                .collect(),
            app.directory_freshness(),
            None,
        )
        .unwrap()
        .value
        .unwrap()
        .key_package_event_id
    };
    assert_eq!(select(vec![amethyst.clone()]), amethyst.id);
    assert_eq!(
        select(vec![amethyst.clone(), untagged.clone()]),
        untagged.id
    );
    assert_eq!(
        select(vec![other.clone(), untagged.clone(), amethyst.clone()]),
        untagged.id
    );
    assert_eq!(
        select(vec![
            other.clone(),
            white.clone(),
            amethyst.clone(),
            untagged.clone()
        ]),
        white.id
    );
    assert_eq!(
        select(vec![white.clone(), newest_white.clone()]),
        newest_white.id
    );
    let mut invalid = newest_white.clone();
    invalid.content = "not base64".into();
    assert_eq!(select(vec![amethyst.clone(), invalid]), amethyst.id);
    let mut future = newest_white.clone();
    future.created_at = u64::MAX;
    assert_eq!(select(vec![amethyst.clone(), future]), amethyst.id);
    // A newer replacement in the same slot supersedes the old client label.
    let replaced = candidate(account, package.clone(), "white", Some("amethyst"), now);
    assert_eq!(select(vec![white, replaced, untagged.clone()]), untagged.id);
    // NIP-89 may carry an application reference after the client name.
    let mut referenced_amethyst = amethyst.clone();
    referenced_amethyst
        .tags
        .iter_mut()
        .find(|tag| tag[0] == "client")
        .unwrap()
        .push("31990:application:amethyst".into());
    assert_eq!(
        select(vec![referenced_amethyst, untagged.clone()]),
        untagged.id
    );
    let not_exact = candidate(
        account,
        package,
        "lookalike",
        Some("whitenoise-other"),
        now - 25,
    );
    assert_eq!(select(vec![not_exact, other.clone()]), other.id);
}

#[tokio::test]
async fn malformed_replacement_suppresses_older_package_in_the_same_slot() {
    let (_dir, app, accounts, _) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let package = fresh_key_package_for_account(&app, account, false).await;
    let now = unix_now_seconds();
    let old = candidate(
        account,
        package.clone(),
        "white",
        Some("whitenoise"),
        now - 10,
    );
    let fallback = candidate(
        account,
        package.clone(),
        "amethyst",
        Some("amethyst"),
        now - 20,
    );
    let replacement = candidate(account, package, "white", Some("whitenoise"), now);
    let mut bad_content = replacement.clone();
    bad_content.content = "not base64".into();
    let mut bad_metadata = replacement;
    bad_metadata
        .tags
        .iter_mut()
        .find(|tag| tag[0] == "i")
        .unwrap()[1] = "incorrect-reference".into();
    let select = |events: Vec<NostrTransportEvent>| {
        preferred_fresh_key_package_from_records(
            &account.account_id_hex,
            events
                .into_iter()
                .map(|event| RelayEventRecord {
                    event,
                    endpoints: vec![],
                })
                .collect(),
            app.directory_freshness(),
            None,
        )
    };
    for malformed in [bad_content, bad_metadata] {
        // An independent slot remains usable, but the superseded White Noise
        // package must never be resurrected when its replacement is invalid.
        assert_eq!(
            select(vec![old.clone(), malformed.clone(), fallback.clone()])
                .unwrap()
                .value
                .unwrap()
                .key_package_event_id,
            fallback.id,
        );
        assert!(select(vec![old.clone(), malformed.clone()]).is_err());
        // Freshness is checked before replacement: future events cannot hide
        // the current publication.
        let mut future = malformed;
        future.created_at = u64::MAX;
        assert_eq!(
            select(vec![old.clone(), future])
                .unwrap()
                .value
                .unwrap()
                .key_package_event_id,
            old.id,
        );
    }
}

#[tokio::test]
async fn client_preference_is_used_in_batch_and_single_author_fallback() {
    for reject_batch in [false, true] {
        let (_dir, app, accounts, fetcher) = member_resolution_fixture(2, false).await;
        fetcher
            .reject_multi_author
            .store(reject_batch, std::sync::atomic::Ordering::SeqCst);
        let mut expected = Vec::new();
        fetcher
            .events
            .lock()
            .unwrap()
            .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        for account in &accounts {
            let package = fresh_key_package_for_account(&app, account, false).await;
            let white = candidate(
                account,
                package.clone(),
                "white",
                Some("whitenoise"),
                unix_now_seconds() - 10,
            );
            let amethyst = candidate(
                account,
                package,
                "amethyst",
                Some("amethyst"),
                unix_now_seconds(),
            );
            expected.push(white.id.clone());
            fetcher.events.lock().unwrap().extend([amethyst, white]);
        }
        let refs = accounts
            .iter()
            .map(|a| a.account_id_hex.as_str())
            .collect::<Vec<_>>();
        let actual = app.resolve_member_key_packages(&refs).await.unwrap();
        assert_eq!(
            actual
                .iter()
                .map(|kp| hex::encode(kp.source.as_ref().unwrap().event_id.as_slice()))
                .collect::<Vec<_>>(),
            expected
        );
    }
}

#[tokio::test]
async fn client_preference_skips_incompatible_whitenoise_for_create_and_invite() {
    let (_dir, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let bob = &accounts[0];
    app.account_home().create_account("alice").unwrap();
    let good = fresh_key_package_for_account(&app, bob, false).await;
    let limited = fresh_key_package_with_components(
        &app,
        bob,
        false,
        app.supported_app_component_ids()
            .into_iter()
            .filter(|id| *id != GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID)
            .collect(),
    )
    .await;
    let white = candidate(
        bob,
        limited,
        "white",
        Some("whitenoise"),
        unix_now_seconds(),
    );
    let fallback = candidate(
        bob,
        good.clone(),
        "other",
        Some("amethyst"),
        unix_now_seconds() - 10,
    );
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    fetcher
        .events
        .lock()
        .unwrap()
        .extend([white.clone(), fallback.clone()]);
    let mut alice = client_on_app_relay_plane(&app, "alice").await;
    let group = alice
        .create_group("compatible creation", &[bob.account_id_hex.as_str()])
        .await
        .unwrap();
    assert_eq!(alice.members(&group).unwrap().len(), 2);
    let empty = alice.create_group("compatible invite", &[]).await.unwrap();
    let requirements = alice
        .runtime
        .session()
        .invite_key_package_requirements(&empty)
        .unwrap();
    let reinvite = app
        .resolve_compatible_member_key_packages(
            vec![bob.account_id_hex.clone()],
            &requirements,
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        hex::encode(
            reinvite.key_packages[0]
                .source
                .as_ref()
                .unwrap()
                .event_id
                .as_slice()
        ),
        fallback.id
    );
    alice
        .invite_members(&empty, &[bob.account_id_hex.as_str()])
        .await
        .unwrap();
    assert_eq!(alice.members(&empty).unwrap().len(), 2);
    // No compatible candidate means no group mutation, even if White Noise is present.
    let no_fallback = alice
        .create_group("no compatible candidate", &[])
        .await
        .unwrap();
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.id != fallback.id);
    assert!(
        alice
            .invite_members(&no_fallback, &[bob.account_id_hex.as_str()])
            .await
            .is_err()
    );
    assert_eq!(alice.members(&no_fallback).unwrap().len(), 1);
}

#[tokio::test]
async fn publication_client_name_is_opt_in_and_signed_retries_keep_original_tags() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let account = app.account_home().create_account("alice").unwrap();
    let package = fresh_key_package_for_account(&app, &account, false).await;
    let publication = KeyPackagePublication {
        account_id: MemberId::new(hex::decode(&account.account_id_hex).unwrap()),
        key_package: package,
        slot_id: "slot".into(),
        created_at: Timestamp(unix_now_seconds()),
        endpoints: vec![TransportEndpoint("wss://relay.example".into())],
    };
    let publisher = |app: &MarmotApp| AppKeyPackagePublisher {
        app: app.clone(),
        account_label: account.label.clone(),
        signer: app.account_signer_for_summary(&account).unwrap(),
    };
    let original = publisher(&app)
        .prepare_key_package(publication.clone())
        .await
        .unwrap();
    let original_event: NostrTransportEvent = serde_json::from_slice(&original.bytes).unwrap();
    assert_eq!(original_event.tag_value("client"), None);
    app.config.key_package_client_name = Some("  whitenoise  ".into());
    publisher(&app)
        .publish_prepared_key_package(&publication, &original)
        .await
        .unwrap();
    assert_eq!(
        relay.published_events.lock().unwrap().last().unwrap(),
        &original_event
    );
    let tagged = publisher(&app)
        .prepare_key_package(publication.clone())
        .await
        .unwrap();
    let tagged_event: NostrTransportEvent = serde_json::from_slice(&tagged.bytes).unwrap();
    assert_eq!(tagged_event.tag_value("client"), Some("whitenoise"));
    app.config.key_package_client_name = None;
    publisher(&app)
        .publish_prepared_key_package(&publication, &tagged)
        .await
        .unwrap();
    assert_eq!(
        relay.published_events.lock().unwrap().last().unwrap(),
        &tagged_event
    );
    app.config.key_package_client_name = Some(" \t ".into());
    let blank = publisher(&app)
        .prepare_key_package(publication)
        .await
        .unwrap();
    let blank: NostrTransportEvent = serde_json::from_slice(&blank.bytes).unwrap();
    assert_eq!(blank.tag_value("client"), None);
}
