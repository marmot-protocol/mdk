//! The KeyPackage `client` tag: the sender's bounds, the shared reader at each
//! place MDK reads the tag, selection ignoring it, and no other published event
//! shape carrying it.

use super::invite_recovery::package_expiring_at;
use super::*;
use crate::key_package_records::select_key_packages_from_records;
use std::collections::BTreeSet;
use transport_nostr_adapter::{CLIENT_NAME_MAX_BYTES, CLIENT_TAG};

const RELAY: &str = "wss://relay.example";

fn client_tags(tags: &[Vec<String>]) -> Vec<&Vec<String>> {
    tags.iter()
        .filter(|tag| tag.first().is_some_and(|name| name == CLIENT_TAG))
        .collect()
}

fn client_tag(values: &[&str]) -> Vec<String> {
    std::iter::once(CLIENT_TAG)
        .chain(values.iter().copied())
        .map(str::to_owned)
        .collect()
}

fn overlong_name() -> String {
    "x".repeat(CLIENT_NAME_MAX_BYTES + 1)
}

/// Tag sets the receiver rule reads as no `client` tag. Each names `name`, or
/// an over-long name, so a reader that skipped the rule would see a label.
fn unreadable_client_tags(name: &str) -> Vec<Vec<Vec<String>>> {
    vec![
        vec![client_tag(&[name]), client_tag(&[name])],
        vec![client_tag(&[name]), client_tag(&[])],
        vec![client_tag(&[])],
        vec![client_tag(&[""])],
        vec![client_tag(&[&overlong_name()])],
    ]
}

fn publication_for(account: &AccountSummary, key_package: KeyPackage) -> KeyPackagePublication {
    KeyPackagePublication {
        account_id: MemberId::new(hex::decode(&account.account_id_hex).unwrap()),
        key_package,
        slot_id: "slot".into(),
        created_at: Timestamp(unix_now_seconds()),
        endpoints: vec![TransportEndpoint(RELAY.into())],
    }
}

fn publisher_for(app: &MarmotApp, account: &AccountSummary) -> AppKeyPackagePublisher {
    AppKeyPackagePublisher {
        app: app.clone(),
        account_label: account.label.clone(),
        signer: app.account_signer_for_summary(account).unwrap(),
    }
}

fn prepared_event(artifact: &cgka_traits::SignedPublicationArtifact) -> NostrTransportEvent {
    serde_json::from_slice(&artifact.bytes).unwrap()
}

/// Re-sign a prepared KeyPackage artifact with `client_tags` in place of its own.
fn artifact_with_client_tags(
    keys: &Keys,
    prepared: &cgka_traits::SignedPublicationArtifact,
    client_tags: Vec<Vec<String>>,
) -> cgka_traits::SignedPublicationArtifact {
    let event = prepared_event(prepared);
    let tags = event
        .tags
        .into_iter()
        .filter(|tag| tag[0] != CLIENT_TAG)
        .chain(client_tags)
        .map(|tag| Tag::parse(tag).unwrap());
    let signed = EventBuilder::new(Kind::from(event.kind as u16), event.content)
        .tags(tags)
        .custom_created_at(NostrTimestamp::from_secs(event.created_at))
        .finalize(keys)
        .unwrap();
    cgka_traits::SignedPublicationArtifact {
        id: cgka_traits::MessageId::new(signed.id.to_bytes().to_vec()),
        created_at: prepared.created_at,
        bytes: serde_json::to_vec(&NostrTransportEvent::from_nostr_event(&signed).unwrap())
            .unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_client_name_publishes_one_bounded_tag_or_none() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app = MarmotApp::with_relay(dir.path(), RELAY).with_test_relay_client(relay);
    let account = app.account_home().create_account("alice").unwrap();
    let publication = publication_for(
        &account,
        fresh_key_package_for_account(&app, &account, false).await,
    );
    let longest = "x".repeat(CLIENT_NAME_MAX_BYTES);
    // 32 two-byte characters fit; 33 do not.
    let longest_wide = "é".repeat(CLIENT_NAME_MAX_BYTES / 2);
    for (configured, published) in [
        ("  whitenoise  ".to_owned(), Some("whitenoise")),
        (format!(" {longest} "), Some(longest.as_str())),
        (longest_wide.clone(), Some(longest_wide.as_str())),
        // An out-of-bounds name is omitted, never truncated, and the
        // KeyPackage still publishes.
        (overlong_name(), None),
        ("é".repeat(CLIENT_NAME_MAX_BYTES / 2 + 1), None),
        (" \t ".to_owned(), None),
    ] {
        app.config.key_package_client_name = Some(configured.clone());
        let event = prepared_event(
            &publisher_for(&app, &account)
                .prepare_key_package(publication.clone())
                .await
                .unwrap(),
        );
        let expected = published.map(|name| client_tag(&[name]));
        assert_eq!(
            client_tags(&event.tags),
            expected.iter().collect::<Vec<_>>(),
            "{configured:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_retry_reads_its_client_tag_through_the_shared_reader() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), RELAY).with_test_relay_client(relay.clone());
    let account = app.account_home().create_account("alice").unwrap();
    let keys = app
        .account_home()
        .load_signing_keys(&account.label)
        .unwrap();
    let publication = publication_for(
        &account,
        fresh_key_package_for_account(&app, &account, false).await,
    );
    let publisher = publisher_for(&app, &account);
    let prepared = publisher
        .prepare_key_package(publication.clone())
        .await
        .unwrap();

    let written = artifact_with_client_tags(&keys, &prepared, vec![client_tag(&["whitenoise"])]);
    publisher
        .publish_prepared_key_package(&publication, &written)
        .await
        .unwrap();
    assert_eq!(
        relay.attempted_events().last(),
        Some(&prepared_event(&written))
    );

    // A retry resends only the tag shape the sender writes. Values after the
    // name are ignored on read, so that artifact no longer matches either.
    let mut never_written = unreadable_client_tags("whitenoise");
    never_written.push(vec![client_tag(&["whitenoise", "31990:abc:app"])]);
    // Such an artifact is unusable rather than retryable, so the runtime
    // re-signs it instead of retrying it until it expires (D8).
    for tags in never_written {
        let artifact = artifact_with_client_tags(&keys, &prepared, tags.clone());
        let attempts = relay.attempted_events().len();
        let error = publisher
            .publish_prepared_key_package(&publication, &artifact)
            .await
            .expect_err(&format!("{tags:?}"));
        assert!(
            error.artifact_unusable && !error.externally_exposed,
            "{tags:?}"
        );
        assert_eq!(relay.attempted_events().len(), attempts, "{tags:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selection_ignores_the_client_tag() {
    let (_dir, app, accounts, _) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let now = unix_now_seconds();
    let slot_event = |slot: &str, client_tags: Vec<Vec<String>>, created_at: u64| {
        // Each slot is its own device, so neither collapses into the other.
        let event = member_resolution_key_package_event(
            account,
            package_expiring_at(&app, account, now + 3_000, true),
        );
        let mut tags = event.tags;
        tags.iter_mut().find(|tag| tag[0] == "d").unwrap()[1] = slot.into();
        tags.extend(client_tags);
        NostrTransportEvent::new_unsigned_at(
            event.pubkey,
            event.kind,
            tags,
            event.content,
            created_at,
        )
    };
    let select = |events: Vec<NostrTransportEvent>| {
        select_key_packages_from_records(
            &account.account_id_hex,
            &events
                .into_iter()
                .map(|event| RelayEventRecord {
                    event,
                    endpoints: vec![],
                })
                .collect::<Vec<_>>(),
            app.directory().directory_freshness_for_test(),
            None,
        )
        .unwrap()
        .value
        .into_iter()
        .map(|fetched| fetched.key_package_event_id)
        .collect::<Vec<_>>()
    };
    let untagged = slot_event("untagged", Vec::new(), now - 10);
    let mut every_shape = vec![
        vec![client_tag(&["amethyst"])],
        vec![client_tag(&[
            "amethyst",
            "31990:abc:app",
            "wss://hint.example",
        ])],
    ];
    every_shape.extend(unreadable_client_tags("amethyst"));
    for tags in every_shape {
        // Neither a readable nor an unreadable tag rejects the package or
        // moves it: recency alone ranks the two devices.
        let labelled = slot_event("labelled", tags.clone(), now);
        assert_eq!(
            select(vec![untagged.clone(), labelled.clone()]),
            vec![labelled.id.clone(), untagged.id.clone()],
            "{tags:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_key_package_events_carry_the_client_tag() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice_account = home.create_account("alice").unwrap();
    let bob_account = home.create_account("bob").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        RELAY,
        MarmotAppConfig::white_noise().with_key_package_client_name(Some("whitenoise".into())),
    )
    .with_test_relay_client(relay.clone());
    remember_test_member_inbox(&app, &bob_account.account_id_hex, RELAY);
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();
    let mut alice = app.client("alice").await.unwrap();
    alice.publish_key_package().await.unwrap();
    let group = alice
        .create_group("client tags", &[&bob_account.account_id_hex])
        .await
        .unwrap();
    alice.send(&group, b"hello").await.unwrap();
    let bootstrap =
        || AccountRelayListBootstrap::new(vec![TransportEndpoint(RELAY.into())], vec![]);
    app.publish_account_relay_lists("alice", bootstrap())
        .await
        .unwrap();
    app.publish_user_profile(
        "alice",
        UserProfileMetadata {
            name: Some("Alice".into()),
            ..UserProfileMetadata::default()
        },
        bootstrap(),
    )
    .await
    .unwrap();
    app.publish_account_follow_list("alice", &[], bootstrap())
        .await
        .unwrap();
    let alice_key_package = relay
        .attempted_events()
        .into_iter()
        .find(|event| {
            event.kind == KIND_MARMOT_KEY_PACKAGE && event.pubkey == alice_account.account_id_hex
        })
        .unwrap();
    app.delete_key_package_event(
        "alice",
        &alice_key_package.id,
        vec![TransportEndpoint(RELAY.into())],
    )
    .await
    .unwrap();

    let keys_for = |account_id_hex: &str| {
        let label = [&alice_account, &bob_account]
            .into_iter()
            .find(|account| account.account_id_hex == account_id_hex)
            .unwrap()
            .label
            .clone();
        home.load_signing_keys(&label).unwrap()
    };
    let mut kinds = BTreeSet::new();
    for event in relay.attempted_events() {
        kinds.insert(event.kind);
        if event.kind == KIND_MARMOT_KEY_PACKAGE {
            assert_eq!(
                client_tags(&event.tags),
                [&client_tag(&["whitenoise"])],
                "a KeyPackage carries exactly the configured tag"
            );
            continue;
        }
        assert!(
            client_tags(&event.tags).is_empty(),
            "kind {} carries a client tag",
            event.kind
        );
        if event.kind == 1059 {
            // The seal and the rumor inside a gift wrap carry none either.
            let wrap = event.to_verified_nostr_event().unwrap();
            let recipient = event.single_tag_value("p").unwrap();
            let keys = keys_for(recipient);
            let seal: NostrTransportEvent = serde_json::from_str(
                &nostr::nips::nip44::decrypt(keys.secret_key(), &wrap.pubkey, &wrap.content)
                    .unwrap(),
            )
            .unwrap();
            assert!(
                client_tags(&seal.tags).is_empty(),
                "a seal carries a client tag"
            );
            let rumor = nostr::nips::nip59::extract_rumor(&keys, &wrap)
                .unwrap()
                .rumor;
            let rumor_tags = rumor
                .tags
                .iter()
                .map(|tag| tag.as_slice().to_vec())
                .collect::<Vec<_>>();
            assert!(
                client_tags(&rumor_tags).is_empty(),
                "a kind {} rumor carries a client tag",
                rumor.kind
            );
            kinds.insert(u64::from(rumor.kind.as_u16()));
        }
    }
    for kind in [
        KIND_MARMOT_KEY_PACKAGE,
        1059,
        444,
        transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE,
        5,
        KIND_NIP65_RELAY_LIST,
        KIND_MARMOT_INBOX_RELAY_LIST,
        0,
        3,
    ] {
        assert!(
            kinds.contains(&kind),
            "the sweep never published kind {kind}"
        );
    }
}
