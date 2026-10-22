//! Follow and unfollow edit the current kind-3 event in place and never
//! republish a list MDK could only read part of (mdk#2268).

use std::time::Duration;

use cgka_traits::TransportEndpoint;
use marmot_account::AccountHome;

use crate::{AccountRelayListBootstrap, AppError, MarmotApp, MarmotAppRuntime};
use nostr_directory::MAX_FOLLOW_LIST_ENTRIES;

struct Fixture {
    _relay: nostr_relay_builder::MockRelay,
    _directory: tempfile::TempDir,
    app: MarmotApp,
    runtime: MarmotAppRuntime,
    label: String,
    account_id_hex: String,
    endpoint: TransportEndpoint,
}

impl Fixture {
    async fn new() -> Self {
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let directory = tempfile::tempdir().unwrap();
        let alice = AccountHome::open(directory.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(directory.path(), url.clone());
        let runtime = app.runtime();
        Self {
            _relay: relay,
            _directory: directory,
            app,
            runtime,
            label: alice.label,
            account_id_hex: alice.account_id_hex,
            endpoint: TransportEndpoint(url),
        }
    }

    fn bootstrap(&self) -> AccountRelayListBootstrap {
        AccountRelayListBootstrap::new(vec![self.endpoint.clone()], vec![self.endpoint.clone()])
    }

    /// Publish a kind-3 event with exactly these tags and content, then step
    /// past its second so a later edit is the newer replaceable event.
    async fn seed(&self, tags: Vec<Vec<String>>, content: &str) {
        let follows = nostr_directory::follows_from_tags(&tags);
        self.app
            .publish_account_follow_list_event(
                &self.label,
                tags,
                content.to_owned(),
                follows,
                self.bootstrap(),
            )
            .await
            .expect("seed follow list");
        tokio::time::sleep(Duration::from_millis(1_050)).await;
    }

    async fn published(&self) -> (Vec<Vec<String>>, String) {
        let current = self
            .app
            .directory()
            .fetch_current_follow_list_event_for_account_id(
                &self.account_id_hex,
                vec![self.endpoint.clone()],
            )
            .await
            .expect("fetch follow list")
            .expect("a current follow list");
        (current.tags, current.content)
    }
}

fn account_id() -> String {
    nostr::prelude::Keys::generate().public_key().to_hex()
}

fn tag(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn p_tags(count: usize) -> Vec<Vec<String>> {
    (0..count).map(|_| tag(&["p", &account_id()])).collect()
}

fn sorted(mut ids: Vec<String>) -> Vec<String> {
    ids.sort();
    ids
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn follow_and_unfollow_keep_every_other_tag_and_the_content() {
    let fixture = Fixture::new().await;
    let (bob, carol, dave) = (account_id(), account_id(), account_id());
    let content = r#"{"wss://relay.example":{"read":true,"write":true}}"#;
    let seeded = vec![
        tag(&["p", &bob, "wss://bob.example", "bob"]),
        tag(&["t", "nostr"]),
        tag(&["p", &carol, "", "carol"]),
        tag(&["custom", "value"]),
    ];
    fixture.seed(seeded.clone(), content).await;

    let follows = fixture
        .runtime
        .follow_user(&fixture.label, &dave)
        .await
        .expect("follow dave");
    assert_eq!(
        follows,
        sorted(vec![bob.clone(), carol.clone(), dave.clone()])
    );
    let mut expected = seeded;
    expected.push(tag(&["p", &dave]));
    assert_eq!(fixture.published().await, (expected, content.to_owned()));
    tokio::time::sleep(Duration::from_millis(1_050)).await;

    let follows = fixture
        .runtime
        .unfollow_user(&fixture.label, &carol)
        .await
        .expect("unfollow carol");
    assert_eq!(follows, sorted(vec![bob.clone(), dave.clone()]));
    assert_eq!(
        fixture.published().await,
        (
            vec![
                tag(&["p", &bob, "wss://bob.example", "bob"]),
                tag(&["t", "nostr"]),
                tag(&["custom", "value"]),
                tag(&["p", &dave]),
            ],
            content.to_owned()
        )
    );
    assert_eq!(
        fixture.runtime.account_follows(&fixture.label).unwrap(),
        follows
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_follow_list_at_the_cap_refuses_edits_without_publishing() {
    let fixture = Fixture::new().await;
    let mut seeded = p_tags(MAX_FOLLOW_LIST_ENTRIES - 1);
    seeded.push(tag(&["t", "nostr"]));
    fixture.seed(seeded.clone(), "").await;

    // One below the cap still takes a follow, which fills the list.
    let last = account_id();
    let follows = fixture
        .runtime
        .follow_user(&fixture.label, &last)
        .await
        .expect("a list below the cap takes a follow");
    assert_eq!(follows.len(), MAX_FOLLOW_LIST_ENTRIES);
    seeded.push(tag(&["p", &last]));
    assert_eq!(fixture.published().await, (seeded.clone(), String::new()));
    tokio::time::sleep(Duration::from_millis(1_050)).await;

    let error = fixture
        .runtime
        .follow_user(&fixture.label, &account_id())
        .await
        .expect_err("a follow must not publish a list MDK read only up to its cap");
    assert!(matches!(error, AppError::FollowListTooLarge), "{error:?}");
    let error = fixture
        .runtime
        .unfollow_user(&fixture.label, &last)
        .await
        .expect_err("an unfollow must not publish a list MDK read only up to its cap");
    assert!(matches!(error, AppError::FollowListTooLarge), "{error:?}");
    assert_eq!(
        fixture.published().await,
        (seeded, String::new()),
        "refused edits leave the published list untouched"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_follow_list_over_the_cap_refuses_edits_without_publishing() {
    let fixture = Fixture::new().await;
    let seeded = p_tags(MAX_FOLLOW_LIST_ENTRIES + 10);
    let listed_last = seeded.last().unwrap()[1].clone();
    fixture.seed(seeded.clone(), "").await;

    for following in [true, false] {
        let error = fixture
            .runtime
            .update_account_follow_list(
                &fixture.label,
                &listed_last,
                following,
                vec![fixture.endpoint.clone()],
                fixture.bootstrap(),
            )
            .await
            .expect_err("a list past the cap must not be republished");
        assert!(matches!(error, AppError::FollowListTooLarge), "{error:?}");
    }
    assert_eq!(fixture.published().await, (seeded, String::new()));
}
