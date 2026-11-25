//! Existing-key onboarding against relays that fail the way production relays
//! do, over real WebSockets (see `support/fault_relay.rs`).
//!
//! Each test signs in a fresh key through `MarmotAppRuntime::account_setup`.
//! The cases cover transport errors and their effect on the user's options,
//! using signed records and the real inspector and publisher.
//!
//! Every relay is loopback, so `append_public_indexers` adds nothing. The
//! White Noise scenario still searches indexers the way Android does: Android
//! passes the indexers as discovery relays, and the deployment names the same
//! loopback relays as its indexers, so `authoritative_answered` sees them as
//! indexers.
//!
//! Run `cargo test -p marmot-app --test onboarding_relay_faults -- --nocapture`
//! to see each scenario's pauses and decisions. The traces record current
//! outcomes for #3730 while assertions check contracts common to the fixes.

#[path = "support/fault_relay.rs"]
mod fault_relay;

use fault_relay::{FaultRelay, Faults, Traffic, Upgrade, Write};
use marmot_app::{
    MarmotApp, MarmotAppConfig, MarmotAppRuntime, MarmotDeployment, OnboardingAction as Action,
    OnboardingFindingContext, OnboardingIssue as Issue, OnboardingOptions,
    OnboardingRelayRepairMode, OnboardingRelayTagDisposition, OnboardingSnapshot,
    OnboardingStatus as Status, OnboardingStep, OnboardingStepState,
};
use nostr::prelude::ToBech32;
use nostr_relay_builder::RelayBuilder;
use nostr_relay_builder::builder::{RelayBuilderNip42, RelayBuilderNip42Mode};
use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

const NIP05_BLOCK: &str = "blocked: NIP-05 verification needed to publish events";

/// Named relays. Names stand in for the production hosts they imitate.
struct Net(Vec<(&'static str, FaultRelay)>);

impl Net {
    fn relay(&self, name: &str) -> &FaultRelay {
        &self.0.iter().find(|(n, _)| *n == name).unwrap().1
    }

    fn url(&self, name: &str) -> String {
        self.relay(name).url.clone()
    }

    fn urls(&self, names: &[&str]) -> Vec<String> {
        names.iter().map(|name| self.url(name)).collect()
    }

    fn name(&self, url: &str) -> String {
        let url = url.trim_end_matches('/');
        self.0
            .iter()
            .find(|(_, relay)| relay.url == url)
            .map_or_else(|| url.to_owned(), |(name, _)| (*name).to_owned())
    }

    async fn seed(&self, names: &[&str], events: &[String]) {
        for name in names {
            for event in events {
                self.relay(name).seed(event).await;
            }
        }
    }
}

/// What the host app passes: its relays and the deployment's indexers.
struct Host<'a> {
    discovery: &'a [&'a str],
    defaults: &'a [&'a str],
    inbox: &'a [&'a str],
    indexers: &'a [&'a str],
}

struct Account {
    _dir: tempfile::TempDir,
    runtime: MarmotAppRuntime,
    keys: Keys,
    id: String,
}

/// An app whose deployment names `host.indexers` as its public indexers.
fn app(net: &Net, host: &Host<'_>) -> (tempfile::TempDir, MarmotAppRuntime) {
    storage_sqlite::relax_storage_for_test_process();
    let dir = tempfile::tempdir().unwrap();
    let deployment = MarmotDeployment {
        discovery_indexer_relays: net.urls(host.indexers),
        recovery_operated_relays: net.urls(host.inbox),
        relay_event_limits: Vec::new(),
        ..MarmotDeployment::white_noise()
    };
    let config = MarmotAppConfig::white_noise()
        .with_deployment(deployment)
        .with_open_ranking_provider(None, Vec::new())
        .with_allow_loopback_relay_endpoints(true);
    let app = MarmotApp::with_relays_and_config(dir.path(), net.urls(host.defaults), config);
    (dir, MarmotAppRuntime::new(app))
}

#[allow(
    clippy::needless_update,
    reason = "Inherit the defaults of new optional host settings"
)]
fn options(net: &Net, host: &Host<'_>) -> OnboardingOptions {
    OnboardingOptions {
        default_relays: net.urls(host.defaults),
        discovery_relays: net.urls(host.discovery),
        inbox_relays: net.urls(host.inbox),
        ..OnboardingOptions::default()
    }
}

impl Account {
    /// Start onboarding a fresh local key as Android does.
    async fn begin(net: &Net, host: &Host<'_>) -> Self {
        let keys = Keys::generate();
        let (dir, runtime) = app(net, host);
        let snapshot = runtime
            .account_setup()
            .begin_onboarding(
                zeroize::Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
                options(net, host),
            )
            .await
            .unwrap();
        assert!(!snapshot.ready);
        Self {
            _dir: dir,
            runtime,
            id: keys.public_key().to_hex(),
            keys,
        }
    }

    fn record(&self, kind: u16, tags: &[&[&str]], content: &str, created_at: u64) -> String {
        let tags = tags
            .iter()
            .map(|fields| Tag::parse(fields.iter().copied()).unwrap())
            .collect::<Vec<_>>();
        let event = EventBuilder::new(Kind::from(kind), content)
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(created_at))
            .finalize(&self.keys)
            .unwrap();
        serde_json::to_string(&event).unwrap()
    }

    /// A valid profile and follow list.
    fn profile_and_follows(&self) -> Vec<String> {
        let at = now() - 3_600;
        let follow = Keys::generate().public_key().to_hex();
        vec![
            self.record(0, &[], r#"{"name":"Existing user"}"#, at),
            self.record(3, &[&["p", &follow]], "", at),
        ]
    }

    /// A kind-10002 with unmarked `r` tags for `relays`.
    fn relay_list(&self, net: &Net, relays: &[&str], at: u64) -> String {
        let urls = net.urls(relays);
        let tags = urls.iter().map(|url| vec!["r", url]).collect::<Vec<_>>();
        let tags = tags.iter().map(Vec::as_slice).collect::<Vec<_>>();
        self.record(10002, &tags, "", at)
    }

    async fn shutdown(self) {
        // Setup may have queued worker startup by the time it returns ready.
        self.runtime.shutdown().await;
        self.runtime.shutdown_and_close().await.unwrap();
    }
}

fn now() -> u64 {
    Timestamp::now().as_secs()
}

fn step(snapshot: &OnboardingSnapshot, step: OnboardingStep) -> &OnboardingStepState {
    snapshot.steps.iter().find(|s| s.step == step).unwrap()
}

fn current(snapshot: &OnboardingSnapshot) -> Option<&OnboardingStepState> {
    snapshot
        .steps
        .iter()
        .find(|s| !matches!(s.status, Status::Passed | Status::Skipped))
}

/// The issue onboarding reports for `relay`'s record lookup, if any.
fn issue_for(net: &Net, state: &OnboardingStepState, relay: &str) -> Option<Issue> {
    state
        .findings
        .iter()
        .find(|f| f.endpoint.as_deref().is_some_and(|e| net.name(e) == relay))
        .map(|f| f.issue)
}

fn describe(net: &Net, snapshot: &OnboardingSnapshot, state: &OnboardingStepState) -> String {
    let findings = state
        .findings
        .iter()
        .map(|f| match &f.endpoint {
            Some(endpoint) => format!("{:?}@{}/{:?}", f.issue, net.name(endpoint), f.context),
            None => format!("{:?}/{:?}", f.issue, f.context),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let proposal = snapshot.proposal.as_ref().map_or(String::new(), |p| {
        let added = p.relay_repair.as_ref().map_or(Vec::new(), |r| {
            r.changes
                .iter()
                .filter(|c| c.disposition == OnboardingRelayTagDisposition::Added)
                .filter_map(|c| c.endpoint.as_deref().map(|e| net.name(e)))
                .collect()
        });
        let mode = p.relay_repair.as_ref().map(|r| r.mode);
        format!(
            " proposal={mode:?} adds={added:?} inconclusive={}",
            p.inconclusive
        )
    });
    format!(
        "{:?} {:?} [{findings}] actions={:?}{proposal}",
        state.step, state.status, state.actions
    )
}

/// The pauses and decisions of one onboarding attempt.
struct Drive {
    snapshot: OnboardingSnapshot,
    transcript: Vec<String>,
    /// Decisions a user made (automatic follow-list skips excluded).
    decisions: usize,
    /// The pause Android could not get past, if any.
    stuck: Option<String>,
}

impl Drive {
    fn print(&self, scenario: &str) {
        eprintln!("== {scenario}");
        for line in &self.transcript {
            eprintln!("   {line}");
        }
        eprintln!(
            "   => ready={} decisions={} stuck={:?}",
            self.snapshot.ready, self.decisions, self.stuck
        );
    }
}

/// Answer each pause with Android's primary button (`AccountSetupButtons`):
/// approve a repair, continue without an optional record, acknowledge the
/// device notice, review suggested relay changes, else retry. Follows are
/// skipped automatically (`AccountSetupDefaults.advance`). A pause that
/// recurs unchanged after its answer is a stall.
async fn drive_like_android(
    net: &Net,
    account: &Account,
    mut snapshot: OnboardingSnapshot,
    max_decisions: usize,
) -> Drive {
    let setup = account.runtime.account_setup();
    let id = account.id.as_str();
    let mut transcript = Vec::new();
    let mut decisions = 0;
    let mut seen = HashSet::new();
    let mut stuck = None;
    loop {
        if snapshot.ready {
            transcript.push("ready".to_owned());
            break;
        }
        let Some(state) = current(&snapshot).cloned() else {
            break;
        };
        let pause = describe(net, &snapshot, &state);
        if !seen.insert(pause.clone()) || decisions >= max_decisions {
            stuck = Some(pause);
            break;
        }
        let has = |action| state.actions.contains(&action);
        let started = Instant::now();
        let (label, result, automatic) = if matches!(state.status, Status::Pending) {
            ("resume checks", setup.run_onboarding(id).await, true)
        } else if snapshot.proposal.is_some() && has(Action::ApproveRepair) {
            let result = setup.approve_onboarding_repair(id, snapshot.revision).await;
            ("approve", result, false)
        } else if snapshot.proposal.as_ref().is_some_and(|p| {
            p.relay_repair
                .as_ref()
                .is_some_and(|r| r.mode == OnboardingRelayRepairMode::ManualReview)
        }) {
            stuck = Some(format!("{pause} (manual review only)"));
            break;
        } else if state.step == OnboardingStep::Follows && has(Action::ContinueWithout) {
            let result = setup
                .continue_onboarding_without(id, OnboardingStep::Follows)
                .await;
            ("skip follows", result, true)
        } else if state.step == OnboardingStep::Profile && has(Action::ContinueWithout) {
            let result = setup
                .continue_onboarding_without(id, OnboardingStep::Profile)
                .await;
            ("continue without profile", result, false)
        } else if has(Action::ContinueAnyway) {
            let result = setup
                .acknowledge_onboarding_single_device(id, snapshot.revision)
                .await;
            ("continue anyway", result, false)
        } else if has(Action::UseRecommendedRelays) {
            let result = setup.propose_onboarding_relay_repair(id, state.step).await;
            ("review suggested changes", result, false)
        } else if has(Action::Retry) {
            (
                "retry",
                setup.retry_onboarding_step(id, state.step).await,
                false,
            )
        } else {
            stuck = Some(format!("{pause} (no primary action)"));
            break;
        };
        transcript.push(format!(
            "{pause}\n      -> {label} ({:.1}s)",
            started.elapsed().as_secs_f64()
        ));
        decisions += usize::from(!automatic);
        snapshot = result.unwrap_or_else(|error| panic!("{label} at {pause}: {error:?}"));
    }
    Drive {
        snapshot,
        transcript,
        decisions,
        stuck,
    }
}

/// White Noise's production layout, imitated: two strfry host relays that
/// close 443/10051 reads, the public indexers, and the user's own outboxes.
async fn white_noise_net() -> Net {
    let mut relays = Vec::new();
    for name in ["wn-us", "wn-eu"] {
        relays.push((
            name,
            FaultRelay::with_faults(Faults::white_noise_strfry()).await,
        ));
    }
    for name in [
        "purplepag.es",
        "vertexlab",
        "nos.lol",
        "ditto",
        "primal",
        "nostrdev",
    ] {
        relays.push((name, FaultRelay::with_faults(Faults::default()).await));
    }
    relays.push((
        "einundzwanzig",
        FaultRelay::with_faults(Faults::rejecting_writes(NIP05_BLOCK)).await,
    ));
    relays.push((
        "damus",
        FaultRelay::with_faults(Faults {
            upgrade: Upgrade::Status(503),
            ..Faults::default()
        })
        .await,
    ));
    Net(relays)
}

/// One relay is the host's discovery, default and inbox relay; no indexers.
const ONE_HOST: Host<'static> = Host {
    discovery: &["host"],
    defaults: &["host"],
    inbox: &["host"],
    indexers: &[],
};

/// `AccountSetupCoordinator` / `MarmotClient` options.
const ANDROID: Host<'static> = Host {
    discovery: &[
        "wn-us",
        "wn-eu",
        "purplepag.es",
        "vertexlab",
        "nos.lol",
        "ditto",
        "primal",
    ],
    defaults: &["wn-us", "wn-eu", "nos.lol", "primal", "nostrdev"],
    inbox: &["wn-us", "wn-eu"],
    indexers: &["purplepag.es", "vertexlab", "nos.lol", "ditto", "primal"],
};

const USER_OUTBOXES: &[&str] = &[
    "primal",
    "einundzwanzig",
    "nos.lol",
    "damus",
    "purplepag.es",
];

/// Seed the reported user's records: profile, follows and a five-relay
/// 10002 on every public relay, no 10050 anywhere.
async fn seed_reported_user(net: &Net, account: &Account) {
    let mut records = account.profile_and_follows();
    records.push(account.relay_list(net, USER_OUTBOXES, now() - 600));
    net.seed(
        &[
            "primal",
            "einundzwanzig",
            "nos.lol",
            "damus",
            "purplepag.es",
            "vertexlab",
            "ditto",
        ],
        &records,
    )
    .await;
}

async fn run_reported_user(upgrade: Upgrade) -> Traffic {
    let net = white_noise_net().await;
    net.relay("damus").set_faults(Faults {
        upgrade,
        ..Faults::default()
    });
    let account = Account::begin(&net, &ANDROID).await;
    seed_reported_user(&net, &account).await;
    let started = Instant::now();
    let snapshot = account
        .runtime
        .account_setup()
        .run_onboarding(&account.id)
        .await
        .unwrap();
    let first_run = started.elapsed();
    let drive = drive_like_android(&net, &account, snapshot, 8).await;
    drive.print(&format!(
        "reported user {upgrade:?} (first run {:.1}s, total {:.1}s)",
        first_run.as_secs_f64(),
        started.elapsed().as_secs_f64()
    ));

    assert!(
        ANDROID
            .inbox
            .iter()
            .any(|name| { net.relay(name).traffic().accepted_writes.contains(&10050) })
    );
    // No REQ for 443 or 10051 is ever sent, so strfry's refusal is moot.
    for name in ["wn-us", "wn-eu"] {
        assert!(
            net.relay(name)
                .traffic()
                .reqs
                .iter()
                .flatten()
                .all(|kind| ![443, 10051].contains(kind)),
            "{name}"
        );
    }
    assert!(drive.snapshot.ready, "{:#?}", drive.transcript);
    assert_eq!(drive.stuck, None);
    // Before the fixes, the inbox proposal takes two decisions and the device
    // notice takes one. The fixes can take either pause away.
    assert!(drive.decisions <= 3, "{:#?}", drive.transcript);
    let outbox_traffic = net.relay("damus").traffic();
    account.shutdown().await;
    outbox_traffic
}

/// The reported sign-in uses a working 10002, a missing 10050, one reader
/// returning 503 and one writer refusing publication.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reported_user_can_finish_with_one_unreachable_outbox() {
    let traffic = run_reported_user(Upgrade::Status(503)).await;
    assert!(traffic.rejected_upgrades > 0);
    assert!(traffic.reqs.is_empty(), "{traffic:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reported_user_can_finish_after_one_failed_outbox_upgrade() {
    let traffic = run_reported_user(Upgrade::StatusOnce(503)).await;
    assert_eq!(traffic.rejected_upgrades, 1);
    assert!(
        traffic.reqs.iter().flatten().any(|kind| *kind == 10050),
        "{traffic:?}"
    );
}

/// Fail a source between preview and save. The initial consent cannot
/// authorize a write after that change in the freshness check.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbox_approval_does_not_publish_after_losing_a_freshness_source() {
    let net = white_noise_net().await;
    net.relay("damus").set_faults(Faults::default());
    let account = Account::begin(&net, &ANDROID).await;
    seed_reported_user(&net, &account).await;
    let setup = account.runtime.account_setup();
    let snapshot = setup.run_onboarding(&account.id).await.unwrap();
    let inbox = step(&snapshot, OnboardingStep::InboxRelays);
    assert!(
        inbox.actions.contains(&Action::UseRecommendedRelays),
        "{inbox:?}"
    );
    let preview = setup
        .propose_onboarding_relay_repair(&account.id, OnboardingStep::InboxRelays)
        .await
        .unwrap();
    let proposal = preview.proposal.as_ref().unwrap();
    assert!(!proposal.inconclusive);
    let upgrade_failures = net.relay("damus").traffic().rejected_upgrades;
    net.relay("damus").set_faults(Faults {
        upgrade: Upgrade::Status(503),
        ..Faults::default()
    });
    let approved = setup
        .approve_onboarding_repair(&account.id, preview.revision)
        .await
        .unwrap();
    let inbox = step(&approved, OnboardingStep::InboxRelays);
    eprintln!("== approval flip\n   {}", describe(&net, &approved, inbox));
    assert!(net.relay("damus").traffic().rejected_upgrades > upgrade_failures);
    assert_eq!(issue_for(&net, inbox, "damus"), Some(Issue::Unreachable));
    assert!(
        net.0
            .iter()
            .all(|(_, relay)| !relay.traffic().writes.contains(&10050))
    );
    if let Some(proposal) = &approved.proposal {
        assert!(proposal.inconclusive);
        assert!(inbox.actions.contains(&Action::ApproveRepair));
        assert_ne!(approved.revision, preview.revision);
    }
    account.shutdown().await;
}

/// How a faulty relay misbehaves.
enum Probe {
    Faults(Faults),
    Builder(RelayBuilder),
    Both(RelayBuilder, Faults),
    Refusing,
}

impl Probe {
    async fn spawn(self) -> FaultRelay {
        match self {
            Probe::Faults(faults) => FaultRelay::with_faults(faults).await,
            Probe::Builder(builder) => FaultRelay::spawn(builder, Faults::default()).await,
            Probe::Both(builder, faults) => FaultRelay::spawn(builder, faults).await,
            Probe::Refusing => FaultRelay::refusing(),
        }
    }
}

/// The kinds onboarding's record lookups ask for.
const LOOKUP_KINDS: &[u64] = &[0, 3, 10002, 10050];

fn closing(reason: &str) -> Probe {
    Probe::Faults(Faults::closing(LOOKUP_KINDS, reason))
}

fn faults(faults: Faults) -> Probe {
    Probe::Faults(faults)
}

/// One host relay holds the profile, follows and a 10002 declaring the host
/// and the faulty relay; no 10050 exists and no indexer is configured. The
/// host answers, so the 10002 check passes and the faulty relay alone
/// decides whether the missing inbox list is conclusive.
async fn read_case(behavior: &str, probe: Probe, expected_issues: &[Issue]) {
    let net = Net(vec![
        ("host", FaultRelay::with_faults(Faults::default()).await),
        ("faulty", probe.spawn().await),
    ]);
    let account = Account::begin(&net, &ONE_HOST).await;
    let mut records = account.profile_and_follows();
    records.push(account.relay_list(&net, &["host", "faulty"], now() - 600));
    net.seed(&["host"], &records).await;
    let started = Instant::now();
    let snapshot = account
        .runtime
        .account_setup()
        .run_onboarding(&account.id)
        .await
        .unwrap();
    let elapsed = started.elapsed().as_secs_f64();
    assert_eq!(
        step(&snapshot, OnboardingStep::Relays).status,
        Status::Passed,
        "{snapshot:#?}"
    );
    let inbox = step(&snapshot, OnboardingStep::InboxRelays);
    let traffic = net.relay("faulty").traffic();
    eprintln!(
        "   {behavior} ({elapsed:.1}s): {} | faulty relay saw {} connections, {} REQs, {} AUTH challenges, {} AUTH replies",
        describe(&net, &snapshot, inbox),
        traffic.connections,
        traffic.reqs.len(),
        traffic.challenges,
        traffic.auths
    );
    let issue = issue_for(&net, inbox, "faulty");
    if expected_issues.is_empty() {
        assert_eq!(issue, None, "{behavior}: {inbox:?}");
        if inbox.status == Status::Passed {
            assert!(net.relay("host").traffic().accepted_writes.contains(&10050));
        } else {
            assert!(
                inbox
                    .findings
                    .iter()
                    .any(|finding| finding.issue == Issue::Missing),
                "{behavior}: expected conclusive absence, got {inbox:?}"
            );
        }
    } else {
        assert!(
            issue.is_some_and(|issue| expected_issues.contains(&issue)),
            "{behavior}: expected a relay issue from {expected_issues:?}, got {inbox:?}"
        );
    }
    account.shutdown().await;
}

/// Each row: the relay behaviour, then what MDK makes of it at InboxRelays
/// when the 10050 is absent. Rows run concurrently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_read_behaviours_are_classified_over_the_wire() {
    use Issue::*;
    let cases: Vec<(&str, Probe, &[Issue])> = vec![
        (
            "HTTP 503 on upgrade",
            faults(Faults {
                upgrade: Upgrade::Status(503),
                ..Faults::default()
            }),
            &[Unreachable],
        ),
        ("connection refused", Probe::Refusing, &[Unreachable]),
        (
            "handshake never answered",
            faults(Faults {
                upgrade: Upgrade::Stall,
                ..Faults::default()
            }),
            &[TimedOut],
        ),
        (
            "socket dropped on REQ",
            faults(Faults {
                drop_on_req: true,
                ..Faults::default()
            }),
            &[Unreachable],
        ),
        (
            "REQ never gets EOSE",
            faults(Faults {
                hold_eose: true,
                ..Faults::default()
            }),
            &[TimedOut],
        ),
        (
            "CLOSED bad req: kind not allowed (lookup kinds)",
            closing("bad req: filter validation failed: kind not allowed: 10050"),
            &[AccessRestricted],
        ),
        (
            "CLOSED bad req: kind not allowed (443/10051 only, strfry WN)",
            faults(Faults::white_noise_strfry()),
            &[],
        ),
        (
            "CLOSED rate-limited:",
            closing("rate-limited: slow down"),
            &[AccessRestricted, Unreachable],
        ),
        (
            "CLOSED restricted:",
            closing("restricted: members only"),
            &[AccessRestricted],
        ),
        (
            "CLOSED error: shutting down",
            closing("error: shutting down"),
            &[AccessRestricted, Unreachable],
        ),
        (
            "CLOSED auth-required: with no AUTH challenge ever sent",
            closing("auth-required: members only"),
            &[TimedOut, AuthenticationRequired],
        ),
        (
            "NIP-42 for every read, AUTH refused (OK false restricted:)",
            Probe::Both(
                RelayBuilder::default().nip42(RelayBuilderNip42 {
                    mode: RelayBuilderNip42Mode::Read,
                }),
                Faults {
                    reject_auth: Some("restricted: not on the allow list".into()),
                    ..Faults::default()
                },
            ),
            &[AuthenticationRequired],
        ),
        (
            "CLOSED payment-required:",
            closing("payment-required: pay first"),
            &[PaymentRequired],
        ),
        (
            "EOSE with NIP-67 [\"more\"]",
            faults(Faults {
                eose_hint: Some("more".into()),
                ..Faults::default()
            }),
            &[DiscoveryIncomplete],
        ),
        (
            "EOSE with NIP-67 [\"auth\"]",
            faults(Faults {
                eose_hint: Some("auth".into()),
                ..Faults::default()
            }),
            &[DiscoveryIncomplete, AuthenticationRequired, TimedOut],
        ),
        (
            "NIP-42 required for every read (local key)",
            Probe::Builder(RelayBuilder::default().nip42(RelayBuilderNip42 {
                mode: RelayBuilderNip42Mode::Read,
            })),
            &[],
        ),
        (
            "OK false blocked: NIP-05 (writes only)",
            faults(Faults::rejecting_writes(NIP05_BLOCK)),
            &[],
        ),
        (
            "never sends OK (writes only)",
            faults(Faults {
                write: Write::NeverOk,
                ..Faults::default()
            }),
            &[],
        ),
    ];
    let started = Instant::now();
    futures::future::join_all(
        cases
            .into_iter()
            .map(|(behavior, probe, expected)| read_case(behavior, probe, expected)),
    )
    .await;
    eprintln!(
        "== read behaviours ({:.1}s wall)",
        started.elapsed().as_secs_f64()
    );
}

/// One relay is the host's only relay and the account's only outbox, so its
/// write behaviour alone decides whether onboarding's publications land.
async fn write_case(name: &str, write: Write) {
    let accepts = write == Write::Accept;
    let net = Net(vec![(
        "host",
        FaultRelay::with_faults(Faults {
            write,
            ..Faults::default()
        })
        .await,
    )]);
    let account = Account::begin(&net, &ONE_HOST).await;
    let mut records = account.profile_and_follows();
    records.push(account.relay_list(&net, &["host"], now() - 600));
    net.seed(&["host"], &records).await;
    let snapshot = account
        .runtime
        .account_setup()
        .run_onboarding(&account.id)
        .await
        .unwrap();
    let drive = drive_like_android(&net, &account, snapshot, 6).await;
    drive.print(name);
    let traffic = net.relay("host").traffic();
    assert!(traffic.writes.contains(&10050), "{name}: {traffic:?}");
    assert_eq!(traffic.accepted_writes.contains(&10050), accepts, "{name}");
    assert_eq!(
        drive.snapshot.ready, accepts,
        "{name}: {:#?}",
        drive.transcript
    );
    if !accepts {
        let inbox = step(&drive.snapshot, OnboardingStep::InboxRelays);
        assert_ne!(inbox.status, Status::Passed, "{name}: {inbox:?}");
    }
    account.shutdown().await;
}

/// A single target must acknowledge the inbox list before setup can finish.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writing_an_inbox_list_requires_at_least_one_ack() {
    let cases = [
        ("accepts", Write::Accept),
        (
            "OK false blocked: NIP-05",
            Write::Reject(NIP05_BLOCK.into()),
        ),
        (
            "OK false restricted:",
            Write::Reject("restricted: not a member".into()),
        ),
        (
            "OK false rate-limited:",
            Write::Reject("rate-limited: slow down".into()),
        ),
        ("never sends OK", Write::NeverOk),
    ];
    let started = Instant::now();
    futures::future::join_all(
        cases
            .into_iter()
            .map(|(name, write)| write_case(name, write)),
    )
    .await;
    eprintln!(
        "== write behaviours ({:.1}s wall)",
        started.elapsed().as_secs_f64()
    );
}

/// A relay that requires NIP-42 before serving kind-1059 reads (`auth_dm`)
/// is the declared inbox. With the local key, the probe answers the
/// challenge and the inbox route passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbox_relay_requiring_auth_for_gift_wraps_passes_with_the_local_key() {
    let net = Net(vec![
        ("host", FaultRelay::with_faults(Faults::default()).await),
        (
            "protected-inbox",
            FaultRelay::spawn(RelayBuilder::default().auth_dm(true), Faults::default()).await,
        ),
    ]);
    let account = Account::begin(&net, &ONE_HOST).await;
    let mut records = account.profile_and_follows();
    records.push(account.relay_list(&net, &["host"], now() - 600));
    let inbox = net.url("protected-inbox");
    records.push(account.record(10050, &[&["relay", &inbox]], "", now() - 600));
    net.seed(&["host"], &records).await;
    let snapshot = account
        .runtime
        .account_setup()
        .run_onboarding(&account.id)
        .await
        .unwrap();
    let state = step(&snapshot, OnboardingStep::InboxRelays);
    let traffic = net.relay("protected-inbox").traffic();
    eprintln!(
        "== 1059 auth\n   {} | challenges={} auths={} reqs={:?}",
        describe(&net, &snapshot, state),
        traffic.challenges,
        traffic.auths,
        traffic.reqs
    );
    assert_eq!(state.status, Status::Passed, "{state:?}");
    assert!(traffic.challenges >= 1 && traffic.auths >= 1, "{traffic:?}");
    assert!(traffic.reqs.iter().all(|kinds| kinds == &[1059]));
    account.shutdown().await;
}

/// An external signer whose AUTH prompt stays unanswered until the request is
/// cancelled. Every other request is answered at once.
#[derive(Clone, Debug)]
struct RemoteSigner {
    keys: Keys,
    auth_requests: Arc<AtomicUsize>,
}

type SignerResult<'a, T> =
    transport_nostr_peeler::SignerFuture<'a, Result<T, transport_nostr_peeler::MarmotSignerError>>;

impl transport_nostr_peeler::MarmotNostrSigner for RemoteSigner {
    fn get_public_key(&self) -> SignerResult<'_, nostr::prelude::PublicKey> {
        transport_nostr_peeler::MarmotNostrSigner::get_public_key(&self.keys)
    }
    fn sign_event(
        &self,
        unsigned: nostr::prelude::UnsignedEvent,
    ) -> SignerResult<'_, nostr::prelude::Event> {
        Box::pin(async move {
            if unsigned.kind.as_u16() == 22242 {
                self.auth_requests.fetch_add(1, Ordering::SeqCst);
                return std::future::pending().await;
            }
            transport_nostr_peeler::MarmotNostrSigner::sign_event(&self.keys, unsigned).await
        })
    }
    fn nip04_encrypt<'a>(
        &'a self,
        key: &'a nostr::prelude::PublicKey,
        content: &'a str,
    ) -> SignerResult<'a, String> {
        transport_nostr_peeler::MarmotNostrSigner::nip04_encrypt(&self.keys, key, content)
    }
    fn nip04_decrypt<'a>(
        &'a self,
        key: &'a nostr::prelude::PublicKey,
        payload: &'a str,
    ) -> SignerResult<'a, String> {
        transport_nostr_peeler::MarmotNostrSigner::nip04_decrypt(&self.keys, key, payload)
    }
    fn nip44_encrypt<'a>(
        &'a self,
        key: &'a nostr::prelude::PublicKey,
        content: &'a str,
    ) -> SignerResult<'a, String> {
        transport_nostr_peeler::MarmotNostrSigner::nip44_encrypt(&self.keys, key, content)
    }
    fn nip44_decrypt<'a>(
        &'a self,
        key: &'a nostr::prelude::PublicKey,
        payload: &'a str,
    ) -> SignerResult<'a, String> {
        transport_nostr_peeler::MarmotNostrSigner::nip44_decrypt(&self.keys, key, payload)
    }
}

impl cgka_engine::account_identity_proof::AccountIdentityProofSigner for RemoteSigner {
    fn sign_account_identity_proof(
        &self,
        request: &cgka_engine::account_identity_proof::AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        let event = request
            .proof_event()
            .and_then(|event| event.finalize(&self.keys).map_err(|err| err.to_string()))?;
        request.signature_from_signed_event(event)
    }
}

/// A protected inbox route with unanswered AUTH stays unverified. The trace
/// shows how many prompts come from onboarding when the relay is also an
/// outbox used for ordinary lookups.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_remote_signer_does_not_verify_a_protected_inbox() {
    async fn case(
        inbox_relay: RelayBuilder,
        declare_in_outboxes: bool,
    ) -> (OnboardingSnapshot, usize, String, f64) {
        let net = Net(vec![
            ("host", FaultRelay::with_faults(Faults::default()).await),
            (
                "auth",
                FaultRelay::spawn(inbox_relay, Faults::default()).await,
            ),
        ]);
        let keys = Keys::generate();
        let signer = RemoteSigner {
            keys: keys.clone(),
            auth_requests: Default::default(),
        };
        let requests = signer.auth_requests.clone();
        let (dir, runtime) = app(&net, &ONE_HOST);
        let id = keys.public_key().to_hex();
        runtime
            .account_setup()
            .begin_external_signer_onboarding(id.clone(), signer, options(&net, &ONE_HOST))
            .await
            .unwrap();
        let account = Account {
            _dir: dir,
            runtime,
            keys,
            id,
        };
        let outboxes: &[&str] = if declare_in_outboxes {
            &["host", "auth"]
        } else {
            &["host"]
        };
        let mut records = account.profile_and_follows();
        records.push(account.relay_list(&net, outboxes, now() - 600));
        let auth = net.url("auth");
        records.push(account.record(10050, &[&["relay", &auth]], "", now() - 600));
        net.seed(&["host"], &records).await;
        let started = Instant::now();
        let snapshot = account
            .runtime
            .account_setup()
            .run_onboarding(&account.id)
            .await
            .unwrap();
        let elapsed = started.elapsed().as_secs_f64();
        let inbox = describe(
            &net,
            &snapshot,
            step(&snapshot, OnboardingStep::InboxRelays),
        );
        account.shutdown().await;
        (snapshot, requests.load(Ordering::SeqCst), inbox, elapsed)
    }
    let (
        (gift_wraps, gift_wrap_prompts, gift_wrap_inbox, gift_wrap_time),
        (reads, read_prompts, reads_inbox, reads_time),
    ) = tokio::join!(
        case(RelayBuilder::default().auth_dm(true), false),
        case(
            RelayBuilder::default().nip42(RelayBuilderNip42 {
                mode: RelayBuilderNip42Mode::Read,
            }),
            true,
        ),
    );
    eprintln!(
        "== slow remote signer\n   AUTH for 1059 only ({gift_wrap_time:.1}s, {gift_wrap_prompts} AUTH prompts): {gift_wrap_inbox}\n   AUTH for every read, relay also an outbox ({reads_time:.1}s, {read_prompts} AUTH prompts): {reads_inbox}"
    );
    assert!(gift_wrap_prompts >= 1);
    for snapshot in [&gift_wraps, &reads] {
        let inbox = step(snapshot, OnboardingStep::InboxRelays);
        assert!(!snapshot.ready, "{snapshot:?}");
        if inbox.status != Status::WaitingForSigner {
            assert!(
                matches!(inbox.status, Status::NeedsInput | Status::RetryableFailure),
                "{inbox:?}"
            );
            assert!(
                inbox.findings.iter().any(|finding| {
                    finding.context == OnboardingFindingContext::DeclaredRoute
                        && matches!(
                            finding.issue,
                            Issue::TimedOut | Issue::AuthenticationRequired
                        )
                }),
                "{inbox:?}"
            );
        }
    }
}
