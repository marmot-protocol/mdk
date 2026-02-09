//! Relay compatibility testing tool for MDK/Marmot Protocol.
//!
//! Tests whether relays support NIP-70 protected events, which is required
//! for MLS key package publishing (kind 443).
//!
//! # Usage
//!
//! ```bash
//! # Test default relay set
//! cargo run -- --all
//!
//! # Test with NIP-42 authentication
//! cargo run -- --all --with-auth
//!
//! # Discover relays via NIP-66 and test them
//! cargo run -- --discover
//!
//! # Test specific relays
//! cargo run -- --relays wss://relay.damus.io,wss://nos.lol
//!
//! # Output JSON for CI/tooling
//! cargo run -- --all --json
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::Parser;
use colored::Colorize;
use nostr::prelude::*;
use nostr_sdk::{Client, RelayMessage, RelayPoolNotification};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// Relay compatibility tester for NIP-70 protected events.
#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Args {
    /// Relay URL(s) to probe, e.g. wss://nos.lol
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    relays: Vec<String>,

    /// Probe the default relay set (popular relays + known working ones).
    #[arg(long)]
    all: bool,

    /// Discover relays via NIP-66 (kind 30166) events from known monitors.
    #[arg(long)]
    discover: bool,

    /// Maximum number of relays to discover via NIP-66.
    #[arg(long, default_value_t = 50)]
    discover_limit: usize,

    /// Perform NIP-42 authentication before testing protected events.
    #[arg(long)]
    with_auth: bool,

    /// Output results as JSON.
    #[arg(long)]
    json: bool,

    /// Seconds to wait for relay responses.
    #[arg(long, default_value_t = 10)]
    timeout_secs: u64,

    /// Also test kind 443 (MLS key package) in addition to kind 1.
    #[arg(long, default_value_t = true)]
    kind_443: bool,

    /// Update the relay status file after testing.
    #[arg(long)]
    update_status: bool,
}

/// Result of testing a single relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayTestResult {
    /// Relay URL.
    url: String,
    /// Whether the relay is reachable.
    reachable: bool,
    /// Whether relay sent an AUTH challenge.
    auth_challenge_received: bool,
    /// Whether NIP-42 authentication succeeded.
    auth_success: bool,
    /// Results for each event kind tested (without auth).
    kind_results: HashMap<u16, KindTestResult>,
    /// Results for each event kind tested (with auth, if --with-auth).
    #[serde(skip_serializing_if = "Option::is_none")]
    kind_results_with_auth: Option<HashMap<u16, KindTestResult>>,
    /// Error message if connection failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// When the test was performed.
    tested_at: DateTime<Utc>,
}

/// Result of testing a specific event kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KindTestResult {
    /// Whether unprotected events are accepted.
    unprotected_accepted: bool,
    /// Whether NIP-70 protected events are accepted.
    protected_accepted: bool,
    /// Error/rejection message for protected events.
    #[serde(skip_serializing_if = "Option::is_none")]
    protected_rejection_reason: Option<String>,
}

/// Relay status file format.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayStatusFile {
    /// Last update timestamp.
    last_updated: DateTime<Utc>,
    /// Relay test results.
    relays: Vec<RelayTestResult>,
}

/// Tracks AUTH challenge state for a relay connection.
#[derive(Debug, Default)]
struct AuthState {
    challenge: Option<String>,
}

/// Default relays to test - comprehensive list from nostr.co.uk and other sources.
fn default_relays() -> Vec<String> {
    vec![
        // Popular public relays
        "wss://relay.damus.io".to_string(),
        "wss://relay.primal.net".to_string(),
        "wss://nos.lol".to_string(),
        "wss://relay.nostr.band".to_string(),
        "wss://relay.snort.social".to_string(),
        // Paid/premium relays
        "wss://relay.nostr.wine".to_string(),
        "wss://eden.nostr.land".to_string(),
        "wss://nostr.land".to_string(),
        // Specialized relays
        "wss://nostr.mutinywallet.com".to_string(), // Blastr - broadcast relay
        "wss://cache1.primal.net".to_string(),      // Primal cache
        "wss://purplepag.es".to_string(),           // Long-form content
        "wss://filter.nostr1.com".to_string(),      // Filtering relay
        "wss://wot.nostr.party".to_string(),        // Web of Trust
        // Regional relays
        "wss://relay.nostr.dev.br".to_string(), // Brazil/South America
        "wss://relay.nostr.inosta.cc".to_string(), // Japan/Asia
        "wss://relay.nostr.pub".to_string(),    // Europe
        "wss://nostr.rocks".to_string(),        // North America
        "wss://relay.nostr.info".to_string(),   // Europe (legacy)
        "wss://relay.nostrich.de".to_string(),  // Germany/Europe
        // Known to work with NIP-70 protected events (from whitenoise/pika testing)
        "wss://nostr-pub.wellorder.net".to_string(),
        "wss://relay.wellorder.net".to_string(),
        "wss://nostr-01.yakihonne.com".to_string(),
        "wss://nostr-02.yakihonne.com".to_string(),
        "wss://relay.satlantis.io".to_string(),
        // Bitcoin-focused relays
        "wss://relay.bitcoiner.social".to_string(),
        "wss://relay.current.fyi".to_string(),
    ]
}

/// Relays known to have NIP-66 relay discovery events.
fn nip66_source_relays() -> Vec<&'static str> {
    vec![
        "wss://relay.nostr.band",
        "wss://nos.lol",
        "wss://relay.damus.io",
        "wss://purplepag.es",
        "wss://relay.snort.social",
    ]
}

/// Discover relays via NIP-66 (kind 30166) events.
async fn discover_relays_nip66(limit: usize, json_output: bool) -> Result<Vec<String>> {
    if !json_output {
        println!(
            "{} Discovering relays via NIP-66 (kind 30166)...",
            "INFO:".cyan()
        );
    }

    let client = Client::default();

    // Add source relays for discovery
    for relay_url in nip66_source_relays() {
        let _ = client.add_relay(relay_url).await;
    }

    client.connect().await;
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Query for kind 30166 (relay discovery) events
    // These are published by relay monitors per NIP-66
    let filter = Filter::new().kind(Kind::Custom(30166)).limit(limit * 2); // Request more to account for duplicates

    let events = client
        .fetch_events(filter, Duration::from_secs(10))
        .await
        .unwrap_or_default();

    client.disconnect().await;

    // Extract relay URLs from the `d` tag of each event
    let mut relay_urls: HashSet<String> = HashSet::new();

    for event in events.iter() {
        // The `d` tag contains the relay URL per NIP-66
        if let Some(d_tag) = event.tags.iter().find(|t| t.kind() == TagKind::d()) {
            if let Some(url) = d_tag.content() {
                let url_str = url.to_string();
                // Validate it looks like a public websocket URL (not localhost)
                if url_str.starts_with("wss://")
                    && !url_str.contains("localhost")
                    && !url_str.contains("127.0.0.1")
                {
                    relay_urls.insert(url_str);
                }
            }
        }
    }

    if !json_output {
        println!(
            "{} Found {} unique relays from {} NIP-66 events",
            "INFO:".cyan(),
            relay_urls.len(),
            events.len()
        );
    }

    let mut urls: Vec<String> = relay_urls.into_iter().collect();
    urls.sort();
    urls.truncate(limit);

    Ok(urls)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let relays = if args.discover {
        // Discover relays via NIP-66
        let discovered = discover_relays_nip66(args.discover_limit, args.json).await?;
        if discovered.is_empty() {
            if !args.json {
                eprintln!("Warning: No relays discovered via NIP-66, falling back to defaults");
            }
            default_relays()
        } else {
            discovered
        }
    } else if args.all {
        default_relays()
    } else if !args.relays.is_empty() {
        args.relays.clone()
    } else {
        eprintln!(
            "Error: provide --relays wss://..., --all for defaults, or --discover for NIP-66"
        );
        std::process::exit(1);
    };

    let keys = Keys::generate();
    let timeout = Duration::from_secs(args.timeout_secs);

    if !args.json && args.with_auth {
        println!(
            "{} Testing with NIP-42 authentication enabled",
            "INFO:".cyan()
        );
        println!("{} Test pubkey: {}", "INFO:".cyan(), keys.public_key());
    }

    let mut results = Vec::new();

    for relay_url in &relays {
        if !args.json {
            println!("\n{} {}", "Testing:".cyan().bold(), relay_url);
        }

        let result = test_relay(relay_url, &keys, timeout, args.kind_443, args.with_auth).await;

        if !args.json {
            print_result(&result, args.with_auth);
        }

        results.push(result);
    }

    if args.json {
        let status = RelayStatusFile {
            last_updated: Utc::now(),
            relays: results.clone(),
        };
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("\n{}", "Summary".cyan().bold());
        println!("{}", "=".repeat(60));
        print_summary(&results, args.with_auth);
    }

    if args.update_status {
        let status = RelayStatusFile {
            last_updated: Utc::now(),
            relays: results,
        };
        let path = std::path::Path::new("relay-status.json");
        std::fs::write(path, serde_json::to_string_pretty(&status)?)?;
        if !args.json {
            println!("\nUpdated {}", path.display());
        }
    }

    Ok(())
}

async fn test_relay(
    relay_url: &str,
    keys: &Keys,
    timeout: Duration,
    test_kind_443: bool,
    with_auth: bool,
) -> RelayTestResult {
    let mut result = RelayTestResult {
        url: relay_url.to_string(),
        reachable: false,
        auth_challenge_received: false,
        auth_success: false,
        kind_results: HashMap::new(),
        kind_results_with_auth: None,
        error: None,
        tested_at: Utc::now(),
    };

    // Create client with signer
    let client = Client::new(keys.clone());
    let auth_state = Arc::new(Mutex::new(AuthState::default()));

    // Try to connect
    if let Err(e) = client.add_relay(relay_url).await {
        result.error = Some(format!("Failed to add relay: {e}"));
        return result;
    }

    client.connect().await;

    // Wait briefly for connection to establish and potential AUTH challenge
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Check if connected
    let relay = match client.relay(relay_url).await {
        Ok(r) => r,
        Err(e) => {
            result.error = Some(format!("Failed to get relay handle: {e}"));
            return result;
        }
    };

    if !relay.is_connected() {
        result.error = Some("Failed to connect".to_string());
        return result;
    }

    result.reachable = true;

    // Listen for AUTH challenge in background
    let auth_state_clone = auth_state.clone();
    let mut notifications = client.notifications();

    // Check for any pending AUTH challenge (drain notification queue briefly)
    let check_auth = async {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, notifications.recv()).await {
                Ok(Ok(notification)) => {
                    if let RelayPoolNotification::Message { message, .. } = notification {
                        if let RelayMessage::Auth { challenge } = message {
                            let mut state = auth_state_clone.lock().await;
                            state.challenge = Some(challenge.to_string());
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
    };
    check_auth.await;

    // Check if we received an AUTH challenge
    {
        let state = auth_state.lock().await;
        result.auth_challenge_received = state.challenge.is_some();
    }

    // Test without authentication first
    if let Ok(kind_result) = test_kind(&client, keys, Kind::TextNote, timeout, None).await {
        result.kind_results.insert(1, kind_result);
    }

    if test_kind_443 {
        if let Ok(kind_result) = test_kind(&client, keys, Kind::MlsKeyPackage, timeout, None).await
        {
            result.kind_results.insert(443, kind_result);
        }
    }

    // If --with-auth is enabled, try to authenticate and test again
    if with_auth {
        // Try to get a challenge if we don't have one yet
        // Send a dummy protected event to trigger auth-required response
        if auth_state.lock().await.challenge.is_none() {
            let trigger_event = EventBuilder::new(Kind::TextNote, "auth-trigger")
                .tag(Tag::protected())
                .sign(keys)
                .await
                .ok();

            if let Some(event) = trigger_event {
                let mut notifications = client.notifications();
                let _ = client.send_event(&event).await;

                // Wait for AUTH challenge or rejection
                let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
                loop {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match tokio::time::timeout(remaining, notifications.recv()).await {
                        Ok(Ok(notification)) => {
                            if let RelayPoolNotification::Message { message, .. } = notification {
                                match message {
                                    RelayMessage::Auth { challenge } => {
                                        let mut state = auth_state.lock().await;
                                        state.challenge = Some(challenge.to_string());
                                        result.auth_challenge_received = true;
                                        break;
                                    }
                                    RelayMessage::Ok { .. } => break,
                                    _ => continue,
                                }
                            }
                        }
                        _ => break,
                    }
                }
            }
        }

        // If we have a challenge, perform NIP-42 authentication
        let challenge = auth_state.lock().await.challenge.clone();
        if let Some(challenge) = challenge {
            // Create NIP-42 AUTH event (kind 22242) using EventBuilder::auth
            let relay_url_parsed = RelayUrl::parse(relay_url).unwrap_or_else(|_| {
                RelayUrl::parse(&format!("wss://{}", relay_url.trim_start_matches("wss://")))
                    .unwrap()
            });
            let auth_event = EventBuilder::auth(challenge, relay_url_parsed)
                .sign(keys)
                .await;

            if let Ok(auth_event) = auth_event {
                // Send AUTH event
                let mut notifications = client.notifications();
                let auth_result = client.send_event(&auth_event).await;

                if auth_result.is_ok() {
                    // Wait for OK response to AUTH
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
                    loop {
                        let remaining =
                            deadline.saturating_duration_since(tokio::time::Instant::now());
                        if remaining.is_zero() {
                            break;
                        }
                        match tokio::time::timeout(remaining, notifications.recv()).await {
                            Ok(Ok(notification)) => {
                                if let RelayPoolNotification::Message { message, .. } = notification
                                {
                                    if let RelayMessage::Ok {
                                        event_id,
                                        status,
                                        message: _,
                                    } = message
                                    {
                                        if event_id == auth_event.id {
                                            result.auth_success = status;
                                            break;
                                        }
                                    }
                                }
                            }
                            _ => break,
                        }
                    }
                }
            }

            // If authentication succeeded, test again with auth
            if result.auth_success {
                let mut auth_results = HashMap::new();

                // Small delay after auth
                tokio::time::sleep(Duration::from_millis(200)).await;

                if let Ok(kind_result) =
                    test_kind(&client, keys, Kind::TextNote, timeout, Some(relay_url)).await
                {
                    auth_results.insert(1, kind_result);
                }

                if test_kind_443 {
                    if let Ok(kind_result) =
                        test_kind(&client, keys, Kind::MlsKeyPackage, timeout, Some(relay_url))
                            .await
                    {
                        auth_results.insert(443, kind_result);
                    }
                }

                if !auth_results.is_empty() {
                    result.kind_results_with_auth = Some(auth_results);
                }
            }
        }
    }

    // Disconnect
    client.disconnect().await;

    result
}

async fn test_kind(
    client: &Client,
    keys: &Keys,
    kind: Kind,
    timeout: Duration,
    _relay_url: Option<&str>,
) -> Result<KindTestResult> {
    let content = format!("MDK relay test - {} - {}", kind, Utc::now().timestamp());

    // Test unprotected event
    let unprotected_event = EventBuilder::new(kind, &content).sign(keys).await?;

    let unprotected_accepted = publish_and_check(client, &unprotected_event, timeout)
        .await
        .unwrap_or(false);

    // Test protected event (NIP-70) - add the "-" tag
    let protected_event = EventBuilder::new(kind, &content)
        .tag(Tag::protected())
        .sign(keys)
        .await?;

    let (protected_accepted, rejection_reason) =
        match publish_and_check_with_reason(client, &protected_event, timeout).await {
            Ok(accepted) => (accepted, None),
            Err(reason) => (false, Some(reason)),
        };

    Ok(KindTestResult {
        unprotected_accepted,
        protected_accepted,
        protected_rejection_reason: rejection_reason,
    })
}

async fn publish_and_check(client: &Client, event: &Event, timeout: Duration) -> Result<bool> {
    let (accepted, _) = publish_and_check_with_reason(client, event, timeout)
        .await
        .map(|a| (a, None))
        .unwrap_or((false, Some("error".to_string())));
    Ok(accepted)
}

async fn publish_and_check_with_reason(
    client: &Client,
    event: &Event,
    timeout: Duration,
) -> std::result::Result<bool, String> {
    let event_id = event.id;

    // Subscribe to notifications
    let mut notifications = client.notifications();

    // Send the event
    if let Err(e) = client.send_event(event).await {
        return Err(format!("Send failed: {e}"));
    }

    // Wait for OK response
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("Timeout waiting for response".to_string());
        }

        match tokio::time::timeout(remaining, notifications.recv()).await {
            Ok(Ok(notification)) => {
                if let RelayPoolNotification::Message { message, .. } = notification {
                    match message {
                        RelayMessage::Ok {
                            event_id: id,
                            status,
                            message,
                        } if id == event_id => {
                            if status {
                                return Ok(true);
                            }
                            return Err(message.to_string());
                        }
                        RelayMessage::Auth { .. } => {
                            // AUTH challenge received - continue waiting for OK
                            continue;
                        }
                        _ => continue,
                    }
                }
            }
            Ok(Err(_)) => return Err("Notification channel closed".to_string()),
            Err(_) => return Err("Timeout".to_string()),
        }
    }
}

fn print_result(result: &RelayTestResult, with_auth: bool) {
    if !result.reachable {
        println!(
            "  {} {}",
            "UNREACHABLE:".red().bold(),
            result.error.as_deref().unwrap_or("Unknown error")
        );
        return;
    }

    println!("  {} Connected", "OK:".green());

    if with_auth {
        let auth_status = if result.auth_challenge_received {
            if result.auth_success {
                "challenge received, auth SUCCESS".green()
            } else {
                "challenge received, auth FAILED".yellow()
            }
        } else {
            "no challenge received".normal()
        };
        println!("  NIP-42 AUTH: {auth_status}");
    }

    println!("  {} (without auth):", "Results".cyan());
    print_kind_results(&result.kind_results);

    if let Some(ref auth_results) = result.kind_results_with_auth {
        println!("  {} (with auth):", "Results".cyan());
        print_kind_results(auth_results);
    }
}

fn print_kind_results(results: &HashMap<u16, KindTestResult>) {
    for (kind, kind_result) in results {
        let kind_str = match *kind {
            1 => "kind 1 (text note)".to_string(),
            443 => "kind 443 (MLS key package)".to_string(),
            k => format!("kind {k}"),
        };

        let unprotected_status = if kind_result.unprotected_accepted {
            "accepted".green()
        } else {
            "rejected".red()
        };

        let protected_status = if kind_result.protected_accepted {
            "accepted".green()
        } else {
            "rejected".red()
        };

        println!("    {kind_str}:");
        println!("      Unprotected: {unprotected_status}");
        print!("      Protected (NIP-70): {protected_status}");

        if let Some(ref reason) = kind_result.protected_rejection_reason {
            print!(" ({})", reason.yellow());
        }
        println!();
    }
}

fn print_summary(results: &[RelayTestResult], with_auth: bool) {
    let total = results.len();
    let reachable = results.iter().filter(|r| r.reachable).count();

    let kind_443_protected_working: Vec<_> = results
        .iter()
        .filter(|r| {
            r.kind_results
                .get(&443)
                .is_some_and(|kr| kr.protected_accepted)
        })
        .map(|r| r.url.as_str())
        .collect();

    let kind_443_protected_rejected: Vec<_> = results
        .iter()
        .filter(|r| {
            r.reachable
                && r.kind_results
                    .get(&443)
                    .is_some_and(|kr| !kr.protected_accepted)
        })
        .map(|r| r.url.as_str())
        .collect();

    println!("Reachable: {reachable}/{total}");
    println!();

    println!(
        "{} (can be used for key packages):",
        "NIP-70 PROTECTED ACCEPTED (without auth)".green().bold()
    );
    if kind_443_protected_working.is_empty() {
        println!("  (none)");
    } else {
        for url in &kind_443_protected_working {
            println!("  - {url}");
        }
    }

    println!();
    println!(
        "{} (cannot be used for key packages without auth):",
        "NIP-70 PROTECTED REJECTED (without auth)".red().bold()
    );
    if kind_443_protected_rejected.is_empty() {
        println!("  (none)");
    } else {
        for url in &kind_443_protected_rejected {
            println!("  - {url}");
        }
    }

    // Show auth results if available
    if with_auth {
        let auth_challenged: Vec<_> = results
            .iter()
            .filter(|r| r.auth_challenge_received)
            .map(|r| (r.url.as_str(), r.auth_success))
            .collect();

        let auth_helped: Vec<_> = results
            .iter()
            .filter(|r| {
                // Check if auth made protected events work
                r.kind_results_with_auth
                    .as_ref()
                    .is_some_and(|auth_results| {
                        auth_results
                            .get(&443)
                            .is_some_and(|kr| kr.protected_accepted)
                    })
                    && r.kind_results
                        .get(&443)
                        .is_some_and(|kr| !kr.protected_accepted)
            })
            .map(|r| r.url.as_str())
            .collect();

        println!();
        println!("{}", "NIP-42 AUTH Results:".cyan().bold());
        println!(
            "  Relays that sent AUTH challenge: {}",
            auth_challenged.len()
        );
        for (url, success) in &auth_challenged {
            let status = if *success { "OK".green() } else { "FAIL".red() };
            println!("    - {url}: {status}");
        }

        if !auth_helped.is_empty() {
            println!();
            println!(
                "{}",
                "AUTH HELPS - Protected events accepted AFTER auth:"
                    .green()
                    .bold()
            );
            for url in &auth_helped {
                println!("  - {url}");
            }
        }
    }

    println!();
    println!("{}", "Recommendation:".cyan().bold());
    println!("Use kind 10051 (MLS Key Package Relays) to advertise key package relays separately");
    println!("from general-purpose relays (kind 10002 / NIP-65).");
    println!();
    println!("Recommended key package relays:");
    for url in &kind_443_protected_working {
        println!("  - {url}");
    }
}
