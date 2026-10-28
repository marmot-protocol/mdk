//! Relay caps for the time-sliced history sweep (#2660), read from each
//! relay's NIP-11 document and cached per relay.
//!
//! A fetch first clears the relay dial gate (`RelaySafetyPolicy`): retired,
//! invalid and unsafe relays, and loopback ones without the dev flag, are
//! refused before any DNS. It then resolves once, validates and pins every
//! address through `collector_host_safety`, and sends one GET with
//! `Accept: application/nostr+json` to the relay's own URL over HTTPS (HTTP only
//! for a loopback `ws://` relay the dev flag admits). TLS verifies against the
//! bundled roots for the configured host name, never a resolved address.
//! Redirects are refused.
//!
//! A missing, malformed, oversized or unreachable document reads as unknown
//! caps ([`RelayCaps::default`]), so the sweep infers the cap from full replies
//! instead. Unknown caps are retried sooner than a document is refreshed.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cgka_traits::app_components::is_loopback_host;
use reqwest::header::{ACCEPT, CONTENT_LENGTH};
use tokio::time::Instant;
use transport_nostr::{RelayEndpointPolicy, RelaySafetyPolicy};
use transport_nostr_adapter::sweep::RelayCaps;
use url::Url;

use crate::collector_host_safety;

/// Relay connects use 5 s (`dial-safety.md`); the document fetch matches.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Whole request, from connect to the last body byte.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// A NIP-11 document is a few KiB; anything past this is not one.
const MAX_DOCUMENT_BYTES: usize = 64 * 1024;
/// How long a fetched document's caps hold. A relay that lowers its cap is
/// trusted at the old one for at most this long.
const DOCUMENT_FRESH_FOR: Duration = Duration::from_secs(60 * 60);
/// How long unknown caps hold before the document is asked for again.
const UNKNOWN_FRESH_FOR: Duration = Duration::from_secs(5 * 60);
/// Relays the cache holds at once. Past it, the entry due soonest goes.
const MAX_CACHED_RELAYS: usize = 256;

type ResolveFuture = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>>;
type Resolver = Arc<dyn Fn(String, u16) -> ResolveFuture + Send + Sync>;

/// Why a relay's caps are unknown. Labels only; never the relay or the reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Nip11Failure {
    /// The dial gate refused the relay or one of its resolved addresses.
    Refused,
    /// The relay did not answer within the request limits.
    TimedOut,
    /// No connection, or the reply was cut off.
    Unreachable,
    /// A reply other than 2xx, including a redirect.
    Missing,
    /// Not JSON, or larger than [`MAX_DOCUMENT_BYTES`].
    Malformed,
}

impl Nip11Failure {
    fn label(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::TimedOut => "timed_out",
            Self::Unreachable => "unreachable",
            Self::Missing => "missing",
            Self::Malformed => "malformed",
        }
    }
}

/// How one NIP-11 document is fetched. Tests replace the resolver and limits.
#[derive(Clone)]
struct Nip11Fetch {
    resolver: Resolver,
    connect_timeout: Duration,
    request_timeout: Duration,
}

impl Default for Nip11Fetch {
    fn default() -> Self {
        Self {
            resolver: Arc::new(|host, port| {
                Box::pin(collector_host_safety::system_resolve(host, port))
            }),
            connect_timeout: CONNECT_TIMEOUT,
            request_timeout: REQUEST_TIMEOUT,
        }
    }
}

impl Nip11Fetch {
    /// `url` comes from [`document_url`], which already cleared the dial gate.
    async fn caps(&self, url: Url, allow_loopback: bool) -> Result<RelayCaps, Nip11Failure> {
        let loopback = allow_loopback && url.host().is_some_and(is_loopback_host);
        let resolver = self.resolver.clone();
        let pin =
            collector_host_safety::pin_with(url, loopback, self.connect_timeout, |host, port| {
                resolver(host, port)
            })
            .await
            .map_err(|_| Nip11Failure::Refused)?;
        let client = pin
            .build_client_with_timeouts(self.connect_timeout, self.request_timeout)
            .map_err(|_| Nip11Failure::Refused)?;
        let mut response = client
            .get(pin.url.clone())
            .header(ACCEPT, "application/nostr+json")
            .send()
            .await
            .map_err(request_failure)?;
        if !response.status().is_success() {
            return Err(Nip11Failure::Missing);
        }
        let declared = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|length| length.to_str().ok()?.parse::<usize>().ok());
        if declared.is_some_and(|length| length > MAX_DOCUMENT_BYTES) {
            return Err(Nip11Failure::Malformed);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(request_failure)? {
            if body.len() + chunk.len() > MAX_DOCUMENT_BYTES {
                return Err(Nip11Failure::Malformed);
            }
            body.extend_from_slice(&chunk);
        }
        let json = std::str::from_utf8(&body).map_err(|_| Nip11Failure::Malformed)?;
        RelayCaps::from_nip11_json(json).map_err(|_| Nip11Failure::Malformed)
    }
}

fn request_failure(error: reqwest::Error) -> Nip11Failure {
    if error.is_timeout() {
        Nip11Failure::TimedOut
    } else {
        Nip11Failure::Unreachable
    }
}

/// The relay's own URL with its HTTP scheme, once the dial gate admits it.
fn document_url(endpoint: &str, allow_loopback: bool) -> Result<Url, Nip11Failure> {
    let classification = RelaySafetyPolicy::with_allow_loopback(allow_loopback)
        .classify_endpoints(vec![endpoint.to_owned()])
        .pop()
        .ok_or(Nip11Failure::Refused)?;
    if classification.policy != RelayEndpointPolicy::Allowed {
        return Err(Nip11Failure::Refused);
    }
    let mut url = classification
        .normalized_endpoint
        .and_then(|normalized| Url::parse(&normalized).ok())
        .ok_or(Nip11Failure::Refused)?;
    // The gate admits `ws://` only for a loopback relay under the dev flag.
    let scheme = match url.scheme() {
        "wss" => "https",
        "ws" => "http",
        _ => return Err(Nip11Failure::Refused),
    };
    url.set_scheme(scheme).map_err(|()| Nip11Failure::Refused)?;
    Ok(url)
}

struct CachedCaps {
    caps: RelayCaps,
    fresh_until: Instant,
}

type Slot = Arc<tokio::sync::Mutex<Option<CachedCaps>>>;

/// Each relay's NIP-11 caps, fetched at most once per freshness window.
/// Concurrent callers for one relay share one fetch.
#[derive(Clone, Default)]
pub(crate) struct RelayCapsCache {
    slots: Arc<Mutex<HashMap<String, Slot>>>,
    fetch: Nip11Fetch,
}

impl RelayCapsCache {
    /// The relay's caps, from cache or a fresh fetch. Unknown caps when the
    /// document is missing, malformed, unreachable or refused.
    pub(crate) async fn caps(&self, endpoint: &str, allow_loopback: bool) -> RelayCaps {
        // Refused relays cost no I/O, so they take no cache entry.
        let url = match document_url(endpoint, allow_loopback) {
            Ok(url) => url,
            Err(failure) => {
                log_unknown(failure);
                return RelayCaps::default();
            }
        };
        let slot = self.slot(url.as_str());
        let mut cached = slot.lock().await;
        if let Some(entry) = cached.as_ref()
            && Instant::now() < entry.fresh_until
        {
            return entry.caps;
        }
        let (caps, fresh_for) = match self.fetch.caps(url, allow_loopback).await {
            Ok(caps) => (caps, DOCUMENT_FRESH_FOR),
            Err(failure) => {
                log_unknown(failure);
                (RelayCaps::default(), UNKNOWN_FRESH_FOR)
            }
        };
        *cached = Some(CachedCaps {
            caps,
            fresh_until: Instant::now() + fresh_for,
        });
        caps
    }

    /// The slot for one relay, keyed by its normalized document URL.
    fn slot(&self, key: &str) -> Slot {
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(slot) = slots.get(key) {
            return slot.clone();
        }
        while slots.len() >= MAX_CACHED_RELAYS && evict_one(&mut slots) {}
        slots.entry(key.to_owned()).or_default().clone()
    }
}

fn log_unknown(failure: Nip11Failure) {
    tracing::debug!(
        target: "marmot_app::relay_caps",
        method = "caps",
        outcome = failure.label(),
        "relay information document unavailable; sweep caps are inferred"
    );
}

/// Drops the idle entry due soonest, or an idle empty one, and says whether
/// it dropped one. An entry is idle when the map holds its only reference:
/// slots are handed out only under the map lock, so no caller can be about
/// to use it. When every entry is held the map grows past the bound, and the
/// next insert after those callers finish shrinks it back.
fn evict_one(slots: &mut HashMap<String, Slot>) -> bool {
    let victim = slots
        .iter()
        .filter(|(_, slot)| Arc::strong_count(slot) == 1)
        .filter_map(|(endpoint, slot)| {
            let cached = slot.try_lock().ok()?;
            Some((cached.as_ref().map(|entry| entry.fresh_until), endpoint))
        })
        .min_by_key(|(fresh_until, _)| *fresh_until)
        .map(|(_, endpoint)| endpoint.clone());
    victim.is_some_and(|endpoint| slots.remove(&endpoint).is_some())
}

#[cfg(test)]
mod tests;
