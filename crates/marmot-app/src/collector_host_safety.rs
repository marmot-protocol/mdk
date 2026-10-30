//! Per-attempt collector resolution and pinning. No DNS cache or connection
//! pool survives an export attempt; retries must clear the same gate again.
//! Relay NIP-11 fetches (`relay_caps.rs`) pin through [`pin_with`] too.

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::OnceLock,
    time::Duration,
};

use cgka_traits::app_components::{is_loopback_ip, reject_non_public_ip};
use url::{Host, Url};

use crate::export_config::{endpoint_host_is_loopback, parse_relay_telemetry_endpoint};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Applies the process network proxy policy to an HTTP client builder.
pub type HttpClientBuilder =
    fn(reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder, &'static str>;

/// The process SOCKS5 policy every collector client is built through. `marmot-app` hands in
/// its one builder when it builds a `MarmotApp`. Until then no collector client is built, so
/// nothing dials.
static HTTP_BUILDER: OnceLock<HttpClientBuilder> = OnceLock::new();

/// Hands in the process proxy policy. Only the first call takes effect.
pub fn hand_in_http_builder(builder: HttpClientBuilder) {
    let _ = HTTP_BUILDER.set(builder);
}

fn http_builder() -> Option<HttpClientBuilder> {
    HTTP_BUILDER.get().copied()
}

/// For this set's own tests that dial a loopback collector without a `MarmotApp`: a builder that
/// only drops environment proxies, as the process policy does with no SOCKS5 proxy configured.
/// The tests of the policy itself live in `marmot-app` and hand in its builder.
#[cfg(test)]
pub(crate) fn hand_in_direct_http_builder() {
    hand_in_http_builder(|builder| Ok(builder.no_proxy()));
}

/// Context-free failure from collector resolution or client construction.
///
/// Display and Debug stay free of endpoint, DNS, and address material so the
/// helper can be used from default-build upload paths without a feature-gated
/// public error variant.
#[derive(Debug)]
pub struct CollectorRequestError;

impl std::fmt::Display for CollectorRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("collector request failed")
    }
}

impl std::error::Error for CollectorRequestError {}

// Deliberately no Debug: the configured URL and DNS answers are private.
pub struct PinnedCollector {
    pub(crate) url: Url,
    addrs: Vec<SocketAddr>,
}

impl PinnedCollector {
    /// The URL this pin was made for; a client from [`Self::build_client`]
    /// dials its host only at the pinned addresses.
    pub fn url(&self) -> &Url {
        &self.url
    }

    pub(crate) fn build_client(&self) -> Result<reqwest::Client, CollectorRequestError> {
        self.build_client_with_timeouts(CONNECT_TIMEOUT, REQUEST_TIMEOUT)
    }

    /// [`Self::build_client`] with its own connect and whole-request limits.
    // `build_client_from` applies the process proxy policy.
    #[allow(clippy::disallowed_methods)]
    pub fn build_client_with_timeouts(
        &self,
        connect: Duration,
        request: Duration,
    ) -> Result<reqwest::Client, CollectorRequestError> {
        self.build_client_from(reqwest::Client::builder(), connect, request)
    }

    fn build_client_from(
        &self,
        builder: reqwest::ClientBuilder,
        connect: Duration,
        request: Duration,
    ) -> Result<reqwest::Client, CollectorRequestError> {
        let http_builder = http_builder().ok_or(CollectorRequestError)?;
        http_builder(builder)
            .map_err(|_| CollectorRequestError)?
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(connect)
            .timeout(request)
            .resolve_to_addrs(
                self.url.host_str().ok_or(CollectorRequestError)?,
                &self.addrs,
            )
            // Keep the original URL for TLS trust/SNI and the HTTP Host header.
            // Literal IP URLs dial that already-validated IP without DNS.
            .build()
            .map_err(|_| CollectorRequestError)
    }
}

pub async fn system_resolve(host: String, port: u16) -> std::io::Result<Vec<IpAddr>> {
    tokio::net::lookup_host((host.as_str(), port))
        .await
        .map(|addrs| addrs.map(|addr| addr.ip()).collect())
}

pub(crate) async fn resolve_with<F, Fut>(
    endpoint: &str,
    resolver: F,
) -> Result<PinnedCollector, CollectorRequestError>
where
    F: FnOnce(String, u16) -> Fut,
    Fut: Future<Output = std::io::Result<Vec<IpAddr>>>,
{
    let url = parse_relay_telemetry_endpoint(endpoint).ok_or(CollectorRequestError)?;
    // The test endpoint must stay on this device. In particular, HTTP
    // localhost resolving to a public IP must never send plaintext auth.
    let loopback_test = endpoint_host_is_loopback(url.as_str());
    pin_with(url, loopback_test, CONNECT_TIMEOUT, resolver).await
}

/// Resolves `url`'s host once within `resolve_timeout`, validates every
/// address and pins them all. `loopback` admits loopback addresses and then
/// requires every address to be one; callers set it only for a literal
/// loopback host the configuration opted into, never from a resolved address.
pub async fn pin_with<F, Fut>(
    url: Url,
    loopback: bool,
    resolve_timeout: Duration,
    resolver: F,
) -> Result<PinnedCollector, CollectorRequestError>
where
    F: FnOnce(String, u16) -> Fut,
    Fut: Future<Output = std::io::Result<Vec<IpAddr>>>,
{
    let port = url.port_or_known_default().ok_or(CollectorRequestError)?;
    let ips = match url.host().ok_or(CollectorRequestError)? {
        Host::Domain(host) => {
            tokio::time::timeout(resolve_timeout, resolver(host.to_owned(), port))
                .await
                .map_err(|_| CollectorRequestError)?
                .map_err(|_| CollectorRequestError)?
        }
        Host::Ipv4(ip) => vec![IpAddr::V4(ip)],
        Host::Ipv6(ip) => vec![IpAddr::V6(ip)],
    };
    if ips.is_empty() {
        return Err(CollectorRequestError);
    }
    for ip in &ips {
        if loopback && !is_loopback_ip(*ip) {
            return Err(CollectorRequestError);
        }
        reject_non_public_ip(*ip, loopback).map_err(|_| CollectorRequestError)?;
    }
    Ok(PinnedCollector {
        url,
        addrs: ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect(),
    })
}

/// Test hooks for the proxy tests in `marmot-app` (#2627). Each calls the crate-private item of
/// the same name; `new_for_test` builds a pin without resolution, so a fixture can pin an
/// unresolvable name to a loopback address.
#[cfg(any(test, feature = "test-support"))]
#[cfg_attr(not(test), allow(dead_code))]
impl PinnedCollector {
    pub fn new_for_test(url: Url, addrs: Vec<SocketAddr>) -> Self {
        Self { url, addrs }
    }

    pub fn build_client_for_test(&self) -> Result<reqwest::Client, CollectorRequestError> {
        self.build_client()
    }

    pub fn build_client_from_for_test(
        &self,
        builder: reqwest::ClientBuilder,
        connect: Duration,
        request: Duration,
    ) -> Result<reqwest::Client, CollectorRequestError> {
        self.build_client_from(builder, connect, request)
    }
}

#[cfg(any(test, feature = "test-support"))]
#[cfg_attr(not(test), allow(dead_code))]
pub async fn resolve_with_for_test<F, Fut>(
    endpoint: &str,
    resolver: F,
) -> Result<PinnedCollector, CollectorRequestError>
where
    F: FnOnce(String, u16) -> Fut,
    Fut: Future<Output = std::io::Result<Vec<IpAddr>>>,
{
    resolve_with(endpoint, resolver).await
}

#[cfg(test)]
mod tests;
