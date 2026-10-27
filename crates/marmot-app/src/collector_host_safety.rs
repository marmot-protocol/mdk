//! Per-attempt collector resolution and pinning. No DNS cache or connection
//! pool survives an export attempt; retries must clear the same gate again.

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::OnceLock,
    time::Duration,
};

use cgka_traits::app_components::{is_loopback_ip, reject_non_public_ip};
use url::{Host, Url};

use crate::export_config::{endpoint_host_is_loopback, parse_relay_telemetry_endpoint};

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Applies the process network proxy policy to an HTTP client builder.
pub(crate) type HttpClientBuilder =
    fn(reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder, &'static str>;

/// The process SOCKS5 policy every collector client is built through. `marmot-app` hands in
/// its one builder when it builds a `MarmotApp`. Until then no collector client is built, so
/// nothing dials.
static HTTP_BUILDER: OnceLock<HttpClientBuilder> = OnceLock::new();

/// Hands in the process proxy policy. Only the first call takes effect.
pub(crate) fn hand_in_http_builder(builder: HttpClientBuilder) {
    let _ = HTTP_BUILDER.set(builder);
}

#[cfg(not(test))]
fn http_builder() -> Option<HttpClientBuilder> {
    HTTP_BUILDER.get().copied()
}

/// Unit tests build collectors without a `MarmotApp`, so they fall back to the builder it hands
/// in.
#[cfg(test)]
fn http_builder() -> Option<HttpClientBuilder> {
    Some(
        HTTP_BUILDER
            .get()
            .copied()
            .unwrap_or(crate::network_proxy::http_builder),
    )
}

/// Context-free failure from collector resolution or client construction.
///
/// Display and Debug stay free of endpoint, DNS, and address material so the
/// helper can be used from default-build upload paths without a feature-gated
/// public error variant.
#[derive(Debug)]
pub(crate) struct CollectorRequestError;

impl std::fmt::Display for CollectorRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("collector request failed")
    }
}

impl std::error::Error for CollectorRequestError {}

// Deliberately no Debug: the configured URL and DNS answers are private.
pub(crate) struct PinnedCollector {
    pub(crate) url: Url,
    addrs: Vec<SocketAddr>,
}

impl PinnedCollector {
    // `build_client_from` applies the process proxy policy.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn build_client(&self) -> Result<reqwest::Client, CollectorRequestError> {
        self.build_client_from(reqwest::Client::builder())
    }

    fn build_client_from(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> Result<reqwest::Client, CollectorRequestError> {
        let http_builder = http_builder().ok_or(CollectorRequestError)?;
        http_builder(builder)
            .map_err(|_| CollectorRequestError)?
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
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

pub(crate) async fn system_resolve(host: String, port: u16) -> std::io::Result<Vec<IpAddr>> {
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
    let port = url.port_or_known_default().ok_or(CollectorRequestError)?;
    let loopback_test = endpoint_host_is_loopback(url.as_str());
    let ips = match url.host().ok_or(CollectorRequestError)? {
        Host::Domain(host) => {
            tokio::time::timeout(CONNECT_TIMEOUT, resolver(host.to_owned(), port))
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
        // The test endpoint must stay on this device. In particular, HTTP
        // localhost resolving to a public IP must never send plaintext auth.
        if loopback_test && !is_loopback_ip(*ip) {
            return Err(CollectorRequestError);
        }
        reject_non_public_ip(*ip, loopback_test).map_err(|_| CollectorRequestError)?;
    }
    Ok(PinnedCollector {
        url,
        addrs: ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect(),
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod proxy_tests;
