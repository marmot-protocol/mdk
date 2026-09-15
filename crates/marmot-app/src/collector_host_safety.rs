//! Per-attempt collector resolution and pinning. No DNS cache or connection
//! pool survives an export attempt; retries must clear the same gate again.

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use cgka_traits::app_components::{is_loopback_ip, reject_non_public_ip};
use url::{Host, Url};

use crate::config::{endpoint_host_is_loopback, parse_relay_telemetry_endpoint};

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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
    pub(crate) fn build_client(&self) -> Result<reqwest::Client, CollectorRequestError> {
        self.build_client_from(reqwest::Client::builder())
    }

    fn build_client_from(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> Result<reqwest::Client, CollectorRequestError> {
        builder
            // Proxies can resolve the original hostname themselves, bypassing
            // the validated addresses. This exporter always dials directly.
            .no_proxy()
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
