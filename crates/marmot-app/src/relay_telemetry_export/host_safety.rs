//! Per-attempt collector resolution and pinning. No DNS cache or connection
//! pool survives an export attempt; retries must clear the same gate again.

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use cgka_traits::app_components::{is_loopback_ip, reject_non_public_ip};
use url::{Host, Url};

use super::RelayExportError;
use crate::config::{endpoint_host_is_loopback, parse_relay_telemetry_endpoint};

pub(super) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

// Deliberately no Debug: the configured URL and DNS answers are private.
pub(super) struct PinnedCollector {
    pub(super) url: Url,
    addrs: Vec<SocketAddr>,
}

impl PinnedCollector {
    pub(super) fn build_client(&self) -> Result<reqwest::Client, RelayExportError> {
        self.build_client_from(reqwest::Client::builder())
    }

    fn build_client_from(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> Result<reqwest::Client, RelayExportError> {
        builder
            // Proxies can resolve the original hostname themselves, bypassing
            // the validated addresses. This exporter always dials directly.
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .resolve_to_addrs(
                self.url.host_str().ok_or(RelayExportError::Request)?,
                &self.addrs,
            )
            // Keep the original URL for TLS trust/SNI and the HTTP Host header.
            // Literal IP URLs dial that already-validated IP without DNS.
            .build()
            .map_err(|_| RelayExportError::Request)
    }
}

pub(super) async fn system_resolve(host: String, port: u16) -> std::io::Result<Vec<IpAddr>> {
    tokio::net::lookup_host((host.as_str(), port))
        .await
        .map(|addrs| addrs.map(|addr| addr.ip()).collect())
}

pub(super) async fn resolve_with<F, Fut>(
    endpoint: &str,
    resolver: F,
) -> Result<PinnedCollector, RelayExportError>
where
    F: FnOnce(String, u16) -> Fut,
    Fut: Future<Output = std::io::Result<Vec<IpAddr>>>,
{
    let url = parse_relay_telemetry_endpoint(endpoint).ok_or(RelayExportError::Request)?;
    let port = url
        .port_or_known_default()
        .ok_or(RelayExportError::Request)?;
    let loopback_test = endpoint_host_is_loopback(url.as_str());
    let ips = match url.host().ok_or(RelayExportError::Request)? {
        Host::Domain(host) => {
            tokio::time::timeout(CONNECT_TIMEOUT, resolver(host.to_owned(), port))
                .await
                .map_err(|_| RelayExportError::Request)?
                .map_err(|_| RelayExportError::Request)?
        }
        Host::Ipv4(ip) => vec![IpAddr::V4(ip)],
        Host::Ipv6(ip) => vec![IpAddr::V6(ip)],
    };
    if ips.is_empty() {
        return Err(RelayExportError::Request);
    }
    for ip in &ips {
        // The test endpoint must stay on this device. In particular, HTTP
        // localhost resolving to a public IP must never send plaintext auth.
        if loopback_test && !is_loopback_ip(*ip) {
            return Err(RelayExportError::Request);
        }
        reject_non_public_ip(*ip, loopback_test).map_err(|_| RelayExportError::Request)?;
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
