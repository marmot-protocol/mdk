use std::net::IpAddr;

use cgka_traits::app_components::{is_loopback_host, reject_non_public_ip};
use cgka_traits::{
    TransportAccountActivation, TransportEndpoint, TransportGroupSync, TransportPublishRequest,
    TransportPublishTarget,
};
use nostr_sdk::prelude::RelayUrl;
use url::{Host, Url};

const MAX_RELAY_ENDPOINTS_PER_ROUTE: usize = 16;

#[derive(Clone, Debug)]
pub(crate) struct RelaySafetyPolicy {
    max_endpoints_per_route: usize,
    /// Dev/test opt-in for loopback relay endpoints
    /// (`MarmotAppConfig::allow_loopback_relay_endpoints`). Off by default:
    /// production rejects relay endpoints whose LITERAL host is loopback (or
    /// any other non-public IP literal) before the URL reaches the relay pool.
    allow_loopback: bool,
}

impl Default for RelaySafetyPolicy {
    fn default() -> Self {
        Self {
            max_endpoints_per_route: MAX_RELAY_ENDPOINTS_PER_ROUTE,
            allow_loopback: false,
        }
    }
}

impl RelaySafetyPolicy {
    pub(crate) fn with_allow_loopback(allow_loopback: bool) -> Self {
        Self {
            allow_loopback,
            ..Self::default()
        }
    }

    pub(crate) fn sanitize_activation(
        &self,
        mut activation: TransportAccountActivation,
    ) -> Result<TransportAccountActivation, String> {
        activation.inbox_endpoints =
            self.sanitize_endpoints(activation.inbox_endpoints, "account inbox")?;
        for group in &mut activation.group_subscriptions {
            group.endpoints = self.sanitize_endpoints(group.endpoints.clone(), "group route")?;
        }
        Ok(activation)
    }

    pub(crate) fn sanitize_group_sync(
        &self,
        mut sync: TransportGroupSync,
    ) -> Result<TransportGroupSync, String> {
        for group in &mut sync.group_subscriptions {
            group.endpoints = self.sanitize_endpoints(group.endpoints.clone(), "group route")?;
        }
        Ok(sync)
    }

    pub(crate) fn sanitize_publish_request(
        &self,
        mut request: TransportPublishRequest,
    ) -> Result<TransportPublishRequest, String> {
        match &mut request.target {
            TransportPublishTarget::Group { endpoints, .. } => {
                *endpoints = self.sanitize_endpoints(endpoints.clone(), "group publish")?;
            }
            TransportPublishTarget::Inbox { endpoints, .. } => {
                *endpoints = self.sanitize_endpoints(endpoints.clone(), "inbox publish")?;
            }
        }
        Ok(request)
    }

    pub(crate) fn sanitize_endpoints(
        &self,
        endpoints: Vec<TransportEndpoint>,
        context: &str,
    ) -> Result<Vec<TransportEndpoint>, String> {
        let mut sanitized = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            let raw = endpoint.as_str().trim();
            if raw.is_empty() {
                return Err(format!("{context}: invalid relay endpoint"));
            }
            let relay_url = RelayUrl::parse(raw)
                .map_err(|err| format!("{context}: invalid relay endpoint: {err}"))?;
            reject_unsafe_relay_host(&relay_url, self.allow_loopback)
                .map_err(|reason| format!("{context}: {reason}"))?;
            let endpoint = TransportEndpoint(relay_url.to_string());
            if !sanitized.contains(&endpoint) {
                sanitized.push(endpoint);
            }
        }
        if sanitized.len() > self.max_endpoints_per_route {
            return Err(format!(
                "{context}: relay endpoint count {} exceeds limit {}",
                sanitized.len(),
                self.max_endpoints_per_route
            ));
        }
        Ok(sanitized)
    }
}

/// Require TLS for every public relay. Plaintext `ws://` is admitted only for
/// an explicitly enabled loopback host; private/link-local/CGNAT and public
/// plaintext endpoints stay rejected even with the dev flag. Relay
/// endpoints arrive from signed routing components and relay-list events, so a
/// poisoned record must not steer the relay pool at internal services (SSRF;
/// see `docs/marmot-architecture/overview/dial-safety.md`). A `wss://` DOMAIN
/// host is accepted here: nostr-sdk owns DNS resolution and the WebSocket, so
/// resolve-time validation cannot be pinned at this layer — an accepted LOW
/// residual, per the dial-safety note. Error strings stay URL-free.
fn reject_unsafe_relay_host(url: &RelayUrl, allow_loopback: bool) -> Result<(), String> {
    let parsed = Url::parse(url.as_str()).map_err(|_| "invalid relay endpoint".to_owned())?;
    let host = parsed
        .host()
        .ok_or_else(|| "relay endpoint is missing a host".to_owned())?;
    if parsed.scheme() == "ws" {
        return if allow_loopback && is_loopback_host(host) {
            Ok(())
        } else {
            Err("plaintext relay endpoints are allowed only for loopback in dev mode".to_owned())
        };
    }
    match host {
        Host::Ipv4(addr) => reject_non_public_ip(IpAddr::V4(addr), allow_loopback)
            .map_err(|_| "relay endpoint host is not a public address".to_owned()),
        Host::Ipv6(addr) => reject_non_public_ip(IpAddr::V6(addr), allow_loopback)
            .map_err(|_| "relay endpoint host is not a public address".to_owned()),
        Host::Domain(domain) => {
            if is_loopback_host(Host::Domain(domain)) && !allow_loopback {
                return Err("relay endpoint host must not be localhost".to_owned());
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints(urls: &[&str]) -> Vec<TransportEndpoint> {
        urls.iter()
            .map(|url| TransportEndpoint((*url).to_owned()))
            .collect()
    }

    #[test]
    fn rejects_non_public_relay_hosts_by_default() {
        let policy = RelaySafetyPolicy::default();
        for url in [
            "ws://127.0.0.1:8080",
            "ws://10.0.0.1",
            "ws://169.254.169.254",
            "ws://[::1]:8080",
            "ws://[fc00::1]",
            "ws://localhost:7777",
            // Rooted localhost names still resolve to loopback and must be
            // rejected too (they parse as `Host::Domain("localhost.")`).
            "ws://localhost.:7777",
            "ws://dev.localhost.:7777",
        ] {
            assert!(
                policy
                    .sanitize_endpoints(endpoints(&[url]), "test")
                    .is_err(),
                "{url} must be rejected"
            );
        }
    }

    #[test]
    fn accepts_public_relay_hosts_regardless_of_opt_in() {
        for policy in [
            RelaySafetyPolicy::default(),
            RelaySafetyPolicy::with_allow_loopback(true),
        ] {
            let sanitized = policy
                .sanitize_endpoints(endpoints(&["wss://relay.example"]), "test")
                .expect("public relay accepted");
            assert_eq!(sanitized.len(), 1);
        }
    }

    #[test]
    fn rejects_public_plaintext_relays_even_with_dev_opt_in() {
        for policy in [
            RelaySafetyPolicy::default(),
            RelaySafetyPolicy::with_allow_loopback(true),
        ] {
            for url in ["ws://relay.example", "ws://8.8.8.8"] {
                assert!(
                    policy
                        .sanitize_endpoints(endpoints(&[url]), "test")
                        .is_err(),
                    "{url} must require TLS"
                );
            }
        }
    }

    #[test]
    fn dev_opt_in_admits_loopback_but_not_private_ranges() {
        let policy = RelaySafetyPolicy::with_allow_loopback(true);
        for url in ["ws://127.0.0.1:8080", "ws://[::1]:8080", "ws://localhost"] {
            assert!(
                policy.sanitize_endpoints(endpoints(&[url]), "test").is_ok(),
                "{url} must be accepted under the dev opt-in"
            );
        }
        // The opt-in opens loopback only; private/link-local literals stay
        // rejected even in dev mode.
        for url in ["ws://10.0.0.1", "ws://169.254.169.254"] {
            assert!(
                policy
                    .sanitize_endpoints(endpoints(&[url]), "test")
                    .is_err(),
                "{url} must stay rejected even with the dev opt-in"
            );
        }
    }

    #[test]
    fn count_cap_still_enforced() {
        let policy = RelaySafetyPolicy::default();
        let many: Vec<String> = (0..20).map(|i| format!("wss://relay{i}.example")).collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(policy.sanitize_endpoints(endpoints(&refs), "test").is_err());
    }
}
