use std::net::IpAddr;

use cgka_traits::app_components::{is_loopback_host, reject_non_public_ip};
use cgka_traits::{
    TransportAccountActivation, TransportEndpoint, TransportGroupSync, TransportPublishRequest,
    TransportPublishTarget,
};
use nostr_sdk::prelude::RelayUrl;
use serde::{Deserialize, Serialize};
use transport_nostr_adapter::NostrRelayEndpoint;
use url::{Host, Url};

const MAX_RELAY_ENDPOINTS_PER_ROUTE: usize = 16;
const RETIRED_RELAY_HOSTS: &[&str] = &["relay.damus.io", "relay.nostr.band"];

/// The policy decision for one caller-supplied Nostr relay endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayEndpointPolicy {
    Allowed,
    Retired,
    Invalid,
    Unsafe,
}

/// One endpoint's normalized relay URL and policy decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEndpointClassification {
    /// The caller-supplied value, preserved so batch callers can associate the
    /// decision with their input without relying on positional matching.
    pub endpoint: String,
    /// Canonical relay URL when parsing succeeded, including for retired or
    /// unsafe endpoints. Invalid inputs have no normalized representation.
    pub normalized_endpoint: Option<String>,
    pub policy: RelayEndpointPolicy,
}

/// Hostnames that the relay plane will never dial or adopt.
pub fn retired_relay_hosts() -> Vec<String> {
    RETIRED_RELAY_HOSTS
        .iter()
        .map(|host| (*host).to_owned())
        .collect()
}

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

    pub(crate) fn classify_endpoints(
        &self,
        endpoints: Vec<String>,
    ) -> Vec<RelayEndpointClassification> {
        endpoints
            .into_iter()
            .map(|endpoint| self.classify_endpoint(endpoint))
            .collect()
    }

    fn classify_endpoint(&self, endpoint: String) -> RelayEndpointClassification {
        let raw = endpoint.trim();
        let Ok(relay_endpoint) = NostrRelayEndpoint::parse(raw) else {
            return RelayEndpointClassification {
                endpoint,
                normalized_endpoint: None,
                policy: RelayEndpointPolicy::Invalid,
            };
        };
        let normalized_endpoint = Some(relay_endpoint.transport_endpoint().0);
        let policy = match relay_endpoint {
            NostrRelayEndpoint::WebSocket(relay_url) => {
                match evaluate_relay_url(&relay_url, self.allow_loopback) {
                    Ok(()) => RelayEndpointPolicy::Allowed,
                    Err(rejection) => rejection.policy(),
                }
            }
            // A FIPS npub names the remote node inside the FIPS overlay. It is
            // not a DNS/IP dial target and cannot bypass WebSocket host safety.
            NostrRelayEndpoint::Fips(_) => RelayEndpointPolicy::Allowed,
        };
        RelayEndpointClassification {
            endpoint,
            normalized_endpoint,
            policy,
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

    /// Keep the endpoints that pass the host-safety rule and drop the rest.
    ///
    /// The counterpart to [`Self::sanitize_endpoints`] for endpoints that were
    /// *discovered* rather than configured — a relay list published by another
    /// account, say. Sanitizing is fail-closed because a configured relay set
    /// is the operator's stated intent, and one bad entry there is a mistake
    /// worth surfacing. A published list is untrusted input: rejecting all of
    /// it over one bad entry would let anyone make themselves unresolvable by
    /// appending a single loopback URL. Every endpoint is checked against the
    /// same rule; only the response to a rejection differs.
    ///
    /// The result still passes through [`Self::sanitize_endpoints`] at the
    /// dial chokepoint, so this narrows what is offered rather than replacing
    /// the check.
    pub(crate) fn retain_safe_endpoints(
        &self,
        endpoints: Vec<TransportEndpoint>,
        context: &str,
    ) -> Vec<TransportEndpoint> {
        let offered = endpoints.len();
        let mut kept: Vec<TransportEndpoint> = Vec::new();
        for endpoint in endpoints {
            let Ok(relay_endpoint) = NostrRelayEndpoint::parse(endpoint.as_str().trim()) else {
                continue;
            };
            if let NostrRelayEndpoint::WebSocket(relay_url) = &relay_endpoint
                && reject_unsafe_relay_host(relay_url, self.allow_loopback).is_err()
            {
                continue;
            }
            let endpoint = relay_endpoint.transport_endpoint();
            if !kept.contains(&endpoint) {
                kept.push(endpoint);
            }
        }
        if kept.len() != offered {
            // Aggregate counts only: a rejected relay URL is somebody's
            // published data and never reaches a log line.
            tracing::debug!(
                target: "marmot_app::relay_plane",
                method = "retain_safe_endpoints",
                context = context,
                offered = offered,
                kept = kept.len(),
                "dropped discovered relay endpoints that failed the host-safety rule"
            );
        }
        kept
    }

    /// Safe WebSocket-only subset for Nostr directory and KeyPackage work.
    /// Direct FIPS delivery is intentionally limited to the Marmot transport
    /// plane in this spike.
    pub(crate) fn retain_safe_websocket_endpoints(
        &self,
        endpoints: Vec<TransportEndpoint>,
        context: &str,
    ) -> Vec<TransportEndpoint> {
        let offered = endpoints.len();
        let kept = self
            .retain_safe_endpoints(endpoints, context)
            .into_iter()
            .filter(|endpoint| {
                matches!(
                    NostrRelayEndpoint::parse(endpoint.as_str()),
                    Ok(NostrRelayEndpoint::WebSocket(_))
                )
            })
            .collect::<Vec<_>>();
        if kept.len() != offered {
            tracing::debug!(
                target: "marmot_app::relay_plane",
                method = "retain_safe_websocket_endpoints",
                context = context,
                offered = offered,
                kept = kept.len(),
                "narrowed endpoints to the WebSocket-only relay plane"
            );
        }
        kept
    }

    pub(crate) fn sanitize_websocket_endpoints(
        &self,
        endpoints: Vec<TransportEndpoint>,
        context: &str,
    ) -> Result<Vec<TransportEndpoint>, String> {
        let offered = endpoints.len();
        let endpoints = self.sanitize_endpoints(endpoints, context)?;
        let kept = endpoints
            .into_iter()
            .filter(|endpoint| {
                matches!(
                    NostrRelayEndpoint::parse(endpoint.as_str()),
                    Ok(NostrRelayEndpoint::WebSocket(_))
                )
            })
            .collect::<Vec<_>>();
        if offered > 0 && kept.is_empty() {
            return Err(format!(
                "{context}: operation requires at least one WebSocket relay endpoint"
            ));
        }
        Ok(kept)
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
            let relay_endpoint = NostrRelayEndpoint::parse(raw)
                .map_err(|err| format!("{context}: invalid relay endpoint: {err}"))?;
            if let NostrRelayEndpoint::WebSocket(relay_url) = &relay_endpoint {
                reject_unsafe_relay_host(relay_url, self.allow_loopback)
                    .map_err(|reason| format!("{context}: {reason}"))?;
            }
            let endpoint = relay_endpoint.transport_endpoint();
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
    evaluate_relay_url(url, allow_loopback).map_err(|rejection| rejection.reason().to_owned())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelayEndpointRejection {
    Invalid,
    Retired,
    PlaintextPublic,
    NonPublicAddress,
    Localhost,
}

impl RelayEndpointRejection {
    fn policy(self) -> RelayEndpointPolicy {
        match self {
            Self::Invalid => RelayEndpointPolicy::Invalid,
            Self::Retired => RelayEndpointPolicy::Retired,
            Self::PlaintextPublic | Self::NonPublicAddress | Self::Localhost => {
                RelayEndpointPolicy::Unsafe
            }
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::Invalid => "invalid relay endpoint",
            Self::Retired => "relay endpoint host is retired",
            Self::PlaintextPublic => {
                "plaintext relay endpoints are allowed only for loopback in dev mode"
            }
            Self::NonPublicAddress => "relay endpoint host is not a public address",
            Self::Localhost => "relay endpoint host must not be localhost",
        }
    }
}

fn evaluate_relay_url(url: &RelayUrl, allow_loopback: bool) -> Result<(), RelayEndpointRejection> {
    let parsed = Url::parse(url.as_str()).map_err(|_| RelayEndpointRejection::Invalid)?;
    let host = parsed.host().ok_or(RelayEndpointRejection::Invalid)?;
    if is_retired_relay_host(&host) {
        return Err(RelayEndpointRejection::Retired);
    }
    if parsed.scheme() == "ws" {
        return if allow_loopback && is_loopback_host(host) {
            Ok(())
        } else {
            Err(RelayEndpointRejection::PlaintextPublic)
        };
    }
    match host {
        Host::Ipv4(addr) => reject_non_public_ip(IpAddr::V4(addr), allow_loopback)
            .map_err(|_| RelayEndpointRejection::NonPublicAddress),
        Host::Ipv6(addr) => reject_non_public_ip(IpAddr::V6(addr), allow_loopback)
            .map_err(|_| RelayEndpointRejection::NonPublicAddress),
        Host::Domain(domain) => {
            if is_loopback_host(Host::Domain(domain)) && !allow_loopback {
                return Err(RelayEndpointRejection::Localhost);
            }
            Ok(())
        }
    }
}

fn is_retired_relay_host(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => {
            let domain = domain.trim_end_matches('.');
            RETIRED_RELAY_HOSTS
                .iter()
                .any(|retired| domain.eq_ignore_ascii_case(retired))
        }
        Host::Ipv4(_) | Host::Ipv6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fips_endpoint() -> String {
        let public_key = nostr::PublicKey::from_hex(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        format!(
            "fips://{}",
            nostr::ToBech32::to_bech32(&public_key).unwrap()
        )
    }

    fn endpoints(urls: &[&str]) -> Vec<TransportEndpoint> {
        urls.iter()
            .map(|url| TransportEndpoint((*url).to_owned()))
            .collect()
    }

    /// Relay lists published by other accounts are input, not configuration.
    /// One hostile or malformed entry in somebody's NIP-65 list must not deny
    /// every other relay they publish -- otherwise anyone could make themselves
    /// unresolvable, or take the outbox path down for everyone, by adding a
    /// single bad URL. The host rule applied to each entry is the same one
    /// `sanitize_endpoints` enforces; only the answer to a rejection differs.
    #[test]
    fn discovered_endpoints_drop_the_unsafe_and_keep_the_rest() {
        let policy = RelaySafetyPolicy::default();

        let kept = policy.retain_safe_endpoints(
            endpoints(&[
                "wss://good.example",
                "ws://127.0.0.1:8080",
                "not a url",
                "wss://also-good.example",
                "ws://169.254.169.254",
            ]),
            "test",
        );

        assert_eq!(
            kept,
            endpoints(&["wss://good.example", "wss://also-good.example"])
        );
    }

    #[test]
    fn discovered_endpoints_are_deduplicated() {
        let policy = RelaySafetyPolicy::default();

        let kept = policy.retain_safe_endpoints(
            endpoints(&["wss://relay.example", "wss://relay.example"]),
            "test",
        );

        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn retired_relay_hosts_are_rejected_at_the_relay_plane_boundary() {
        let policy = RelaySafetyPolicy::default();
        for endpoint in [
            "wss://relay.damus.io",
            "wss://relay.nostr.band",
            "wss://RELAY.DAMUS.IO./path",
        ] {
            let offered = endpoints(&[endpoint, "wss://good.example"]);
            assert!(
                policy.sanitize_endpoints(offered.clone(), "test").is_err(),
                "configured routes must fail closed when they contain a retired relay"
            );
            assert_eq!(
                policy.retain_safe_endpoints(offered, "test"),
                endpoints(&["wss://good.example"]),
                "discovered routes must drop retired relays and keep safe siblings"
            );
        }
    }

    #[test]
    fn relay_endpoint_classifier_uses_the_dial_policy() {
        let policy = RelaySafetyPolicy::default();
        let classified = policy.classify_endpoints(vec![
            " wss://relay.example ".to_owned(),
            "wss://RELAY.DAMUS.IO./path".to_owned(),
            "not a relay".to_owned(),
            "ws://relay.example".to_owned(),
            "wss://127.0.0.1".to_owned(),
        ]);

        assert_eq!(
            classified
                .iter()
                .map(|result| result.policy)
                .collect::<Vec<_>>(),
            vec![
                RelayEndpointPolicy::Allowed,
                RelayEndpointPolicy::Retired,
                RelayEndpointPolicy::Invalid,
                RelayEndpointPolicy::Unsafe,
                RelayEndpointPolicy::Unsafe,
            ]
        );
        assert_eq!(classified[0].endpoint, " wss://relay.example ");
        assert!(classified[0].normalized_endpoint.is_some());
        assert!(classified[1].normalized_endpoint.is_some());
        assert_eq!(classified[2].normalized_endpoint, None);
    }

    #[test]
    fn relay_endpoint_classifier_respects_the_loopback_dev_opt_in() {
        let classified = RelaySafetyPolicy::with_allow_loopback(true)
            .classify_endpoints(vec!["ws://localhost:8080".to_owned()]);

        assert_eq!(classified[0].policy, RelayEndpointPolicy::Allowed);
    }

    #[test]
    fn retired_relay_host_list_is_stable_and_scheme_free() {
        assert_eq!(
            retired_relay_hosts(),
            vec!["relay.damus.io", "relay.nostr.band"]
        );
    }

    /// A published list of only unsafe hosts yields nothing, rather than
    /// falling back to anything the caller did not ask for.
    #[test]
    fn discovered_endpoints_can_all_be_dropped() {
        let policy = RelaySafetyPolicy::default();

        assert!(
            policy
                .retain_safe_endpoints(endpoints(&["ws://127.0.0.1", "ws://10.0.0.1"]), "test")
                .is_empty()
        );
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
    fn accepts_exact_fips_node_endpoints_without_treating_them_as_hosts() {
        let endpoint = fips_endpoint();
        for policy in [
            RelaySafetyPolicy::default(),
            RelaySafetyPolicy::with_allow_loopback(true),
        ] {
            assert_eq!(
                policy
                    .sanitize_endpoints(endpoints(&[&endpoint]), "test")
                    .unwrap(),
                endpoints(&[&endpoint])
            );
        }
    }

    #[test]
    fn rejects_extended_fips_node_endpoints() {
        let endpoint = fips_endpoint();
        let policy = RelaySafetyPolicy::default();
        for candidate in [
            format!("{endpoint}/"),
            format!("{endpoint}:443"),
            format!("{endpoint}?service=relay"),
        ] {
            assert!(
                policy
                    .sanitize_endpoints(endpoints(&[&candidate]), "test")
                    .is_err()
            );
        }
    }

    #[test]
    fn websocket_only_operations_drop_fips_siblings() {
        let fips = fips_endpoint();
        let policy = RelaySafetyPolicy::default();

        let sanitized = policy
            .sanitize_websocket_endpoints(
                endpoints(&["wss://relay.example", &fips]),
                "directory fetch",
            )
            .unwrap();

        assert_eq!(sanitized, endpoints(&["wss://relay.example"]));
        assert!(
            policy
                .sanitize_websocket_endpoints(endpoints(&[&fips]), "directory fetch")
                .is_err()
        );
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
