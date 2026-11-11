use std::net::IpAddr;

use cgka_traits::app_components::{is_loopback_host, reject_non_public_ip};
use cgka_traits::{
    MessageId, TransportAccountActivation, TransportAdapterError, TransportEndpoint,
    TransportEndpointFailure, TransportEndpointFailureKind, TransportGroupSync,
    TransportPublishFailure, TransportPublishReport, TransportPublishRequest,
    TransportPublishTarget,
};
use nostr_sdk::prelude::RelayUrl;
use serde::{Deserialize, Serialize};
use url::{Host, Url};

const MAX_RELAY_ENDPOINTS_PER_ROUTE: usize = 16;
const RETIRED_RELAY_HOSTS: &[&str] = &["relay.nostr.band"];

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

/// The reason of a publish endpoint the host-safety rule refused. It names
/// no endpoint, and audit records it as a failure before exposure.
pub(crate) const REFUSED_BY_SAFETY_RULE_REASON: &str =
    "relay endpoint refused by the host-safety rule";

/// A publish endpoint the host-safety rule refused, under the spelling the
/// request gave, so the caller finds the endpoint it asked for. Nothing was
/// sent there, and the same event can never be sent there.
fn refused_by_safety_rule(endpoint: TransportEndpoint) -> TransportEndpointFailure {
    TransportEndpointFailure {
        endpoint,
        reason: REFUSED_BY_SAFETY_RULE_REASON.to_owned(),
        kind: TransportEndpointFailureKind::NotExposed,
        rejection_category: None,
        size_class: None,
    }
}

/// The request's own spelling of each publish endpoint admission respelled.
///
/// Admission parses every endpoint, so a relay a group or inbox list spells
/// with an upper-case host or an explicit default port is sent to, and
/// answers, under its parsed spelling. The caller finds each answer by the
/// spelling it asked for, so publish reports every one under that spelling
/// (mdk#3305). Where the request spells one relay several ways, the relay's
/// one answer goes to the spelling admission keeps, or else to the first, so
/// a result never counts a relay twice.
pub(crate) struct RequestedSpellings(Vec<(TransportEndpoint, TransportEndpoint)>);

impl RequestedSpellings {
    fn restore(&self, endpoint: &mut TransportEndpoint) {
        if let Some((_, requested)) = self.0.iter().find(|(admitted, _)| admitted == endpoint) {
            *endpoint = requested.clone();
        }
    }

    /// `report`, with every relay named as the request named it.
    pub(crate) fn restore_report(&self, report: &mut TransportPublishReport) {
        for receipt in &mut report.accepted {
            self.restore(&mut receipt.endpoint);
        }
        for failure in &mut report.failed {
            self.restore(&mut failure.endpoint);
        }
    }

    /// `error`, with every relay it reports named as the request named it.
    pub(crate) fn restore_error(&self, mut error: TransportAdapterError) -> TransportAdapterError {
        if let TransportAdapterError::PublishEndpoints(failure) = &mut error {
            for failure in &mut failure.endpoint_failures {
                self.restore(&mut failure.endpoint);
            }
        }
        error
    }
}

/// A publish that failed on the relays it was sent to, joined by the relays
/// the host-safety rule refused. They leave its size proof alone, which covers
/// only the relays publish can reach. A whole-call error stays whole, as it
/// does when joined by size refusals.
pub(crate) fn join_unsafe_refusals(
    error: TransportAdapterError,
    refused: Vec<TransportEndpointFailure>,
) -> TransportAdapterError {
    match error {
        TransportAdapterError::PublishEndpoints(mut failure) => {
            failure.endpoint_failures.extend(refused);
            TransportAdapterError::PublishEndpoints(failure)
        }
        error => error,
    }
}

/// Hostnames that the relay plane will never dial or adopt.
pub fn retired_relay_hosts() -> Vec<String> {
    RETIRED_RELAY_HOSTS
        .iter()
        .map(|host| (*host).to_owned())
        .collect()
}

#[derive(Clone, Debug)]
pub struct RelaySafetyPolicy {
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
    pub fn with_allow_loopback(allow_loopback: bool) -> Self {
        Self {
            allow_loopback,
            ..Self::default()
        }
    }

    pub fn classify_endpoints(&self, endpoints: Vec<String>) -> Vec<RelayEndpointClassification> {
        endpoints
            .into_iter()
            .map(|endpoint| self.classify_endpoint(endpoint))
            .collect()
    }

    fn classify_endpoint(&self, endpoint: String) -> RelayEndpointClassification {
        let raw = endpoint.trim();
        let Ok(relay_url) = RelayUrl::parse(raw) else {
            return RelayEndpointClassification {
                endpoint,
                normalized_endpoint: None,
                policy: RelayEndpointPolicy::Invalid,
            };
        };
        let normalized_endpoint = Some(relay_url.to_string());
        let policy = match evaluate_relay_url(&relay_url, self.allow_loopback) {
            Ok(()) => RelayEndpointPolicy::Allowed,
            Err(rejection) => rejection.policy(),
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
        self.filter_group_routes(&mut activation.group_subscriptions);
        Ok(activation)
    }

    pub(crate) fn sanitize_group_sync(
        &self,
        mut sync: TransportGroupSync,
    ) -> Result<TransportGroupSync, String> {
        self.filter_group_routes(&mut sync.group_subscriptions);
        Ok(sync)
    }

    fn filter_group_routes(&self, groups: &mut Vec<cgka_traits::TransportGroupSubscription>) {
        // Signed group routes are peer input. An unusable route must not
        // prevent the account's inbox or other groups from subscribing.
        let offered = groups.len();
        groups.retain_mut(|group| {
            group.endpoints =
                self.usable_group_endpoints(std::mem::take(&mut group.endpoints), "group route");
            !group.endpoints.is_empty()
        });
        let dropped_routes = offered - groups.len();
        if dropped_routes != 0 {
            tracing::warn!(
                target: "marmot_app::relay_plane",
                method = "filter_group_routes",
                dropped_routes,
                "omitted group routes with no usable relay endpoints"
            );
        }
    }

    fn usable_group_endpoints(
        &self,
        endpoints: Vec<TransportEndpoint>,
        context: &str,
    ) -> Vec<TransportEndpoint> {
        let mut kept = self.retain_safe_endpoints(endpoints, context);
        kept.truncate(self.max_endpoints_per_route);
        kept
    }

    /// One publish request as the rule lets it go out: the request with the
    /// endpoints it may send to, and a failure before exposure for each
    /// endpoint the rule refused. Nothing is ever sent to a refused endpoint,
    /// so its outcome is definite (mdk#3276). A request the rule lets send
    /// nowhere fails with those same failures. A request refused for another
    /// reason, such as an inbox list over the route cap, fails whole.
    pub(crate) fn admit_publish_request(
        &self,
        request: TransportPublishRequest,
        message_id: Option<MessageId>,
    ) -> Result<(TransportPublishRequest, Vec<TransportEndpointFailure>), TransportAdapterError>
    {
        let requested = request.target.endpoints().len();
        let refused = request
            .target
            .endpoints()
            .iter()
            .filter(|endpoint| self.admitted_relay_url(endpoint).is_none())
            .cloned()
            .map(refused_by_safety_rule)
            .collect::<Vec<_>>();
        match self.sanitize_publish_request(request) {
            Ok(request) => Ok((request, refused)),
            Err(_) if !refused.is_empty() && refused.len() == requested => {
                let mut failure = TransportPublishFailure::with_endpoint_failures(
                    REFUSED_BY_SAFETY_RULE_REASON,
                    refused,
                );
                failure.message_id = message_id;
                Err(TransportAdapterError::PublishEndpoints(failure))
            }
            Err(reason) => Err(TransportAdapterError::Publish(reason)),
        }
    }

    /// How a publish to `requested` names each relay it sends to, against the
    /// request's own spelling. See [`RequestedSpellings`].
    pub(crate) fn requested_spellings(
        &self,
        requested: &[TransportEndpoint],
    ) -> RequestedSpellings {
        RequestedSpellings(
            requested
                .iter()
                .filter_map(|endpoint| {
                    let admitted = self.admitted_spelling(endpoint)?;
                    (!requested.contains(&admitted)).then(|| (admitted, endpoint.clone()))
                })
                .collect(),
        )
    }

    pub(crate) fn sanitize_publish_request(
        &self,
        mut request: TransportPublishRequest,
    ) -> Result<TransportPublishRequest, String> {
        request.target = self.sanitize_publish_target(request.target)?;
        Ok(request)
    }

    /// The endpoints one publish request to `target` may send to, or why it
    /// may send to none. Every publish request passes here, and so does the
    /// size preflight, through [`Self::reachable_publish_endpoints`].
    ///
    /// Both targets drop the endpoints the rule refuses and keep the rest.
    /// A Welcome's inbox list is the recipient's published list, not this
    /// device's configuration, so one bad entry in it must not stop the
    /// Welcome reaching the others.
    fn sanitize_publish_target(
        &self,
        mut target: TransportPublishTarget,
    ) -> Result<TransportPublishTarget, String> {
        match &mut target {
            TransportPublishTarget::Group { endpoints, .. } => {
                *endpoints =
                    self.usable_group_endpoints(std::mem::take(endpoints), "group publish");
                if endpoints.is_empty() {
                    return Err("group publish: no safe relay endpoints".to_owned());
                }
            }
            TransportPublishTarget::Inbox { endpoints, .. } => {
                let offered = endpoints.len();
                *endpoints = self.retain_safe_endpoints(std::mem::take(endpoints), "inbox publish");
                if endpoints.is_empty() && offered != 0 {
                    return Err("inbox publish: no safe relay endpoints".to_owned());
                }
                if endpoints.len() > self.max_endpoints_per_route {
                    return Err(format!(
                        "inbox publish: relay endpoint count {} exceeds limit {}",
                        endpoints.len(),
                        self.max_endpoints_per_route
                    ));
                }
            }
        }
        Ok(target)
    }

    /// Every endpoint of `target` that some publish request to it can send to.
    ///
    /// The session publishes a group event one endpoint per request, and
    /// retries a Welcome the same way after its first request for the whole
    /// inbox list. So this is each endpoint a one-endpoint request keeps. A
    /// request for several endpoints reaches no other: sanitizing a list only
    /// drops endpoints, caps them, or refuses the list.
    pub(crate) fn reachable_publish_endpoints(
        &self,
        target: &TransportPublishTarget,
    ) -> Vec<TransportEndpoint> {
        let mut reachable: Vec<TransportEndpoint> = Vec::new();
        for endpoint in target.endpoints() {
            let one = match target {
                TransportPublishTarget::Group {
                    group_id,
                    transport_group_id,
                    ..
                } => TransportPublishTarget::Group {
                    group_id: group_id.clone(),
                    transport_group_id: transport_group_id.clone(),
                    endpoints: vec![endpoint.clone()],
                },
                TransportPublishTarget::Inbox { recipient, .. } => TransportPublishTarget::Inbox {
                    recipient: recipient.clone(),
                    endpoints: vec![endpoint.clone()],
                },
            };
            let Ok(one) = self.sanitize_publish_target(one) else {
                continue;
            };
            for endpoint in one.endpoints() {
                if !reachable.contains(endpoint) {
                    reachable.push(endpoint.clone());
                }
            }
        }
        reachable
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
    /// Group routes also apply the route limit through
    /// [`Self::usable_group_endpoints`].
    pub(crate) fn retain_safe_endpoints(
        &self,
        endpoints: Vec<TransportEndpoint>,
        context: &str,
    ) -> Vec<TransportEndpoint> {
        let offered = endpoints.len();
        let mut kept: Vec<TransportEndpoint> = Vec::new();
        for endpoint in endpoints {
            let Some(endpoint) = self.admitted_spelling(&endpoint) else {
                continue;
            };
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

    /// The relay URL of a discovered endpoint that passes the host-safety
    /// rule. Every publish and discovered-list decision asks this.
    fn admitted_relay_url(&self, endpoint: &TransportEndpoint) -> Option<RelayUrl> {
        let relay_url = RelayUrl::parse(endpoint.as_str().trim()).ok()?;
        reject_unsafe_relay_host(&relay_url, self.allow_loopback)
            .is_ok()
            .then_some(relay_url)
    }

    /// The spelling a discovered endpoint that passes the host-safety rule
    /// goes on under: its parsed relay URL.
    fn admitted_spelling(&self, endpoint: &TransportEndpoint) -> Option<TransportEndpoint> {
        self.admitted_relay_url(endpoint)
            .map(|relay_url| TransportEndpoint(relay_url.to_string()))
    }

    pub fn sanitize_endpoints(
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

impl super::MarmotRelayPlaneAccountAdapter {
    #[doc(hidden)]
    pub fn recovery_admitted_endpoints(&self, endpoints: &[TransportEndpoint]) -> Vec<String> {
        let admitted: std::collections::HashSet<_> = self
            .relay_plane
            .inner
            .relay_safety
            .usable_group_endpoints(endpoints.to_vec(), "recovery scope")
            .into_iter()
            .map(|endpoint| endpoint.0)
            .collect();
        // Preserve signed spelling in the frozen goal. Membership queries use
        // the adapter's forward canonical identity lookup, never URL rewrites.
        let mut result = endpoints
            .iter()
            .filter(|endpoint| {
                RelayUrl::parse(endpoint.as_str().trim())
                    .is_ok_and(|url| admitted.contains(url.as_str()))
            })
            .map(|endpoint| endpoint.0.clone())
            .collect::<Vec<_>>();
        result.sort();
        result.dedup();
        result
    }
}

/// Whether two endpoint spellings name the same relay. Parsing normalizes
/// case and default ports, which a route's signed spelling may not.
pub fn same_relay(left: &str, right: &str) -> bool {
    left == right
        || matches!(
            (RelayUrl::parse(left.trim()), RelayUrl::parse(right.trim())),
            (Ok(left), Ok(right)) if left == right
        )
}

/// One spelling per relay, so endpoint strings from different layers can key
/// one ledger row: the parsed URL, or the trimmed input when it does not
/// parse. Parsing keeps a root path's slash as given, so a bare root slash is
/// dropped; any other path, slash included, still names its own endpoint.
pub fn canonical_relay(endpoint: &str) -> String {
    let endpoint = endpoint.trim();
    let mut parsed =
        RelayUrl::parse(endpoint).map_or_else(|_| endpoint.to_owned(), |url| url.to_string());
    let authority = parsed.find("://").map_or(0, |index| index + 3);
    if parsed[authority..]
        .find('/')
        .is_some_and(|slash| authority + slash + 1 == parsed.len())
    {
        parsed.pop();
    }
    parsed
}

/// The endpoints whose comparison certifies a recovery scope, chosen from the
/// ones recovery may contact (`admitted`): the route's operated relays. Any
/// other relay is best effort and never blocks completion. A route with no
/// operated relay requires all of its admitted relays, so its history can
/// still certify. A relay the plane refuses, such as a retired or unsafe
/// host, or one past the per-route cap, is never compared and never required.
pub fn recovery_required_endpoints(admitted: &[String], operated: &[String]) -> Vec<String> {
    let operated = operated
        .iter()
        .filter_map(|relay| RelayUrl::parse(relay.trim()).ok())
        .collect::<std::collections::HashSet<_>>();
    let is_operated = |endpoint: &&String| {
        RelayUrl::parse(endpoint.trim()).is_ok_and(|url| operated.contains(&url))
    };
    let mut required = if admitted.iter().any(|endpoint| is_operated(&endpoint)) {
        admitted
            .iter()
            .filter(is_operated)
            .cloned()
            .collect::<Vec<_>>()
    } else {
        admitted.to_vec()
    };
    required.sort();
    required.dedup();
    required
}

/// Require TLS for every public relay. Plaintext `ws://` is admitted only for
/// an explicitly enabled loopback host; private/link-local/CGNAT and public
/// plaintext endpoints stay rejected even with the dev flag. Relay
/// endpoints arrive from signed routing components and relay-list events, so a
/// poisoned record must not steer the relay pool at internal services (SSRF;
/// see `docs/marmot-architecture/overview/dial-safety.md`). A `wss://` DOMAIN
/// host other than `.onion` is accepted here: nostr-sdk owns DNS resolution and the WebSocket, so
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
    TorRequired,
}

impl RelayEndpointRejection {
    fn policy(self) -> RelayEndpointPolicy {
        match self {
            Self::Invalid => RelayEndpointPolicy::Invalid,
            Self::Retired => RelayEndpointPolicy::Retired,
            Self::PlaintextPublic
            | Self::NonPublicAddress
            | Self::Localhost
            | Self::TorRequired => RelayEndpointPolicy::Unsafe,
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
            Self::TorRequired => "onion relay endpoints require a Tor transport",
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
            if domain.trim_end_matches('.').ends_with(".onion") {
                return Err(RelayEndpointRejection::TorRequired);
            }
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

    fn strings(urls: &[&str]) -> Vec<String> {
        urls.iter().map(|url| (*url).to_owned()).collect()
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
        for endpoint in ["wss://relay.nostr.band", "wss://RELAY.NOSTR.BAND./path"] {
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
            "wss://RELAY.NOSTR.BAND./path".to_owned(),
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
        assert_eq!(retired_relay_hosts(), vec!["relay.nostr.band"]);
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
    fn onion_relays_require_tor() {
        for policy in [
            RelaySafetyPolicy::default(),
            RelaySafetyPolicy::with_allow_loopback(true),
        ] {
            for url in [
                "ws://relay.onion",
                "wss://relay.onion",
                "wss://RELAY.ONION.",
            ] {
                assert_eq!(
                    policy.classify_endpoint(url.into()).policy,
                    RelayEndpointPolicy::Unsafe
                );
                assert!(
                    policy
                        .sanitize_endpoints(endpoints(&[url]), "test")
                        .is_err()
                );
                assert!(
                    policy
                        .retain_safe_endpoints(endpoints(&[url]), "test")
                        .is_empty()
                );
            }
            assert!(
                policy
                    .sanitize_endpoints(endpoints(&["wss://relay.onion.example"]), "test")
                    .is_ok()
            );
        }
    }

    #[test]
    fn same_relay_compares_parsed_identities() {
        assert!(same_relay("wss://relay.example", "wss://relay.example"));
        assert!(same_relay("wss://Relay.Example:443", "wss://relay.example"));
        assert!(same_relay("wss://relay.example/", "wss://relay.example"));
        assert!(!same_relay("wss://relay.example", "wss://other.example"));
    }

    #[test]
    fn canonical_relay_spells_same_relays_alike() {
        for spelling in [
            "wss://relay.example/",
            "wss://Relay.Example:443",
            " wss://relay.example ",
        ] {
            assert_eq!(
                canonical_relay(spelling),
                canonical_relay("wss://relay.example")
            );
        }
        assert_ne!(
            canonical_relay("wss://relay.example"),
            canonical_relay("wss://other.example")
        );
        // A path names its own endpoint, with or without a trailing slash.
        assert_ne!(
            canonical_relay("wss://relay.example/feed"),
            canonical_relay("wss://relay.example/feed/")
        );
        assert_ne!(
            canonical_relay("wss://relay.example/feed"),
            canonical_relay("wss://relay.example")
        );
        assert_ne!(
            canonical_relay("wss://relay.example/?a=1"),
            canonical_relay("wss://relay.example")
        );
        assert_eq!(canonical_relay("wss://"), "wss://");
    }

    #[test]
    fn operated_relays_alone_certify_a_route_that_names_them() {
        let operated = vec![
            "wss://relay.eu.whitenoise.chat".to_owned(),
            "wss://relay.us.whitenoise.chat/".to_owned(),
        ];
        assert_eq!(
            recovery_required_endpoints(
                &strings(&[
                    "wss://relay.primal.net",
                    "wss://relay.us.whitenoise.chat",
                    "wss://nos.lol",
                ]),
                &operated,
            ),
            vec!["wss://relay.us.whitenoise.chat".to_owned()],
            "an operated relay certifies in the route's own spelling; the rest are best effort"
        );
        assert_eq!(
            recovery_required_endpoints(
                &strings(&[
                    "wss://relay.us.whitenoise.chat",
                    "wss://relay.eu.whitenoise.chat"
                ]),
                &operated,
            ),
            vec![
                "wss://relay.eu.whitenoise.chat".to_owned(),
                "wss://relay.us.whitenoise.chat".to_owned(),
            ]
        );
        assert_eq!(
            recovery_required_endpoints(
                &strings(&["wss://nos.lol", "wss://relay.primal.net"]),
                &operated,
            ),
            vec![
                "wss://nos.lol".to_owned(),
                "wss://relay.primal.net".to_owned()
            ],
            "a route with no operated relay still certifies on all of its relays"
        );
        assert!(recovery_required_endpoints(&[], &operated).is_empty());
    }

    #[test]
    fn a_relay_the_plane_refuses_is_never_required() {
        // Required relays are chosen from the admitted ones, so a route with
        // no operated relay can still certify on the relays recovery dials.
        let policy = RelaySafetyPolicy::default();
        let admitted = policy
            .usable_group_endpoints(endpoints(&["wss://nos.lol", "wss://10.0.0.1"]), "test")
            .into_iter()
            .map(|endpoint| endpoint.0)
            .collect::<Vec<_>>();
        assert_eq!(
            recovery_required_endpoints(&admitted, &[]),
            vec!["wss://nos.lol".to_owned()]
        );
    }

    #[test]
    fn count_cap_still_enforced() {
        let policy = RelaySafetyPolicy::default();
        let many: Vec<String> = (0..20).map(|i| format!("wss://relay{i}.example")).collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(policy.sanitize_endpoints(endpoints(&refs), "test").is_err());
    }

    /// A publish to the fixture's group on `endpoints`.
    fn group_target(
        fixture: &crate::test_support::AccountPublishFixture,
        endpoints: Vec<TransportEndpoint>,
    ) -> TransportPublishTarget {
        TransportPublishTarget::Group {
            group_id: cgka_traits::GroupId::new(vec![0xC3; 32]),
            transport_group_id: fixture.transport_group_id.clone(),
            endpoints,
        }
    }

    /// A gift-wrapped Welcome.
    fn welcome() -> cgka_traits::transport::TransportMessage {
        use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};
        use transport_nostr_peeler::NostrTransportEvent;

        NostrTransportEvent::from_nostr_event(
            &EventBuilder::new(Kind::GiftWrap, "sealed welcome")
                .tags([Tag::public_key(
                    Keys::parse(&"33".repeat(32)).unwrap().public_key(),
                )])
                .finalize(&Keys::parse(&"11".repeat(32)).unwrap())
                .unwrap(),
        )
        .unwrap()
        .to_transport_message()
        .unwrap()
    }

    /// A publish of `welcome` to its recipient's inbox list `endpoints`.
    fn inbox_target(
        welcome: &cgka_traits::transport::TransportMessage,
        endpoints: Vec<TransportEndpoint>,
    ) -> TransportPublishTarget {
        let cgka_traits::transport::TransportEnvelope::Welcome { recipient } = &welcome.envelope
        else {
            panic!("a gift wrap is a Welcome");
        };
        TransportPublishTarget::Inbox {
            recipient: recipient.clone(),
            endpoints,
        }
    }

    /// mdk#3276: publish never contacts a relay the host-safety rule refuses,
    /// so it reports each one as a failure before exposure, under the spelling
    /// the request gave, and sends to the rest. A request the rule lets send
    /// nowhere fails with those failures. A whole-call error instead reads to
    /// the caller as a relay that may hold the event, which it retries and
    /// which keeps a refused commit from rolling back.
    #[tokio::test]
    async fn publish_reports_each_refused_relay_as_unexposed_and_sends_to_the_rest() {
        use std::sync::atomic::Ordering;

        use cgka_traits::TransportAdapter;

        use crate::test_support::AccountPublishFixture;

        let fixture = AccountPublishFixture::activate().await;
        let safe = fixture.endpoint.clone();
        let refused = endpoints(&["wss://10.0.0.1", "ws://plaintext.example", "not a url"]);
        let group = |endpoints| group_target(&fixture, endpoints);
        let welcome = welcome();
        let inbox = |endpoints| inbox_target(&welcome, endpoints);
        let with_safe = [refused.clone(), vec![safe.clone()]].concat();

        for (message, target, refused, sent_to) in [
            // The session's group fanout: one relay per request.
            (
                &fixture.message,
                group(refused[..1].to_vec()),
                &refused[..1],
                None,
            ),
            (&fixture.message, group(refused.clone()), &refused[..], None),
            (
                &fixture.message,
                group(with_safe.clone()),
                &refused[..],
                Some(&safe),
            ),
            // A Welcome's first request: the recipient's whole inbox list.
            (&welcome, inbox(refused.clone()), &refused[..], None),
            (
                &welcome,
                inbox(with_safe.clone()),
                &refused[..],
                Some(&safe),
            ),
        ] {
            let calls = fixture.client.calls.load(Ordering::SeqCst);
            let result = fixture
                .adapter
                .publish(TransportPublishRequest {
                    account_id: fixture.account_id.clone(),
                    message: message.clone(),
                    target: target.clone(),
                    required_acks: 1,
                })
                .await;
            let (accepted, failed) = match result {
                Ok(report) => (
                    report
                        .accepted
                        .into_iter()
                        .map(|receipt| receipt.endpoint)
                        .collect::<Vec<_>>(),
                    report.failed,
                ),
                Err(TransportAdapterError::PublishEndpoints(failure)) => {
                    assert_eq!(failure.message_id.as_ref(), Some(&message.id), "{target:?}");
                    (Vec::new(), failure.endpoint_failures)
                }
                Err(error) => panic!("a whole-call error for {target:?}: {error:?}"),
            };
            assert_eq!(accepted, sent_to.cloned().into_iter().collect::<Vec<_>>());
            assert_eq!(
                failed,
                refused
                    .iter()
                    .cloned()
                    .map(|endpoint| TransportEndpointFailure {
                        endpoint,
                        reason: REFUSED_BY_SAFETY_RULE_REASON.to_owned(),
                        kind: TransportEndpointFailureKind::NotExposed,
                        rejection_category: None,
                        size_class: None,
                    })
                    .collect::<Vec<_>>(),
                "{target:?}"
            );
            assert_eq!(
                fixture.client.calls.load(Ordering::SeqCst) - calls,
                usize::from(sent_to.is_some()),
                "only the admitted relay is sent to: {target:?}"
            );
        }
    }

    /// mdk#3305: publish names every relay in its result as the request
    /// spelled it, receipt or failure, in a report or an error. Admission
    /// sends to each relay under its parsed spelling, and the relay client
    /// answers under that spelling, but the caller finds each answer by its
    /// own. A relay a group or inbox list spells with an upper-case host or a
    /// default port otherwise reads as possibly exposed, whatever it answered,
    /// and a commit sent only there never resolves.
    #[tokio::test]
    async fn publish_reports_each_relay_under_the_spelling_the_request_gave() {
        use cgka_traits::TransportAdapter;

        use crate::test_support::{AccountPublishFixture, PublishScript};

        let fixture = AccountPublishFixture::activate().await;
        // Both parse to the fixture's relay, `wss://relay.example`.
        let relay = TransportEndpoint("wss://Relay.example:443".into());
        let also_relay = TransportEndpoint("WSS://RELAY.EXAMPLE".into());
        let other = TransportEndpoint("wss://Other.example".into());
        let welcome = welcome();

        for (message, target, named) in [
            // The session's group fanout: one relay per request.
            (
                &fixture.message,
                group_target(&fixture, vec![relay.clone()]),
                vec![relay.clone()],
            ),
            // A Welcome's first request: the recipient's whole inbox list. A
            // relay it spells twice answers once, under its first spelling...
            (
                &welcome,
                inbox_target(&welcome, vec![relay.clone(), other.clone(), also_relay]),
                vec![relay.clone(), other.clone()],
            ),
            // ...or under the spelling admission gives it, when the list has it.
            (
                &welcome,
                inbox_target(&welcome, vec![relay.clone(), fixture.endpoint.clone()]),
                vec![fixture.endpoint.clone()],
            ),
        ] {
            for script in [
                PublishScript::Accept,
                PublishScript::Refuse,
                PublishScript::RefuseInError,
            ] {
                fixture.client.set_script(script);
                let result = fixture
                    .adapter
                    .publish(TransportPublishRequest {
                        account_id: fixture.account_id.clone(),
                        message: message.clone(),
                        target: target.clone(),
                        required_acks: 1,
                    })
                    .await;
                let mut answered = match result {
                    Ok(report) => report
                        .accepted
                        .into_iter()
                        .map(|receipt| receipt.endpoint)
                        .chain(report.failed.into_iter().map(|failure| failure.endpoint))
                        .collect::<Vec<_>>(),
                    Err(TransportAdapterError::PublishEndpoints(failure)) => failure
                        .endpoint_failures
                        .into_iter()
                        .map(|failure| failure.endpoint)
                        .collect(),
                    Err(error) => panic!("a whole-call error for {target:?}: {error:?}"),
                };
                answered.sort();
                let mut named = named.clone();
                named.sort();
                assert_eq!(answered, named, "{target:?}");
            }
        }
    }
}
