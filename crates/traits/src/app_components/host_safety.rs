//! Public-IP / loopback host classifiers shared by app-component validators and
//! app fetch/upload code.
//!
//! This module owns the canonical unsafe-host set from
//! `spec/foundation/host-safety.md`. Callers keep their own URL/scheme policy and
//! error wording, but share these low-level host and IP classifiers so SSRF
//! hardening cannot drift across crates.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use url::Host;

/// Whether `host` is `localhost`, a subdomain of `.localhost`, or an IP
/// loopback literal. A rooted (fully-qualified) name keeps a trailing dot
/// (`localhost.`, `dev.localhost.`), which system resolution still maps to
/// loopback, so a single trailing dot is stripped before matching.
pub fn is_loopback_host(host: Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => is_loopback_domain(domain),
        Host::Ipv4(addr) => addr.is_loopback(),
        Host::Ipv6(addr) => addr.is_loopback(),
    }
}

fn is_loopback_domain(domain: &str) -> bool {
    let lowered = domain.to_ascii_lowercase();
    let unrooted = lowered.strip_suffix('.').unwrap_or(&lowered);
    unrooted == "localhost" || unrooted.ends_with(".localhost")
}

/// Whether a `quic://` broker candidate host is a literal loopback: exactly
/// `localhost` (rooted or not) or a loopback IP literal. Deliberately narrower
/// than [`is_loopback_host`] — it does not match `*.localhost` subdomains —
/// because it gates the no-cert-verification `InsecureLocal` trust, which must
/// only be reachable for an unambiguous local endpoint plus an explicit dev
/// flag. Shared by the agent-stream watch and agent-connector dial sites so the
/// two cannot drift.
pub fn is_loopback_candidate_host(host: &str) -> bool {
    let unrooted = host.strip_suffix('.').unwrap_or(host);
    if unrooted.eq_ignore_ascii_case("localhost") {
        return true;
    }
    unrooted
        .parse::<IpAddr>()
        .map(is_loopback_ip)
        .unwrap_or(false)
}

/// Whether `addr` is an IPv4 or IPv6 loopback address.
pub fn is_loopback_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => addr.is_loopback(),
        IpAddr::V6(addr) => addr.is_loopback(),
    }
}

/// Whether `addr` is public/global-routable under Marmot's canonical
/// unsafe-host set.
pub fn is_public_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => is_public_ipv4(addr),
        IpAddr::V6(addr) => is_public_ipv6(addr),
    }
}

/// Whether an IPv4 address is public/global-routable under Marmot's canonical
/// unsafe-host set.
pub fn is_public_ipv4(addr: Ipv4Addr) -> bool {
    let [a, b, c, d] = addr.octets();
    !matches!(
        (a, b, c, d),
        (0, _, _, _)
            | (10, _, _, _)
            | (100, 64..=127, _, _)
            | (127, _, _, _)
            | (169, 254, _, _)
            | (172, 16..=31, _, _)
            | (192, 0, 0, _)
            | (192, 0, 2, _)
            | (192, 88, 99, _)
            | (192, 168, _, _)
            | (198, 18..=19, _, _)
            | (198, 51, 100, _)
            | (203, 0, 113, _)
            | (224..=255, _, _, _)
    )
}

/// Whether an IPv6 address is public/global-routable under Marmot's canonical
/// unsafe-host set. IPv4-mapped IPv6 addresses are classified by their embedded
/// IPv4 address.
pub fn is_public_ipv6(addr: Ipv6Addr) -> bool {
    if let Some(mapped) = addr.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    if addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() {
        return false;
    }
    let segments = addr.segments();
    let first = segments[0];
    let second = segments[1];
    if (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 {
        return false;
    }
    // Reject IPv6 transition mechanisms that can route to an embedded IPv4
    // endpoint through host-local tunnel configuration, bypassing IPv4 checks.
    if first == 0x2002 || (first == 0x2001 && second == 0x0000) {
        return false;
    }
    if first == 0x2001 && second == 0x0db8 {
        return false;
    }
    // Documentation 3fff::/20 (RFC 9637): first hextet 0x3fff with the top
    // nibble of the second hextet zero. It falls inside global-unicast
    // 2000::/3, so the terminal rule below would otherwise accept it.
    if first == 0x3fff && (second & 0xf000) == 0 {
        return false;
    }
    // Only global unicast 2000::/3 is routable today; reject anything else not
    // already caught above.
    (first & 0xe000) == 0x2000
}

/// Reject `addr` unless it is public/global-routable. When `allow_loopback`
/// is set (an explicit dev/test opt-in, never inferred from resolution), an IP
/// loopback literal is also accepted. Every other non-public address (private,
/// link-local, CGNAT, ULA, multicast, unspecified, documentation, IPv6
/// transition) is always rejected. This is the shared dial-policy gate every
/// outbound connector runs each resolved address through; see
/// `docs/marmot-architecture/overview/dial-safety.md`.
pub fn reject_non_public_ip(addr: IpAddr, allow_loopback: bool) -> Result<(), String> {
    if (allow_loopback && is_loopback_ip(addr)) || is_public_ip(addr) {
        return Ok(());
    }
    Err("address is not a public unicast address".into())
}

/// [`reject_non_public_ip`] for an already-resolved socket address.
pub fn reject_non_public_socket_addr(addr: SocketAddr, allow_loopback: bool) -> Result<(), String> {
    reject_non_public_ip(addr.ip(), allow_loopback)
}

pub(crate) fn reject_non_routable_ipv4(addr: Ipv4Addr) -> Result<(), String> {
    if !is_public_ipv4(addr) {
        return Err("group avatar URL must not point at a non-routable address".into());
    }
    Ok(())
}

pub(crate) fn reject_non_routable_ipv6(addr: Ipv6Addr) -> Result<(), String> {
    if !is_public_ipv6(addr) {
        return Err("group avatar URL must not point at a non-routable address".into());
    }
    Ok(())
}
