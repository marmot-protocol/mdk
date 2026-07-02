//! Public-IP / loopback host classifiers shared by app-component validators and
//! app fetch/upload code.
//!
//! This module owns the canonical unsafe-host set from
//! `spec/foundation/host-safety.md`. Callers keep their own URL/scheme policy and
//! error wording, but share these low-level host and IP classifiers so SSRF
//! hardening cannot drift across crates.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Host;

/// Whether `host` is `localhost`, a subdomain of `.localhost`, or an IP
/// loopback literal.
pub fn is_loopback_host(host: Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => {
            let lowered = domain.to_ascii_lowercase();
            lowered == "localhost" || lowered.ends_with(".localhost")
        }
        Host::Ipv4(addr) => addr.is_loopback(),
        Host::Ipv6(addr) => addr.is_loopback(),
    }
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
    // Documentation 3fff::/20 (RFC 9637). It falls inside global-unicast
    // 2000::/3, so the terminal rule below would otherwise accept it.
    if (first & 0xfff0) == 0x3ff0 {
        return false;
    }
    // Only global unicast 2000::/3 is routable today; reject anything else not
    // already caught above.
    (first & 0xe000) == 0x2000
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
