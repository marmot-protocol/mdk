use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use cgka_traits::app_components::{
    is_loopback_candidate_host, is_loopback_host, is_loopback_ip, is_public_ip, is_public_ipv4,
    is_public_ipv6, reject_non_public_ip, reject_non_public_socket_addr,
};
use url::Host;

#[test]
fn shared_host_safety_classifies_loopback_hosts() {
    assert!(is_loopback_host(Host::Domain("localhost")));
    assert!(is_loopback_host(Host::Domain("dev.localhost")));
    assert!(is_loopback_host(Host::Ipv4(Ipv4Addr::LOCALHOST)));
    assert!(is_loopback_host(Host::Ipv6(Ipv6Addr::LOCALHOST)));
    assert!(is_loopback_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert!(is_loopback_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));

    assert!(!is_loopback_host(Host::Domain("example.localhost.evil")));
    assert!(!is_loopback_host(Host::Ipv4(Ipv4Addr::new(
        93, 184, 216, 34
    ))));

    // Rooted (fully-qualified) forms keep a trailing dot but still resolve to
    // loopback, so they must classify like their unrooted forms.
    assert!(is_loopback_host(Host::Domain("localhost.")));
    assert!(is_loopback_host(Host::Domain("dev.localhost.")));
    assert!(is_loopback_host(Host::Domain("LOCALHOST.")));
}

#[test]
fn shared_host_safety_classifies_loopback_candidate_hosts() {
    // The QUIC-candidate loopback gate is narrower than `is_loopback_host`:
    // only exact `localhost` (rooted or not) or a loopback IP literal.
    for host in ["localhost", "localhost.", "LOCALHOST", "127.0.0.1", "::1"] {
        assert!(is_loopback_candidate_host(host), "{host}");
    }
    // `*.localhost` subdomains are NOT candidate-loopback (they do not
    // unambiguously name a local endpoint for the insecure-trust gate).
    for host in [
        "dev.localhost",
        "dev.localhost.",
        "broker.example",
        "203.0.113.10",
    ] {
        assert!(!is_loopback_candidate_host(host), "{host}");
    }
}

#[test]
fn shared_host_safety_classifies_canonical_ipv4_ranges() {
    assert!(is_public_ipv4(Ipv4Addr::new(93, 184, 216, 34)));
    assert!(is_public_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));

    for raw in [
        "0.0.0.1",      // this-host 0.0.0.0/8
        "10.0.0.1",     // private
        "100.64.0.1",   // CGNAT
        "127.0.0.1",    // loopback
        "169.254.1.1",  // link-local
        "172.16.0.1",   // private
        "192.0.0.1",    // IETF protocol assignments
        "192.0.2.1",    // documentation
        "192.88.99.1",  // 6to4 relay anycast
        "192.168.1.1",  // private
        "198.18.0.1",   // benchmarking
        "198.51.100.1", // documentation
        "203.0.113.1",  // documentation
        "224.0.0.1",    // multicast/reserved
        "240.0.0.1",    // reserved
    ] {
        let addr: Ipv4Addr = raw.parse().expect("test IPv4 literal parses");
        assert!(!is_public_ipv4(addr), "{raw} should be rejected");
        assert!(!is_public_ip(IpAddr::V4(addr)), "{raw} should be rejected");
    }
}

#[test]
fn shared_host_safety_classifies_canonical_ipv6_ranges() {
    assert!(is_public_ipv6("2606:4700::1".parse().unwrap()));
    assert!(is_public_ipv6("::ffff:93.184.216.34".parse().unwrap()));
    assert!(is_public_ip(IpAddr::V6("2606:4700::1".parse().unwrap())));

    // Only the actual RFC 9637 block 3fff:0000::/20 is documentation space.
    // Neighbouring global-unicast hextets (3ff0:: to 3ffe::) and 3fff:: past the
    // /20 boundary (second hextet >= 0x1000) are ordinary routable space.
    for raw in ["3ff0::1", "3ffe::1", "3fff:1000::1", "3fff:ffff::1"] {
        let addr: Ipv6Addr = raw.parse().expect("test IPv6 literal parses");
        assert!(is_public_ipv6(addr), "{raw} should be accepted");
        assert!(is_public_ip(IpAddr::V6(addr)), "{raw} should be accepted");
    }

    for raw in [
        "::1",              // loopback
        "::",               // unspecified
        "ff00::1",          // multicast
        "::ffff:127.0.0.1", // mapped loopback IPv4
        "::ffff:10.0.0.1",  // mapped private IPv4
        "fc00::1",          // unique-local
        "fe80::1",          // link-local
        "2002::1",          // 6to4 transition prefix
        "2001::1",          // Teredo 2001:0000::/32
        "2001:db8::1",      // documentation
        "3fff::1",          // documentation 3fff::/20 (lower edge)
        "3fff:0fff::1",     // documentation 3fff::/20 (upper edge)
        "4000::1",          // outside global-unicast 2000::/3
    ] {
        let addr: Ipv6Addr = raw.parse().expect("test IPv6 literal parses");
        assert!(!is_public_ipv6(addr), "{raw} should be rejected");
        assert!(!is_public_ip(IpAddr::V6(addr)), "{raw} should be rejected");
    }
}

#[test]
fn shared_dial_gate_rejects_non_public_addresses() {
    // Public control addresses pass regardless of the loopback opt-in.
    for raw in ["93.184.216.34", "2606:4700::1"] {
        let addr: IpAddr = raw.parse().expect("test IP literal parses");
        assert!(reject_non_public_ip(addr, false).is_ok(), "{raw}");
        assert!(reject_non_public_ip(addr, true).is_ok(), "{raw}");
    }

    // Loopback is accepted only under the explicit dev/test opt-in.
    for raw in ["127.0.0.1", "::1"] {
        let addr: IpAddr = raw.parse().expect("test IP literal parses");
        assert!(reject_non_public_ip(addr, false).is_err(), "{raw}");
        assert!(reject_non_public_ip(addr, true).is_ok(), "{raw}");
    }

    // Every other non-public class stays rejected even with the loopback
    // opt-in: the flag opens loopback only, never private/link-local ranges.
    // Mapped loopback (`::ffff:127.0.0.1`) is not a plain loopback literal and
    // stays rejected too.
    for raw in [
        "10.0.0.1",         // private
        "100.64.0.1",       // CGNAT
        "169.254.169.254",  // link-local (cloud metadata)
        "172.16.0.1",       // private
        "192.168.1.1",      // private
        "fc00::1",          // unique-local
        "fe80::1",          // link-local
        "::ffff:10.0.0.1",  // mapped private IPv4
        "::ffff:127.0.0.1", // mapped loopback
    ] {
        let addr: IpAddr = raw.parse().expect("test IP literal parses");
        assert!(reject_non_public_ip(addr, false).is_err(), "{raw}");
        assert!(reject_non_public_ip(addr, true).is_err(), "{raw}");
    }
}

#[test]
fn shared_dial_gate_socket_addr_form_matches_ip_form() {
    let public: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let loopback: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let private: SocketAddr = "[fc00::1]:4433".parse().unwrap();

    assert!(reject_non_public_socket_addr(public, false).is_ok());
    assert!(reject_non_public_socket_addr(loopback, false).is_err());
    assert!(reject_non_public_socket_addr(loopback, true).is_ok());
    assert!(reject_non_public_socket_addr(private, true).is_err());
}
