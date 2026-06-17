use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use cgka_traits::app_components::{
    is_loopback_host, is_loopback_ip, is_public_ip, is_public_ipv4, is_public_ipv6,
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
        "3fff::1",          // documentation 3fff::/20
        "4000::1",          // outside global-unicast 2000::/3
    ] {
        let addr: Ipv6Addr = raw.parse().expect("test IPv6 literal parses");
        assert!(!is_public_ipv6(addr), "{raw} should be rejected");
        assert!(!is_public_ip(IpAddr::V6(addr)), "{raw} should be rejected");
    }
}
