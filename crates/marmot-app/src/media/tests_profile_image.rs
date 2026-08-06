//! Profile-image dial-safe fetch acceptance tests (mdk#1287).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use cgka_traits::app_components::ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN;
use url::Url;

use super::blossom::{
    plan_profile_image_pin, profile_operation_timeout_for_test, read_limited_blossom_body,
};
use super::host_safety::validate_profile_image_fetch_url;
use super::{
    MAX_PROFILE_IMAGE_BYTES, download_profile_image, download_profile_image_with_injected_addrs,
    normalize_profile_image_max_bytes_for_test,
};

fn public_socket_addr(byte: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, byte)), 443)
}

#[tokio::test]
async fn download_profile_image_rejects_loopback_literal_before_network() {
    let err = download_profile_image("https://127.0.0.1/avatar.png".to_owned(), 1024)
        .await
        .expect_err("loopback profile URL must not be dialed");
    assert!(
        err.to_string().contains("localhost") || err.to_string().contains("public unicast"),
        "expected pre-dial rejection, got {err}"
    );
}

#[test]
fn profile_image_fetch_url_rejects_rooted_localhost_forms() {
    for url in [
        "https://localhost./avatar.png",
        "https://dev.localhost./avatar.png",
    ] {
        let parsed = Url::parse(url).unwrap();
        let err = validate_profile_image_fetch_url(&parsed).unwrap_err();
        assert!(err.contains("localhost"), "url {url}: {err}");
    }
}

#[test]
fn profile_image_fetch_url_rejects_private_and_special_use_literals() {
    for url in [
        "https://127.0.0.1/avatar.png",
        "https://localhost/avatar.png",
        "https://sub.localhost/avatar.png",
        "https://10.0.0.1/avatar.png",
        "https://169.254.169.254/avatar.png",
        "https://[::1]/avatar.png",
        "https://[fc00::1]/avatar.png",
        "https://[3fff::1]/avatar.png",
    ] {
        let parsed = Url::parse(url).unwrap();
        let err = validate_profile_image_fetch_url(&parsed).unwrap_err();
        assert!(
            err.contains("localhost") || err.contains("public unicast"),
            "url {url}: {err}"
        );
    }
}

#[test]
fn profile_image_fetch_url_length_boundary_and_over_limit() {
    let prefix = "https://media.example/";
    let under = format!(
        "{}{}",
        prefix,
        "a".repeat(ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN - prefix.len())
    );
    assert!(validate_profile_image_fetch_url(&Url::parse(&under).unwrap()).is_ok());

    let over = format!(
        "{}{}",
        prefix,
        "a".repeat(ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN - prefix.len() + 1)
    );
    let err = validate_profile_image_fetch_url(&Url::parse(&over).unwrap()).unwrap_err();
    assert!(err.contains("exceeds"));
}

#[test]
fn profile_image_fetch_url_rejects_credentials_fragments_scheme_and_custom_port() {
    let base = "https://media.example/avatar.png";
    for (url, needle) in [
        ("https://user@media.example/avatar.png", "credentials"),
        ("https://media.example/avatar.png#frag", "fragment"),
        ("http://media.example/avatar.png", "https"),
        (
            "https://media.example:8443/avatar.png",
            "default HTTPS port",
        ),
    ] {
        let parsed = Url::parse(url).unwrap();
        let err = validate_profile_image_fetch_url(&parsed).unwrap_err();
        assert!(err.contains(needle), "url {url}: {err}");
    }
    assert!(validate_profile_image_fetch_url(&Url::parse(base).unwrap()).is_ok());
}

#[test]
fn profile_image_redirect_validation_allows_cross_domain_public_targets() {
    let current = Url::parse("https://profiles.example/a.png").unwrap();
    let next = Url::parse("https://cdn.other.example/b.png").unwrap();
    assert!(validate_profile_image_fetch_url(&current).is_ok());
    assert!(validate_profile_image_fetch_url(&next).is_ok());
    assert!(
        super::blossom::validate_blossom_redirect_target(&current, &next, false).is_err(),
        "Blossom must keep registrable-domain affinity"
    );
}

#[test]
fn profile_image_redirect_validation_rejects_unsafe_targets_before_resolve() {
    let safe = Url::parse("https://profiles.example/a.png").unwrap();
    for bad in [
        "http://cdn.other.example/b.png",
        "https://127.0.0.1/b.png",
        "https://localhost./b.png",
        "https://dev.localhost./b.png",
        "https://user@cdn.other.example/b.png",
        "https://cdn.other.example/b.png#x",
        "https://cdn.other.example:8443/b.png",
    ] {
        let parsed = Url::parse(bad).unwrap();
        assert!(
            validate_profile_image_fetch_url(&parsed).is_err(),
            "redirect target must be rejected: {bad}"
        );
    }
    assert!(validate_profile_image_fetch_url(&safe).is_ok());
}

#[test]
fn profile_image_max_bytes_zero_ceiling_and_exact_ceiling() {
    assert!(
        normalize_profile_image_max_bytes_for_test(0)
            .unwrap_err()
            .to_string()
            .contains("positive")
    );
    assert!(
        normalize_profile_image_max_bytes_for_test(MAX_PROFILE_IMAGE_BYTES as u64 + 1)
            .unwrap_err()
            .to_string()
            .contains("ceiling")
    );
    assert_eq!(
        normalize_profile_image_max_bytes_for_test(MAX_PROFILE_IMAGE_BYTES as u64).unwrap(),
        MAX_PROFILE_IMAGE_BYTES as u64
    );
}

#[tokio::test]
async fn download_profile_image_rejects_injected_private_resolve_before_dial() {
    let err = download_profile_image_with_injected_addrs(
        "https://profile.example/avatar.png",
        1024,
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)],
    )
    .await
    .expect_err("private injected resolve");
    assert!(err.to_string().contains("public unicast"));
}

#[test]
fn profile_image_pin_plan_rejects_private_injected_addresses_before_dial() {
    let url = Url::parse("https://profile.example/avatar.png").unwrap();
    let public = public_socket_addr(34);
    let err = plan_profile_image_pin(
        &url,
        &[
            public,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
        ],
    )
    .expect_err("mixed public/private inject");
    assert!(err.to_string().contains("public unicast"));
}

#[test]
fn profile_image_pin_plan_returns_exact_vetted_set_for_one_hop() {
    let url = Url::parse("https://profile.example/avatar.png").unwrap();
    let first = vec![public_socket_addr(34), public_socket_addr(35)];
    let (domain, pinned) = plan_profile_image_pin(&url, &first)
        .expect("pin plan")
        .expect("domain pin");
    assert_eq!(domain, "profile.example");
    assert_eq!(pinned, first);

    let rebound = vec![public_socket_addr(36)];
    let (_, second_pin) = plan_profile_image_pin(&url, &rebound)
        .expect("second plan")
        .expect("second pin");
    assert_eq!(second_pin, rebound);
    assert_ne!(
        pinned, second_pin,
        "rebound answers must not merge across plans"
    );
}

#[tokio::test]
async fn profile_image_operation_deadline_covers_the_whole_future() {
    let err = profile_operation_timeout_for_test(Duration::from_millis(1))
        .await
        .expect_err("pending operation must hit the overall deadline");
    assert!(err.to_string().contains("timed out"));
}

#[tokio::test]
async fn profile_image_shared_reader_bounds_content_length_and_chunked_to_caller_max() {
    let caller_max = 5_u64;
    let over_body = spawn_http_response(http_ok_response(&[0_u8; 8]));
    let response = reqwest::Client::new()
        .get(over_body)
        .send()
        .await
        .expect("fetch test body");
    let err = read_limited_blossom_body(response, caller_max)
        .await
        .expect_err("content-length overflow");
    assert!(
        err.to_string()
            .contains(&format!("download exceeds {caller_max} bytes")),
        "{err}"
    );

    let chunked = spawn_http_response(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nabcdef\r\n0\r\n\r\n"
            .to_vec(),
    );
    let response = reqwest::Client::new()
        .get(chunked)
        .send()
        .await
        .expect("fetch chunked test body");
    let err = read_limited_blossom_body(response, caller_max)
        .await
        .expect_err("chunked overflow");
    assert!(
        err.to_string()
            .contains(&format!("download exceeds {caller_max} bytes")),
        "{err}"
    );
}

fn spawn_http_response(response: Vec<u8>) -> String {
    super::tests::spawn_http_response(response)
}

fn http_ok_response(body: &[u8]) -> Vec<u8> {
    super::tests::http_ok_response(body)
}
