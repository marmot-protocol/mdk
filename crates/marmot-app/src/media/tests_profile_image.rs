//! Profile-image dial-safe fetch acceptance tests (mdk#1287).

use cgka_traits::app_components::ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN;
use url::Url;

use super::blossom::{
    build_pinned_media_http_client_with_proxy_for_test, read_limited_blossom_body,
    vet_profile_fetch_resolved_addresses,
};
use super::host_safety::{parse_profile_image_fetch_url, validate_profile_image_fetch_url};
use super::tests::{
    http_ok_response, http_redirect_response, spawn_http_response, spawn_http_responses,
};
use super::{
    MAX_PROFILE_IMAGE_BYTES, download_profile_image, download_profile_image_with_test_loopback,
    normalize_profile_image_max_bytes_for_test,
};
use crate::AppError;

fn localhost_url(raw: &str) -> String {
    let mut url = Url::parse(raw).expect("test listener URL");
    url.set_host(Some("localhost"))
        .expect("replace loopback literal with localhost");
    url.into()
}

#[tokio::test]
async fn download_profile_image_rejects_loopback_literal_before_network() {
    let err = download_profile_image("https://127.0.0.1/avatar.png".to_owned(), 1024)
        .await
        .expect_err("loopback profile URL must not be dialed");
    assert!(
        matches!(err, AppError::UnsafeMediaFetch(_)),
        "expected pre-dial safety rejection, got {err}"
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
fn profile_image_raw_url_length_checked_before_parse_normalization() {
    let prefix = "https://media.example/";
    let padding = ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN - prefix.len() + 64;
    let raw = format!("{prefix}{}/avatar.png", "../".repeat(padding));
    assert!(raw.len() > ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN);
    let normalized = Url::parse(&raw).expect("url must parse");
    assert!(normalized.as_str().len() <= ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN);

    let err = parse_profile_image_fetch_url(&raw).unwrap_err();
    assert!(err.contains("exceeds"));
}

#[test]
fn profile_image_raw_url_length_checked_before_whitespace_trimming() {
    let valid = "https://media.example/avatar.png";
    let raw = format!(
        "{}{}",
        " ".repeat(ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN),
        valid
    );
    assert!(raw.len() > ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN);
    assert_eq!(raw.trim(), valid);

    let err = parse_profile_image_fetch_url(&raw).unwrap_err();
    assert!(err.contains("exceeds"));
}

#[test]
fn profile_image_redirect_length_checked_before_whitespace_trimming() {
    let current = Url::parse("https://media.example/start.png").unwrap();
    let raw_location = format!(
        "{}{}",
        " ".repeat(ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN),
        "/avatar.png"
    );
    assert!(raw_location.len() > ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN);
    assert_eq!(raw_location.trim(), "/avatar.png");

    let err =
        super::host_safety::parse_profile_image_redirect_url(&current, &raw_location).unwrap_err();
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

#[test]
fn profile_image_vet_resolved_addresses_rejects_private_before_dial() {
    let err = vet_profile_fetch_resolved_addresses(&[
        std::net::SocketAddr::from(([93, 184, 216, 34], 443)),
        std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 443)),
    ])
    .expect_err("one unsafe answer must reject the whole DNS result");
    assert!(matches!(err, AppError::UnsafeMediaFetch(_)));
}

#[tokio::test]
async fn download_profile_image_follows_redirect_to_local_listener() {
    let final_server = localhost_url(&spawn_http_response(http_ok_response(b"avatar-bytes")));
    let final_url = format!("{final_server}/avatar.png");
    let redirecting_server =
        localhost_url(&spawn_http_response(http_redirect_response(&final_url)));
    let url = format!("{redirecting_server}/start.png");

    let bytes = download_profile_image_with_test_loopback(url, 1024)
        .await
        .expect("profile fetch should follow one redirect to the final body");

    assert_eq!(bytes, b"avatar-bytes");
}

#[tokio::test]
async fn pinned_media_client_ignores_configured_proxy() {
    let origin_url = spawn_http_response(http_ok_response(b"direct-origin"));
    let origin = Url::parse(&origin_url).expect("origin listener URL");
    let origin_addr = std::net::SocketAddr::new(
        origin.host_str().unwrap().parse().unwrap(),
        origin.port().unwrap(),
    );
    let proxy_url = spawn_http_response(http_ok_response(b"proxy-used"));
    let client = build_pinned_media_http_client_with_proxy_for_test(
        Some(("profile-image.test".into(), vec![origin_addr])),
        &proxy_url,
    )
    .expect("build pinned client with a configured proxy");

    let response = client
        .get(format!(
            "http://profile-image.test:{}/avatar.png",
            origin_addr.port()
        ))
        .send()
        .await
        .expect("pinned client must dial the vetted origin directly");
    let body = response.bytes().await.expect("read origin response");

    assert_eq!(body.as_ref(), b"direct-origin");
}

#[tokio::test]
async fn download_profile_image_rejects_redirect_chain_over_limit() {
    let responses = (0..6)
        .map(|idx| http_redirect_response(&format!("/hop-{idx}/avatar.png")))
        .collect::<Vec<_>>();
    let server = localhost_url(&spawn_http_responses(responses));
    let url = format!("{server}/start.png");

    let err = download_profile_image_with_test_loopback(url, 1024)
        .await
        .expect_err("six redirects must exceed the hop cap");

    assert!(
        err.to_string().contains("exceeded 5 hops"),
        "expected hop-limit error, got {err}"
    );
}

#[tokio::test]
async fn download_profile_image_classifies_unsafe_redirect_before_dial() {
    let redirecting_server = localhost_url(&spawn_http_response(http_redirect_response(
        "https://127.0.0.1/avatar.png",
    )));
    let url = format!("{redirecting_server}/start.png");

    let err = download_profile_image_with_test_loopback(url, 1024)
        .await
        .expect_err("unsafe redirect target must be rejected before its dial");

    assert!(matches!(err, AppError::UnsafeMediaFetch(_)));
}

#[tokio::test]
async fn download_profile_image_bounds_raw_redirect_before_normalization() {
    let raw_location = format!(
        "/{}/avatar.png",
        "../".repeat(ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN)
    );
    assert!(raw_location.len() > ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN);

    let server = localhost_url(&spawn_http_responses(vec![
        http_redirect_response(&raw_location),
        http_ok_response(b"must-not-be-fetched"),
    ]));
    let url = format!("{server}/start.png");

    let err = download_profile_image_with_test_loopback(url, 1024)
        .await
        .expect_err("raw redirect target must be bounded before URL normalization");

    assert!(matches!(err, AppError::UnsafeMediaFetch(_)));
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

#[tokio::test]
async fn unsafe_profile_url_maps_to_unsafe_media_fetch_not_blob_store() {
    let err = download_profile_image("https://127.0.0.1/avatar.png".into(), 1024)
        .await
        .unwrap_err();
    assert!(matches!(err, AppError::UnsafeMediaFetch(_)));
}

#[tokio::test]
async fn dns_operational_failure_stays_blob_store_for_retryable_runtime() {
    let err = download_profile_image(
        "https://this-host-should-not-resolve.invalid.test/avatar.png".into(),
        1024,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AppError::BlobStore(_)),
        "DNS failure should remain operational, got {err}"
    );
    assert!(
        err.to_string().contains("DNS lookup failed"),
        "unexpected message: {err}"
    );
}
