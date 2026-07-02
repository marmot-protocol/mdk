use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use url::Url;

use super::blossom::{MAX_ENCRYPTED_MEDIA_BLOB_BYTES, read_limited_blossom_body};
use super::host_safety::validate_blossom_fetch_url;

fn valid_imeta_tag() -> Vec<String> {
    vec![
        "imeta".to_owned(),
        "v encrypted-media-v1".to_owned(),
        format!(
            "locator blossom-v1 https://media.example/{}.bin",
            "11".repeat(32)
        ),
        format!("ciphertext_sha256 {}", "11".repeat(32)),
        format!("plaintext_sha256 {}", "22".repeat(32)),
        "nonce 333333333333333333333333".to_owned(),
        "m image/png".to_owned(),
        "filename diagram.png".to_owned(),
    ]
}

fn valid_hash() -> String {
    "11".repeat(32)
}

fn tag_with_locator(locator: String) -> Vec<String> {
    let mut tag = valid_imeta_tag();
    tag[2] = format!("locator blossom-v1 {locator}");
    tag
}

#[test]
fn imeta_parser_rejects_duplicate_single_occurrence_field() {
    // Baseline valid tag parses.
    assert!(media_attachment_from_imeta_tag(&valid_imeta_tag(), None, false).is_ok());
    // A duplicate of a single-occurrence field MUST be rejected, especially the
    // key/AAD-determining ones (m, filename, plaintext_sha256).
    for dup in [
        "m image/jpeg".to_owned(),
        "filename evil.png".to_owned(),
        format!("plaintext_sha256 {}", "44".repeat(32)),
        format!("ciphertext_sha256 {}", "55".repeat(32)),
        "nonce 444444444444444444444444".to_owned(),
    ] {
        let mut tag = valid_imeta_tag();
        tag.push(dup.clone());
        assert!(
            media_attachment_from_imeta_tag(&tag, None, false).is_err(),
            "duplicate field {dup:?} must be rejected"
        );
    }
    // A repeated `locator` is allowed (locator is one-or-more).
    let mut multi = valid_imeta_tag();
    multi.push(format!(
        "locator blossom-v1 https://media2.example/{}.bin",
        "11".repeat(32)
    ));
    assert!(media_attachment_from_imeta_tag(&multi, None, false).is_ok());
}

fn spawn_http_responses(responses: Vec<Vec<u8>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let addr = listener.local_addr().expect("test server addr");
    thread::spawn(move || {
        for response in responses {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0_u8; 1024];
                let _ = stream.read(&mut request);
                let _ = stream.write_all(&response);
            }
        }
    });
    format!("http://{addr}")
}

fn spawn_http_response(response: Vec<u8>) -> String {
    spawn_http_responses(vec![response])
}

fn http_redirect_response(location: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn http_ok_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn http_json_response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

fn http_status_response(status: u16, reason: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

fn blossom_endpoint(base_url: String) -> BlobStoreEndpointV1 {
    BlobStoreEndpointV1 {
        locator_kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
        base_url,
    }
}

fn media_upload_request(blossom_server: Option<String>) -> MediaUploadRequest {
    MediaUploadRequest {
        attachments: vec![MediaUploadAttachmentRequest {
            file_name: "diagram.png".to_owned(),
            media_type: "image/png".to_owned(),
            plaintext: b"hello encrypted media".to_vec(),
            dim: None,
            thumbhash: None,
        }],
        caption: None,
        send: false,
        blossom_server,
    }
}

fn signing_keys() -> nostr::Keys {
    nostr::Keys::generate()
}

fn media_secret() -> [u8; 32] {
    [7_u8; 32]
}

fn http_not_found_response() -> Vec<u8> {
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
}

#[tokio::test]
async fn upload_encrypted_media_falls_back_to_second_blossom_endpoint() {
    let failing = spawn_http_response(http_status_response(500, "Internal Server Error"));
    let succeeding = spawn_http_response(http_json_response("{}"));
    let endpoints = [
        blossom_endpoint(failing.clone()),
        blossom_endpoint(succeeding.clone()),
    ];
    let allowed = [BLOSSOM_LOCATOR_KIND_V1.to_owned()];
    let secret = media_secret();
    let keys = signing_keys();

    let result = upload_encrypted_media(
        media_upload_request(None),
        42,
        &secret,
        &keys,
        &endpoints,
        &allowed,
        true,
    )
    .await
    .expect("second Blossom endpoint should absorb first endpoint failure");

    let locator = &result.attachments[0].reference.locators[0];
    assert_eq!(locator.kind, BLOSSOM_LOCATOR_KIND_V1);
    assert!(
        locator.value.starts_with(&format!("{succeeding}/")),
        "upload locator should come from fallback server, got {}",
        locator.value
    );
    assert!(
        !locator.value.starts_with(&failing),
        "upload must not use the failed server locator"
    );
}

#[tokio::test]
async fn upload_encrypted_media_reports_all_blossom_endpoint_failures() {
    let first = spawn_http_response(http_status_response(500, "Internal Server Error"));
    let second = spawn_http_response(http_status_response(502, "Bad Gateway"));
    let endpoints = [
        blossom_endpoint(first.clone()),
        blossom_endpoint(second.clone()),
    ];
    let secret = media_secret();
    let keys = signing_keys();

    let err = upload_encrypted_media(
        media_upload_request(None),
        42,
        &secret,
        &keys,
        &endpoints,
        &[],
        true,
    )
    .await
    .expect_err("all failing endpoints should aggregate their failures");

    let AppError::BlobStore(message) = err else {
        panic!("expected aggregated BlobStore error");
    };
    assert!(
        message.contains("upload failed for all Blossom servers"),
        "unexpected error: {message}"
    );
    assert!(message.contains("server 1: upload returned HTTP 500"));
    assert!(message.contains("server 2: upload returned HTTP 502"));
    assert!(
        !message.contains(&first) && !message.contains(&second),
        "aggregated error must not embed Blossom server URLs: {message}"
    );
}

#[tokio::test]
async fn explicit_blossom_server_override_skips_default_endpoint_failover() {
    let override_server = spawn_http_response(http_status_response(500, "Internal Server Error"));
    let default_server = spawn_http_response(http_json_response("{}"));
    let endpoints = [blossom_endpoint(default_server.clone())];
    let secret = media_secret();
    let keys = signing_keys();

    let err = upload_encrypted_media(
        media_upload_request(Some(override_server.clone())),
        42,
        &secret,
        &keys,
        &endpoints,
        &[],
        true,
    )
    .await
    .expect_err("explicit override must remain a single-server bypass");

    let AppError::BlobStore(message) = err else {
        panic!("expected single override BlobStore error");
    };
    assert!(message.contains("server 1: upload returned HTTP 500"));
    assert!(
        !message.contains("server 2") && !message.contains(&default_server),
        "override failure should not include default endpoint fallback: {message}"
    );
}

#[test]
fn imeta_parser_rejects_legacy_version_even_when_later_current_version_present() {
    let mut tag = valid_imeta_tag();
    tag.insert(1, "v legacy-media-v0".to_owned());

    assert!(media_attachment_from_imeta_tag(&tag, None, false).is_err());
    assert!(!media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn imeta_parser_rejects_duplicate_current_version_fields() {
    let mut tag = valid_imeta_tag();
    tag.insert(1, "v encrypted-media-v1".to_owned());

    assert!(media_attachment_from_imeta_tag(&tag, None, false).is_err());
    assert!(!media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn out_of_policy_locator_kind_is_kept_not_dropped_on_ingest() {
    // PR #328 review Finding 2 (the reviewer's "delayed old media message
    // rejected after a policy update" regression): ingest is purely
    // structural, so a structurally well-formed locator whose kind is NOT in
    // the group's current `allowed_locator_kinds` MUST NOT invalidate the
    // reference or drop the containing kind-9 message. Media is authenticated
    // by its hashes + AEAD independent of the locator, so an out-of-policy
    // locator cannot forge content; it only becomes unfetchable at download
    // time. (The ingest parser no longer takes a policy at all.)
    let mut tag = valid_imeta_tag();
    // A non-blossom locator that is not in any default policy. It is
    // structurally well-formed (parseable URL), so ingest keeps it.
    tag.insert(2, "locator ipfs-v1 ipfs://bafybeigdyrexample".to_owned());

    let reference = media_attachment_from_imeta_tag(&tag, None, false)
        .expect("an out-of-policy but well-formed locator must not drop the message");
    assert_eq!(reference.locators.len(), 2);
    assert!(media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn structurally_malformed_reference_is_rejected_on_ingest() {
    // PR #328 review Finding 2: structural malformation (here a non-hex
    // ciphertext hash) still invalidates the reference and drops the message,
    // exactly as before. The "never drop" rule applies only to locator-kind
    // policy, never to structural integrity.
    let mut tag = valid_imeta_tag();
    // Replace the valid `ciphertext_sha256` with a non-hex value.
    let bad = tag
        .iter_mut()
        .find(|field| field.starts_with("ciphertext_sha256 "))
        .expect("fixture has a ciphertext_sha256 field");
    *bad = "ciphertext_sha256 not-a-valid-hash".to_owned();

    assert!(media_attachment_from_imeta_tag(&tag, None, false).is_err());
    assert!(!media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn imeta_parser_rejects_non_https_media_locator() {
    let tag = tag_with_locator(format!("http://media.example/{}.bin", valid_hash()));
    let err = media_attachment_from_imeta_tag(&tag, None, false).unwrap_err();

    assert!(err.to_string().contains("scheme must be https"));
    assert!(!media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn locator_with_unparseable_url_is_rejected_on_ingest() {
    // A locator value that does not parse as a URL is structural malformation
    // and MUST invalidate the reference even though the kind is `blossom-v1`.
    let mut tag = valid_imeta_tag();
    let locator = tag
        .iter_mut()
        .find(|field| field.starts_with("locator "))
        .expect("fixture has a locator field");
    *locator = "locator blossom-v1 not a url".to_owned();

    assert!(media_attachment_from_imeta_tag(&tag, None, false).is_err());
}

fn blossom_reference() -> MediaAttachmentReference {
    let mut reference = loopback_reference();
    reference.locators = vec![MediaLocator {
        kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
        // The blossom locator URL must carry the ciphertext hash (= the
        // reference's `ciphertext_sha256`, `11`*32) per the merged blossom
        // content-hash binding.
        value: format!("https://media.example/{}.bin", "11".repeat(32)),
    }];
    reference
}

#[test]
fn outbound_validation_rejects_blossom_reference_when_policy_disallows_blossom() {
    // PR #328 review Finding 1: the sender MUST NOT emit a `blossom-v1`
    // reference to a group whose policy does not allow `blossom-v1`, since
    // receivers would treat the locator as unfetchable. A non-empty policy
    // that omits `blossom-v1` must fail outbound validation.
    let reference = blossom_reference();
    let allowed = vec!["ipfs-v1".to_owned()];
    assert!(
        reference.validate_outbound(&allowed, false).is_err(),
        "a blossom reference must be rejected when the policy omits blossom-v1"
    );
    // The same reference is valid against a policy that does allow blossom-v1.
    let allowed = vec![BLOSSOM_LOCATOR_KIND_V1.to_owned()];
    reference
        .validate_outbound(&allowed, false)
        .expect("a blossom reference is valid when the policy allows blossom-v1");
}

#[test]
fn canonical_media_type_trims_ascii_whitespace_only() {
    // ASCII whitespace on the edges is stripped per the spec algorithm.
    assert_eq!(
        canonical_media_type("  image/png \t").expect("ascii-trimmed type is valid"),
        "image/png",
    );

    // A leading U+00A0 (non-breaking space) is Unicode whitespace but NOT
    // ASCII whitespace, so it MUST be preserved: trimming it would derive a
    // different file_key/AAD than a spec-conformant peer that keeps it.
    let canonical =
        canonical_media_type("\u{00A0}image/png").expect("non-empty MIME type is valid");
    assert_eq!(canonical, "\u{00A0}image/png");
    assert!(canonical.starts_with('\u{00A0}'));
}

#[test]
fn is_loopback_http_endpoint_classifies_only_cleartext_loopback() {
    // Cleartext loopback hosts are loopback-HTTP endpoints.
    assert!(is_loopback_http_endpoint("http://127.0.0.1:8080/up"));
    assert!(is_loopback_http_endpoint("http://localhost:3000"));
    assert!(is_loopback_http_endpoint("http://sub.localhost/blob"));
    assert!(is_loopback_http_endpoint("http://[::1]:8080"));
    // HTTPS (even to loopback) and routable HTTP hosts are not.
    assert!(!is_loopback_http_endpoint("https://127.0.0.1:8080"));
    assert!(!is_loopback_http_endpoint("http://media.example/blob"));
    assert!(!is_loopback_http_endpoint("https://blossom.example"));
    assert!(!is_loopback_http_endpoint("not a url"));
}

fn loopback_reference() -> MediaAttachmentReference {
    MediaAttachmentReference {
        locators: vec![MediaLocator {
            kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
            value: format!("http://127.0.0.1:8080/{}.bin", "11".repeat(32)),
        }],
        ciphertext_sha256: "11".repeat(32),
        plaintext_sha256: "22".repeat(32),
        nonce_hex: "33".repeat(12),
        file_name: "diagram.png".to_owned(),
        media_type: "image/png".to_owned(),
        version: ENCRYPTED_MEDIA_VERSION.to_owned(),
        source_epoch: 0,
        dim: None,
        thumbhash: None,
    }
}

#[test]
fn loopback_locator_validation_follows_runtime_flag_not_build_profile() {
    // Issue #341 regression: the runtime `allow_loopback_http` flag (driven by
    // `MarmotAppConfig::allow_loopback_blob_endpoints`) is now the SOLE
    // authority for accepting a cleartext-`http` loopback `blossom-v1` locator,
    // replacing the old compile-time `cfg!(debug_assertions)` gate. The
    // reference carries a hash-bearing loopback URL so it clears the Blossom
    // content-hash binding and the loopback host is the only thing under test.
    // Outcome must depend on the flag in EVERY build profile (this test runs
    // under `debug_assertions`, where the old gate would have force-allowed it).
    let reference = loopback_reference();
    assert!(
        reference.validate(false).is_err(),
        "a loopback-HTTP blossom locator must be rejected when the flag is off",
    );
    reference
        .validate(true)
        .expect("a loopback-HTTP blossom locator must be accepted when the flag is on");

    // The same authority must hold on the ingest parser path
    // (`media_attachment_from_imeta_tag` / `media_imeta_tags_are_valid`).
    let tag = reference.imeta_tag();
    let tags = std::slice::from_ref(&tag);
    assert!(
        media_attachment_from_imeta_tag(&tag, None, false).is_err(),
        "ingest must reject a loopback-HTTP blossom locator when the flag is off",
    );
    assert!(!media_imeta_tags_are_valid(tags, false));
    media_attachment_from_imeta_tag(&tag, None, true)
        .expect("ingest must accept a loopback-HTTP blossom locator when the flag is on");
    assert!(media_imeta_tags_are_valid(tags, true));
}

#[tokio::test]
async fn production_config_does_not_fetch_loopback_endpoint() {
    // With the dev/test gate off, a loopback-HTTP locator is dropped from the
    // candidate set, so no GET is issued and the fetch fails as "no supported
    // locators" rather than attempting to reach the local host.
    let reference = loopback_reference();
    let err = fetch_encrypted_media_blob(&reference, &[], &[], false)
        .await
        .expect_err("loopback-only reference must be unfetchable in production");
    match err {
        AppError::InvalidEncryptedMedia(message) => {
            assert!(
                message.contains("no supported locators"),
                "expected unfetchable error, got: {message}"
            );
        }
        other => panic!("expected InvalidEncryptedMedia, got {other:?}"),
    }
}

#[tokio::test]
async fn loopback_fallback_endpoint_is_skipped_in_production() {
    // The same gate applies to remote-admin policy fallback endpoints. With
    // no supported locator on the message, a loopback-HTTP fallback is the
    // only candidate; in production it is filtered out, so the fetch fails as
    // unfetchable instead of GETting the local host.
    let mut reference = loopback_reference();
    // Drop the message-carried locator so the loopback fallback is the only
    // candidate under test, keeping one policy-allowed-but-unsupported
    // locator so the reference stays structurally valid.
    reference.locators.clear();
    reference.locators.push(MediaLocator {
        kind: "ipfs-v1".to_owned(),
        value: "ipfs://bafyexample".to_owned(),
    });
    let fallback = [BlobStoreEndpointV1 {
        locator_kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
        base_url: "http://127.0.0.1:8080".to_owned(),
    }];
    let err = fetch_encrypted_media_blob(&reference, &fallback, &[], false)
        .await
        .expect_err("loopback fallback must be unfetchable in production");
    match err {
        AppError::InvalidEncryptedMedia(message) => assert!(
            message.contains("no supported locators"),
            "expected unfetchable error, got: {message}"
        ),
        other => panic!("expected InvalidEncryptedMedia, got {other:?}"),
    }
    // The loopback fallback would survive the candidate filter only when the
    // dev/test gate is on; assert the classifier agrees so the gate stays the
    // single decision point.
    assert!(is_loopback_http_endpoint(&blossom_blob_url(
        &fallback[0].base_url,
        &reference.ciphertext_sha256,
    )));
}

#[tokio::test]
async fn out_of_policy_blossom_locator_is_unfetchable_not_a_hard_error() {
    // PR #328 review Finding 2: when the group's CURRENT policy does not allow
    // `blossom-v1`, a blossom locator is out of policy and this client cannot
    // fetch it. The fetch MUST degrade to the unfetchable outcome ("no
    // supported locators") rather than a hard error that looks like content
    // corruption. The reference itself stays structurally valid and the
    // message was already delivered at ingest.
    let mut reference = loopback_reference();
    // Use a routable https locator so loopback gating is not what skips it;
    // the only reason it is unfetchable is the out-of-policy locator kind.
    reference.locators = vec![MediaLocator {
        kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
        value: format!("https://media.example/{}.bin", "11".repeat(32)),
    }];
    // A non-empty policy that allows only a non-blossom kind: blossom is out
    // of policy, so there is no fetchable locator for this client.
    let allowed = vec!["ipfs-v1".to_owned()];
    let err = fetch_encrypted_media_blob(&reference, &[], &allowed, true)
        .await
        .expect_err("an out-of-policy blossom locator must be unfetchable");
    match err {
        AppError::InvalidEncryptedMedia(message) => assert!(
            message.contains("no supported locators"),
            "expected unfetchable error, got: {message}"
        ),
        other => panic!("expected InvalidEncryptedMedia, got {other:?}"),
    }
    // The reference is still structurally valid: out-of-policy is a
    // fetchability concern, not a structural one.
    reference
        .validate(false)
        .expect("an out-of-policy reference is still structurally valid");
}

#[test]
fn imeta_parser_rejects_private_ip_media_locator() {
    let tag = tag_with_locator(format!("https://10.0.0.5/{}.bin", valid_hash()));
    let err = media_attachment_from_imeta_tag(&tag, None, false).unwrap_err();

    assert!(err.to_string().contains("non-public"));
    assert!(!media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn imeta_parser_rejects_ipv6_transition_prefix_media_locators() {
    for locator in [
        // 6to4 wraps 10.0.0.5 in the two segments after 2002::/16.
        format!("https://[2002:a00:5::]/{}.bin", valid_hash()),
        // Teredo carries the obfuscated client IPv4 in the low 32 bits: !10.0.0.5.
        format!(
            "https://[2001:0:4136:e378:8000:63bf:f5ff:fffa]/{}.bin",
            valid_hash()
        ),
    ] {
        let tag = tag_with_locator(locator);
        let err = media_attachment_from_imeta_tag(&tag, None, false).unwrap_err();

        assert!(err.to_string().contains("non-public"));
        assert!(!media_imeta_tags_are_valid(&[tag], false));
    }
}

#[test]
fn imeta_parser_rejects_ipv6_documentation_3fff_media_locator() {
    // 3fff::/20 (RFC 9637) is documentation space that sits inside global-unicast
    // 2000::/3, so it must be rejected explicitly (canonical unsafe-host set).
    let tag = tag_with_locator(format!("https://[3fff::1]/{}.bin", valid_hash()));
    let err = media_attachment_from_imeta_tag(&tag, None, false).unwrap_err();

    assert!(err.to_string().contains("non-public"));
    assert!(!media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn imeta_parser_accepts_public_ipv6_media_locator() {
    let tag = tag_with_locator(format!("https://[2606:4700::]/{}.bin", valid_hash()));

    assert!(media_attachment_from_imeta_tag(&tag, None, false).is_ok());
    assert!(media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn imeta_parser_rejects_locator_without_content_hash() {
    let tag = tag_with_locator("https://media.example/download.bin".to_owned());
    let err = media_attachment_from_imeta_tag(&tag, None, false).unwrap_err();

    assert!(
        err.to_string()
            .contains("must include the encrypted blob hash")
    );
    assert!(!media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn imeta_parser_rejects_locator_hash_mismatch() {
    let tag = tag_with_locator(format!("https://media.example/{}.bin", "33".repeat(32)));
    let err = media_attachment_from_imeta_tag(&tag, None, false).unwrap_err();

    assert!(err.to_string().contains("hash does not match"));
    assert!(!media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn media_fetch_url_policy_allows_loopback_http_only_when_explicitly_enabled() {
    let url = Url::parse(&format!("http://127.0.0.1:3000/{}.bin", valid_hash())).unwrap();

    assert!(validate_blossom_fetch_url(&url, true).is_ok());
    assert!(validate_blossom_fetch_url(&url, false).is_err());
}

#[test]
fn blossom_redirect_validation_allows_same_registrable_domain() {
    let current = Url::parse(&format!("https://blossom.primal.net/{}.bin", valid_hash())).unwrap();
    let next = Url::parse(&format!(
        "https://r2a.primal.net/uploads/{}.bin",
        valid_hash()
    ))
    .unwrap();

    super::blossom::validate_blossom_redirect_target(&current, &next, false)
        .expect("same registrable domain redirect must be allowed");
}

#[test]
fn blossom_redirect_validation_rejects_cross_scheme_private_ip_and_cross_domain() {
    let current = Url::parse(&format!("https://media.example/{}.bin", valid_hash())).unwrap();
    for (next, expected) in [
        (
            format!("http://media.example/{}.bin", valid_hash()),
            "scheme must be https",
        ),
        (
            format!("https://10.0.0.5/{}.bin", valid_hash()),
            "non-public",
        ),
        (
            format!("https://cdn.attacker.net/{}.bin", valid_hash()),
            "same host or registrable domain",
        ),
    ] {
        let next = Url::parse(&next).unwrap();
        let err = super::blossom::validate_blossom_redirect_target(&current, &next, false)
            .expect_err("unsafe redirect must be rejected");
        assert!(
            err.to_string().contains(expected),
            "expected {expected:?}, got {err}"
        );
    }
}

#[tokio::test]
async fn fetch_blossom_blob_follows_hashless_redirect_targets() {
    let final_server = spawn_http_response(http_ok_response(b"hello"));
    let final_url = format!("{final_server}/signed/opaque-key?X-Amz-Signature=test");
    let redirecting_server = spawn_http_response(http_redirect_response(&final_url));
    let url = format!("{redirecting_server}/{}.bin", valid_hash());

    let bytes = fetch_blossom_blob(&url, true)
        .await
        .expect("valid redirect should fetch final blob");

    assert_eq!(bytes, b"hello");
}

#[tokio::test]
async fn fetch_blossom_blob_rejects_redirect_chain_over_limit() {
    let responses = (0..6)
        .map(|idx| http_redirect_response(&format!("/hop-{idx}/{}.bin", valid_hash())))
        .collect::<Vec<_>>();
    let server = spawn_http_responses(responses);
    let url = format!("{server}/{}.bin", valid_hash());
    let err = fetch_blossom_blob(&url, true).await.unwrap_err();

    assert!(err.to_string().contains("exceeded 5 hops"));
}

#[tokio::test]
async fn fetch_blossom_blob_rejects_redirect_without_location() {
    let server = spawn_http_response(
        b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
    );
    let url = format!("{server}/{}.bin", valid_hash());
    let err = fetch_blossom_blob(&url, true).await.unwrap_err();

    assert!(
        err.to_string()
            .contains("redirect response did not include Location")
    );
}

#[tokio::test]
async fn fetch_blossom_blob_reports_terminal_status_after_redirect() {
    let server = spawn_http_responses(vec![
        http_redirect_response("/missing-opaque-key"),
        http_not_found_response(),
    ]);
    let url = format!("{server}/{}.bin", valid_hash());
    let err = fetch_blossom_blob(&url, true).await.unwrap_err();

    assert!(
        err.to_string().contains("download returned HTTP 404"),
        "expected terminal status, got: {err}"
    );
}

#[tokio::test]
async fn fetch_blossom_blob_follows_redirect_target_with_different_path_hash() {
    let final_server = spawn_http_response(http_ok_response(b"hello"));
    let final_url = format!("{final_server}/{}.bin", "22".repeat(32));
    let redirecting_server = spawn_http_response(http_redirect_response(&final_url));
    let url = format!("{redirecting_server}/{}.bin", valid_hash());

    let bytes = fetch_blossom_blob(&url, true)
        .await
        .expect("redirect target path hash is not authoritative for content integrity");

    assert_eq!(bytes, b"hello");
}

#[tokio::test]
async fn fetch_blossom_blob_rejects_oversized_content_length() {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        MAX_ENCRYPTED_MEDIA_BLOB_BYTES + 1
    );
    let server = spawn_http_response(response.into_bytes());
    let url = format!("{server}/{}.bin", valid_hash());
    let err = fetch_blossom_blob(&url, true).await.unwrap_err();

    assert!(err.to_string().contains("download exceeds"));
}

#[tokio::test]
async fn limited_body_reader_rejects_chunked_body_over_cap() {
    let server = spawn_http_response(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nabcdef\r\n0\r\n\r\n"
            .to_vec(),
    );
    let response = reqwest::Client::new()
        .get(format!("{server}/{}.bin", valid_hash()))
        .send()
        .await
        .expect("fetch chunked test body");
    let err = read_limited_blossom_body(response, 5).await.unwrap_err();

    assert!(err.to_string().contains("download exceeds 5 bytes"));
}
