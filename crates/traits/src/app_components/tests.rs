use super::*;
// Crate-internal helpers/bounds these tests hand-build bytes against; they live
// in the per-concern submodules and are not part of the public surface.
use super::codec::encode_var_bytes;
use super::encrypted_media::{
    ENCRYPTED_MEDIA_BLOB_ENDPOINTS_VECTOR_MAX_LEN, ENCRYPTED_MEDIA_LOCATOR_KINDS_VECTOR_MAX_LEN,
};

#[test]
fn component_list_round_trips_sorted_ids() {
    let ids = BTreeSet::from([
        GROUP_ADMIN_POLICY_COMPONENT_ID,
        GROUP_PROFILE_COMPONENT_ID,
        NOSTR_ROUTING_COMPONENT_ID,
    ]);

    let encoded = encode_components_list(&ids);

    assert_eq!(decode_components_list(&encoded).unwrap(), ids);
}

#[test]
fn component_list_rejects_duplicate_or_trailing_bytes() {
    let duplicate_profile = vec![4, 0x80, 0x01, 0x80, 0x01];
    assert_eq!(
        decode_components_list(&duplicate_profile),
        Err("component list contains duplicate ids".into())
    );

    let mut trailing = encode_components_list(&BTreeSet::from([GROUP_PROFILE_COMPONENT_ID]));
    trailing.push(0);
    assert_eq!(
        decode_components_list(&trailing),
        Err("component list has trailing bytes".into())
    );
}

#[test]
fn quic_varint_decoder_rejects_non_canonical_lengths() {
    assert_eq!(
        decode_quic_varint(&[0x40, 0x3f]),
        Err("non-canonical QUIC varint length".into())
    );
}

#[test]
fn nostr_routing_round_trips_canonical_state() {
    let routing = NostrRoutingV1::new(
        [0x42; 32],
        vec![
            "wss://relay-b.example".into(),
            "wss://relay-a.example".into(),
        ],
    )
    .unwrap();

    let encoded = encode_nostr_routing_v1(&routing).unwrap();
    let decoded = decode_nostr_routing_v1(&encoded).unwrap();

    assert_eq!(
        decoded.relays,
        vec!["wss://relay-a.example", "wss://relay-b.example"]
    );
    assert_eq!(decoded.nostr_group_id, [0x42; 32]);
}

#[test]
fn encrypted_media_policy_round_trips_ordered_endpoints() {
    let policy = EncryptedMediaPolicyV1::blossom_default(
        vec![
            "https://blossom-a.example/upload-root/".to_owned(),
            "https://blossom-b.example".to_owned(),
        ],
        false,
    )
    .unwrap();

    let encoded = encode_encrypted_media_policy_v1(&policy).unwrap();
    let decoded = decode_encrypted_media_policy_v1(&encoded).unwrap();

    assert_eq!(decoded.media_format, ENCRYPTED_MEDIA_FORMAT_V1);
    assert_eq!(decoded.allowed_locator_kinds, vec![BLOSSOM_LOCATOR_KIND_V1]);
    // WHATWG serialization preserves a non-empty path's trailing slash and
    // serializes an empty path as `/`, so both stored URLs end in `/`.
    assert_eq!(
        decoded.default_blob_endpoints,
        vec![
            BlobStoreEndpointV1 {
                locator_kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
                base_url: "https://blossom-a.example/upload-root/".to_owned(),
            },
            BlobStoreEndpointV1 {
                locator_kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
                base_url: "https://blossom-b.example/".to_owned(),
            },
        ]
    );
}

#[test]
fn encrypted_media_policy_decode_rejects_oversized_top_level_vectors() {
    let mut oversized_allowed = Vec::new();
    encode_var_bytes(ENCRYPTED_MEDIA_FORMAT_V1.as_bytes(), &mut oversized_allowed);
    encode_quic_varint(
        (ENCRYPTED_MEDIA_LOCATOR_KINDS_VECTOR_MAX_LEN + 1) as u64,
        &mut oversized_allowed,
    );
    assert_eq!(
        decode_encrypted_media_policy_v1(&oversized_allowed),
        Err("encrypted media locator kinds exceeds maximum length".into())
    );

    let mut oversized_endpoints = Vec::new();
    encode_var_bytes(
        ENCRYPTED_MEDIA_FORMAT_V1.as_bytes(),
        &mut oversized_endpoints,
    );
    encode_var_bytes(&[], &mut oversized_endpoints);
    encode_quic_varint(
        (ENCRYPTED_MEDIA_BLOB_ENDPOINTS_VECTOR_MAX_LEN + 1) as u64,
        &mut oversized_endpoints,
    );
    assert_eq!(
        decode_encrypted_media_policy_v1(&oversized_endpoints),
        Err("encrypted media default blob endpoints exceeds maximum length".into())
    );
}

#[test]
fn encrypted_media_policy_rejects_non_https_except_loopback_dev_http() {
    assert!(
        EncryptedMediaPolicyV1::blossom_default(vec!["http://media.example".to_owned()], false,)
            .is_err()
    );
    assert!(
        EncryptedMediaPolicyV1::blossom_default(vec!["http://127.0.0.1:3000".to_owned()], false,)
            .is_err()
    );
    let local =
        EncryptedMediaPolicyV1::blossom_default(vec!["http://127.0.0.1:3000/".to_owned()], true)
            .unwrap();
    // WHATWG keeps the path's `/`; the dev loopback http URL is stored as-is.
    assert_eq!(
        local.default_blob_endpoints[0].base_url,
        "http://127.0.0.1:3000/"
    );
    assert_eq!(
        validate_and_normalize_blob_endpoint_url("https://10.0.0.1", false),
        Err("encrypted media endpoint URL must not point at a non-routable address".into())
    );
}

/// Regression for #374: the spec's invalidity list (group-encrypted-media-v1.md)
/// names only userinfo / fragments / missing-host / unsafe-host. A query string
/// is NOT invalid, and WHATWG parse-and-serialize preserves it, so a query-bearing
/// endpoint is valid normalized state and must be accepted on the decode/commit
/// path. The sibling avatar validator behaves the same way.
#[test]
fn encrypted_media_endpoint_accepts_query_string() {
    assert_eq!(
        validate_and_normalize_blob_endpoint_url("https://blossom.example/?x=1", false),
        Ok("https://blossom.example/?x=1".to_owned())
    );
    // The regression that forked commit acceptance was on the decode path, so
    // exercise it explicitly: a query-bearing endpoint must survive the full
    // encode -> decode_encrypted_media_policy_v1 round-trip (which dispatches
    // through validate_blob_endpoint_url_is_canonical, the commit-acceptance
    // check #374 names), not just producer-side construction.
    let policy = EncryptedMediaPolicyV1::blossom_default(
        vec!["https://blossom.example/?x=1".to_owned()],
        false,
    )
    .expect("query-bearing endpoint is valid policy state");
    let encoded = encode_encrypted_media_policy_v1(&policy).expect("query-bearing policy encodes");
    let decoded = decode_encrypted_media_policy_v1(&encoded)
        .expect("query-bearing endpoint is accepted on the decode/commit-acceptance path");
    assert_eq!(
        decoded.default_blob_endpoints,
        vec![BlobStoreEndpointV1 {
            locator_kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
            base_url: "https://blossom.example/?x=1".to_owned(),
        }]
    );
}

/// Fixed encode→bytes vector pinning the corrected #171 layout: each
/// `BlobStoreEndpointV1` is the concatenation `{locator_kind, base_url}` with
/// NO per-item length wrapper, matching `allowed_locator_kinds` and the spec's
/// `Type items<V>` (one outer length, then concatenated items).
///
/// Policy:
///   media_format           = "encrypted-media-v1"
///   allowed_locator_kinds  = ["blossom-v1"]
///   default_blob_endpoints = [{ "blossom-v1", "https://blossom.primal.net/" }]
#[test]
fn encrypted_media_policy_encodes_endpoints_without_per_item_wrapper() {
    const EXPECTED: &[u8] = &[
        0x12, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x2d, 0x6d, 0x65, 0x64, 0x69,
        0x61, 0x2d, 0x76, 0x31, // <media_format len=0x12>"encrypted-media-v1"
        0x0b, // allowed_locator_kinds outer length = 11
        0x0a, 0x62, 0x6c, 0x6f, 0x73, 0x73, 0x6f, 0x6d, 0x2d, 0x76,
        0x31, // <kind len=0x0a>"blossom-v1"
        0x27, // default_blob_endpoints outer length = 39 (= 11 kind + 28 url, no wrapper)
        0x0a, 0x62, 0x6c, 0x6f, 0x73, 0x73, 0x6f, 0x6d, 0x2d, 0x76,
        0x31, // <kind len=0x0a>"blossom-v1"
        0x1b, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x62, 0x6c, 0x6f, 0x73, 0x73, 0x6f,
        0x6d, 0x2e, 0x70, 0x72, 0x69, 0x6d, 0x61, 0x6c, 0x2e, 0x6e, 0x65, 0x74,
        0x2f, // <url len=0x1b>"https://blossom.primal.net/"
    ];

    let policy = EncryptedMediaPolicyV1::blossom_default(
        vec!["https://blossom.primal.net".to_owned()],
        false,
    )
    .unwrap();
    let encoded = encode_encrypted_media_policy_v1(&policy).unwrap();
    assert_eq!(encoded, EXPECTED);
    // The fixed bytes round-trip back to the same policy.
    assert_eq!(decode_encrypted_media_policy_v1(EXPECTED).unwrap(), policy);
}

/// Decode is strict: a body carrying the OLD per-item-wrapped endpoint layout
/// (an extra QUIC length prefix around each `{locator_kind, base_url}`) is not
/// canonical and MUST be rejected, not silently re-parsed.
#[test]
fn encrypted_media_policy_decode_rejects_extra_per_item_endpoint_prefix() {
    // Same policy as the fixed vector above, but with the legacy wrapper byte
    // (0x28 outer endpoints length, 0x27 per-item wrapper) before the item.
    const OLD_WRAPPED: &[u8] = &[
        0x12, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x2d, 0x6d, 0x65, 0x64, 0x69,
        0x61, 0x2d, 0x76, 0x31, 0x0b, 0x0a, 0x62, 0x6c, 0x6f, 0x73, 0x73, 0x6f, 0x6d, 0x2d, 0x76,
        0x31, 0x28, // endpoints outer length = 40 (1 wrapper byte + 39 item)
        0x27, // legacy per-item wrapper length = 39
        0x0a, 0x62, 0x6c, 0x6f, 0x73, 0x73, 0x6f, 0x6d, 0x2d, 0x76, 0x31, 0x1b, 0x68, 0x74, 0x74,
        0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x62, 0x6c, 0x6f, 0x73, 0x73, 0x6f, 0x6d, 0x2e, 0x70, 0x72,
        0x69, 0x6d, 0x61, 0x6c, 0x2e, 0x6e, 0x65, 0x74, 0x2f,
    ];
    assert!(decode_encrypted_media_policy_v1(OLD_WRAPPED).is_err());
}

/// Decode rejects a duplicate entry in `allowed_locator_kinds` rather than
/// deduplicating it (canonical-encoding.md "Canonical decoding").
#[test]
fn encrypted_media_policy_decode_rejects_duplicate_allowed_locator_kind() {
    let mut allowed = Vec::new();
    encode_var_bytes(BLOSSOM_LOCATOR_KIND_V1.as_bytes(), &mut allowed);
    encode_var_bytes(BLOSSOM_LOCATOR_KIND_V1.as_bytes(), &mut allowed);
    let mut endpoints = Vec::new();
    encode_var_bytes(BLOSSOM_LOCATOR_KIND_V1.as_bytes(), &mut endpoints);
    encode_var_bytes(b"https://blossom.primal.net/", &mut endpoints);
    let bytes = encode_component_vectors(&[
        ENCRYPTED_MEDIA_FORMAT_V1.as_bytes(),
        allowed.as_slice(),
        endpoints.as_slice(),
    ]);
    assert_eq!(
        decode_encrypted_media_policy_v1(&bytes),
        Err("encrypted media policy has a duplicate allowed locator kind".into())
    );
}

/// Decode rejects a duplicate `default_blob_endpoints` entry rather than
/// deduplicating it.
#[test]
fn encrypted_media_policy_decode_rejects_duplicate_endpoint() {
    let mut allowed = Vec::new();
    encode_var_bytes(BLOSSOM_LOCATOR_KIND_V1.as_bytes(), &mut allowed);
    let mut endpoints = Vec::new();
    for _ in 0..2 {
        encode_var_bytes(BLOSSOM_LOCATOR_KIND_V1.as_bytes(), &mut endpoints);
        encode_var_bytes(b"https://blossom.primal.net/", &mut endpoints);
    }
    let bytes = encode_component_vectors(&[
        ENCRYPTED_MEDIA_FORMAT_V1.as_bytes(),
        allowed.as_slice(),
        endpoints.as_slice(),
    ]);
    assert_eq!(
        decode_encrypted_media_policy_v1(&bytes),
        Err("encrypted media policy has a duplicate default blob endpoint".into())
    );
}

/// Decode rejects a non-normalized endpoint base URL (missing the WHATWG
/// empty-path `/`) rather than repairing it.
#[test]
fn encrypted_media_policy_decode_rejects_non_normalized_endpoint_url() {
    let mut allowed = Vec::new();
    encode_var_bytes(BLOSSOM_LOCATOR_KIND_V1.as_bytes(), &mut allowed);
    let mut endpoints = Vec::new();
    encode_var_bytes(BLOSSOM_LOCATOR_KIND_V1.as_bytes(), &mut endpoints);
    // WHATWG-normalized form is "https://blossom.primal.net/"; the trailing
    // slash is missing here, so the stored bytes are not canonical.
    encode_var_bytes(b"https://blossom.primal.net", &mut endpoints);
    let bytes = encode_component_vectors(&[
        ENCRYPTED_MEDIA_FORMAT_V1.as_bytes(),
        allowed.as_slice(),
        endpoints.as_slice(),
    ]);
    assert_eq!(
        decode_encrypted_media_policy_v1(&bytes),
        Err("encrypted media endpoint base URL is not normalized".into())
    );
}

/// Decode rejects a non-canonical locator kind (uppercase) rather than
/// lowercasing it.
#[test]
fn encrypted_media_policy_decode_rejects_non_canonical_locator_kind() {
    let mut allowed = Vec::new();
    encode_var_bytes(b"Blossom-V1", &mut allowed);
    let mut endpoints = Vec::new();
    encode_var_bytes(b"Blossom-V1", &mut endpoints);
    encode_var_bytes(b"https://blossom.primal.net/", &mut endpoints);
    let bytes = encode_component_vectors(&[
        ENCRYPTED_MEDIA_FORMAT_V1.as_bytes(),
        allowed.as_slice(),
        endpoints.as_slice(),
    ]);
    assert!(decode_encrypted_media_policy_v1(&bytes).is_err());
}

/// Decode rejects a non-canonical `media_format` (e.g. with surrounding
/// whitespace) rather than trimming it.
#[test]
fn encrypted_media_policy_decode_rejects_non_canonical_media_format() {
    let mut allowed = Vec::new();
    encode_var_bytes(BLOSSOM_LOCATOR_KIND_V1.as_bytes(), &mut allowed);
    let mut endpoints = Vec::new();
    encode_var_bytes(BLOSSOM_LOCATOR_KIND_V1.as_bytes(), &mut endpoints);
    encode_var_bytes(b"https://blossom.primal.net/", &mut endpoints);
    let bytes = encode_component_vectors(&[
        b" encrypted-media-v1 ",
        allowed.as_slice(),
        endpoints.as_slice(),
    ]);
    assert_eq!(
        decode_encrypted_media_policy_v1(&bytes),
        Err(format!(
            "encrypted media format must be {ENCRYPTED_MEDIA_FORMAT_V1}"
        ))
    );
}

#[test]
fn group_avatar_url_rejects_documentation_ipv6_ranges() {
    // 2001:db8::/32 is the spec-required documentation range; 3fff::/20 is the
    // newer RFC 9637 documentation range.
    for raw in [
        "https://[2001:db8::1]/a.png",
        "https://[2001:db8:abcd:12::1]/a.png",
        "https://[3fff::1]/a.png",
        "https://[3fff:ffff::1]/a.png",
    ] {
        assert!(
            validate_and_normalize_group_avatar_url(raw).is_err(),
            "{raw} should be rejected"
        );
    }
    // A globally-routable IPv6 address is still accepted.
    assert!(validate_and_normalize_group_avatar_url("https://[2606:4700::1]/a.png").is_ok());
}

#[test]
fn nostr_routing_rejects_non_canonical_relay_list() {
    let routing = NostrRoutingV1 {
        nostr_group_id: [0x42; 32],
        relays: vec![
            "wss://relay-b.example".into(),
            "wss://relay-a.example".into(),
        ],
    };

    assert_eq!(
        encode_nostr_routing_v1(&routing),
        Err("Nostr relay URLs must be sorted and unique".into())
    );
}

#[test]
fn nostr_routing_rejects_invalid_relay_urls() {
    for relay in [
        "https://relay.example",
        "wss://user@relay.example",
        "wss://relay.example#fragment",
        "wss://",
    ] {
        let routing = NostrRoutingV1 {
            nostr_group_id: [0x42; 32],
            relays: vec![relay.to_owned()],
        };
        assert!(
            encode_nostr_routing_v1(&routing).is_err(),
            "{relay} should be rejected"
        );
    }
}

#[test]
fn group_avatar_url_round_trips_all_fields() {
    let avatar = GroupAvatarUrlV1 {
        url: "https://cdn.example.com/avatar.png".to_owned(),
        dim: Some("512x512".to_owned()),
        thumbhash: Some("abc123".to_owned()),
    };
    let bytes = encode_group_avatar_url_v1(&avatar).unwrap();
    assert_eq!(decode_group_avatar_url_v1(&bytes).unwrap(), avatar);
}

#[test]
fn group_avatar_url_round_trips_url_only() {
    let avatar = GroupAvatarUrlV1 {
        url: "https://cdn.example.com/avatar.png".to_owned(),
        dim: None,
        thumbhash: None,
    };
    let bytes = encode_group_avatar_url_v1(&avatar).unwrap();
    assert_eq!(decode_group_avatar_url_v1(&bytes).unwrap(), avatar);
}

#[test]
fn group_avatar_url_empty_state_round_trips_as_absent() {
    let absent = GroupAvatarUrlV1::default();
    let bytes = encode_group_avatar_url_v1(&absent).unwrap();
    assert_eq!(decode_group_avatar_url_v1(&bytes).unwrap(), absent);
}

#[test]
fn group_avatar_url_absent_state_rejects_hints() {
    let absent_with_hint = GroupAvatarUrlV1 {
        url: String::new(),
        dim: Some("512x512".to_owned()),
        thumbhash: None,
    };

    assert!(encode_group_avatar_url_v1(&absent_with_hint).is_err());
}

#[test]
fn group_avatar_url_requires_https() {
    for raw in [
        "http://cdn.example.com/a.png",
        "ftp://cdn.example.com/a.png",
        "ws://cdn.example.com/a.png",
    ] {
        assert!(
            validate_and_normalize_group_avatar_url(raw).is_err(),
            "{raw} should be rejected"
        );
    }
}

#[test]
fn group_avatar_url_rejects_localhost_and_non_routable_hosts() {
    for raw in [
        "https://localhost/a.png",
        "https://app.localhost/a.png",
        "https://127.0.0.1/a.png",
        "https://10.0.0.5/a.png",
        "https://192.168.1.2/a.png",
        "https://172.16.0.1/a.png",
        "https://169.254.1.1/a.png",
        // Ranges aligned with the canonical unsafe-host set / media validator.
        "https://0.0.0.1/a.png",     // 0.0.0.0/8 this-host
        "https://100.64.0.1/a.png",  // CGNAT 100.64.0.0/10
        "https://192.0.0.1/a.png",   // IETF protocol assignments 192.0.0.0/24
        "https://192.88.99.1/a.png", // 6to4 relay anycast 192.88.99.0/24
        "https://198.18.0.1/a.png",  // benchmarking 198.18.0.0/15
        "https://240.0.0.1/a.png",   // reserved 240.0.0.0/4
        "https://[::1]/a.png",
        "https://[::ffff:127.0.0.1]/a.png",
        "https://[::ffff:10.0.0.1]/a.png",
        "https://[fc00::1]/a.png",
        "https://[fe80::1]/a.png",
        "https://[2002::1]/a.png", // 6to4 transition prefix
        "https://[2001::1]/a.png", // Teredo 2001:0000::/32
        "https://[3fff::1]/a.png", // documentation 3fff::/20 (RFC 9637)
        "https://[4000::1]/a.png", // outside global unicast 2000::/3
    ] {
        assert!(
            validate_and_normalize_group_avatar_url(raw).is_err(),
            "{raw} should be rejected"
        );
    }
}

#[test]
fn group_avatar_url_rejects_credentials_and_fragment() {
    assert!(
        validate_and_normalize_group_avatar_url("https://user:pass@cdn.example.com/a").is_err()
    );
    assert!(validate_and_normalize_group_avatar_url("https://cdn.example.com/a#frag").is_err());
}

#[test]
fn group_avatar_url_enforces_max_length() {
    let long = format!(
        "https://cdn.example.com/{}",
        "a".repeat(GROUP_AVATAR_URL_MAX_LEN)
    );
    assert!(validate_and_normalize_group_avatar_url(&long).is_err());
}

#[test]
fn group_avatar_url_normalizes_on_ingest() {
    let normalized =
        validate_and_normalize_group_avatar_url("https://CDN.Example.COM:443/a.png").unwrap();
    // Host lowercased and default https port dropped.
    assert_eq!(normalized, "https://cdn.example.com/a.png");
}

#[test]
fn group_avatar_url_decode_rejects_non_normalized_url() {
    // Hand-build bytes carrying a non-normalized (uppercase host) URL.
    let mut bytes = Vec::new();
    let raw = "https://CDN.EXAMPLE.COM/a.png";
    encode_var_bytes(raw.as_bytes(), &mut bytes);
    encode_var_bytes(b"", &mut bytes);
    encode_var_bytes(b"", &mut bytes);
    assert!(decode_group_avatar_url_v1(&bytes).is_err());
}

#[test]
fn group_avatar_url_decode_rejects_absent_state_with_hints() {
    let mut bytes = Vec::new();
    encode_var_bytes(b"", &mut bytes);
    encode_var_bytes(b"512x512", &mut bytes);
    encode_var_bytes(b"", &mut bytes);

    assert!(decode_group_avatar_url_v1(&bytes).is_err());
}

#[test]
fn group_avatar_url_decode_rejects_trailing_bytes() {
    let avatar = GroupAvatarUrlV1 {
        url: "https://cdn.example.com/a.png".to_owned(),
        dim: None,
        thumbhash: None,
    };
    let mut bytes = encode_group_avatar_url_v1(&avatar).unwrap();
    bytes.push(0);
    assert!(decode_group_avatar_url_v1(&bytes).is_err());
}

#[test]
fn group_avatar_url_decode_treats_non_utf8_hint_as_absent() {
    // dim/thumbhash are opaque length-bounded hints: a non-UTF-8 hint MUST NOT
    // invalidate the component (else the same commit forks accept/reject across
    // clients). It is interpreted as absent.
    let url = validate_and_normalize_group_avatar_url("https://cdn.example.com/a.png").unwrap();
    let mut bytes = Vec::new();
    encode_var_bytes(url.as_bytes(), &mut bytes);
    encode_var_bytes(&[0xff, 0xfe], &mut bytes); // non-UTF-8 dim
    encode_var_bytes(&[0x80, 0x81, 0x82], &mut bytes); // non-UTF-8 thumbhash

    let decoded = decode_group_avatar_url_v1(&bytes)
        .expect("non-UTF-8 opaque hints must not invalidate the avatar component");
    assert_eq!(decoded.url, url);
    assert_eq!(decoded.dim, None);
    assert_eq!(decoded.thumbhash, None);

    // A within-bounds UTF-8 hint is still surfaced for rendering.
    let mut bytes = Vec::new();
    encode_var_bytes(url.as_bytes(), &mut bytes);
    encode_var_bytes(b"512x512", &mut bytes);
    encode_var_bytes(b"", &mut bytes);
    let decoded = decode_group_avatar_url_v1(&bytes).unwrap();
    assert_eq!(decoded.dim.as_deref(), Some("512x512"));
}

#[test]
fn group_avatar_hint_length_is_bounded() {
    let avatar = GroupAvatarUrlV1 {
        url: "https://cdn.example.com/a.png".to_owned(),
        dim: Some("a".repeat(GROUP_AVATAR_HINT_MAX_LEN + 1)),
        thumbhash: None,
    };
    assert!(encode_group_avatar_url_v1(&avatar).is_err());
}
