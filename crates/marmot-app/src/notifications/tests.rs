use super::*;
use secp256k1::{Keypair, Secp256k1, ecdh::SharedSecret};

fn server_secret() -> SecretKey {
    let secp = Secp256k1::new();
    for candidate in 1_u8..=u8::MAX {
        let secret = SecretKey::from_slice(&[candidate; 32]).unwrap();
        let public = SecpPublicKey::from_secret_key(&secp, &secret);
        let (_, parity) = public.x_only_public_key();
        if parity == Parity::Even {
            return secret;
        }
    }
    unreachable!("test secret with even x-only parity should exist")
}

fn server_pubkey_hex(secret: &SecretKey) -> String {
    let secp = Secp256k1::new();
    let public = SecpPublicKey::from_secret_key(&secp, secret);
    let (xonly, _) = public.x_only_public_key();
    hex::encode(xonly.serialize())
}

#[test]
fn trigger_relays_prefer_record_hints_over_10050_fallback() {
    // Hint present -> hint (the 10050 list is not consulted).
    let selected = select_notification_trigger_relays(
        &["wss://hint.example".to_owned()],
        &["wss://inbox.example".to_owned()],
    );
    assert_eq!(selected, vec!["wss://hint.example".to_owned()]);
}

#[test]
fn trigger_relays_fall_back_to_10050_when_no_hint() {
    // Hint absent -> the server account's published kind-10050 inbox relays.
    let selected = select_notification_trigger_relays(
        &[],
        &[
            "wss://inbox-a.example".to_owned(),
            "wss://inbox-b.example".to_owned(),
        ],
    );
    assert_eq!(
        selected,
        vec![
            "wss://inbox-a.example".to_owned(),
            "wss://inbox-b.example".to_owned(),
        ]
    );
}

#[test]
fn trigger_relays_empty_when_neither_hint_nor_10050() {
    // Neither -> unreachable (caller skips as the genuine last resort).
    assert!(select_notification_trigger_relays(&[], &[]).is_empty());
    // Blank entries are not relays.
    assert!(select_notification_trigger_relays(&["   ".to_owned()], &["".to_owned()]).is_empty());
}

#[test]
fn trigger_relays_dedup_with_stable_order() {
    let selected = select_notification_trigger_relays(
        &[
            "wss://a.example".to_owned(),
            "wss://a.example".to_owned(),
            "wss://b.example".to_owned(),
        ],
        &[],
    );
    assert_eq!(
        selected,
        vec!["wss://a.example".to_owned(), "wss://b.example".to_owned()]
    );
}

#[test]
fn token_records_by_server_keeps_hintless_records_for_10050_fallback() {
    // A token record with no relay hint must still be grouped so the trigger
    // publisher can fall back to the server's kind-10050 inbox relays. Only
    // the local account's own tokens are dropped here.
    let server = "aa".repeat(32);
    let group_id_hex = "ee".repeat(32);
    let tokens = vec![
        GroupPushTokenRecord {
            group_id_hex: group_id_hex.clone(),
            member_id_hex: "bb".repeat(32),
            leaf_index: 1,
            platform: PushPlatform::Apns,
            token_fingerprint: "fp1".to_owned(),
            server_pubkey_hex: server.clone(),
            relay_hint: None,
            encrypted_token: vec![1, 2, 3],
            owner_ts: 0,
            owner_sig: String::new(),
            updated_at_ms: 0,
        },
        GroupPushTokenRecord {
            group_id_hex,
            member_id_hex: "cc".repeat(32),
            leaf_index: 2,
            platform: PushPlatform::Fcm,
            token_fingerprint: "fp2".to_owned(),
            server_pubkey_hex: server.clone(),
            relay_hint: Some("wss://hint.example".to_owned()),
            encrypted_token: vec![4, 5, 6],
            owner_ts: 0,
            owner_sig: String::new(),
            updated_at_ms: 0,
        },
    ];
    let grouped = token_records_by_server(tokens, "dd".repeat(32).as_str());
    let records = grouped.get(&server).expect("server group present");
    assert_eq!(records.len(), 2);
}

fn device_token_record(
    member_id_hex: &str,
    leaf_index: u32,
    device_token: &[u8],
    owner_ts: i64,
) -> GroupPushTokenRecord {
    GroupPushTokenRecord {
        group_id_hex: "ee".repeat(32),
        member_id_hex: member_id_hex.to_owned(),
        leaf_index,
        platform: PushPlatform::Apns,
        token_fingerprint: push_token_fingerprint(PushPlatform::Apns, device_token),
        server_pubkey_hex: "aa".repeat(32),
        relay_hint: Some("wss://hint.example".to_owned()),
        encrypted_token: vec![leaf_index as u8; PUSH_ENCRYPTED_TOKEN_LEN],
        owner_ts,
        owner_sig: String::new(),
        updated_at_ms: owner_ts,
    }
}

fn selected_leaves(grouped: &BTreeMap<String, Vec<GroupPushTokenRecord>>) -> Vec<(String, u32)> {
    grouped
        .values()
        .flatten()
        .map(|record| (record.member_id_hex.clone(), record.leaf_index))
        .collect()
}

#[test]
fn token_records_by_server_keeps_every_sibling_leaf() {
    let bob = "bb".repeat(32);
    let tokens = vec![
        device_token_record(&bob, 1, b"phone", 1),
        device_token_record(&bob, 4, b"tablet", 1),
    ];
    let grouped = token_records_by_server(tokens, "dd".repeat(32).as_str());
    assert_eq!(selected_leaves(&grouped), vec![(bob.clone(), 1), (bob, 4)]);
}

#[test]
fn token_records_by_server_sends_one_push_per_device_token() {
    let bob = "bb".repeat(32);
    let carol = "cc".repeat(32);
    let tokens = vec![
        device_token_record(&bob, 1, b"phone", 10),
        device_token_record(&bob, 2, b"tablet", 5),
        device_token_record(&bob, 3, b"tablet", 5),
        device_token_record(&bob, 4, b"phone", 20),
        // Another account naming the same token is not collapsed into Bob's.
        device_token_record(&carol, 5, b"phone", 1),
    ];
    let grouped = token_records_by_server(tokens, "dd".repeat(32).as_str());
    // The newest owner_ts wins; equal stamps keep the lowest leaf.
    assert_eq!(
        selected_leaves(&grouped),
        vec![(bob.clone(), 2), (bob, 4), (carol, 5)]
    );
}

#[test]
fn token_records_by_server_excludes_local_sibling_leaves() {
    let local = "dd".repeat(32);
    let bob = "bb".repeat(32);
    let tokens = vec![
        device_token_record(&bob, 1, b"bob-phone", 1),
        device_token_record(&local, 0, b"local-phone", 1),
        device_token_record(&local, 3, b"local-tablet", 1),
    ];
    let grouped = token_records_by_server(tokens, &local);
    assert_eq!(selected_leaves(&grouped), vec![(bob, 1)]);
}

fn debug_info_for(
    tokens: Vec<GroupPushTokenRecord>,
    local: &str,
    member_leaves: &[(&String, u32)],
    local_leaf_index: Option<u32>,
) -> GroupPushDebugInfo {
    let member_leaves = member_leaves
        .iter()
        .map(|(member, leaf_index)| ((*member).clone(), *leaf_index))
        .collect::<Vec<_>>();
    group_debug_info(
        NotificationSettings {
            account_ref: "local".to_owned(),
            account_id_hex: local.to_owned(),
            local_notifications_enabled: true,
            native_push_enabled: true,
        },
        None,
        tokens,
        local,
        &member_leaves,
        local_leaf_index,
    )
}

/// `(member, leaf, active_leaf, member_matches_active_leaf)` per entry.
fn debug_leaf_states(info: &GroupPushDebugInfo) -> Vec<(String, u32, bool, bool)> {
    let mut states = info
        .tokens
        .iter()
        .map(|entry| {
            (
                entry.member_id_hex.clone(),
                entry.leaf_index,
                entry.active_leaf,
                entry.member_matches_active_leaf,
            )
        })
        .collect::<Vec<_>>();
    states.sort();
    states
}

#[test]
fn group_debug_info_matches_records_past_a_blank_leaf() {
    let alice = "aa".repeat(32);
    let bob = "bb".repeat(32);
    let carol = "cc".repeat(32);
    // Bob's removal blanked leaf 1, so Carol is second in member order but
    // still holds leaf 2.
    let info = debug_info_for(
        vec![
            device_token_record(&alice, 0, b"alice", 1),
            device_token_record(&bob, 1, b"bob", 1),
            device_token_record(&carol, 2, b"carol", 1),
        ],
        &carol,
        &[(&alice, 0), (&carol, 2)],
        Some(2),
    );
    assert_eq!(
        debug_leaf_states(&info),
        vec![
            (alice, 0, true, true),
            (bob, 1, false, false),
            (carol, 2, true, true),
        ]
    );
    assert_eq!(
        (
            info.total_token_count,
            info.active_token_count,
            info.stale_token_count
        ),
        (3, 2, 1)
    );
    assert_eq!(info.local_registration.local_leaf_index, Some(2));
}

#[test]
fn group_debug_info_counts_each_sibling_leaf_and_old_leaves_as_stale() {
    let local = "dd".repeat(32);
    let bob = "bb".repeat(32);
    // Bob's devices hold leaves 1 and 3; his record on leaf 2 is from a device
    // that left. Leaf 2 now holds the local device's sibling.
    let info = debug_info_for(
        vec![
            device_token_record(&bob, 1, b"bob-phone", 1),
            device_token_record(&bob, 2, b"bob-old-phone", 1),
            device_token_record(&bob, 3, b"bob-tablet", 1),
            device_token_record(&bob, 5, b"bob-older-phone", 1),
            device_token_record(&local, 4, b"local-tablet", 1),
        ],
        &local,
        &[(&local, 0), (&bob, 1), (&local, 2), (&bob, 3), (&local, 4)],
        Some(4),
    );
    assert_eq!(
        debug_leaf_states(&info),
        vec![
            (bob.clone(), 1, true, true),
            (bob.clone(), 2, true, false),
            (bob.clone(), 3, true, true),
            (bob, 5, true, false),
            (local, 4, true, true),
        ]
    );
    assert_eq!(
        (
            info.total_token_count,
            info.active_token_count,
            info.stale_token_count
        ),
        (5, 3, 2)
    );
    // The local account holds three leaves; the device's own is reported.
    assert_eq!(info.local_registration.local_leaf_index, Some(4));
}

#[test]
fn apns_token_encryption_uses_platform_byte_0x01() {
    let secret = server_secret();
    let blob = encrypted_push_token(
        PushPlatform::Apns,
        &[0xAA, 0xBB, 0xCC],
        &server_pubkey_hex(&secret),
    )
    .unwrap();
    assert_eq!(blob.len(), PUSH_ENCRYPTED_TOKEN_LEN);
    let (platform, token) = decrypt_push_token_for_test(&blob, &secret).unwrap();
    assert_eq!(platform.platform_byte(), 0x01);
    assert_eq!(token, vec![0xAA, 0xBB, 0xCC]);
}

#[test]
fn fcm_token_encryption_uses_platform_byte_0x02() {
    let secret = server_secret();
    let blob = encrypted_push_token(
        PushPlatform::Fcm,
        b"opaque-fcm-token",
        &server_pubkey_hex(&secret),
    )
    .unwrap();
    assert_eq!(blob.len(), PUSH_ENCRYPTED_TOKEN_LEN);
    let (platform, token) = decrypt_push_token_for_test(&blob, &secret).unwrap();
    assert_eq!(platform.platform_byte(), 0x02);
    assert_eq!(token, b"opaque-fcm-token");
}

#[test]
fn push_key_derivation_uses_raw_shared_point_x_coordinate() {
    let server_secret = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let peer_secret = SecretKey::from_slice(&[0x22; 32]).unwrap();
    let peer_public = SecpPublicKey::from_secret_key(&Secp256k1::new(), &peer_secret);

    let shared_x = secp256k1_ecdh_x(&peer_public, &server_secret);
    let raw_x_key = push_encryption_key(&shared_x).unwrap();

    let hashed_shared = SharedSecret::new(&peer_public, &server_secret).secret_bytes();
    let hashed_helper_key = push_encryption_key(&hashed_shared).unwrap();

    assert_ne!(raw_x_key, hashed_helper_key);
}

#[test]
fn apns_hex_and_fcm_opaque_tokens_are_accepted() {
    assert_eq!(
        parse_provider_token(PushPlatform::Apns, "00aaff").unwrap(),
        vec![0x00, 0xAA, 0xFF]
    );
    assert_eq!(
        parse_provider_token(PushPlatform::Fcm, "abc.DEF:_-").unwrap(),
        b"abc.DEF:_-"
    );
}

#[test]
fn empty_malformed_or_too_long_tokens_are_rejected_without_secret_material() {
    for (platform, token) in [
        (PushPlatform::Apns, ""),
        (PushPlatform::Apns, "AABB"),
        (PushPlatform::Apns, "not-hex"),
        (PushPlatform::Fcm, ""),
    ] {
        let err = parse_provider_token(platform, token).expect_err("token should fail");
        if !token.is_empty() {
            assert!(!err.to_string().contains(token));
        }
    }
    let too_long = "x".repeat(PUSH_MAX_PROVIDER_TOKEN_LEN + 1);
    let err = parse_provider_token(PushPlatform::Fcm, &too_long).unwrap_err();
    assert!(!err.to_string().contains(&too_long));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_token_gossip_normalizes_relay_hint_before_signing_and_storage() {
    let owner = Keys::generate();
    let token_bytes = b"provider-token".to_vec();
    let registration = StoredPushRegistration {
        registration: PushRegistration {
            account_ref: "alice".to_owned(),
            account_id_hex: owner.public_key().to_hex(),
            platform: PushPlatform::Fcm,
            token_fingerprint: push_token_fingerprint(PushPlatform::Fcm, &token_bytes),
            server_pubkey_hex: Keys::generate().public_key().to_hex(),
            relay_hint: Some(" \twss://relay.example\n".to_owned()),
            created_at_ms: 1,
            updated_at_ms: 1,
            last_shared_at_ms: None,
        },
        token_bytes,
    };

    let (payload, record) = local_token_gossip_payload(
        "ef".repeat(16),
        owner.public_key().to_hex(),
        1,
        &registration,
        &owner,
    )
    .await
    .unwrap();

    assert_eq!(record.relay_hint.as_deref(), Some("wss://relay.example"));
    assert_eq!(
        payload.tokens[0].relay_hint.as_deref(),
        Some("wss://relay.example")
    );
    assert_eq!(
        record.owner_proof_event().unwrap().kind,
        Kind::Custom(PUSH_OWNER_PROOF_EVENT_KIND)
    );
    assert!(record.verify_owner_sig(ProtocolProfile::Current));
}

#[test]
fn kind_446_content_is_base64_concatenated_tokens_with_version_tag() {
    let token = vec![7_u8; PUSH_ENCRYPTED_TOKEN_LEN];
    let content = build_notification_rumor_content(&[token.clone(), token.clone()]).unwrap();
    let decoded = BASE64_STANDARD.decode(content).unwrap();
    assert_eq!(decoded.len(), PUSH_ENCRYPTED_TOKEN_LEN * 2);
}

#[test]
fn kind_446_content_is_bounded_to_32_encrypted_tokens() {
    let token = vec![7_u8; PUSH_ENCRYPTED_TOKEN_LEN];
    assert!(
        build_notification_rumor_content(&vec![
            token.clone();
            PUSH_MAX_NOTIFICATION_TRIGGER_TOKENS
        ])
        .is_ok()
    );
    assert!(
        build_notification_rumor_content(&vec![token; PUSH_MAX_NOTIFICATION_TRIGGER_TOKENS + 1])
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_chunks_round_trip_at_wire_size_boundary() {
    let server = Keys::generate();
    let tokens = (0..20)
        .map(|index| vec![index as u8; PUSH_ENCRYPTED_TOKEN_LEN])
        .collect::<Vec<_>>();
    let oversized = build_notification_gift_wrap(&server.public_key().to_hex(), &tokens)
        .await
        .unwrap()
        .to_verified_nostr_event()
        .unwrap();
    assert!(serde_json::to_vec(&oversized).unwrap().len() > 65_536);

    let mut received = Vec::new();
    let mut chunk_sizes = Vec::new();
    for chunk in padded_notification_trigger_chunks(&tokens) {
        let wrap = build_notification_gift_wrap(&server.public_key().to_hex(), &chunk)
            .await
            .unwrap();
        let event = wrap.to_verified_nostr_event().unwrap();
        assert!(serde_json::to_vec(&event).unwrap().len() <= 65_536);
        let gift = nostr::nips::nip59::extract_rumor(&server, &event).unwrap();
        assert_eq!(
            gift.rumor.kind,
            Kind::Custom(KIND_MARMOT_NOTIFICATION_RUMOR as u16)
        );
        let content = BASE64_STANDARD.decode(gift.rumor.content).unwrap();
        assert_eq!(content.len() % PUSH_ENCRYPTED_TOKEN_LEN, 0);
        chunk_sizes.push(content.len() / PUSH_ENCRYPTED_TOKEN_LEN);
        let (real, padding) = content.split_at(content.len() - PUSH_ENCRYPTED_TOKEN_LEN);
        assert!(!tokens.iter().any(|token| token == padding));
        received.extend_from_slice(real);
    }
    // 18 real tokens plus one padding chunk fill the 19-chunk wire limit.
    assert_eq!(chunk_sizes, [19, 3]);
    assert_eq!(received, tokens.concat());
}

#[test]
fn trigger_padding_is_fresh_per_send_and_never_decrypts() {
    let secret = server_secret();
    let token = encrypted_push_token(
        PushPlatform::Fcm,
        b"opaque-fcm-token",
        &server_pubkey_hex(&secret),
    )
    .unwrap();
    let tokens = vec![token.clone()];
    let first = padded_notification_trigger_chunks(&tokens).collect::<Vec<_>>();
    let second = padded_notification_trigger_chunks(&tokens).collect::<Vec<_>>();
    for chunks in [&first, &second] {
        assert_eq!(chunks.len(), 1);
        let [real, padding] = chunks[0].as_slice() else {
            panic!("one real token and one padding chunk");
        };
        assert_eq!(real, &token);
        assert!(decrypt_push_token_for_test(real, &secret).is_ok());
        assert_eq!(padding.len(), PUSH_ENCRYPTED_TOKEN_LEN);
        assert!(decrypt_push_token_for_test(padding, &secret).is_err());
    }
    // Servers dedup triggers on the decoded content's SHA-256.
    let digest = |chunks: &[Vec<Vec<u8>>]| {
        let content = build_notification_rumor_content(&chunks[0]).unwrap();
        Sha256::digest(BASE64_STANDARD.decode(content).unwrap())
    };
    assert_ne!(digest(&first), digest(&second));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kind_446_rumor_only_carries_version_tag_and_no_routing_metadata() {
    use nostr::nips::nip59::UnwrappedGift;

    let secret = server_secret();
    let server_pubkey_hex = server_pubkey_hex(&secret);
    let token = vec![7_u8; PUSH_ENCRYPTED_TOKEN_LEN];

    let wrap = build_notification_gift_wrap(&server_pubkey_hex, &[token.clone(), token])
        .await
        .unwrap();
    let event = wrap.to_verified_nostr_event().unwrap();

    let server_keys = Keys::new(nostr::prelude::SecretKey::from(secret));
    let UnwrappedGift { rumor, .. } = UnwrappedGift::from_gift_wrap(&server_keys, &event).unwrap();

    assert_eq!(
        rumor.kind,
        Kind::Custom(KIND_MARMOT_NOTIFICATION_RUMOR as u16)
    );
    let tag_slices: Vec<&[String]> = rumor.tags.iter().map(|tag| tag.as_slice()).collect();
    assert_eq!(
        tag_slices,
        vec![[NOTIFICATION_VERSION_TAG.to_owned(), PUSH_VERSION.to_owned()].as_slice()],
        "rumor must carry only the version tag; any p/e/k/h/d/relays tag would leak routing metadata"
    );

    let decoded = BASE64_STANDARD.decode(&rumor.content).unwrap();
    assert_eq!(decoded.len(), PUSH_ENCRYPTED_TOKEN_LEN * 2);
}

#[test]
fn malformed_push_gossip_returns_error_without_leaking_payload_content() {
    let group_id_hex = "ab".repeat(32);
    let garbage = "not-json {{ <invalid> deadbeefcafe";

    for kind in [
        MARMOT_APP_EVENT_KIND_PUSH_TOKEN_UPDATE,
        MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST,
        MARMOT_APP_EVENT_KIND_PUSH_TOKEN_REMOVAL,
    ] {
        let err =
            parse_push_gossip(kind, &group_id_hex, garbage).expect_err("garbage gossip must error");
        assert!(matches!(err, AppError::InvalidPushGossip(_)));
        let rendered = err.to_string();
        assert!(
            !rendered.contains("deadbeefcafe") && !rendered.contains(garbage),
            "InvalidPushGossip display must not leak raw payload bytes (kind {kind})"
        );
    }
}

#[test]
fn push_gossip_with_wrong_version_is_rejected_as_advisory() {
    let group_id_hex = "ab".repeat(32);
    let stale_payload = r#"{"v":"stale-legacy","tokens":[]}"#;
    let err = parse_push_gossip(
        MARMOT_APP_EVENT_KIND_PUSH_TOKEN_UPDATE,
        &group_id_hex,
        stale_payload,
    )
    .expect_err("wrong version must error");
    assert!(matches!(err, AppError::InvalidPushGossip(_)));
}

#[test]
fn unsupported_push_gossip_kind_returns_error_not_panic() {
    let err = parse_push_gossip(99_999, "00".repeat(32).as_str(), "{}")
        .expect_err("unsupported kind must error cleanly");
    assert!(matches!(err, AppError::InvalidPushGossip(_)));
}

fn valid_push_entry_json() -> serde_json::Value {
    serde_json::json!({
        "member_id_hex": "ab".repeat(32),
        "leaf_index": 1,
        "platform": "apns",
        "token_fingerprint": "sha256:0123456789abcdef01234567",
        "server_pubkey_hex": "cd".repeat(32),
        "relay_hint": "wss://relay.example",
        "encrypted_token": BASE64_STANDARD.encode(vec![0_u8; PUSH_ENCRYPTED_TOKEN_LEN]),
        "owner_ts": 1,
        "owner_sig": "00".repeat(64),
    })
}

fn valid_push_removal_json() -> serde_json::Value {
    let mut entry = valid_push_entry_json();
    let object = entry.as_object_mut().expect("entry is an object");
    object.remove("relay_hint");
    object.remove("encrypted_token");
    entry
}

#[test]
fn push_gossip_array_boundaries_accept_0_1_31_and_32_entries() {
    let group_id_hex = "ef".repeat(32);
    for len in [0, 1, 31, PUSH_MAX_GOSSIP_ENTRIES] {
        let add = serde_json::json!({
            "v": PUSH_VERSION,
            "tokens": vec![valid_push_entry_json(); len],
        })
        .to_string();
        let remove = serde_json::json!({
            "v": PUSH_VERSION,
            "removals": vec![valid_push_removal_json(); len],
        })
        .to_string();

        assert!(
            parse_push_gossip(MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST, &group_id_hex, &add).is_ok(),
            "add length {len} must be accepted"
        );
        assert!(
            parse_push_gossip(
                MARMOT_APP_EVENT_KIND_PUSH_TOKEN_REMOVAL,
                &group_id_hex,
                &remove,
            )
            .is_ok(),
            "removal length {len} must be accepted"
        );
    }
}

#[test]
fn maliciously_large_arrays_stop_at_the_bounded_preflight() {
    let entries = std::iter::repeat_n("{}", 100_000)
        .collect::<Vec<_>>()
        .join(",");
    let add = format!(r#"{{"v":"{PUSH_VERSION}","tokens":[{entries}]}}"#);
    let remove = format!(r#"{{"v":"{PUSH_VERSION}","removals":[{entries}]}}"#);

    let add_error = serde_json::from_str::<PushTokenGossipShape>(&add)
        .err()
        .expect("oversized add array must stop at entry 33");
    let removal_error = serde_json::from_str::<PushTokenRemovalShape>(&remove)
        .err()
        .expect("oversized removal array must stop at entry 33");
    let expected = format!("exceeds {PUSH_MAX_GOSSIP_ENTRIES} entries");
    assert!(add_error.to_string().contains(&expected));
    assert!(removal_error.to_string().contains(&expected));
}

#[test]
fn oversized_arrays_do_zero_signature_verifications_and_yield_zero_records() {
    let owner = Keys::generate();
    let owner_id = owner.public_key().to_hex();
    let group_id_hex = "ef".repeat(32);
    let server = "cd".repeat(32);
    let record = signed_token_record(&owner, &group_id_hex, 1, &server, 100);
    let removal = signed_removal_record(&owner, &group_id_hex, 1, &server, 101);
    let add_entry = serde_json::to_value(PushTokenGossipEntry::from_record(&record)).unwrap();
    let removal_entry = serde_json::json!({
        "member_id_hex": removal.member_id_hex,
        "leaf_index": removal.leaf_index,
        "platform": removal.platform.as_str(),
        "token_fingerprint": removal.token_fingerprint,
        "server_pubkey_hex": removal.server_pubkey_hex,
        "owner_ts": removal.owner_ts,
        "owner_sig": removal.owner_sig,
    });

    let single = serde_json::json!({"v": PUSH_VERSION, "tokens": [add_entry.clone()]}).to_string();
    reset_owner_signature_verification_count();
    let verified = verify_push_gossip(
        parse_push_gossip(
            MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST,
            &group_id_hex,
            &single,
        )
        .unwrap(),
        &group_id_hex,
        std::slice::from_ref(&owner_id),
    );
    assert!(matches!(verified, PushGossipAction::Upsert(records) if records.len() == 1));
    assert_eq!(
        owner_signature_verification_count(),
        1,
        "positive control: the counter observes real owner-proof verification"
    );

    for (kind, content) in [
        (
            MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST,
            serde_json::json!({
                "v": PUSH_VERSION,
                "tokens": vec![add_entry; 33],
            })
            .to_string(),
        ),
        (
            MARMOT_APP_EVENT_KIND_PUSH_TOKEN_REMOVAL,
            serde_json::json!({
                "v": PUSH_VERSION,
                "removals": vec![removal_entry; 33],
            })
            .to_string(),
        ),
    ] {
        reset_owner_signature_verification_count();
        let mut yielded_records = 0_usize;
        let result = parse_push_gossip(kind, &group_id_hex, &content)
            .map(|action| {
                verify_push_gossip(action, &group_id_hex, std::slice::from_ref(&owner_id))
            })
            .map(|action| match action {
                PushGossipAction::Upsert(records) => yielded_records += records.len(),
                PushGossipAction::Remove(removals) => yielded_records += removals.len(),
            });

        assert!(matches!(result, Err(AppError::InvalidPushGossip(_))));
        assert_eq!(owner_signature_verification_count(), 0);
        assert_eq!(yielded_records, 0);
    }
}

#[test]
fn malformed_push_gossip_entries_do_not_poison_valid_siblings() {
    let group_id_hex = "ef".repeat(32);
    let malformed = serde_json::json!({"platform": "bogus"});

    let mut second_add = valid_push_entry_json();
    second_add["leaf_index"] = serde_json::json!(2);
    let add = serde_json::json!({
        "v": PUSH_VERSION,
        "tokens": [valid_push_entry_json(), malformed.clone(), second_add],
    })
    .to_string();
    match parse_push_gossip(MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST, &group_id_hex, &add)
        .expect("the bounded array itself is structurally valid")
    {
        PushGossipAction::Upsert(records) => {
            assert_eq!(
                records
                    .iter()
                    .map(|record| record.leaf_index)
                    .collect::<Vec<_>>(),
                vec![1, 2]
            );
        }
        other => panic!("expected upsert action, got {other:?}"),
    }

    let mut second_removal = valid_push_removal_json();
    second_removal["leaf_index"] = serde_json::json!(2);
    let remove = serde_json::json!({
        "v": PUSH_VERSION,
        "removals": [valid_push_removal_json(), malformed, second_removal],
    })
    .to_string();
    match parse_push_gossip(
        MARMOT_APP_EVENT_KIND_PUSH_TOKEN_REMOVAL,
        &group_id_hex,
        &remove,
    )
    .expect("the bounded array itself is structurally valid")
    {
        PushGossipAction::Remove(removals) => {
            assert_eq!(
                removals
                    .iter()
                    .map(|removal| removal.leaf_index)
                    .collect::<Vec<_>>(),
                vec![1, 2]
            );
        }
        other => panic!("expected removal action, got {other:?}"),
    }
}

#[test]
fn identical_push_gossip_entries_are_deduplicated_before_verification() {
    let group_id_hex = "ef".repeat(32);
    let add = serde_json::json!({
        "v": PUSH_VERSION,
        "tokens": vec![valid_push_entry_json(); PUSH_MAX_GOSSIP_ENTRIES],
    })
    .to_string();
    let remove = serde_json::json!({
        "v": PUSH_VERSION,
        "removals": vec![valid_push_removal_json(); PUSH_MAX_GOSSIP_ENTRIES],
    })
    .to_string();

    match parse_push_gossip(MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST, &group_id_hex, &add)
        .expect("32 entries are within the message bound")
    {
        PushGossipAction::Upsert(records) => assert_eq!(records.len(), 1),
        other => panic!("expected upsert action, got {other:?}"),
    }
    match parse_push_gossip(
        MARMOT_APP_EVENT_KIND_PUSH_TOKEN_REMOVAL,
        &group_id_hex,
        &remove,
    )
    .expect("32 removals are within the message bound")
    {
        PushGossipAction::Remove(removals) => assert_eq!(removals.len(), 1),
        other => panic!("expected removal action, got {other:?}"),
    }
}

#[test]
fn normalized_relay_hint_duplicates_are_deduplicated_before_verification_and_apply() {
    let owner = Keys::generate();
    let owner_id = owner.public_key().to_hex();
    let group_id = cgka_traits::GroupId::new(vec![0xEF; 16]);
    let group_id_hex = hex::encode(group_id.as_slice());
    let server = "cd".repeat(32);
    let mut record = signed_token_record(&owner, &group_id_hex, 1, &server, 100);
    record.relay_hint = None;
    record.sign_owner(&owner).unwrap();

    let omitted_hint = serde_json::to_value(PushTokenGossipEntry::from_record(&record)).unwrap();
    let mut blank_hint = omitted_hint.clone();
    blank_hint["relay_hint"] = serde_json::json!(" \t");
    let payload = serde_json::json!({
        "v": PUSH_VERSION,
        "tokens": [omitted_hint, blank_hint],
    })
    .to_string();

    let dir = tempfile::tempdir().unwrap();
    marmot_account::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let message = ReceivedMessage {
        authority: None,
        message_id_hex: "11".repeat(32),
        source_message_id_hex: "22".repeat(32),
        sender: owner_id.clone(),
        sender_display_name: None,
        group_id,
        source_epoch: 1,
        retention: None,
        plaintext: payload,
        kind: MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST,
        tags: vec![vec!["v".to_owned(), PUSH_VERSION.to_owned()]],
        recorded_at: 1,
        received_at: 1,
    };

    reset_owner_signature_verification_count();
    app.ingest_push_gossip_message(
        "alice",
        &message,
        &[cgka_traits::engine::GroupMemberLeaf {
            member: cgka_traits::MemberId::new(owner.public_key().to_bytes().to_vec()),
            leaf_index: 1,
        }],
        ProtocolProfile::Current,
    )
    .unwrap();

    assert_eq!(
        owner_signature_verification_count(),
        1,
        "wire variants of one canonical record must verify only once"
    );
    let stored = app.group_push_tokens("alice", &group_id_hex).unwrap();
    assert_eq!(stored.len(), 1, "the canonical record applies only once");
    assert_eq!(stored[0].relay_hint, None);
}

#[test]
fn surrounding_relay_hint_whitespace_is_deduplicated_before_verification() {
    let owner = Keys::generate();
    let owner_id = owner.public_key().to_hex();
    let group_id_hex = hex::encode([0xEF; 16]);
    let record = signed_token_record(&owner, &group_id_hex, 1, &"cd".repeat(32), 100);
    let canonical = serde_json::to_value(PushTokenGossipEntry::from_record(&record)).unwrap();
    let mut padded = canonical.clone();
    padded["relay_hint"] = serde_json::json!(" \twss://relay.example\n");
    let payload = serde_json::json!({
        "v": PUSH_VERSION,
        "tokens": [canonical, padded],
    })
    .to_string();

    reset_owner_signature_verification_count();
    let action = verify_push_gossip(
        parse_push_gossip(
            MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST,
            &group_id_hex,
            &payload,
        )
        .unwrap(),
        &group_id_hex,
        std::slice::from_ref(&owner_id),
    );

    assert_eq!(
        owner_signature_verification_count(),
        1,
        "signed-record-equivalent relay hints must verify only once"
    );
    match action {
        PushGossipAction::Upsert(records) => {
            assert_eq!(records.len(), 1);
            assert_eq!(
                records[0].relay_hint.as_deref(),
                Some("wss://relay.example")
            );
        }
        other => panic!("expected upsert action, got {other:?}"),
    }
}

fn push_gossip_test_app(dir: &tempfile::TempDir) -> MarmotApp {
    marmot_account::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    MarmotApp::with_relay(dir.path(), "wss://relay.example")
}

fn push_gossip_message(
    sender: &Keys,
    group_id: &cgka_traits::GroupId,
    kind: u64,
    plaintext: String,
) -> ReceivedMessage {
    ReceivedMessage {
        authority: None,
        message_id_hex: "11".repeat(32),
        source_message_id_hex: "22".repeat(32),
        sender: sender.public_key().to_hex(),
        sender_display_name: None,
        group_id: group_id.clone(),
        source_epoch: 1,
        retention: None,
        plaintext,
        kind,
        tags: vec![vec!["v".to_owned(), PUSH_VERSION.to_owned()]],
        recorded_at: 1,
        received_at: 1,
    }
}

fn removal_payload(removals: &[&PushTokenRemovalRecord]) -> String {
    serde_json::to_string(&PushTokenRemovalPayload {
        v: PUSH_VERSION.to_owned(),
        removals: removals
            .iter()
            .map(|removal| PushTokenRemovalEntry::from_record(removal))
            .collect(),
    })
    .unwrap()
}

/// Any member can relay a stored tombstone in a kind 449 that recipients
/// verify under the group's owner-proof rules, legacy proof forms included. A
/// tombstone written before migration 0118 lists as local-only until the same
/// removal arrives again.
#[test]
fn stored_tombstones_relay_as_owner_verified_removals() {
    let owner = Keys::generate();
    let owner_id = owner.public_key().to_hex();
    let group_id = cgka_traits::GroupId::new(vec![0xEF; 16]);
    let group_id_hex = hex::encode(group_id.as_slice());
    let server = "cd".repeat(32);
    let current = signed_removal_record(&owner, &group_id_hex, 1, &server, 100);
    let mut raw_legacy = signed_removal_record(&owner, &group_id_hex, 2, &server, 100);
    sign_removal_record_raw_legacy(&mut raw_legacy, &group_id_hex, &owner);
    let leaves = [1, 2, 3].map(|leaf_index| cgka_traits::engine::GroupMemberLeaf {
        member: cgka_traits::MemberId::new(owner.public_key().to_bytes().to_vec()),
        leaf_index,
    });

    let dir = tempfile::tempdir().unwrap();
    let app = push_gossip_test_app(&dir);
    app.ingest_push_gossip_message(
        "alice",
        &push_gossip_message(
            &owner,
            &group_id,
            MARMOT_APP_EVENT_KIND_PUSH_TOKEN_REMOVAL,
            removal_payload(&[&current, &raw_legacy]),
        ),
        &leaves,
        ProtocolProfile::Legacy,
    )
    .unwrap();
    let earlier = signed_removal_record(&owner, &group_id_hex, 3, &server, 100);
    let mut local_only =
        crate::conversions::account_push_token_tombstone_from_removal(&group_id_hex, &earlier, 1)
            .unwrap();
    local_only.removal_proof = None;
    app.account_storage("alice")
        .unwrap()
        .app_storage()
        .apply_group_push_token_tombstone(&local_only)
        .unwrap();

    let stored = app
        .group_push_token_tombstones("alice", &group_id_hex)
        .unwrap();
    assert_eq!(stored.len(), 3);
    assert_eq!(
        stored[2].removal, None,
        "pre-0118 tombstones start local-only"
    );
    assert_eq!(stored[2].record_digest, local_only.record_digest);

    // A member relaying the same removal later makes it relayable here too.
    app.ingest_push_gossip_message(
        "alice",
        &push_gossip_message(
            &owner,
            &group_id,
            MARMOT_APP_EVENT_KIND_PUSH_TOKEN_REMOVAL,
            removal_payload(&[&earlier]),
        ),
        &leaves,
        ProtocolProfile::Current,
    )
    .unwrap();
    let stored = app
        .group_push_token_tombstones("alice", &group_id_hex)
        .unwrap();
    assert_eq!(stored.len(), 3);
    for (tombstone, original) in stored.iter().zip([&current, &raw_legacy, &earlier]) {
        let removal = tombstone.removal.as_ref().expect("tombstone is relayable");
        assert_eq!(
            removal, original,
            "the relayed removal is the owner's, unchanged"
        );
        assert_eq!(
            tombstone.record_digest,
            removal.record_digest(&group_id_hex).unwrap()
        );
    }

    // A recipient parses and verifies the relay exactly as it would the
    // owner's own kind 449.
    let relay = removal_payload(
        &stored
            .iter()
            .filter_map(|tombstone| tombstone.removal.as_ref())
            .collect::<Vec<_>>(),
    );
    let verified = |profile| match verify_push_gossip_for_profile(
        parse_push_gossip(
            MARMOT_APP_EVENT_KIND_PUSH_TOKEN_REMOVAL,
            &group_id_hex,
            &relay,
        )
        .unwrap(),
        &group_id_hex,
        std::slice::from_ref(&owner_id),
        profile,
    ) {
        PushGossipAction::Remove(removals) => removals,
        other => panic!("expected removals, got {other:?}"),
    };
    assert_eq!(
        verified(ProtocolProfile::Legacy),
        vec![current.clone(), raw_legacy, earlier.clone()]
    );
    assert_eq!(verified(ProtocolProfile::Current), vec![current, earlier]);
}

/// Read-back returns a record's stored digest only while the record's fields
/// still produce it. The record itself is always returned.
#[test]
fn stored_token_digests_are_checked_on_read_back() {
    let owner = Keys::generate();
    let group_id_hex = hex::encode([0xEF; 16]);
    let server = "cd".repeat(32);
    let dir = tempfile::tempdir().unwrap();
    let app = push_gossip_test_app(&dir);
    let storage = app.account_storage("alice").unwrap().app_storage();

    let matching = signed_token_record(&owner, &group_id_hex, 1, &server, 100);
    let stale = signed_token_record(&owner, &group_id_hex, 2, &server, 100);
    let mut placeholder = signed_token_record(&owner, &group_id_hex, 3, &server, 100);
    placeholder.token_fingerprint = "not-a-fingerprint".to_owned();
    for record in [&matching, &placeholder] {
        app.upsert_group_push_token("alice", record).unwrap();
    }
    let mut stale_row = crate::conversions::account_group_push_token_from_app(&stale);
    stale_row.record_digest = matching.record_digest().unwrap();
    storage.upsert_group_push_token(&stale_row).unwrap();

    let stored = app
        .stored_group_push_tokens("alice", &group_id_hex)
        .unwrap();
    let digests = stored
        .iter()
        .map(|stored| stored.record_digest.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        digests,
        vec![Some(matching.record_digest().unwrap()), None, None]
    );
    assert_eq!(
        app.group_push_tokens("alice", &group_id_hex).unwrap(),
        vec![matching, stale, placeholder]
    );
}

fn stored_token(record: &GroupPushTokenRecord) -> StoredGroupPushToken {
    StoredGroupPushToken {
        record: record.clone(),
        record_digest: Some(record.record_digest().unwrap()),
    }
}

fn stored_tombstone(
    group_id_hex: &str,
    removal: &PushTokenRemovalRecord,
) -> StoredPushTokenTombstone {
    StoredPushTokenTombstone {
        record_digest: removal.record_digest(group_id_hex).unwrap(),
        removal: Some(removal.clone()),
    }
}

/// Published size bound of the group message carrying one list `content`.
fn list_published_len(
    intent: crate::messages::AppMessageIntent,
    sender_hex: &str,
    group_id_len: usize,
) -> usize {
    let event = crate::messages::build_inner_event(&intent, sender_hex, u64::MAX).unwrap();
    let inner = crate::messages::encode_inner_event(&event).unwrap();
    lists::published_len_bound(group_id_len, inner.len())
}

/// A snapshot relays every stored record and tombstone exactly as its owner
/// signed it, so a recipient verifies the relay as it would the owner's own
/// update. A record whose stored digest its fields do not produce, and a
/// tombstone without its removal proof, are left out.
#[test]
fn push_gossip_lists_relay_stored_entries_unchanged() {
    let owner = Keys::generate();
    let owner_id = owner.public_key().to_hex();
    let relayer = Keys::generate().public_key().to_hex();
    let group_id_hex = hex::encode([0xEF; 16]);
    let server = "cd".repeat(32);
    let now = unix_now_ms();
    let records = [1, 2].map(|leaf| signed_token_record(&owner, &group_id_hex, leaf, &server, now));
    let removal = signed_removal_record(&owner, &group_id_hex, 3, &server, now);
    let mut unverified = stored_token(&signed_token_record(&owner, &group_id_hex, 4, &server, now));
    unverified.record_digest = None;
    let mut unsigned = stored_tombstone(
        &group_id_hex,
        &signed_removal_record(&owner, &group_id_hex, 5, &server, now),
    );
    unsigned.removal = None;

    let lists = push_gossip_lists(
        &[
            stored_token(&records[0]),
            unverified,
            stored_token(&records[1]),
        ],
        &[unsigned, stored_tombstone(&group_id_hex, &removal)],
        &relayer,
        16,
    )
    .unwrap();
    assert_eq!(
        (
            lists.unverified_records,
            lists.unsigned_tombstones,
            lists.oversized_entries
        ),
        (1, 1, 0)
    );
    assert_eq!((lists.token_lists.len(), lists.removal_lists.len()), (1, 1));

    let verified = |kind, content: &str| {
        verify_push_gossip_for_profile(
            parse_push_gossip(kind, &group_id_hex, content).unwrap(),
            &group_id_hex,
            std::slice::from_ref(&owner_id),
            ProtocolProfile::Current,
        )
    };
    let PushGossipAction::Upsert(upserts) =
        verified(MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST, &lists.token_lists[0])
    else {
        panic!("a token list upserts");
    };
    let signed = |record: &GroupPushTokenRecord| {
        (
            record.leaf_index,
            record.relay_hint.clone(),
            record.encrypted_token.clone(),
            record.owner_ts,
            record.owner_sig.clone(),
        )
    };
    assert_eq!(
        upserts.iter().map(signed).collect::<Vec<_>>(),
        records.iter().map(signed).collect::<Vec<_>>()
    );
    assert_eq!(
        verified(
            MARMOT_APP_EVENT_KIND_PUSH_TOKEN_REMOVAL,
            &lists.removal_lists[0]
        ),
        PushGossipAction::Remove(vec![removal])
    );
    assert_eq!(
        push_gossip_lists(&[], &[], &relayer, 16).unwrap(),
        lists::PushGossipLists::default(),
        "a device that holds nothing sends nothing"
    );
}

/// The widest record entry this crate stores: an escape-heavy relay hint of
/// `hint_len` characters, the widest leaf index and stamp.
fn widest_token(group_id_hex: &str, server_index: usize, hint_len: usize) -> StoredGroupPushToken {
    let hint = "\"\\\u{1}x"
        .chars()
        .cycle()
        .take(hint_len)
        .collect::<String>();
    StoredGroupPushToken {
        record: GroupPushTokenRecord {
            group_id_hex: group_id_hex.to_owned(),
            member_id_hex: "ab".repeat(32),
            leaf_index: u32::MAX,
            platform: PushPlatform::Apns,
            token_fingerprint: push_token_fingerprint(PushPlatform::Apns, &[1]),
            server_pubkey_hex: format!("{server_index:064x}"),
            relay_hint: Some(hint),
            encrypted_token: vec![0xFF; PUSH_ENCRYPTED_TOKEN_LEN],
            owner_ts: i64::MIN,
            owner_sig: "ef".repeat(64),
            updated_at_ms: 0,
        },
        record_digest: Some("00".repeat(32)),
    }
}

/// Each list fits the 64 KiB group message with at most 32 entries, packs as
/// many entries as fit, and keeps storage order. One entry too large for a
/// message on its own is left out; the largest one that fits is sent. Removals
/// hit the 32-entry cap before the byte budget.
#[test]
fn push_gossip_lists_split_worst_case_entries_by_size_and_count() {
    let sender = "ab".repeat(32);
    for group_id_len in [16, 32, 255] {
        let group_id_hex = hex::encode(vec![0xEF; group_id_len]);
        let tokens = (0..100)
            .map(|index| widest_token(&group_id_hex, index, (index * 211) % 4_000))
            .collect::<Vec<_>>();
        let lists = push_gossip_lists(&tokens, &[], &sender, group_id_len).unwrap();
        assert_eq!(lists.oversized_entries, 0);
        let parsed = lists
            .token_lists
            .iter()
            .map(|content| {
                serde_json::from_str::<PushTokenGossipPayload>(content)
                    .unwrap()
                    .tokens
            })
            .collect::<Vec<_>>();
        assert_eq!(
            parsed
                .iter()
                .flatten()
                .map(|entry| entry.server_pubkey_hex.clone())
                .collect::<Vec<_>>(),
            tokens
                .iter()
                .map(|stored| stored.record.server_pubkey_hex.clone())
                .collect::<Vec<_>>(),
            "every entry is sent once, in storage order"
        );
        for (index, content) in lists.token_lists.iter().enumerate() {
            let len = list_published_len(
                crate::messages::AppMessageIntent::PushTokenList {
                    content: content.clone(),
                },
                &sender,
                group_id_len,
            );
            assert!(
                len <= lists::PUSH_GOSSIP_EVENT_MAX_BYTES,
                "list {index} is {len} bytes"
            );
            assert!((1..=32).contains(&parsed[index].len()));
            if let Some(next) = parsed.get(index + 1).and_then(|next| next.first()) {
                let mut grown = parsed[index].clone();
                grown.push(next.clone());
                let grown = serde_json::to_string(&PushTokenGossipPayload {
                    v: PUSH_VERSION.to_owned(),
                    tokens: grown,
                })
                .unwrap();
                assert!(
                    list_published_len(
                        crate::messages::AppMessageIntent::PushTokenList { content: grown },
                        &sender,
                        group_id_len
                    ) > lists::PUSH_GOSSIP_EVENT_MAX_BYTES,
                    "list {index} could not take the next entry"
                );
            }
        }

        // The largest hint whose lone entry fits, by direct measurement.
        let alone = |hint_len| {
            let entry =
                PushTokenGossipEntry::from_record(&widest_token(&group_id_hex, 0, hint_len).record);
            let content = serde_json::to_string(&PushTokenGossipPayload {
                v: PUSH_VERSION.to_owned(),
                tokens: vec![entry],
            })
            .unwrap();
            list_published_len(
                crate::messages::AppMessageIntent::PushTokenList { content },
                &sender,
                group_id_len,
            )
        };
        let (mut low, mut high) = (0_usize, 65_536);
        while low < high {
            let mid = (low + high).div_ceil(2);
            if alone(mid) <= lists::PUSH_GOSSIP_EVENT_MAX_BYTES {
                low = mid
            } else {
                high = mid - 1
            }
        }
        let largest = widest_token(&group_id_hex, 1, low);
        let too_large = widest_token(&group_id_hex, 2, low + 1);
        assert!(alone(low + 1) > lists::PUSH_GOSSIP_EVENT_MAX_BYTES);
        let lists =
            push_gossip_lists(&[too_large, largest.clone()], &[], &sender, group_id_len).unwrap();
        assert_eq!(lists.oversized_entries, 1);
        assert_eq!(lists.token_lists.len(), 1);
        assert_eq!(
            serde_json::from_str::<PushTokenGossipPayload>(&lists.token_lists[0])
                .unwrap()
                .tokens,
            vec![PushTokenGossipEntry::from_record(&largest.record)]
        );
    }

    let group_id_hex = hex::encode([0xEF; 16]);
    let removals = (0..70)
        .map(|index| {
            let removal = PushTokenRemovalRecord {
                member_id_hex: "ab".repeat(32),
                leaf_index: u32::MAX,
                platform: PushPlatform::Apns,
                token_fingerprint: push_token_fingerprint(PushPlatform::Apns, &[1]),
                server_pubkey_hex: format!("{index:064x}"),
                owner_ts: i64::MIN,
                owner_sig: "ef".repeat(64),
            };
            stored_tombstone(&group_id_hex, &removal)
        })
        .collect::<Vec<_>>();
    let lists = push_gossip_lists(&[], &removals, &sender, 16).unwrap();
    assert_eq!(
        lists
            .removal_lists
            .iter()
            .map(
                |content| serde_json::from_str::<PushTokenRemovalPayload>(content)
                    .unwrap()
                    .removals
                    .len()
            )
            .collect::<Vec<_>>(),
        vec![32, 32, 6]
    );
}

/// An announce carries the sender's own records and names, each once, its
/// own records, then the held records and tombstones they do not replace. A
/// record whose stored digest does not verify is left out; a tombstone without
/// its removal proof is still named.
#[test]
fn push_announce_names_what_the_sender_holds() {
    let owner = Keys::generate();
    let other = Keys::generate();
    let sender = owner.public_key().to_hex();
    let group_id_hex = hex::encode([0xEF; 16]);
    let server = "cd".repeat(32);
    let now = unix_now_ms();
    let own = signed_token_record(&owner, &group_id_hex, 1, &server, now);
    let replaced = signed_token_record(&owner, &group_id_hex, 1, &server, now - 1);
    let held = signed_token_record(&other, &group_id_hex, 2, &server, now);
    let mut unverified = stored_token(&signed_token_record(&other, &group_id_hex, 3, &server, now));
    unverified.record_digest = None;
    let removal = signed_removal_record(&other, &group_id_hex, 4, &server, now);
    let mut unsigned = stored_tombstone(
        &group_id_hex,
        &signed_removal_record(&other, &group_id_hex, 5, &server, now),
    );
    unsigned.removal = None;
    let replaced_removal = signed_removal_record(&owner, &group_id_hex, 1, &server, now - 2);
    let element = |digest: String| push_have_element(&digest).unwrap();

    let announce = push_announce(
        std::slice::from_ref(&own),
        &[
            stored_token(&held),
            stored_token(&replaced),
            unverified,
            stored_token(&held),
        ],
        &[
            stored_tombstone(&group_id_hex, &removal),
            stored_tombstone(&group_id_hex, &replaced_removal),
            unsigned.clone(),
        ],
        &sender,
        16,
    )
    .unwrap();
    let payload: PushTokenAnnouncePayload = serde_json::from_str(&announce.content).unwrap();
    assert_eq!(payload.v, PUSH_VERSION);
    assert_eq!(
        payload.tokens,
        vec![PushTokenGossipEntry::from_record(&own)]
    );
    assert_eq!(
        payload.have,
        vec![
            element(own.record_digest().unwrap()),
            element(held.record_digest().unwrap()),
            element(removal.record_digest(&group_id_hex).unwrap()),
            element(unsigned.record_digest.clone()),
        ]
    );
    assert!(payload.have.iter().all(|element| element.len() == 12));
    assert_eq!(
        (announce.listed, announce.unlisted, announce.unknown_digests),
        (4, 0, 1)
    );

    // A device with no record of its own announces `tokens: []`.
    let empty = push_announce(&[], &[], &[], &sender, 16).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&empty.content).unwrap(),
        serde_json::json!({"v": PUSH_VERSION, "tokens": [], "have": []})
    );
}

/// A sender that holds more than fits names the prefix that keeps the
/// carrying group message within 64 KiB, own records first.
#[test]
fn push_announce_names_a_prefix_that_fits_64_kib() {
    let owner = Keys::generate();
    let sender = owner.public_key().to_hex();
    for group_id_len in [16, 32, 255] {
        let group_id_hex = hex::encode(vec![0xEF; group_id_len]);
        let own = signed_token_record(&owner, &group_id_hex, 1, &"cd".repeat(32), 100);
        let tombstones = (0..5_000_u64)
            .map(|index| StoredPushTokenTombstone {
                record_digest: hex::encode(Sha256::digest(index.to_be_bytes())),
                removal: None,
            })
            .collect::<Vec<_>>();
        let announce = push_announce(
            std::slice::from_ref(&own),
            &[],
            &tombstones,
            &sender,
            group_id_len,
        )
        .unwrap();
        assert_eq!(announce.listed + announce.unlisted, 5_001);
        assert!(announce.unlisted > 0);
        let payload: PushTokenAnnouncePayload = serde_json::from_str(&announce.content).unwrap();
        assert_eq!(payload.have.len(), announce.listed);
        assert!(payload.have.len() <= PUSH_MAX_HAVE_ENTRIES);
        assert_eq!(
            payload.have[0],
            push_have_element(&own.record_digest().unwrap()).unwrap()
        );
        let published = |content: String| {
            list_published_len(
                crate::messages::AppMessageIntent::PushTokenUpdate { content },
                &sender,
                group_id_len,
            )
        };
        let len = published(announce.content.clone());
        assert!(len <= lists::PUSH_GOSSIP_EVENT_MAX_BYTES, "{len} bytes");
        let mut grown = payload;
        grown
            .have
            .push(push_have_element(&tombstones[4_999].record_digest).unwrap());
        assert!(
            published(serde_json::to_string(&grown).unwrap()) > lists::PUSH_GOSSIP_EVENT_MAX_BYTES,
            "the next element would not fit"
        );
    }
}

/// A kind 447 asks for repair as an announce, by the 8-byte digests its
/// `have` names, or as a request, an empty or missing `tokens` with no `have`, which
/// names nothing. A self-update without `have`, a `have` that is not an array
/// or holds more than 4,096 elements, and another version ask for nothing.
#[test]
fn repair_ask_reads_have_and_takes_a_request_as_an_empty_have() {
    let digest = "ab".repeat(32);
    let element = push_have_element(&digest).unwrap();
    let ask = |tokens: serde_json::Value, have: Option<serde_json::Value>| {
        let mut content = serde_json::json!({"v": PUSH_VERSION, "tokens": tokens});
        if let Some(have) = have {
            content["have"] = have;
        }
        parse_push_repair_ask(&content.to_string())
    };
    let entry = serde_json::json!([{"member_id_hex": "not checked here"}]);
    assert_eq!(ask(serde_json::json!([]), None), Some(PushHave::new()));
    assert_eq!(
        ask(serde_json::json!([]), Some(serde_json::json!([]))),
        Some(PushHave::new())
    );
    assert_eq!(
        ask(
            entry.clone(),
            Some(serde_json::json!([
                element,
                element,
                "not base64!",
                7,
                null,
                BASE64_STANDARD.encode([1_u8; 9]),
                BASE64_STANDARD.encode([1_u8; 7]),
            ]))
        ),
        Some(PushHave::from([push_have_prefix(&digest).unwrap()]))
    );
    let at_cap = vec![serde_json::json!(0); PUSH_MAX_HAVE_ENTRIES];
    assert_eq!(
        ask(
            serde_json::json!([]),
            Some(serde_json::Value::Array(at_cap))
        ),
        Some(PushHave::new())
    );

    assert_eq!(ask(entry, None), None, "a self-update");
    for have in [
        serde_json::json!("not an array"),
        serde_json::Value::Null,
        serde_json::json!({"0": element}),
        serde_json::json!(7),
        serde_json::Value::Array(vec![serde_json::json!(element); PUSH_MAX_HAVE_ENTRIES + 1]),
    ] {
        assert_eq!(ask(serde_json::json!([]), Some(have)), None);
    }
    assert_eq!(
        parse_push_repair_ask(
            &serde_json::json!({"v": "marmot-push-v2", "tokens": []}).to_string()
        ),
        None
    );
    assert_eq!(
        parse_push_repair_ask(r#"{"v": "marmot-push-v1"}"#),
        Some(PushHave::new()),
        "a missing `tokens` reads as an empty one"
    );
    assert_eq!(
        parse_push_repair_ask(r#"{"v": "marmot-push-v1", "tokens": {}}"#),
        None
    );
    assert_eq!(parse_push_repair_ask("not json"), None);
}

/// Inbound kind 447 decoding ignores `have`, whatever it holds, and applies
/// the announce's `tokens` as a self-update.
#[test]
fn inbound_announce_applies_its_tokens_and_ignores_have() {
    let owner = Keys::generate();
    let group_id_hex = hex::encode([0xEF; 16]);
    let record = signed_token_record(&owner, &group_id_hex, 1, &"cd".repeat(32), unix_now_ms());
    let entry = serde_json::to_value(PushTokenGossipEntry::from_record(&record)).unwrap();
    let element = push_have_element(&record.record_digest().unwrap()).unwrap();
    for have in [
        serde_json::json!([element]),
        serde_json::json!(["not base64", 7, null]),
        serde_json::json!("not an array"),
        serde_json::Value::Array(vec![serde_json::json!(element); PUSH_MAX_HAVE_ENTRIES + 1]),
    ] {
        let content =
            serde_json::json!({"v": PUSH_VERSION, "tokens": [entry], "have": have}).to_string();
        let PushGossipAction::Upsert(records) = verify_push_gossip_for_profile(
            parse_push_gossip(
                MARMOT_APP_EVENT_KIND_PUSH_TOKEN_UPDATE,
                &group_id_hex,
                &content,
            )
            .unwrap(),
            &group_id_hex,
            &[owner.public_key().to_hex()],
            ProtocolProfile::Current,
        ) else {
            panic!("an announce upserts its tokens");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].owner_sig, record.owner_sig);
    }
    let request = serde_json::json!({"v": PUSH_VERSION, "tokens": [], "have": []}).to_string();
    assert_eq!(
        parse_push_gossip(
            MARMOT_APP_EVENT_KIND_PUSH_TOKEN_UPDATE,
            &group_id_hex,
            &request
        )
        .unwrap(),
        PushGossipAction::Upsert(Vec::new())
    );
}

#[test]
fn mixed_entry_permutations_apply_the_same_valid_winner() {
    let owner = Keys::generate();
    let owner_id = owner.public_key().to_hex();
    let group_id = cgka_traits::GroupId::new(vec![0xEF; 16]);
    let group_id_hex = hex::encode(group_id.as_slice());
    let server = "cd".repeat(32);
    let older = signed_token_record(&owner, &group_id_hex, 1, &server, 100);
    let newer = signed_token_record(&owner, &group_id_hex, 1, &server, 200);
    let older_entry = serde_json::to_value(PushTokenGossipEntry::from_record(&older)).unwrap();
    let newer_entry = serde_json::to_value(PushTokenGossipEntry::from_record(&newer)).unwrap();
    let malformed = serde_json::json!({"platform": "bogus"});
    let payloads = [
        serde_json::json!({
            "v": PUSH_VERSION,
            "tokens": [
                older_entry.clone(),
                malformed.clone(),
                newer_entry.clone(),
                older_entry.clone(),
            ],
        })
        .to_string(),
        serde_json::json!({
            "v": PUSH_VERSION,
            "tokens": [newer_entry, older_entry.clone(), malformed, older_entry],
        })
        .to_string(),
    ];

    let mut winner_digests = Vec::new();
    for payload in payloads {
        let dir = tempfile::tempdir().unwrap();
        marmot_account::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let message = ReceivedMessage {
            authority: None,
            message_id_hex: "11".repeat(32),
            source_message_id_hex: "22".repeat(32),
            sender: owner_id.clone(),
            sender_display_name: None,
            group_id: group_id.clone(),
            source_epoch: 1,
            retention: None,
            plaintext: payload,
            kind: MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST,
            tags: vec![vec!["v".to_owned(), PUSH_VERSION.to_owned()]],
            recorded_at: 1,
            received_at: 1,
        };

        reset_owner_signature_verification_count();
        app.ingest_push_gossip_message(
            "alice",
            &message,
            &[cgka_traits::engine::GroupMemberLeaf {
                member: cgka_traits::MemberId::new(owner.public_key().to_bytes().to_vec()),
                leaf_index: 1,
            }],
            ProtocolProfile::Current,
        )
        .unwrap();
        assert_eq!(
            owner_signature_verification_count(),
            2,
            "two distinct valid records verify once each; malformed and duplicate entries do not"
        );
        let stored = app.group_push_tokens("alice", &group_id_hex).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].owner_ts, 200);
        winner_digests.push(stored[0].record_digest().unwrap());
    }

    assert_eq!(winner_digests[0], winner_digests[1]);
}

#[test]
fn token_fingerprint_is_redacted_and_stable() {
    let token = b"provider-token-secret";
    let fingerprint = push_token_fingerprint(PushPlatform::Fcm, token);
    assert!(fingerprint.starts_with("sha256:"));
    assert_eq!(fingerprint.len(), "sha256:".len() + 24);
    assert!(!fingerprint.contains("provider"));
    assert_eq!(
        fingerprint,
        push_token_fingerprint(PushPlatform::Fcm, token)
    );
}

#[test]
fn token_fingerprint_validation_rejects_uppercase_hex() {
    assert!(validate_fingerprint("sha256:0123456789abcdef01234567").is_ok());
    assert!(validate_fingerprint("sha256:0123456789ABCDEF01234567").is_err());
}

fn timeline_target(kind: u64, plaintext: &str) -> TimelineMessageTarget {
    TimelineMessageTarget {
        sender: "bb".repeat(32),
        plaintext: plaintext.to_owned(),
        kind,
        deleted: false,
        invalidated: false,
    }
}

fn received_reaction(emoji: &str, target_message_id: &str) -> ReceivedMessage {
    ReceivedMessage {
        authority: None,
        message_id_hex: "ff".repeat(32),
        source_message_id_hex: "ff".repeat(32),
        sender: "bb".repeat(32),
        sender_display_name: None,
        group_id: cgka_traits::GroupId::new(vec![0xEE; 32]),
        source_epoch: 1,
        retention: None,
        plaintext: emoji.to_owned(),
        kind: MARMOT_APP_EVENT_KIND_REACTION,
        tags: vec![vec![EVENT_REF_TAG.to_owned(), target_message_id.to_owned()]],
        recorded_at: 0,
        received_at: 0,
    }
}

fn received_chat(plaintext: &str, tags: Vec<Vec<String>>) -> ReceivedMessage {
    ReceivedMessage {
        authority: None,
        message_id_hex: "ee".repeat(32),
        source_message_id_hex: "ee".repeat(32),
        sender: "bb".repeat(32),
        sender_display_name: None,
        group_id: cgka_traits::GroupId::new(vec![0xEE; 32]),
        source_epoch: 1,
        retention: None,
        plaintext: plaintext.to_owned(),
        kind: cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT,
        tags,
        recorded_at: 0,
        received_at: 0,
    }
}

#[test]
fn mention_classification_uses_receiver_p_tag() {
    let receiver = "aa".repeat(32);
    let message = received_chat(
        "hi",
        vec![vec![
            "p".to_owned(),
            receiver.clone(),
            "wss://relay.example".to_owned(),
        ]],
    );

    assert!(message_mentions_account(&message, &receiver));
}

#[test]
fn mention_classification_normalizes_npub_p_tags() {
    let receiver = nostr::prelude::Keys::generate().public_key().to_hex();
    let npub = crate::npub_for_account_id(&receiver).unwrap();
    let message = received_chat("hi", vec![vec!["p".to_owned(), npub]]);

    assert!(message_mentions_account(&message, &receiver));
}

#[test]
fn mention_classification_uses_inline_nip27_entities() {
    let receiver = nostr::prelude::Keys::generate().public_key().to_hex();
    let npub = crate::npub_for_account_id(&receiver).unwrap();
    let nprofile = crate::nprofile_for_account_id(&receiver, &[]).unwrap();

    // NIP-27 `nostr:` URIs carry bech32 entities (npub/nprofile), which the
    // markdown tokenizer renders as mentions.
    for token in [npub.as_str(), nprofile.as_str()] {
        let message = received_chat(&format!("hi nostr:{token}"), Vec::new());
        assert!(
            message_mentions_account(&message, &receiver),
            "mention token form failed: {token}"
        );
    }

    // `nostr:<raw-hex>` is not a NIP-21 URI, so the tokenizer leaves it as
    // literal text and it is not classified as a mention (mdk#617).
    let raw_hex = received_chat(&format!("hi nostr:{receiver}"), Vec::new());
    assert!(!message_mentions_account(&raw_hex, &receiver));
}

#[test]
fn mention_classification_ignores_plain_preview_text() {
    let receiver = "aa".repeat(32);
    let message = received_chat(&format!("hi {receiver}"), Vec::new());

    assert!(!message_mentions_account(&message, &receiver));
}

#[test]
fn mention_classification_ignores_non_chat_p_tags() {
    let receiver = "aa".repeat(32);
    let mut message = received_chat("👍", vec![vec!["p".to_owned(), receiver.clone()]]);
    message.kind = cgka_traits::app_event::MARMOT_APP_EVENT_KIND_REACTION;

    assert!(!message_mentions_account(&message, &receiver));
}

#[test]
fn message_text_mentions_account_matches_message_mentions_account() {
    let receiver = nostr::prelude::Keys::generate().public_key().to_hex();
    let npub = crate::npub_for_account_id(&receiver).unwrap();
    let other = nostr::prelude::Keys::generate().public_key().to_hex();

    let cases = [
        // p-tag hex mention.
        received_chat("hi", vec![vec!["p".to_owned(), receiver.clone()]]),
        // npub p-tag mention (normalized to hex).
        received_chat("hi", vec![vec!["p".to_owned(), npub.clone()]]),
        // inline NIP-27 mention.
        received_chat(&format!("hi nostr:{npub}"), Vec::new()),
        // negative: mentions a different account.
        received_chat("hi", vec![vec!["p".to_owned(), other.clone()]]),
        // negative: plain text containing the hex is not a mention.
        received_chat(&format!("hi {receiver}"), Vec::new()),
    ];

    for message in cases {
        assert_eq!(
            message_text_mentions_account(
                message.kind,
                &message.plaintext,
                &message.tags,
                &receiver,
            ),
            message_mentions_account(&message, &receiver),
            "parity mismatch for plaintext={:?} tags={:?}",
            message.plaintext,
            message.tags,
        );
    }

    // The p-tag case is a genuine positive (guards against the parity check
    // passing only because both always return false).
    assert!(message_text_mentions_account(
        MARMOT_APP_EVENT_KIND_CHAT,
        "hi",
        &[vec!["p".to_owned(), receiver.clone()]],
        &receiver,
    ));
    assert!(!message_text_mentions_account(
        MARMOT_APP_EVENT_KIND_CHAT,
        "hi",
        &[vec!["p".to_owned(), other]],
        &receiver,
    ));
}

#[test]
fn mention_classification_covers_bare_npub_mention() {
    // The form clients actually emit is the bare `@npub1…` handle (no
    // `nostr:` scheme and no `p`-tag). It must still classify as a mention so
    // `is_mention` / unread-mention surfaces fire. Regression for
    // mdk#617.
    let receiver = nostr::prelude::Keys::generate().public_key().to_hex();
    let npub = crate::npub_for_account_id(&receiver).unwrap();

    let message = received_chat(&format!("hey @{npub} ping"), Vec::new());
    assert!(message_mentions_account(&message, &receiver));

    // A bare `@npub1…` for a different account is not a mention of `receiver`.
    let other = nostr::prelude::Keys::generate().public_key().to_hex();
    let other_npub = crate::npub_for_account_id(&other).unwrap();
    let other_message = received_chat(&format!("hey @{other_npub} ping"), Vec::new());
    assert!(!message_mentions_account(&other_message, &receiver));
}

#[test]
fn mention_classification_uses_p_tag_for_mentions_beyond_inline_scan_cap() {
    let receiver = nostr::prelude::Keys::generate().public_key().to_hex();
    let npub = crate::npub_for_account_id(&receiver).unwrap();
    let cap = cgka_traits::agent_text_stream::AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize;
    let plaintext = format!("{} @{npub}", "a".repeat(cap + 1));

    // The inline fallback intentionally scans only the bounded prefix. A
    // mention beyond that prefix is classified only when the sender supplied
    // the NIP-27 p-tag; this keeps receive-side notification parsing bounded.
    assert!(!message_text_mentions_account(
        MARMOT_APP_EVENT_KIND_CHAT,
        &plaintext,
        &[],
        &receiver,
    ));
    assert!(message_text_mentions_account(
        MARMOT_APP_EVENT_KIND_CHAT,
        &plaintext,
        &[vec![PUBKEY_REF_TAG.to_owned(), receiver.clone()]],
        &receiver,
    ));
}

#[test]
fn mention_notification_suppresses_self_mentions() {
    let receiver = "aa".repeat(32);
    let message = received_chat("hi", vec![vec!["p".to_owned(), receiver.clone()]]);

    assert!(notification_is_mention(&message, &receiver, false));
    assert!(!notification_is_mention(&message, &receiver, true));
}

/// A muted live event emits only the receiver's typed chat mention; unmute restores ordinary traffic.
#[test]
fn muted_chat_live_event_resolver_emits_only_direct_mentions() {
    let dir = tempfile::tempdir().unwrap();
    let home = marmot_account::AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let receiver = account.account_id_hex;
    let other = nostr::prelude::Keys::generate().public_key().to_hex();
    let sender = "bb".repeat(32);
    let group = "ee".repeat(32);
    let mut resolver = NotificationResolver::default();
    seed_group_state_resolver(
        &mut resolver,
        "alice",
        &receiver,
        &group,
        Some(&sender),
        true,
        true,
    );

    let mut cases = vec![
        ("ordinary", received_chat("hi", vec![]), false),
        (
            "own mention",
            received_chat("hi", vec![vec!["p".to_owned(), receiver.clone()]]),
            true,
        ),
        (
            "other account mention",
            received_chat("hi", vec![vec!["p".to_owned(), other]]),
            false,
        ),
    ];
    let mut self_mention = received_chat("hi", vec![vec!["p".to_owned(), receiver.clone()]]);
    self_mention.sender = receiver.clone();
    cases.push(("self mention", self_mention, false));

    for (name, message, expected) in cases {
        let event = MarmotAppEvent::MessageReceived(RuntimeMessageReceived {
            account_id_hex: receiver.clone(),
            account_label: "alice".to_owned(),
            message,
        });
        let update = notification_update_from_event_cached(&app, &mut resolver, &event).unwrap();
        assert_eq!(update.is_some(), expected, "{name}");
        if let Some(update) = update {
            assert!(update.is_mention, "{name}");
        }
    }

    resolver
        .chat_muted
        .insert(("alice".to_owned(), group), false);
    let event = MarmotAppEvent::MessageReceived(RuntimeMessageReceived {
        account_id_hex: receiver,
        account_label: "alice".to_owned(),
        message: received_chat("ordinary after unmute", vec![]),
    });
    assert!(
        notification_update_from_event_cached(&app, &mut resolver, &event)
            .unwrap()
            .is_some()
    );
}

#[test]
fn group_invite_notification_is_not_a_mention() {
    let dir = tempfile::tempdir().unwrap();
    let home = marmot_account::AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let group_id = cgka_traits::GroupId::new(vec![0xEE; 32]);

    let update = notification_update_from_group_join(
        &app,
        &mut NotificationResolver::default(),
        "alice",
        &account.account_id_hex,
        &group_id,
    )
    .unwrap()
    .expect("unblocked invitation produces a notification");

    assert!(matches!(update.trigger, NotificationTrigger::GroupInvite));
    assert_eq!(update.traffic_class, NotificationTrafficClass::Standard);
    assert!(!update.is_mention);
}

// #639: the per-batch NotificationResolver caches the raw directory-derived user
// (display_name from the directory, or None). The per-message sender-display-name
// fallback must apply to the RETURNED clone only, never mutate the cache — so two
// messages from the same sender (whose directory entry has no name) each get
// their OWN fallback rather than the first message's leaking to the second.
#[test]
fn resolver_sender_display_name_fallback_is_per_message_not_cached() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let sender = "cc".repeat(32);

    let mut resolver = NotificationResolver::default();
    // Pre-seed the cache as an absent directory entry would (no display name), so
    // the resolver serves this cached user and never queries `app`.
    resolver.users.insert(
        sender.clone(),
        NotificationUser {
            account_id_hex: sender.clone(),
            display_name: None,
            picture_url: None,
        },
    );

    let mut first = received_chat("hi", vec![]);
    first.sender = sender.clone();
    first.sender_display_name = Some("Name From First".to_owned());
    let user_first = notification_user_from_message(&app, &mut resolver, &first).unwrap();
    assert_eq!(user_first.display_name.as_deref(), Some("Name From First"));

    let mut second = received_chat("yo", vec![]);
    second.sender = sender.clone();
    second.sender_display_name = Some("Name From Second".to_owned());
    let user_second = notification_user_from_message(&app, &mut resolver, &second).unwrap();
    // Gets its OWN fallback, not the first message's.
    assert_eq!(
        user_second.display_name.as_deref(),
        Some("Name From Second")
    );
    // The cached user is untouched (still no display name).
    assert_eq!(resolver.users[&sender].display_name, None);
}

#[test]
fn reaction_message_carries_emoji_and_resolved_target_preview() {
    let target = timeline_target(
        cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT,
        "the original message",
    );
    let reaction = received_reaction("  👍  ", &"aa".repeat(32));

    let (emoji, preview) = reaction_notification_fields(&reaction, Some(&target));

    // Emoji is trimmed; preview comes from the resolved live target row.
    assert_eq!(emoji.as_deref(), Some("👍"));
    assert_eq!(preview.as_deref(), Some("the original message"));
}

#[test]
fn reaction_to_deleted_target_yields_emoji_but_no_preview() {
    // The author reacted to a message that was later deleted. The timeline row
    // is kept (deleted = true, plaintext cleared) so authorship still verifies
    // and the author is notified, but the preview is suppressed — the original
    // text must never reach a lock-screen notification.
    let mut target = timeline_target(
        cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT,
        "the original message",
    );
    target.deleted = true;
    let reaction = received_reaction("👍", &"aa".repeat(32));

    let (emoji, preview) = reaction_notification_fields(&reaction, Some(&target));

    assert_eq!(emoji.as_deref(), Some("👍"));
    assert_eq!(preview, None);
}

#[test]
fn reaction_to_invalidated_target_yields_emoji_but_no_preview() {
    // The reacted-to message was convergence-invalidated (losing branch) but
    // kept as a tombstone. Notify with the emoji, never leak its preview.
    let mut target = timeline_target(
        cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT,
        "the original message",
    );
    target.invalidated = true;
    let reaction = received_reaction("❤️", &"aa".repeat(32));

    let (emoji, preview) = reaction_notification_fields(&reaction, Some(&target));

    assert_eq!(emoji.as_deref(), Some("❤️"));
    assert_eq!(preview, None);
}

#[test]
fn reaction_with_unresolvable_target_yields_emoji_but_no_preview() {
    // A truly-absent target (e.g. retention-pruned) is dropped at the caller
    // (`notification_update_from_message` returns `Ok(None)` because authorship
    // can't be verified). This pure helper, given `None`, still yields the
    // emoji with no preview.
    let reaction = received_reaction("❤️", &"aa".repeat(32));
    let (emoji, preview) = reaction_notification_fields(&reaction, None);
    assert_eq!(emoji.as_deref(), Some("❤️"));
    assert_eq!(preview, None);
}

#[test]
fn reaction_with_blank_content_yields_no_emoji() {
    let target = timeline_target(
        cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT,
        "original",
    );
    let reaction = received_reaction("   ", &"aa".repeat(32));
    let (emoji, preview) = reaction_notification_fields(&reaction, Some(&target));
    assert_eq!(emoji, None);
    // Preview still resolves even when the emoji is blank.
    assert_eq!(preview.as_deref(), Some("original"));
}

#[test]
fn normal_message_yields_no_reaction_fields() {
    let mut message = received_reaction("ignored", &"aa".repeat(32));
    message.kind = cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT;
    let target = timeline_target(
        cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT,
        "original",
    );
    let (emoji, preview) = reaction_notification_fields(&message, Some(&target));
    assert_eq!(emoji, None);
    assert_eq!(preview, None);
}

#[test]
fn agent_activity_and_operation_kinds_are_notifiable() {
    use cgka_traits::app_event::{
        MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY, MARMOT_APP_EVENT_KIND_AGENT_OPERATION,
    };

    assert!(notification_traffic_for_kind(MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY).is_some());
    assert!(notification_traffic_for_kind(MARMOT_APP_EVENT_KIND_AGENT_OPERATION).is_some());
}

#[test]
fn state_change_kinds_remain_non_notifiable() {
    use cgka_traits::app_event::{
        MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, MARMOT_APP_EVENT_KIND_DELETE,
        MARMOT_APP_EVENT_KIND_EDIT, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
    };

    assert!(notification_traffic_for_kind(MARMOT_APP_EVENT_KIND_DELETE).is_none());
    assert!(notification_traffic_for_kind(MARMOT_APP_EVENT_KIND_EDIT).is_none());
    assert!(notification_traffic_for_kind(MARMOT_APP_EVENT_KIND_GROUP_SYSTEM).is_none());
    assert!(notification_traffic_for_kind(MARMOT_APP_EVENT_KIND_AGENT_STREAM_START).is_none());
}

#[test]
fn notification_traffic_class_is_deterministic_from_the_wire_kind() {
    use cgka_traits::app_event::{
        MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY, MARMOT_APP_EVENT_KIND_AGENT_OPERATION,
        MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, MARMOT_APP_EVENT_KIND_CHAT,
        MARMOT_APP_EVENT_KIND_REACTION,
    };

    assert_eq!(
        notification_traffic_for_kind(MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY),
        Some(NotificationTrafficClass::AgentActivity),
    );
    assert_eq!(
        notification_traffic_for_kind(MARMOT_APP_EVENT_KIND_AGENT_OPERATION),
        Some(NotificationTrafficClass::AgentActivity),
    );
    assert_eq!(
        notification_traffic_for_kind(MARMOT_APP_EVENT_KIND_CHAT),
        Some(NotificationTrafficClass::Standard),
    );
    assert_eq!(
        notification_traffic_for_kind(MARMOT_APP_EVENT_KIND_REACTION),
        Some(NotificationTrafficClass::Standard),
    );
    assert_eq!(
        notification_traffic_for_kind(MARMOT_APP_EVENT_KIND_AGENT_STREAM_START),
        None,
    );
    assert_eq!(notification_traffic_for_kind(u64::MAX), None);
}

#[test]
fn poll_notification_alerts_without_exposing_question_or_options() {
    assert_eq!(
        notification_traffic_for_kind(MARMOT_APP_EVENT_KIND_POLL),
        Some(NotificationTrafficClass::Standard)
    );
    assert_eq!(
        preview_text_for_kind(MARMOT_APP_EVENT_KIND_POLL, "Where should we meet?"),
        None
    );
}

/// A device-group kind neither alerts nor previews, even as a reaction's
/// target, so its content never reaches a notification.
#[test]
fn device_group_kinds_never_notify_or_preview() {
    for kind in [457, 459, 460, 461, 475, 476] {
        assert_eq!(notification_traffic_for_kind(kind), None);
        assert_eq!(preview_text_for_kind(kind, "{\"v\":1}"), None);
    }
}

#[test]
fn agent_activity_notification_is_non_mention_and_respects_group_mute() {
    use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY;

    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.account_home().create_account("alice").unwrap();
    let account_label = "alice";
    let account_id_hex = "aa".repeat(32);
    let sender_id_hex = "bb".repeat(32);
    let group_id_hex = "ee".repeat(32);
    let message = RuntimeMessageReceived {
        account_id_hex: account_id_hex.clone(),
        account_label: account_label.to_owned(),
        message: ReceivedMessage {
            authority: None,
            message_id_hex: "ff".repeat(32),
            source_message_id_hex: "ff".repeat(32),
            sender: sender_id_hex.clone(),
            sender_display_name: Some("Agent".to_owned()),
            group_id: cgka_traits::GroupId::new(vec![0xEE; 32]),
            source_epoch: 1,
            retention: None,
            plaintext: r#"{"status":"running","text":"Searching relays"}"#.to_owned(),
            kind: MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY,
            // Even a receiver p-tag must not make a non-chat kind a mention.
            tags: vec![vec![PUBKEY_REF_TAG.to_owned(), account_id_hex.clone()]],
            recorded_at: 0,
            received_at: 0,
        },
    };
    let mut resolver = NotificationResolver::default();
    resolver.settings.insert(
        account_label.to_owned(),
        NotificationSettings {
            account_ref: account_label.to_owned(),
            account_id_hex: account_id_hex.clone(),
            local_notifications_enabled: true,
            native_push_enabled: true,
        },
    );
    let conversation = (account_label.to_owned(), group_id_hex.clone());
    resolver.groups.insert(conversation.clone(), None);
    resolver.chat_muted.insert(conversation.clone(), false);
    for account_id in [&account_id_hex, &sender_id_hex] {
        resolver.users.insert(
            account_id.clone(),
            NotificationUser {
                account_id_hex: account_id.clone(),
                display_name: None,
                picture_url: None,
            },
        );
    }

    let update = notification_update_from_message(&app, &mut resolver, &message)
        .unwrap()
        .expect("unmuted agent activity should produce a notification");
    assert_eq!(
        update.traffic_class,
        NotificationTrafficClass::AgentActivity
    );
    assert_eq!(update.preview_text.as_deref(), Some("Searching relays"));
    assert!(!update.is_mention);

    resolver.chat_muted.insert(conversation, true);
    assert_eq!(
        notification_update_from_message(&app, &mut resolver, &message).unwrap(),
        None,
        "agent activity must respect the conversation mute"
    );
}

#[test]
fn agent_activity_notification_preview_uses_the_structured_text() {
    use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY;

    assert_eq!(
        preview_text_for_kind(
            MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY,
            r#"{"status":"running","text":"Searching relays"}"#,
        )
        .as_deref(),
        Some("Searching relays"),
    );
}

#[test]
fn agent_operation_notification_preview_prefers_the_structured_preview() {
    use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_AGENT_OPERATION;

    assert_eq!(
        preview_text_for_kind(
            MARMOT_APP_EVENT_KIND_AGENT_OPERATION,
            r#"{"status":"running","text":"Executing browser tool","preview":"Opening example.com"}"#,
        )
        .as_deref(),
        Some("Opening example.com"),
    );
}

#[test]
fn agent_operation_notification_preview_falls_back_to_text() {
    use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_AGENT_OPERATION;

    assert_eq!(
        preview_text_for_kind(
            MARMOT_APP_EVENT_KIND_AGENT_OPERATION,
            r#"{"status":"running","text":"Executing browser tool"}"#,
        )
        .as_deref(),
        Some("Executing browser tool"),
    );
}

#[test]
fn push_platform_from_str_is_lowercase_only() {
    assert!(matches!(
        PushPlatform::from_str("apns"),
        Ok(PushPlatform::Apns)
    ));
    assert!(matches!(
        PushPlatform::from_str("fcm"),
        Ok(PushPlatform::Fcm)
    ));
    // Case variants MUST be rejected (lowercase-only per spec + no case-fold).
    for bad in ["Apns", "APNS", "Fcm", "FCM", "aPns", " apns", "apns "] {
        assert!(
            PushPlatform::from_str(bad).is_err(),
            "case/whitespace variant {bad:?} must be rejected"
        );
    }
}

// ---- Owner-authenticated token gossip (spec: "Owner authentication") ----

fn signed_token_record(
    keys: &Keys,
    group_id_hex: &str,
    leaf_index: u32,
    server_pubkey_hex: &str,
    owner_ts: i64,
) -> GroupPushTokenRecord {
    let mut record = GroupPushTokenRecord {
        group_id_hex: group_id_hex.to_owned(),
        member_id_hex: keys.public_key().to_hex(),
        leaf_index,
        platform: PushPlatform::Apns,
        // Vary the fingerprint by stamp so distinct records get distinct digests.
        token_fingerprint: push_token_fingerprint(PushPlatform::Apns, &owner_ts.to_be_bytes()),
        server_pubkey_hex: server_pubkey_hex.to_owned(),
        relay_hint: Some("wss://relay.example".to_owned()),
        encrypted_token: vec![0_u8; PUSH_ENCRYPTED_TOKEN_LEN],
        owner_ts,
        owner_sig: String::new(),
        updated_at_ms: owner_ts,
    };
    record.sign_owner(keys).unwrap();
    record
}

fn signed_removal_record(
    keys: &Keys,
    group_id_hex: &str,
    leaf_index: u32,
    server_pubkey_hex: &str,
    owner_ts: i64,
) -> PushTokenRemovalRecord {
    let mut record = PushTokenRemovalRecord {
        member_id_hex: keys.public_key().to_hex(),
        leaf_index,
        platform: PushPlatform::Apns,
        token_fingerprint: push_token_fingerprint(PushPlatform::Apns, &[1, 2, 3]),
        server_pubkey_hex: server_pubkey_hex.to_owned(),
        owner_ts,
        owner_sig: String::new(),
    };
    record.sign_owner(group_id_hex, keys).unwrap();
    record
}

fn sign_token_record_with_event_kind(record: &mut GroupPushTokenRecord, keys: &Keys, kind: u16) {
    let proof_event = record.owner_proof_event_with_kind(kind).unwrap();
    let signed = nostr::prelude::SignEvent::sign_event(keys, proof_event.clone()).unwrap();
    record.owner_sig = push_owner_sig_from_signed_event(&proof_event, signed).unwrap();
}

fn sign_removal_record_with_event_kind(
    record: &mut PushTokenRemovalRecord,
    group_id_hex: &str,
    keys: &Keys,
    kind: u16,
) {
    let proof_event = record
        .owner_proof_event_with_kind(group_id_hex, kind)
        .unwrap();
    let signed = nostr::prelude::SignEvent::sign_event(keys, proof_event.clone()).unwrap();
    record.owner_sig = push_owner_sig_from_signed_event(&proof_event, signed).unwrap();
}

fn sign_token_record_raw_legacy(record: &mut GroupPushTokenRecord, keys: &Keys) {
    let message = record.signing_digest().unwrap();
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), keys.secret_key());
    record.owner_sig = hex::encode(
        Secp256k1::new()
            .sign_schnorr_no_aux_rand(&message, &keypair)
            .to_byte_array(),
    );
}

fn sign_removal_record_raw_legacy(
    record: &mut PushTokenRemovalRecord,
    group_id_hex: &str,
    keys: &Keys,
) {
    let message = record.signing_digest(group_id_hex).unwrap();
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), keys.secret_key());
    record.owner_sig = hex::encode(
        Secp256k1::new()
            .sign_schnorr_no_aux_rand(&message, &keypair)
            .to_byte_array(),
    );
}

#[test]
fn current_and_legacy_profiles_enforce_the_owner_proof_matrix() {
    let keys = Keys::generate();
    let group = "ee".repeat(16);
    let server = "dd".repeat(32);
    let member = keys.public_key().to_hex();

    let current = signed_token_record(&keys, &group, 1, &server, 100);
    for profile in [ProtocolProfile::Current, ProtocolProfile::Legacy] {
        let verified = verify_push_gossip_for_profile(
            PushGossipAction::Upsert(vec![current.clone()]),
            &group,
            std::slice::from_ref(&member),
            profile,
        );
        assert!(
            matches!(verified, PushGossipAction::Upsert(records) if records.len() == 1),
            "kind-451 proof must be accepted for {profile:?}"
        );
    }

    let mut transitional = current.clone();
    sign_token_record_with_event_kind(&mut transitional, &keys, LEGACY_PUSH_OWNER_PROOF_EVENT_KIND);
    let current_result = verify_push_gossip_for_profile(
        PushGossipAction::Upsert(vec![transitional.clone()]),
        &group,
        std::slice::from_ref(&member),
        ProtocolProfile::Current,
    );
    assert!(matches!(current_result, PushGossipAction::Upsert(records) if records.is_empty()));
    let legacy_result = verify_push_gossip_for_profile(
        PushGossipAction::Upsert(vec![transitional]),
        &group,
        std::slice::from_ref(&member),
        ProtocolProfile::Legacy,
    );
    assert!(matches!(legacy_result, PushGossipAction::Upsert(records) if records.len() == 1));

    let mut wrong_registry_kind = current.clone();
    sign_token_record_with_event_kind(&mut wrong_registry_kind, &keys, 452);
    for profile in [ProtocolProfile::Current, ProtocolProfile::Legacy] {
        let result = verify_push_gossip_for_profile(
            PushGossipAction::Upsert(vec![wrong_registry_kind.clone()]),
            &group,
            std::slice::from_ref(&member),
            profile,
        );
        assert!(
            matches!(result, PushGossipAction::Upsert(records) if records.is_empty()),
            "kind-452 proof must be rejected for {profile:?}"
        );
    }

    let mut raw = current;
    sign_token_record_raw_legacy(&mut raw, &keys);
    let current_result = verify_push_gossip_for_profile(
        PushGossipAction::Upsert(vec![raw.clone()]),
        &group,
        std::slice::from_ref(&member),
        ProtocolProfile::Current,
    );
    assert!(matches!(current_result, PushGossipAction::Upsert(records) if records.is_empty()));
    let legacy_result = verify_push_gossip_for_profile(
        PushGossipAction::Upsert(vec![raw]),
        &group,
        std::slice::from_ref(&member),
        ProtocolProfile::Legacy,
    );
    assert!(matches!(legacy_result, PushGossipAction::Upsert(records) if records.len() == 1));
}

#[test]
fn removal_owner_proofs_follow_the_same_profile_matrix() {
    let keys = Keys::generate();
    let group = "ee".repeat(16);
    let server = "dd".repeat(32);
    let member = keys.public_key().to_hex();
    let current = signed_removal_record(&keys, &group, 1, &server, 100);

    let mut transitional = current.clone();
    sign_removal_record_with_event_kind(
        &mut transitional,
        &group,
        &keys,
        LEGACY_PUSH_OWNER_PROOF_EVENT_KIND,
    );
    let current_result = verify_push_gossip_for_profile(
        PushGossipAction::Remove(vec![transitional.clone()]),
        &group,
        std::slice::from_ref(&member),
        ProtocolProfile::Current,
    );
    assert!(matches!(current_result, PushGossipAction::Remove(records) if records.is_empty()));
    let legacy_result = verify_push_gossip_for_profile(
        PushGossipAction::Remove(vec![transitional]),
        &group,
        std::slice::from_ref(&member),
        ProtocolProfile::Legacy,
    );
    assert!(matches!(legacy_result, PushGossipAction::Remove(records) if records.len() == 1));

    let mut raw = current;
    sign_removal_record_raw_legacy(&mut raw, &group, &keys);
    let current_result = verify_push_gossip_for_profile(
        PushGossipAction::Remove(vec![raw.clone()]),
        &group,
        std::slice::from_ref(&member),
        ProtocolProfile::Current,
    );
    assert!(matches!(current_result, PushGossipAction::Remove(records) if records.is_empty()));
    let legacy_result = verify_push_gossip_for_profile(
        PushGossipAction::Remove(vec![raw]),
        &group,
        std::slice::from_ref(&member),
        ProtocolProfile::Legacy,
    );
    assert!(matches!(legacy_result, PushGossipAction::Remove(records) if records.len() == 1));
}

#[test]
fn removal_kind_451_vector_matches_the_adopted_spec() {
    let mut secret = [0_u8; 32];
    secret[31] = 3;
    let keys = Keys::new(nostr::prelude::SecretKey::from_slice(&secret).unwrap());
    let group_id_hex: String = (0_u8..32).map(|byte| format!("{byte:02x}")).collect();
    let record = PushTokenRemovalRecord {
        member_id_hex: keys.public_key().to_hex(),
        leaf_index: 3,
        platform: PushPlatform::Apns,
        token_fingerprint: "sha256:000102030405060708090a0b".to_owned(),
        server_pubkey_hex:
            "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4"
                .to_owned(),
        owner_ts: 1_700_000_000_000,
        owner_sig:
            "04c3588a6533399aeaebb6c596fab896186dd0af1f9724f2926d984d2876490c76e1d149127e0fa697d7f19a0807aa373e942f0eb33edc63071567f274ce3bec"
                .to_owned(),
    };

    let event = record.owner_proof_event(&group_id_hex).unwrap();
    assert_eq!(event.kind, Kind::Custom(PUSH_OWNER_PROOF_EVENT_KIND));
    assert_eq!(
        event.id.expect("owner-proof event id is computed").to_hex(),
        "be12f4d029d3cac4034251949d6c013ff18eae00870e199012c7a97e8960b7a2"
    );
    assert!(record.verify_owner_sig(&group_id_hex, ProtocolProfile::Current));
}

#[test]
fn future_or_negative_owner_timestamps_are_rejected_before_signature_work() {
    let keys = Keys::generate();
    let group = "ee".repeat(16);
    let server = "dd".repeat(32);
    let member = keys.public_key().to_hex();
    let too_future = unix_now_ms()
        .saturating_add(PUSH_OWNER_TS_MAX_FUTURE_MS)
        .saturating_add(60_000);
    let future = signed_token_record(&keys, &group, 1, &server, too_future);
    let negative = signed_token_record(&keys, &group, 2, &server, -1);
    let future_removal = signed_removal_record(&keys, &group, 1, &server, too_future);
    let negative_removal = signed_removal_record(&keys, &group, 2, &server, -1);

    reset_owner_signature_verification_count();
    let upserts = verify_push_gossip_for_profile(
        PushGossipAction::Upsert(vec![future, negative]),
        &group,
        std::slice::from_ref(&member),
        ProtocolProfile::Current,
    );
    let removals = verify_push_gossip_for_profile(
        PushGossipAction::Remove(vec![future_removal, negative_removal]),
        &group,
        std::slice::from_ref(&member),
        ProtocolProfile::Current,
    );
    assert!(matches!(upserts, PushGossipAction::Upsert(records) if records.is_empty()));
    assert!(matches!(removals, PushGossipAction::Remove(records) if records.is_empty()));
    assert_eq!(owner_signature_verification_count(), 0);
}

#[test]
fn verify_keeps_owner_signed_self_update() {
    let keys = Keys::generate();
    let group = "ee".repeat(32);
    let record = signed_token_record(&keys, &group, 1, &"dd".repeat(32), 100);
    let action = verify_push_gossip(
        PushGossipAction::Upsert(vec![record.clone()]),
        &group,
        &[keys.public_key().to_hex()],
    );
    assert_eq!(action, PushGossipAction::Upsert(vec![record]));
}

#[test]
fn verify_keeps_transitively_relayed_record_from_other_member() {
    // A record owned and signed by B, relayed in a kind 448 by C. verify never
    // consults the carrying sender, so B's record applies (offline-member
    // bootstrap) as long as B is a current member.
    let b = Keys::generate();
    let c_id = Keys::generate().public_key().to_hex();
    let group = "ee".repeat(32);
    let record = signed_token_record(&b, &group, 2, &"dd".repeat(32), 100);
    let action = verify_push_gossip(
        PushGossipAction::Upsert(vec![record.clone()]),
        &group,
        &[b.public_key().to_hex(), c_id],
    );
    assert_eq!(action, PushGossipAction::Upsert(vec![record]));
}

#[test]
fn verify_drops_forged_record_for_other_member() {
    // Attacker A signs a record, then relabels it as victim B. B's signature is
    // absent, so it is dropped even though B is a current member.
    let attacker = Keys::generate();
    let victim = Keys::generate();
    let group = "ee".repeat(32);
    let mut record = signed_token_record(&attacker, &group, 1, &"dd".repeat(32), 100);
    record.member_id_hex = victim.public_key().to_hex();
    let action = verify_push_gossip(
        PushGossipAction::Upsert(vec![record]),
        &group,
        &[victim.public_key().to_hex(), attacker.public_key().to_hex()],
    );
    assert_eq!(action, PushGossipAction::Upsert(vec![]));
}

#[test]
fn verify_drops_validly_signed_record_for_non_member() {
    let keys = Keys::generate();
    let group = "ee".repeat(32);
    let record = signed_token_record(&keys, &group, 1, &"dd".repeat(32), 100);
    let action = verify_push_gossip(
        PushGossipAction::Upsert(vec![record]),
        &group,
        &["bb".repeat(32)],
    );
    assert_eq!(action, PushGossipAction::Upsert(vec![]));
}

#[test]
fn verify_drops_record_signed_for_a_different_group() {
    // group_id is bound into the signature: a record signed for X must not verify
    // when relabeled and presented under Y.
    let keys = Keys::generate();
    let group_x = "11".repeat(32);
    let group_y = "22".repeat(32);
    let mut record = signed_token_record(&keys, &group_x, 1, &"dd".repeat(32), 100);
    record.group_id_hex = group_y.clone();
    let action = verify_push_gossip(
        PushGossipAction::Upsert(vec![record]),
        &group_y,
        &[keys.public_key().to_hex()],
    );
    assert_eq!(action, PushGossipAction::Upsert(vec![]));
}

#[test]
fn verify_drops_record_with_repointed_server() {
    // server_pubkey is bound into the signature: repointing it after signing
    // invalidates the record, so a relayer cannot redirect push routing.
    let keys = Keys::generate();
    let group = "ee".repeat(32);
    let mut record = signed_token_record(&keys, &group, 1, &"dd".repeat(32), 100);
    record.server_pubkey_hex = "cc".repeat(32);
    let action = verify_push_gossip(
        PushGossipAction::Upsert(vec![record]),
        &group,
        &[keys.public_key().to_hex()],
    );
    assert_eq!(action, PushGossipAction::Upsert(vec![]));
}

#[test]
fn verify_keeps_owner_signed_removal_and_drops_forged() {
    let owner = Keys::generate();
    let attacker = Keys::generate();
    let group = "ee".repeat(32);
    let good = signed_removal_record(&owner, &group, 1, &"dd".repeat(32), 100);
    let mut forged = signed_removal_record(&attacker, &group, 1, &"dd".repeat(32), 100);
    forged.member_id_hex = owner.public_key().to_hex();
    let action = verify_push_gossip(
        PushGossipAction::Remove(vec![good.clone(), forged]),
        &group,
        &[owner.public_key().to_hex(), attacker.public_key().to_hex()],
    );
    assert_eq!(action, PushGossipAction::Remove(vec![good]));
}

#[test]
fn signed_record_survives_wire_round_trip_and_verifies() {
    // from_record -> JSON content -> parse_push_gossip -> verify, end to end.
    let keys = Keys::generate();
    let group = "ee".repeat(32);
    let record = signed_token_record(&keys, &group, 3, &"dd".repeat(32), 100);
    let payload = PushTokenGossipPayload {
        v: PUSH_VERSION.to_owned(),
        tokens: vec![PushTokenGossipEntry::from_record(&record)],
    };
    let content = serde_json::to_string(&payload).unwrap();
    let action =
        parse_push_gossip(MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST, &group, &content).unwrap();
    let verified = verify_push_gossip(action, &group, &[keys.public_key().to_hex()]);
    match verified {
        PushGossipAction::Upsert(records) => {
            assert_eq!(records.len(), 1);
            assert!(records[0].verify_owner_sig(ProtocolProfile::Current));
        }
        other => panic!("expected upsert, got {other:?}"),
    }
}

#[test]
fn recovery_skips_rows_before_the_subscription_watermark() {
    let mut record = AppMessageRecord {
        authority: None,
        message_id_hex: "11".repeat(32),
        direction: "received".to_owned(),
        group_id_hex: "22".repeat(16),
        sender: "33".repeat(32),
        plaintext: "old local observation".to_owned(),
        kind: 9,
        tags: Vec::new(),
        source_epoch: Some(1),
        retention: None,
        recorded_at: u64::MAX,
        received_at: 10,
        insert_order: 1,
        invalidated: false,
        moderation_grant: false,
    };

    assert!(
        !notification_recovery_is_fresh(&record, Some(11)),
        "a sender-controlled future timestamp must not revive stale history"
    );
    record.received_at = 11;
    assert!(notification_recovery_is_fresh(&record, Some(11)));
    record.received_at = 12;
    assert!(notification_recovery_is_fresh(&record, Some(11)));
    record.received_at = 1;
    assert!(notification_recovery_is_fresh(&record, None));
}

fn member_id_from_hex(value: &str) -> cgka_traits::MemberId {
    cgka_traits::MemberId::new(hex::decode(value).expect("member hex"))
}

fn group_state_event(
    group_id: cgka_traits::GroupId,
    actor: Option<&str>,
    change: cgka_traits::engine::GroupStateChange,
) -> cgka_traits::engine::GroupEvent {
    cgka_traits::engine::GroupEvent::GroupStateChanged {
        group_id,
        epoch: cgka_traits::EpochId(3),
        actor: actor.map(member_id_from_hex),
        change,
        origin_commit_id: Some(cgka_traits::MessageId::new(vec![0xAB; 32])),
    }
}

fn seed_group_state_resolver(
    resolver: &mut NotificationResolver,
    account_label: &str,
    account_id_hex: &str,
    group_id_hex: &str,
    actor_id_hex: Option<&str>,
    local_enabled: bool,
    muted: bool,
) {
    resolver.settings.insert(
        account_label.to_owned(),
        NotificationSettings {
            account_ref: account_label.to_owned(),
            account_id_hex: account_id_hex.to_owned(),
            local_notifications_enabled: local_enabled,
            native_push_enabled: true,
        },
    );
    let conversation = (account_label.to_owned(), group_id_hex.to_owned());
    resolver.groups.insert(conversation.clone(), None);
    resolver.chat_muted.insert(conversation, muted);
    let mut users = vec![account_id_hex];
    if let Some(actor_id_hex) = actor_id_hex {
        users.push(actor_id_hex);
    }
    for account_id in users {
        resolver.users.insert(
            account_id.to_owned(),
            NotificationUser {
                account_id_hex: account_id.to_owned(),
                display_name: None,
                picture_url: None,
            },
        );
    }
}

#[test]
fn group_state_classifier_notifies_only_local_self_affecting_changes() {
    let local = "aa".repeat(32);
    let actor = "bb".repeat(32);
    let other = "cc".repeat(32);

    assert!(matches!(
        classify_local_group_state_notification(
            &local,
            Some(&actor),
            cgka_traits::app_event::GROUP_SYSTEM_TYPE_MEMBER_REMOVED,
            Some(&local),
        ),
        Some(NotificationTrigger::RemovedFromGroup)
    ));
    assert!(matches!(
        classify_local_group_state_notification(
            &local,
            Some(&actor),
            cgka_traits::app_event::GROUP_SYSTEM_TYPE_ADMIN_ADDED,
            Some(&local),
        ),
        Some(NotificationTrigger::MadeAdmin)
    ));
    assert!(matches!(
        classify_local_group_state_notification(
            &local,
            Some(&actor),
            cgka_traits::app_event::GROUP_SYSTEM_TYPE_ADMIN_REMOVED,
            Some(&local),
        ),
        Some(NotificationTrigger::RemovedAsAdmin)
    ));

    assert_eq!(
        classify_local_group_state_notification(
            &local,
            Some(&actor),
            cgka_traits::app_event::GROUP_SYSTEM_TYPE_MEMBER_LEFT,
            Some(&local),
        ),
        None,
        "voluntary leave must not notify"
    );
    assert_eq!(
        classify_local_group_state_notification(
            &local,
            Some(&local),
            cgka_traits::app_event::GROUP_SYSTEM_TYPE_ADMIN_REMOVED,
            Some(&local),
        ),
        None,
        "self-demotion must not notify"
    );
    assert_eq!(
        classify_local_group_state_notification(
            &local,
            Some(&actor),
            cgka_traits::app_event::GROUP_SYSTEM_TYPE_MEMBER_REMOVED,
            Some(&other),
        ),
        None,
        "unrelated subjects must not notify"
    );
    assert!(matches!(
        classify_local_group_state_notification(
            &local,
            None,
            cgka_traits::app_event::GROUP_SYSTEM_TYPE_ADMIN_REMOVED,
            Some(&local),
        ),
        Some(NotificationTrigger::RemovedAsAdmin),
    ));
    assert_eq!(
        classify_local_group_state_notification(
            &local,
            Some(&actor),
            cgka_traits::app_event::GROUP_SYSTEM_TYPE_GROUP_RENAMED,
            None,
        ),
        None
    );
}

#[test]
fn group_state_live_classification_respects_settings_and_mute() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.account_home().create_account("alice").unwrap();
    let account_label = "alice";
    let local = "aa".repeat(32);
    let actor = "bb".repeat(32);
    let group_id = cgka_traits::GroupId::new(vec![0xEE; 16]);
    let group_id_hex = hex::encode(group_id.as_slice());
    let event = MarmotAppEvent::GroupEvent(crate::RuntimeGroupEvent {
        account_id_hex: local.clone(),
        account_label: account_label.to_owned(),
        event: group_state_event(
            group_id.clone(),
            Some(&actor),
            cgka_traits::engine::GroupStateChange::MemberRemoved {
                member: member_id_from_hex(&local),
            },
        ),
    });

    let mut resolver = NotificationResolver::default();
    seed_group_state_resolver(
        &mut resolver,
        account_label,
        &local,
        &group_id_hex,
        Some(&actor),
        true,
        false,
    );
    let update = notification_update_from_event_cached(&app, &mut resolver, &event)
        .unwrap()
        .expect("unmuted eviction of the local account should notify");
    assert!(matches!(
        update.trigger,
        NotificationTrigger::RemovedFromGroup
    ));
    assert!(!update.is_mention);
    assert!(!update.is_from_self);
    assert!(update.notification_key.starts_with("group-state:"));

    resolver
        .chat_muted
        .insert((account_label.to_owned(), group_id_hex.clone()), true);
    assert_eq!(
        notification_update_from_event_cached(&app, &mut resolver, &event).unwrap(),
        None,
        "muted groups must suppress membership notifications"
    );

    seed_group_state_resolver(
        &mut resolver,
        account_label,
        &local,
        &group_id_hex,
        Some(&actor),
        false,
        false,
    );
    assert!(
        matches!(
            notification_update_from_event_cached(&app, &mut resolver, &event),
            Err(crate::AppError::NotificationsDisabled)
        ),
        "disabled local notifications must suppress membership notifications"
    );
}

#[test]
fn group_state_live_and_recovery_share_a_deterministic_key() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.account_home().create_account("alice").unwrap();
    let account_label = "alice";
    let local = "aa".repeat(32);
    let actor = "bb".repeat(32);
    let group_id = cgka_traits::GroupId::new(vec![0xEE; 16]);
    let group_id_hex = hex::encode(group_id.as_slice());
    let change = cgka_traits::engine::GroupStateChange::AdminAdded {
        member: member_id_from_hex(&local),
    };
    let actor_id = member_id_from_hex(&actor);
    let material =
        cgka_traits::app_event::group_system_event_material(&group_id, 3, Some(&actor_id), &change)
            .unwrap();

    let mut resolver = NotificationResolver::default();
    seed_group_state_resolver(
        &mut resolver,
        account_label,
        &local,
        &group_id_hex,
        Some(&actor),
        true,
        false,
    );
    let live = notification_update_from_event_cached(
        &app,
        &mut resolver,
        &MarmotAppEvent::GroupEvent(crate::RuntimeGroupEvent {
            account_id_hex: local.clone(),
            account_label: account_label.to_owned(),
            event: group_state_event(group_id, Some(&actor), change),
        }),
    )
    .unwrap()
    .expect("live admin grant should notify");

    let recovered = notification_update_from_group_system_record(
        &app,
        &mut resolver,
        account_label,
        &local,
        &AppMessageRecord {
            authority: None,
            message_id_hex: material.message_id_hex.clone(),
            direction: "system".to_owned(),
            group_id_hex,
            sender: actor.clone(),
            plaintext: material.content,
            kind: cgka_traits::app_event::MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
            tags: material.tags,
            source_epoch: Some(3),
            retention: None,
            recorded_at: 30,
            received_at: 30,
            insert_order: 1,
            invalidated: false,
            moderation_grant: false,
        },
    )
    .unwrap()
    .expect("fresh kind-1210 recovery should notify");

    assert_eq!(live.notification_key, recovered.notification_key);
    assert!(matches!(live.trigger, NotificationTrigger::MadeAdmin));
    assert!(matches!(recovered.trigger, NotificationTrigger::MadeAdmin));
}

#[test]
fn recovery_skips_invalidated_group_system_rows() {
    let mut record = AppMessageRecord {
        authority: None,
        message_id_hex: "11".repeat(32),
        direction: "system".to_owned(),
        group_id_hex: "22".repeat(16),
        sender: "33".repeat(32),
        plaintext: "system".to_owned(),
        kind: cgka_traits::app_event::MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
        tags: Vec::new(),
        source_epoch: Some(1),
        retention: None,
        recorded_at: 20,
        received_at: 20,
        insert_order: 1,
        invalidated: true,
        moderation_grant: false,
    };
    assert!(!notification_recovery_should_project(&record, Some(10)));
    record.invalidated = false;
    assert!(notification_recovery_should_project(&record, Some(10)));
    record.received_at = 9;
    assert!(!notification_recovery_should_project(&record, Some(10)));
}

#[test]
fn group_state_wake_targets_only_matching_non_self_effects() {
    let local = "aa".repeat(32);
    let bob = "bb".repeat(32);
    let carol = "cc".repeat(32);
    let group_id = cgka_traits::GroupId::new(vec![0xEE; 16]);
    let events = vec![
        group_state_event(
            group_id.clone(),
            Some(&local),
            cgka_traits::engine::GroupStateChange::MemberRemoved {
                member: member_id_from_hex(&bob),
            },
        ),
        group_state_event(
            group_id.clone(),
            Some(&local),
            cgka_traits::engine::GroupStateChange::MemberLeft {
                member: member_id_from_hex(&local),
            },
        ),
        group_state_event(
            group_id.clone(),
            Some(&local),
            cgka_traits::engine::GroupStateChange::AdminRemoved {
                member: member_id_from_hex(&local),
            },
        ),
        group_state_event(
            group_id,
            Some(&local),
            cgka_traits::engine::GroupStateChange::AdminAdded {
                member: member_id_from_hex(&carol),
            },
        ),
    ];
    let targets = wake_member_ids_from_group_events(&local, &events);
    assert!(targets.contains(&bob));
    assert!(targets.contains(&carol));
    assert!(!targets.contains(&local));
}

#[test]
fn group_state_wake_uses_only_snapshotted_target_tokens() {
    let bob = "bb".repeat(32);
    let carol = "cc".repeat(32);
    let group_id_hex = "ee".repeat(16);
    let tokens = vec![
        GroupPushTokenRecord {
            group_id_hex: group_id_hex.clone(),
            member_id_hex: bob.clone(),
            leaf_index: 1,
            platform: PushPlatform::Fcm,
            token_fingerprint: "fp-bob".to_owned(),
            server_pubkey_hex: "aa".repeat(32),
            relay_hint: Some("wss://hint.example".to_owned()),
            encrypted_token: vec![1; PUSH_ENCRYPTED_TOKEN_LEN],
            owner_ts: 0,
            owner_sig: String::new(),
            updated_at_ms: 0,
        },
        GroupPushTokenRecord {
            group_id_hex,
            member_id_hex: carol,
            leaf_index: 2,
            platform: PushPlatform::Fcm,
            token_fingerprint: "fp-carol".to_owned(),
            server_pubkey_hex: "aa".repeat(32),
            relay_hint: Some("wss://hint.example".to_owned()),
            encrypted_token: vec![2; PUSH_ENCRYPTED_TOKEN_LEN],
            owner_ts: 0,
            owner_sig: String::new(),
            updated_at_ms: 0,
        },
    ];
    let filtered = tokens_for_member_ids(tokens, [bob.as_str()]);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].member_id_hex, bob);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn group_state_wake_keeps_kind_446_context_free() {
    use nostr::nips::nip59::UnwrappedGift;

    let secret = server_secret();
    let server_pubkey_hex = server_pubkey_hex(&secret);
    let token = vec![7_u8; PUSH_ENCRYPTED_TOKEN_LEN];
    let wrap = build_notification_gift_wrap(&server_pubkey_hex, &[token])
        .await
        .unwrap();
    let event = wrap.to_verified_nostr_event().unwrap();
    let server_keys = Keys::new(nostr::prelude::SecretKey::from(secret));
    let UnwrappedGift { rumor, .. } = UnwrappedGift::from_gift_wrap(&server_keys, &event).unwrap();
    let tag_slices: Vec<&[String]> = rumor.tags.iter().map(|tag| tag.as_slice()).collect();
    assert_eq!(
        tag_slices,
        vec![[NOTIFICATION_VERSION_TAG.to_owned(), PUSH_VERSION.to_owned()].as_slice()],
        "group-state wakes must reuse the context-free kind-446 rumor"
    );
}

#[test]
fn recover_notification_updates_rebuilds_fresh_kind_1210_rows() {
    let dir = tempfile::tempdir().unwrap();
    let home = marmot_account::AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.notification_settings("alice").unwrap();
    let local = account.account_id_hex.clone();
    let actor = "bb".repeat(32);
    let group_id = cgka_traits::GroupId::new(vec![0xEE; 16]);
    let change = cgka_traits::engine::GroupStateChange::MemberRemoved {
        member: member_id_from_hex(&local),
    };
    let actor_id = member_id_from_hex(&actor);
    let material =
        cgka_traits::app_event::group_system_event_material(&group_id, 4, Some(&actor_id), &change)
            .unwrap();
    app.record_account_app_event_at(
        "alice",
        &crate::AppMessageProjection {
            authority: None,
            message_id_hex: material.message_id_hex.clone(),
            source_message_id_hex: None,
            direction: "system".to_owned(),
            group_id_hex: material.group_id_hex,
            sender: actor,
            plaintext: material.content,
            kind: cgka_traits::app_event::MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
            tags: material.tags,
            source_epoch: Some(4),
            retention: None,
            recorded_at: Some(40),
            origin_commit_id: Some("ab".repeat(32)),
            moderation_grant: false,
        },
        40,
    )
    .unwrap();

    let recovered = recover_notification_updates(&app, Some(40)).unwrap();
    assert_eq!(recovered.len(), 1);
    assert!(matches!(
        recovered[0].trigger,
        NotificationTrigger::RemovedFromGroup
    ));
    assert_eq!(
        recovered[0].notification_key,
        format!("group-state:{local}:{}", material.message_id_hex)
    );

    let stale = recover_notification_updates(&app, Some(41)).unwrap();
    assert!(
        stale.is_empty(),
        "pre-watermark kind-1210 rows must stay history"
    );
}

#[test]
fn system_reaction_preview_decodes_only_supported_nonempty_text() {
    let reaction = received_reaction("👍", &"aa".repeat(32));
    for (content, expected) in [
        (
            r#"{"v":1,"system_type":"member_added","text":"Member added","data":{"actor":"private-id"}}"#,
            Some("Member added"),
        ),
        (
            r#"{"v":1,"system_type":"future_type","text":"Future activity"}"#,
            Some("Future activity"),
        ),
        (r#"{"v":1,"system_type":"member_added","text":"   "}"#, None),
        (
            r#"{"v":2,"system_type":"member_added","text":"future payload"}"#,
            None,
        ),
        (r#"{"v":1,"system_type":"member_added"}"#, None),
        ("not JSON", None),
    ] {
        let mut target = timeline_target(MARMOT_APP_EVENT_KIND_GROUP_SYSTEM, content);
        assert_eq!(
            reaction_notification_fields(&reaction, Some(&target)),
            (Some("👍".into()), expected.map(str::to_owned)),
            "{content}"
        );
        target.deleted = true;
        assert_eq!(
            reaction_notification_fields(&reaction, Some(&target)).1,
            None
        );
        target.deleted = false;
        target.invalidated = true;
        assert_eq!(
            reaction_notification_fields(&reaction, Some(&target)).1,
            None
        );
    }
    let oversized =
        serde_json::json!({"v":1,"system_type":"member_added","text":"x".repeat(16 * 1024)})
            .to_string();
    let target = timeline_target(MARMOT_APP_EVENT_KIND_GROUP_SYSTEM, &oversized);
    assert_eq!(
        reaction_notification_fields(&reaction, Some(&target)).1,
        None
    );
}

#[test]
fn system_reaction_notifications_use_stored_actor_and_respect_origin_withdrawal() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let account = app.account_home().create_account("alice").unwrap();
    let local = account.account_id_hex;
    let peer = "bb".repeat(32);
    let group = cgka_traits::GroupId::new(vec![0xEE; 16]);
    let group_hex = hex::encode(group.as_slice());
    let mut resolver = NotificationResolver::default();
    seed_group_state_resolver(
        &mut resolver,
        "alice",
        &local,
        &group_hex,
        Some(&peer),
        true,
        false,
    );
    for (index, actor) in [Some(local.as_str()), Some(peer.as_str()), None]
        .into_iter()
        .enumerate()
    {
        let material = group_system_event_material(
            &group,
            index as u64,
            actor.map(member_id_from_hex).as_ref(),
            &cgka_traits::engine::GroupStateChange::MemberAdded {
                member: member_id_from_hex(&peer),
            },
        )
        .unwrap();
        let origin = cgka_traits::MessageId::new(vec![index as u8 + 1; 32]);
        let projection = crate::AppMessageProjection {
            authority: None,
            message_id_hex: material.message_id_hex.clone(),
            source_message_id_hex: None,
            group_id_hex: group_hex.clone(),
            direction: "system".into(),
            sender: material.sender,
            plaintext: material.content,
            kind: MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
            tags: material.tags,
            source_epoch: Some(index as u64),
            retention: None,
            recorded_at: Some(10),
            origin_commit_id: Some(hex::encode(origin.as_slice())),
            moderation_grant: false,
        };
        app.record_account_app_event("alice", &projection).unwrap();
        let mut reaction = received_reaction("👍", &projection.message_id_hex);
        reaction.group_id = group.clone();
        let event = RuntimeMessageReceived {
            account_label: "alice".into(),
            account_id_hex: local.clone(),
            message: reaction,
        };
        let alert = notification_update_from_message(&app, &mut resolver, &event).unwrap();
        if actor != Some(local.as_str()) {
            assert!(
                alert.is_none(),
                "another actor or no actor must not notify this account"
            );
            continue;
        }
        assert_eq!(
            alert.unwrap().reacted_to_preview.as_deref(),
            Some("Member added")
        );
        let withdrawal = cgka_traits::engine::GroupEvent::GroupStateInvalidated {
            group_id: group.clone(),
            epoch: cgka_traits::EpochId(index as u64),
            invalidated_commit_id: origin,
            reason: cgka_traits::engine::GroupStateInvalidationReason::SupersededByBranchSelection,
        };
        app.projection_update_for_invalidation_event("alice", &withdrawal)
            .unwrap()
            .unwrap();
        // Replaying the source must not revive a losing commit or its preview.
        app.record_account_app_event("alice", &projection).unwrap();
        let alert = notification_update_from_message(&app, &mut resolver, &event).unwrap();
        assert!(alert.and_then(|alert| alert.reacted_to_preview).is_none());
    }
}
