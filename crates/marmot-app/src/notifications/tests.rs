use super::*;
use nostr::secp256k1::{Secp256k1, ecdh::SharedSecret};

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
    let peer_public = SecpPublicKey::from_secret_key_global(&peer_secret);

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

#[tokio::test]
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
    assert!(record.verify_owner_sig());
}

#[test]
fn kind_446_content_is_base64_concatenated_tokens_with_version_tag() {
    let token = vec![7_u8; PUSH_ENCRYPTED_TOKEN_LEN];
    let content = build_notification_rumor_content(&[token.clone(), token.clone()]).unwrap();
    let decoded = BASE64_STANDARD.decode(content).unwrap();
    assert_eq!(decoded.len(), PUSH_ENCRYPTED_TOKEN_LEN * 2);
}

#[tokio::test]
async fn kind_446_rumor_only_carries_version_tag_and_no_routing_metadata() {
    use nostr::nips::nip59::UnwrappedGift;

    let secret = server_secret();
    let server_pubkey_hex = server_pubkey_hex(&secret);
    let token = vec![7_u8; PUSH_ENCRYPTED_TOKEN_LEN];

    let wrap = build_notification_gift_wrap(&server_pubkey_hex, &[token.clone(), token])
        .await
        .unwrap();
    let event = wrap.to_verified_nostr_event().unwrap();

    let server_keys = Keys::new(nostr::SecretKey::from(secret));
    let UnwrappedGift { rumor, .. } = UnwrappedGift::from_gift_wrap(&server_keys, &event)
        .await
        .unwrap();

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
    assert!(add_error.to_string().contains("exceeds 32 entries"));
    assert!(removal_error.to_string().contains("exceeds 32 entries"));
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
        message_id_hex: "11".repeat(32),
        source_message_id_hex: "22".repeat(32),
        sender: owner_id.clone(),
        sender_display_name: None,
        group_id,
        source_epoch: 1,
        plaintext: payload,
        kind: MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST,
        tags: vec![vec!["v".to_owned(), PUSH_VERSION.to_owned()]],
        recorded_at: 1,
        received_at: 1,
    };

    reset_owner_signature_verification_count();
    app.ingest_push_gossip_message("alice", &message, std::slice::from_ref(&owner_id))
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
            message_id_hex: "11".repeat(32),
            source_message_id_hex: "22".repeat(32),
            sender: owner_id.clone(),
            sender_display_name: None,
            group_id: group_id.clone(),
            source_epoch: 1,
            plaintext: payload,
            kind: MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST,
            tags: vec![vec!["v".to_owned(), PUSH_VERSION.to_owned()]],
            recorded_at: 1,
            received_at: 1,
        };

        reset_owner_signature_verification_count();
        app.ingest_push_gossip_message("alice", &message, std::slice::from_ref(&owner_id))
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
    let receiver = nostr::Keys::generate().public_key().to_hex();
    let npub = crate::npub_for_account_id(&receiver).unwrap();
    let message = received_chat("hi", vec![vec!["p".to_owned(), npub]]);

    assert!(message_mentions_account(&message, &receiver));
}

#[test]
fn mention_classification_uses_inline_nip27_entities() {
    let receiver = nostr::Keys::generate().public_key().to_hex();
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
    let receiver = nostr::Keys::generate().public_key().to_hex();
    let npub = crate::npub_for_account_id(&receiver).unwrap();
    let other = nostr::Keys::generate().public_key().to_hex();

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
    let receiver = nostr::Keys::generate().public_key().to_hex();
    let npub = crate::npub_for_account_id(&receiver).unwrap();

    let message = received_chat(&format!("hey @{npub} ping"), Vec::new());
    assert!(message_mentions_account(&message, &receiver));

    // A bare `@npub1…` for a different account is not a mention of `receiver`.
    let other = nostr::Keys::generate().public_key().to_hex();
    let other_npub = crate::npub_for_account_id(&other).unwrap();
    let other_message = received_chat(&format!("hey @{other_npub} ping"), Vec::new());
    assert!(!message_mentions_account(&other_message, &receiver));
}

#[test]
fn mention_classification_uses_p_tag_for_mentions_beyond_inline_scan_cap() {
    let receiver = nostr::Keys::generate().public_key().to_hex();
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
    .unwrap();

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
fn agent_activity_notification_is_non_mention_and_respects_group_mute() {
    use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY;

    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let account_label = "alice";
    let account_id_hex = "aa".repeat(32);
    let sender_id_hex = "bb".repeat(32);
    let group_id_hex = "ee".repeat(32);
    let message = RuntimeMessageReceived {
        account_id_hex: account_id_hex.clone(),
        account_label: account_label.to_owned(),
        message: ReceivedMessage {
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
            assert!(records[0].verify_owner_sig());
        }
        other => panic!("expected upsert, got {other:?}"),
    }
}
