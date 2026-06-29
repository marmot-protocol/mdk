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
    let blob = encrypted_mip05_token(
        PushPlatform::Apns,
        &[0xAA, 0xBB, 0xCC],
        &server_pubkey_hex(&secret),
    )
    .unwrap();
    assert_eq!(blob.len(), MIP05_ENCRYPTED_TOKEN_LEN);
    let (platform, token) = decrypt_mip05_token_for_test(&blob, &secret).unwrap();
    assert_eq!(platform.platform_byte(), 0x01);
    assert_eq!(token, vec![0xAA, 0xBB, 0xCC]);
}

#[test]
fn fcm_token_encryption_uses_platform_byte_0x02() {
    let secret = server_secret();
    let blob = encrypted_mip05_token(
        PushPlatform::Fcm,
        b"opaque-fcm-token",
        &server_pubkey_hex(&secret),
    )
    .unwrap();
    assert_eq!(blob.len(), MIP05_ENCRYPTED_TOKEN_LEN);
    let (platform, token) = decrypt_mip05_token_for_test(&blob, &secret).unwrap();
    assert_eq!(platform.platform_byte(), 0x02);
    assert_eq!(token, b"opaque-fcm-token");
}

#[test]
fn mip05_key_derivation_uses_raw_shared_point_x_coordinate() {
    let server_secret = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let peer_secret = SecretKey::from_slice(&[0x22; 32]).unwrap();
    let peer_public = SecpPublicKey::from_secret_key_global(&peer_secret);

    let shared_x = secp256k1_ecdh_x(&peer_public, &server_secret);
    let raw_x_key = mip05_encryption_key(&shared_x).unwrap();

    let hashed_shared = SharedSecret::new(&peer_public, &server_secret).secret_bytes();
    let hashed_helper_key = mip05_encryption_key(&hashed_shared).unwrap();

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
    let too_long = "x".repeat(MIP05_MAX_PROVIDER_TOKEN_LEN + 1);
    let err = parse_provider_token(PushPlatform::Fcm, &too_long).unwrap_err();
    assert!(!err.to_string().contains(&too_long));
}

#[test]
fn kind_446_content_is_base64_concatenated_tokens_with_version_tag() {
    let token = vec![7_u8; MIP05_ENCRYPTED_TOKEN_LEN];
    let content = build_notification_rumor_content(&[token.clone(), token.clone()]).unwrap();
    let decoded = BASE64_STANDARD.decode(content).unwrap();
    assert_eq!(decoded.len(), MIP05_ENCRYPTED_TOKEN_LEN * 2);
}

#[tokio::test]
async fn kind_446_rumor_only_carries_version_tag_and_no_routing_metadata() {
    use nostr::nips::nip59::UnwrappedGift;

    let secret = server_secret();
    let server_pubkey_hex = server_pubkey_hex(&secret);
    let token = vec![7_u8; MIP05_ENCRYPTED_TOKEN_LEN];

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
        vec![
            [
                NOTIFICATION_VERSION_TAG.to_owned(),
                MIP05_VERSION.to_owned()
            ]
            .as_slice()
        ],
        "rumor must carry only the version tag; any p/e/k/h/d/relays tag would leak routing metadata"
    );

    let decoded = BASE64_STANDARD.decode(&rumor.content).unwrap();
    assert_eq!(decoded.len(), MIP05_ENCRYPTED_TOKEN_LEN * 2);
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
        plaintext: emoji.to_owned(),
        kind: MARMOT_APP_EVENT_KIND_REACTION,
        tags: vec![vec![EVENT_REF_TAG.to_owned(), target_message_id.to_owned()]],
        recorded_at: 0,
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
        plaintext: plaintext.to_owned(),
        kind: cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT,
        tags,
        recorded_at: 0,
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
    // literal text and it is not classified as a mention (darkmatter#617).
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
    // darkmatter#617.
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

    let update =
        notification_update_from_group_join(&app, "alice", &account.account_id_hex, &group_id)
            .unwrap();

    assert!(matches!(update.trigger, NotificationTrigger::GroupInvite));
    assert!(!update.is_mention);
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
fn only_chat_and_reaction_kinds_are_notifiable() {
    use cgka_traits::app_event::{
        MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, MARMOT_APP_EVENT_KIND_CHAT,
        MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_EDIT,
        MARMOT_APP_EVENT_KIND_GROUP_SYSTEM, MARMOT_APP_EVENT_KIND_REACTION,
    };
    assert!(is_notifiable_message_kind(MARMOT_APP_EVENT_KIND_CHAT));
    assert!(is_notifiable_message_kind(MARMOT_APP_EVENT_KIND_REACTION));
    // State changes, not new user messages — never alert.
    assert!(!is_notifiable_message_kind(MARMOT_APP_EVENT_KIND_DELETE));
    assert!(!is_notifiable_message_kind(MARMOT_APP_EVENT_KIND_EDIT));
    assert!(!is_notifiable_message_kind(
        MARMOT_APP_EVENT_KIND_GROUP_SYSTEM
    ));
    assert!(!is_notifiable_message_kind(
        MARMOT_APP_EVENT_KIND_AGENT_STREAM_START
    ));
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
