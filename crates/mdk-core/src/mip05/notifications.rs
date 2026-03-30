use std::collections::BTreeMap;
use std::collections::HashSet;
use std::ops::Range;

use base64::Engine;
use nostr::nips::nip44;
use nostr::{
    Event, EventBuilder, JsonUtil, Keys, Kind, PublicKey, Tag, TagKind, Timestamp, UnsignedEvent,
};

use super::{
    BASE64_ENCODING, ENCODING_TAG_NAME, ENCRYPTED_TOKEN_LEN, MAX_NOTIFICATION_REQUEST_TOKENS,
    Mip05Error, NOTIFICATION_REQUEST_KIND, NOTIFICATION_REQUEST_VERSION, NotificationEventBatch,
    NotificationRequest, TokenTag, VERSION_TAG_NAME,
};

// NIP-59 recommends randomizing wrapper timestamps across a two-day window.
const RANGE_RANDOM_TIMESTAMP_TWEAK: Range<u64> = 0..172800;

/// Build an unsigned `kind:446` MIP-05 notification request rumor.
///
/// The `pubkey` should be a fresh ephemeral key for the request. Callers that
/// want MDK to handle the ephemeral-key lifecycle should prefer
/// [`build_notification_batches`].
pub fn build_notification_request_rumor(
    pubkey: PublicKey,
    created_at: Timestamp,
    tokens: Vec<super::EncryptedToken>,
) -> Result<UnsignedEvent, Mip05Error> {
    if tokens.is_empty() {
        return Err(Mip05Error::NotificationRequestMustIncludeToken);
    }

    let mut content_bytes = Vec::with_capacity(tokens.len() * ENCRYPTED_TOKEN_LEN);
    for token in &tokens {
        content_bytes.extend_from_slice(token.as_bytes());
    }

    let mut rumor = UnsignedEvent::new(
        pubkey,
        created_at,
        Kind::from(NOTIFICATION_REQUEST_KIND),
        [
            Tag::custom(
                TagKind::Custom(VERSION_TAG_NAME.into()),
                [NOTIFICATION_REQUEST_VERSION],
            ),
            Tag::custom(TagKind::Custom(ENCODING_TAG_NAME.into()), [BASE64_ENCODING]),
        ],
        base64::engine::general_purpose::STANDARD.encode(content_bytes),
    );
    rumor.ensure_id();
    Ok(rumor)
}

/// Parse a typed `kind:446` notification request rumor.
pub fn parse_notification_request_rumor(
    event: &UnsignedEvent,
) -> Result<NotificationRequest, Mip05Error> {
    if event.kind != Kind::from(NOTIFICATION_REQUEST_KIND) {
        return Err(Mip05Error::UnexpectedRumorKind);
    }

    let mut version_tag_seen = false;
    let mut encoding_tag_seen = false;

    for tag in event.tags.iter() {
        let values = tag.as_slice();
        match values.first().map(String::as_str) {
            Some(VERSION_TAG_NAME) => {
                if version_tag_seen {
                    return Err(Mip05Error::DuplicateNotificationRequestVersionTag);
                }
                if values.len() != 2 {
                    return Err(Mip05Error::InvalidNotificationRequestVersionTag);
                }
                if values.get(1).map(String::as_str) != Some(NOTIFICATION_REQUEST_VERSION) {
                    return Err(Mip05Error::InvalidNotificationRequestVersionTag);
                }
                version_tag_seen = true;
            }
            Some(ENCODING_TAG_NAME) => {
                if encoding_tag_seen {
                    return Err(Mip05Error::DuplicateNotificationRequestEncodingTag);
                }
                if values.len() != 2 {
                    return Err(Mip05Error::InvalidNotificationRequestEncodingTag);
                }
                if values.get(1).map(String::as_str) != Some(BASE64_ENCODING) {
                    return Err(Mip05Error::InvalidNotificationRequestEncodingTag);
                }
                encoding_tag_seen = true;
            }
            // Intentionally reject unknown tags to match the current MIP-05 draft exactly.
            _ => return Err(Mip05Error::UnsupportedNotificationRequestTags),
        }
    }

    if !version_tag_seen {
        return Err(Mip05Error::MissingNotificationRequestVersionTag);
    }
    if !encoding_tag_seen {
        return Err(Mip05Error::MissingNotificationRequestEncodingTag);
    }

    let content = base64::engine::general_purpose::STANDARD
        .decode(&event.content)
        .map_err(|_| Mip05Error::InvalidNotificationRequestBase64)?;

    if content.is_empty() {
        return Err(Mip05Error::NotificationRequestMustIncludeToken);
    }
    if content.len() % ENCRYPTED_TOKEN_LEN != 0 {
        return Err(Mip05Error::InvalidNotificationRequestContentLength);
    }

    let tokens = content
        .chunks_exact(ENCRYPTED_TOKEN_LEN)
        .map(super::EncryptedToken::from_slice)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(NotificationRequest { tokens })
}

/// Build ready-to-publish NIP-59 gift-wrapped `kind:446` notification requests.
///
/// Input token tags are grouped by notification server, relay hints are preserved
/// per server, and each server batch is chunked into requests of at most 100 tokens.
pub fn build_notification_batches(
    tokens: Vec<TokenTag>,
) -> Result<Vec<NotificationEventBatch>, Mip05Error> {
    if tokens.is_empty() {
        return Err(Mip05Error::NotificationRequestMustIncludeToken);
    }

    let grouped_tokens = group_tokens_by_server(tokens);

    grouped_tokens
        .into_iter()
        .map(|(server_pubkey, server_tokens)| {
            build_notification_batch_for_server(server_pubkey, server_tokens)
        })
        .collect()
}

fn group_tokens_by_server(tokens: Vec<TokenTag>) -> BTreeMap<PublicKey, Vec<TokenTag>> {
    let mut grouped_tokens: BTreeMap<PublicKey, Vec<TokenTag>> = BTreeMap::new();

    for token in tokens {
        grouped_tokens
            .entry(token.server_pubkey)
            .or_default()
            .push(token);
    }

    grouped_tokens
}

fn build_notification_batch_for_server(
    server_pubkey: PublicKey,
    server_tokens: Vec<TokenTag>,
) -> Result<NotificationEventBatch, Mip05Error> {
    validate_unique_encrypted_tokens(&server_tokens)?;
    let relay_hints = collect_relay_hints(&server_tokens);
    let events = server_tokens
        .chunks(MAX_NOTIFICATION_REQUEST_TOKENS)
        .map(|chunk| {
            let encrypted_tokens = chunk
                .iter()
                .map(|token| token.encrypted_token.clone())
                .collect::<Vec<_>>();
            build_notification_event_chunk(&server_pubkey, encrypted_tokens)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(NotificationEventBatch {
        server_pubkey,
        relay_hints,
        events,
    })
}

fn validate_unique_encrypted_tokens(tokens: &[TokenTag]) -> Result<(), Mip05Error> {
    let mut unique_tokens = HashSet::with_capacity(tokens.len());

    for token in tokens {
        if !unique_tokens.insert(token.encrypted_token.clone()) {
            return Err(Mip05Error::DuplicateEncryptedToken);
        }
    }

    Ok(())
}

fn collect_relay_hints(tokens: &[TokenTag]) -> Vec<nostr::RelayUrl> {
    let mut relay_hints = Vec::new();

    for token in tokens {
        if !relay_hints.contains(&token.relay_hint) {
            relay_hints.push(token.relay_hint.clone());
        }
    }

    relay_hints
}

fn build_notification_event_chunk(
    server_pubkey: &PublicKey,
    encrypted_tokens: Vec<super::EncryptedToken>,
) -> Result<Event, Mip05Error> {
    let sender_keys = Keys::generate();
    let rumor = build_notification_request_rumor(
        sender_keys.public_key(),
        Timestamp::now(),
        encrypted_tokens,
    )?;
    let seal = build_notification_request_seal(&sender_keys, server_pubkey, rumor)?;
    EventBuilder::gift_wrap_from_seal(server_pubkey, &seal, []).map_err(|e| {
        tracing::warn!(
            target: "mdk_core::mip05::notifications",
            error = %e,
            "Failed to gift-wrap notification request"
        );
        Mip05Error::NotificationRequestGiftWrapFailed
    })
}

fn build_notification_request_seal(
    sender_keys: &Keys,
    server_pubkey: &PublicKey,
    rumor: UnsignedEvent,
) -> Result<Event, Mip05Error> {
    let content = nip44::encrypt(
        sender_keys.secret_key(),
        server_pubkey,
        rumor.as_json(),
        nip44::Version::default(),
    )
    .map_err(|e| {
        tracing::warn!(
            target: "mdk_core::mip05::notifications",
            error = %e,
            "Failed to encrypt notification request"
        );
        Mip05Error::NotificationRequestEncryptionFailed
    })?;

    EventBuilder::new(Kind::Seal, content)
        .custom_created_at(Timestamp::tweaked(RANGE_RANDOM_TIMESTAMP_TWEAK))
        .sign_with_keys(sender_keys)
        .map_err(|e| {
            tracing::warn!(
                target: "mdk_core::mip05::notifications",
                error = %e,
                "Failed to sign notification request seal"
            );
            Mip05Error::NotificationRequestSealFailed
        })
}

#[cfg(test)]
mod tests {
    use nostr::TagStandard;
    use nostr::nips::nip59;

    use super::*;

    fn make_token_tag(server_pubkey: PublicKey, relay_hint: &str, byte: u8) -> TokenTag {
        TokenTag {
            encrypted_token: super::super::EncryptedToken::from([byte; ENCRYPTED_TOKEN_LEN]),
            server_pubkey,
            relay_hint: nostr::RelayUrl::parse(relay_hint).unwrap(),
        }
    }

    #[test]
    fn test_build_and_parse_notification_request_rumor() {
        let sender_keys = Keys::generate();
        let rumor = build_notification_request_rumor(
            sender_keys.public_key(),
            Timestamp::from(123u64),
            vec![
                super::super::EncryptedToken::from([1u8; ENCRYPTED_TOKEN_LEN]),
                super::super::EncryptedToken::from([2u8; ENCRYPTED_TOKEN_LEN]),
            ],
        )
        .unwrap();

        assert_eq!(rumor.kind, Kind::from(NOTIFICATION_REQUEST_KIND));
        let parsed = parse_notification_request_rumor(&rumor).unwrap();
        assert_eq!(parsed.tokens.len(), 2);
        assert_eq!(parsed.tokens[0].as_bytes(), &[1u8; ENCRYPTED_TOKEN_LEN]);
        assert_eq!(parsed.tokens[1].as_bytes(), &[2u8; ENCRYPTED_TOKEN_LEN]);
    }

    #[test]
    fn test_parse_notification_request_rejects_invalid_content_length() {
        let mut rumor = UnsignedEvent::new(
            Keys::generate().public_key(),
            Timestamp::from(123u64),
            Kind::from(NOTIFICATION_REQUEST_KIND),
            [
                Tag::custom(
                    TagKind::Custom(VERSION_TAG_NAME.into()),
                    [NOTIFICATION_REQUEST_VERSION],
                ),
                Tag::custom(TagKind::Custom(ENCODING_TAG_NAME.into()), [BASE64_ENCODING]),
            ],
            base64::engine::general_purpose::STANDARD.encode(vec![7u8; ENCRYPTED_TOKEN_LEN - 1]),
        );
        rumor.ensure_id();

        assert_eq!(
            parse_notification_request_rumor(&rumor).unwrap_err(),
            Mip05Error::InvalidNotificationRequestContentLength
        );
    }

    #[test]
    fn test_parse_notification_request_rejects_duplicate_version_tag() {
        let mut rumor = UnsignedEvent::new(
            Keys::generate().public_key(),
            Timestamp::from(123u64),
            Kind::from(NOTIFICATION_REQUEST_KIND),
            [
                Tag::custom(
                    TagKind::Custom(VERSION_TAG_NAME.into()),
                    [NOTIFICATION_REQUEST_VERSION],
                ),
                Tag::custom(
                    TagKind::Custom(VERSION_TAG_NAME.into()),
                    [NOTIFICATION_REQUEST_VERSION],
                ),
                Tag::custom(TagKind::Custom(ENCODING_TAG_NAME.into()), [BASE64_ENCODING]),
            ],
            base64::engine::general_purpose::STANDARD.encode([1u8; ENCRYPTED_TOKEN_LEN]),
        );
        rumor.ensure_id();

        assert_eq!(
            parse_notification_request_rumor(&rumor).unwrap_err(),
            Mip05Error::DuplicateNotificationRequestVersionTag
        );
    }

    #[test]
    fn test_parse_notification_request_rejects_extra_tag_values() {
        let mut rumor = UnsignedEvent::new(
            Keys::generate().public_key(),
            Timestamp::from(123u64),
            Kind::from(NOTIFICATION_REQUEST_KIND),
            [
                Tag::custom(
                    TagKind::Custom(VERSION_TAG_NAME.into()),
                    [NOTIFICATION_REQUEST_VERSION, "extra"],
                ),
                Tag::custom(TagKind::Custom(ENCODING_TAG_NAME.into()), [BASE64_ENCODING]),
            ],
            base64::engine::general_purpose::STANDARD.encode([1u8; ENCRYPTED_TOKEN_LEN]),
        );
        rumor.ensure_id();

        assert_eq!(
            parse_notification_request_rumor(&rumor).unwrap_err(),
            Mip05Error::InvalidNotificationRequestVersionTag
        );
    }

    #[test]
    fn test_build_notification_batches_rejects_empty_input() {
        assert_eq!(
            build_notification_batches(vec![]).unwrap_err(),
            Mip05Error::NotificationRequestMustIncludeToken
        );
    }

    #[test]
    fn test_build_notification_batches_rejects_duplicate_tokens_per_server() {
        let server_keys = Keys::generate();
        let token = make_token_tag(server_keys.public_key(), "wss://relay.example.com", 7);

        assert_eq!(
            build_notification_batches(vec![token.clone(), token]).unwrap_err(),
            Mip05Error::DuplicateEncryptedToken
        );
    }

    #[test]
    fn test_build_notification_batches_chunks_tokens_per_server() {
        let server_keys = Keys::generate();
        let tokens = (0..201)
            .map(|index| {
                make_token_tag(
                    server_keys.public_key(),
                    "wss://relay.example.com",
                    index as u8,
                )
            })
            .collect();

        let batches = build_notification_batches(tokens).unwrap();

        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].server_pubkey, server_keys.public_key());
        assert_eq!(batches[0].events.len(), 3);
        assert_eq!(batches[0].relay_hints.len(), 1);
    }

    #[test]
    fn test_build_notification_batches_groups_by_server_and_collects_relay_hints() {
        let first_server = Keys::generate();
        let second_server = Keys::generate();
        let tokens = vec![
            make_token_tag(first_server.public_key(), "wss://relay.one.example", 1),
            make_token_tag(first_server.public_key(), "wss://relay.two.example", 2),
            make_token_tag(first_server.public_key(), "wss://relay.one.example", 3),
            make_token_tag(second_server.public_key(), "wss://relay.three.example", 4),
        ];

        let batches = build_notification_batches(tokens).unwrap();
        let first_batch = batches
            .iter()
            .find(|batch| batch.server_pubkey == first_server.public_key())
            .unwrap();
        let second_batch = batches
            .iter()
            .find(|batch| batch.server_pubkey == second_server.public_key())
            .unwrap();

        assert_eq!(batches.len(), 2);
        assert_eq!(first_batch.relay_hints.len(), 2);
        assert_eq!(second_batch.relay_hints.len(), 1);
        assert_eq!(first_batch.events.len(), 1);
        assert_eq!(second_batch.events.len(), 1);
    }

    #[tokio::test]
    async fn test_build_notification_batches_roundtrip_with_gift_wrap() {
        let server_keys = Keys::generate();
        let tokens = vec![
            make_token_tag(server_keys.public_key(), "wss://relay.one.example", 9),
            make_token_tag(server_keys.public_key(), "wss://relay.two.example", 10),
        ];

        let batches = build_notification_batches(tokens.clone()).unwrap();

        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].events.len(), 1);
        assert_eq!(batches[0].server_pubkey, server_keys.public_key());
        assert_eq!(batches[0].events[0].kind, Kind::GiftWrap);

        let receiver_tag = batches[0].events[0]
            .tags
            .iter()
            .find_map(|tag| match tag.as_standardized() {
                Some(TagStandard::PublicKey {
                    public_key,
                    relay_url: None,
                    alias: None,
                    uppercase: false,
                }) => Some(*public_key),
                _ => None,
            })
            .unwrap();
        assert_eq!(receiver_tag, server_keys.public_key());

        let unwrapped = nip59::extract_rumor(&server_keys, &batches[0].events[0])
            .await
            .unwrap();
        let parsed = parse_notification_request_rumor(&unwrapped.rumor).unwrap();

        assert_eq!(
            parsed.tokens,
            tokens
                .iter()
                .map(|token| token.encrypted_token.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(unwrapped.rumor.pubkey, unwrapped.sender);
    }
}
