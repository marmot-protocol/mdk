use std::collections::BTreeSet;

use nostr::{EventId, Kind, RelayUrl, Tag, TagKind, Timestamp, UnsignedEvent};

use mdk_storage_traits::messages::types as message_types;

use super::{
    LeafTokenTag, Mip05Error, Mip05GroupMessage, TOKEN_LIST_RESPONSE_KIND, TOKEN_REMOVAL_KIND,
    TOKEN_REQUEST_KIND, TOKEN_TAG_NAME, TokenListResponse, TokenRemoval, TokenRequest, TokenTag,
};

/// Build an unsigned `kind:447` MIP-05 token request rumor.
pub fn build_token_request_rumor(
    pubkey: nostr::PublicKey,
    created_at: Timestamp,
    tokens: Vec<TokenTag>,
) -> Result<UnsignedEvent, Mip05Error> {
    if tokens.is_empty() {
        return Err(Mip05Error::TokenRequestMustIncludeToken);
    }

    let mut rumor = UnsignedEvent::new(
        pubkey,
        created_at,
        Kind::from(TOKEN_REQUEST_KIND),
        build_token_request_tags(tokens),
        String::new(),
    );
    rumor.ensure_id();
    Ok(rumor)
}

/// Build an unsigned `kind:448` MIP-05 token list response rumor.
pub fn build_token_list_response_rumor(
    pubkey: nostr::PublicKey,
    created_at: Timestamp,
    request_event_id: EventId,
    tokens: Vec<LeafTokenTag>,
) -> Result<UnsignedEvent, Mip05Error> {
    if tokens.is_empty() {
        return Err(Mip05Error::TokenListResponseMustIncludeToken);
    }
    validate_unique_leaf_indices(&tokens)?;

    let mut tags = build_token_list_response_tags(tokens);
    tags.push(Tag::custom(TagKind::e(), [request_event_id.to_hex()]));

    let mut rumor = UnsignedEvent::new(
        pubkey,
        created_at,
        Kind::from(TOKEN_LIST_RESPONSE_KIND),
        tags,
        String::new(),
    );
    rumor.ensure_id();
    Ok(rumor)
}

/// Build an unsigned `kind:449` MIP-05 token removal rumor.
pub fn build_token_removal_rumor(
    pubkey: nostr::PublicKey,
    created_at: Timestamp,
) -> Result<UnsignedEvent, Mip05Error> {
    let mut rumor = UnsignedEvent::new(
        pubkey,
        created_at,
        Kind::from(TOKEN_REMOVAL_KIND),
        vec![],
        String::new(),
    );
    rumor.ensure_id();
    Ok(rumor)
}

/// Parse an MIP-05 rumor from a stored processed message.
pub fn parse_group_message(
    message: &message_types::Message,
) -> Result<Mip05GroupMessage, Mip05Error> {
    parse_group_message_rumor(&message.event)
}

/// Parse an MIP-05 token-distribution rumor.
pub fn parse_group_message_rumor(event: &UnsignedEvent) -> Result<Mip05GroupMessage, Mip05Error> {
    match event.kind {
        kind if kind == Kind::from(TOKEN_REQUEST_KIND) => Ok(Mip05GroupMessage::TokenRequest(
            parse_token_request_rumor(event)?,
        )),
        kind if kind == Kind::from(TOKEN_LIST_RESPONSE_KIND) => Ok(
            Mip05GroupMessage::TokenListResponse(parse_token_list_response_rumor(event)?),
        ),
        kind if kind == Kind::from(TOKEN_REMOVAL_KIND) => Ok(Mip05GroupMessage::TokenRemoval(
            parse_token_removal_rumor(event)?,
        )),
        _ => Err(Mip05Error::UnexpectedRumorKind),
    }
}

fn parse_token_request_rumor(event: &UnsignedEvent) -> Result<TokenRequest, Mip05Error> {
    validate_exact_kind(event, TOKEN_REQUEST_KIND)?;
    validate_empty_content(event)?;

    let mut tokens = Vec::new();
    for tag in event.tags.iter() {
        match tag.kind() {
            TagKind::Custom(name) if name.as_ref() == TOKEN_TAG_NAME => {
                tokens.push(parse_token_tag(tag)?);
            }
            _ => return Err(Mip05Error::UnsupportedTokenRequestTags),
        }
    }

    if tokens.is_empty() {
        return Err(Mip05Error::TokenRequestMustIncludeToken);
    }

    Ok(TokenRequest { tokens })
}

fn parse_token_list_response_rumor(event: &UnsignedEvent) -> Result<TokenListResponse, Mip05Error> {
    validate_exact_kind(event, TOKEN_LIST_RESPONSE_KIND)?;
    validate_empty_content(event)?;

    let mut tokens = Vec::new();
    let mut request_event_id = None;

    for tag in event.tags.iter() {
        match tag.kind() {
            TagKind::Custom(name) if name.as_ref() == TOKEN_TAG_NAME => {
                tokens.push(parse_leaf_token_tag(tag)?);
            }
            kind if kind == TagKind::e() => {
                if request_event_id.is_some() {
                    return Err(Mip05Error::TokenListResponseMustContainSingleEventReference);
                }
                request_event_id = Some(parse_event_reference(tag)?);
            }
            _ => return Err(Mip05Error::UnsupportedTokenListResponseTags),
        }
    }

    if tokens.is_empty() {
        return Err(Mip05Error::TokenListResponseMustIncludeToken);
    }

    validate_unique_leaf_indices(&tokens)?;

    Ok(TokenListResponse {
        request_event_id: request_event_id
            .ok_or(Mip05Error::TokenListResponseMustContainSingleEventReference)?,
        tokens,
    })
}

fn parse_token_removal_rumor(event: &UnsignedEvent) -> Result<TokenRemoval, Mip05Error> {
    validate_exact_kind(event, TOKEN_REMOVAL_KIND)?;
    validate_empty_content(event)?;

    if !event.tags.is_empty() {
        return Err(Mip05Error::TokenRemovalMustNotContainTags);
    }

    Ok(TokenRemoval)
}

fn build_token_request_tags(tokens: Vec<TokenTag>) -> Vec<Tag> {
    tokens.into_iter().map(build_token_tag).collect()
}

fn build_token_list_response_tags(tokens: Vec<LeafTokenTag>) -> Vec<Tag> {
    tokens.into_iter().map(build_leaf_token_tag).collect()
}

fn build_token_tag(token: TokenTag) -> Tag {
    Tag::custom(
        TagKind::Custom(TOKEN_TAG_NAME.into()),
        [
            token.encrypted_token.to_base64(),
            token.server_pubkey.to_hex(),
            token.relay_hint.to_string(),
        ],
    )
}

fn build_leaf_token_tag(token: LeafTokenTag) -> Tag {
    Tag::custom(
        TagKind::Custom(TOKEN_TAG_NAME.into()),
        [
            token.token_tag.encrypted_token.to_base64(),
            token.token_tag.server_pubkey.to_hex(),
            token.token_tag.relay_hint.to_string(),
            token.leaf_index.to_string(),
        ],
    )
}

fn parse_token_tag(tag: &Tag) -> Result<TokenTag, Mip05Error> {
    let values = tag.as_slice();
    if values.len() != 4 {
        return Err(Mip05Error::InvalidTokenTagShape);
    }

    Ok(TokenTag {
        encrypted_token: super::EncryptedToken::from_base64(&values[1])?,
        server_pubkey: nostr::PublicKey::from_hex(&values[2])
            .map_err(|_| Mip05Error::InvalidNotificationServerPublicKey)?,
        relay_hint: RelayUrl::parse(&values[3])
            .map_err(|_| Mip05Error::InvalidNotificationRelayHint)?,
    })
}

fn parse_leaf_token_tag(tag: &Tag) -> Result<LeafTokenTag, Mip05Error> {
    let values = tag.as_slice();
    if values.len() != 5 {
        return Err(Mip05Error::InvalidTokenTagShape);
    }

    let token_tag = TokenTag {
        encrypted_token: super::EncryptedToken::from_base64(&values[1])?,
        server_pubkey: nostr::PublicKey::from_hex(&values[2])
            .map_err(|_| Mip05Error::InvalidNotificationServerPublicKey)?,
        relay_hint: RelayUrl::parse(&values[3])
            .map_err(|_| Mip05Error::InvalidNotificationRelayHint)?,
    };
    let leaf_index = values[4]
        .parse::<u32>()
        .map_err(|_| Mip05Error::InvalidLeafIndex)?;

    Ok(LeafTokenTag {
        token_tag,
        leaf_index,
    })
}

fn parse_event_reference(tag: &Tag) -> Result<EventId, Mip05Error> {
    let event_id = tag.content().ok_or(Mip05Error::MissingEventReference)?;
    EventId::from_hex(event_id).map_err(|_| Mip05Error::InvalidEventReference)
}

fn validate_empty_content(event: &UnsignedEvent) -> Result<(), Mip05Error> {
    if !event.content.is_empty() {
        return Err(Mip05Error::NonEmptyContent);
    }
    Ok(())
}

fn validate_exact_kind(event: &UnsignedEvent, expected_kind: u16) -> Result<(), Mip05Error> {
    if event.kind != Kind::from(expected_kind) {
        return Err(Mip05Error::UnexpectedRumorKind);
    }
    Ok(())
}

fn validate_unique_leaf_indices(tokens: &[LeafTokenTag]) -> Result<(), Mip05Error> {
    let unique_leaf_indices: BTreeSet<u32> = tokens.iter().map(|token| token.leaf_index).collect();
    if unique_leaf_indices.len() != tokens.len() {
        return Err(Mip05Error::DuplicateLeafIndex);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use nostr::{Keys, Timestamp};

    use super::*;
    use crate::mip05::ENCRYPTED_TOKEN_LEN;

    #[test]
    fn test_build_and_parse_token_request_rumor() {
        let sender_keys = Keys::generate();
        let relay_hint = RelayUrl::parse("wss://relay.example.com").unwrap();
        let rumor = build_token_request_rumor(
            sender_keys.public_key(),
            Timestamp::from(123u64),
            vec![TokenTag {
                encrypted_token: super::super::EncryptedToken::from([1u8; ENCRYPTED_TOKEN_LEN]),
                server_pubkey: Keys::generate().public_key(),
                relay_hint: relay_hint.clone(),
            }],
        )
        .unwrap();

        let parsed = parse_group_message_rumor(&rumor).unwrap();
        match parsed {
            Mip05GroupMessage::TokenRequest(request) => {
                assert_eq!(request.tokens.len(), 1);
                assert_eq!(request.tokens[0].relay_hint, relay_hint);
            }
            _ => panic!("Expected token request"),
        }
    }

    #[test]
    fn test_build_and_parse_token_list_response_rumor() {
        let sender_keys = Keys::generate();
        let request_event_id =
            EventId::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        let relay_hint = RelayUrl::parse("wss://relay.example.com").unwrap();
        let rumor = build_token_list_response_rumor(
            sender_keys.public_key(),
            Timestamp::from(456u64),
            request_event_id,
            vec![LeafTokenTag {
                token_tag: TokenTag {
                    encrypted_token: super::super::EncryptedToken::from([2u8; ENCRYPTED_TOKEN_LEN]),
                    server_pubkey: Keys::generate().public_key(),
                    relay_hint: relay_hint.clone(),
                },
                leaf_index: 7,
            }],
        )
        .unwrap();

        let parsed = parse_group_message_rumor(&rumor).unwrap();
        match parsed {
            Mip05GroupMessage::TokenListResponse(response) => {
                assert_eq!(response.request_event_id, request_event_id);
                assert_eq!(response.tokens.len(), 1);
                assert_eq!(response.tokens[0].leaf_index, 7);
                assert_eq!(response.tokens[0].token_tag.relay_hint, relay_hint);
            }
            _ => panic!("Expected token list response"),
        }
    }

    #[test]
    fn test_parse_group_message_from_stored_message() {
        let sender_keys = Keys::generate();
        let mut rumor =
            build_token_removal_rumor(sender_keys.public_key(), Timestamp::from(789u64)).unwrap();
        let message = message_types::Message {
            id: rumor.id(),
            pubkey: rumor.pubkey,
            kind: rumor.kind,
            mls_group_id: mdk_storage_traits::GroupId::from_slice(&[1, 2, 3, 4]),
            created_at: rumor.created_at,
            processed_at: Timestamp::from(790u64),
            content: rumor.content.clone(),
            tags: rumor.tags.clone(),
            event: rumor,
            wrapper_event_id: EventId::all_zeros(),
            epoch: Some(1),
            state: message_types::MessageState::Processed,
        };

        let parsed = parse_group_message(&message).unwrap();
        assert!(matches!(
            parsed,
            Mip05GroupMessage::TokenRemoval(TokenRemoval)
        ));
    }

    #[test]
    fn test_parse_token_list_response_rejects_duplicate_leaf_indices() {
        let sender_keys = Keys::generate();
        let server_pubkey = Keys::generate().public_key();
        let relay_hint = RelayUrl::parse("wss://relay.example.com").unwrap();
        let request_event_id =
            EventId::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap();
        let rumor = build_token_list_response_rumor(
            sender_keys.public_key(),
            Timestamp::from(456u64),
            request_event_id,
            vec![
                LeafTokenTag {
                    token_tag: TokenTag {
                        encrypted_token: super::super::EncryptedToken::from(
                            [3u8; ENCRYPTED_TOKEN_LEN],
                        ),
                        server_pubkey,
                        relay_hint: relay_hint.clone(),
                    },
                    leaf_index: 4,
                },
                LeafTokenTag {
                    token_tag: TokenTag {
                        encrypted_token: super::super::EncryptedToken::from(
                            [4u8; ENCRYPTED_TOKEN_LEN],
                        ),
                        server_pubkey,
                        relay_hint,
                    },
                    leaf_index: 4,
                },
            ],
        );

        assert!(matches!(rumor, Err(Mip05Error::DuplicateLeafIndex)));
    }

    #[test]
    fn test_parse_token_request_rejects_non_empty_content() {
        let relay_hint = RelayUrl::parse("wss://relay.example.com").unwrap();
        let mut rumor = build_token_request_rumor(
            Keys::generate().public_key(),
            Timestamp::from(123u64),
            vec![TokenTag {
                encrypted_token: super::super::EncryptedToken::from([5u8; ENCRYPTED_TOKEN_LEN]),
                server_pubkey: Keys::generate().public_key(),
                relay_hint,
            }],
        )
        .unwrap();
        rumor.content = "not-empty".to_string();

        assert!(matches!(
            parse_group_message_rumor(&rumor),
            Err(Mip05Error::NonEmptyContent)
        ));
    }
}
