use thiserror::Error;

/// Errors that can occur while building, parsing, encrypting, or decrypting
/// MIP-05 protocol objects.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Mip05Error {
    /// Notification platform byte is not recognized.
    #[error("invalid notification platform")]
    InvalidNotificationPlatform,
    /// APNs device tokens must be exactly 32 bytes.
    #[error("APNs tokens must be exactly 32 bytes")]
    InvalidApnsTokenLength,
    /// FCM device tokens must be between 1 and 200 bytes.
    #[error("FCM tokens must be between 1 and 200 bytes")]
    InvalidFcmTokenLength,
    /// Padded plaintext or caller-provided padding length is invalid.
    #[error("invalid MIP-05 token padding length")]
    InvalidTokenPaddingLength,
    /// Device token length cannot fit the encoded wire format.
    #[error("device token is too large")]
    DeviceTokenTooLarge,
    /// Padded token plaintext is not 220 bytes.
    #[error("invalid MIP-05 token plaintext length")]
    InvalidTokenPlaintextLength,
    /// Token length field is invalid for the declared platform.
    #[error("invalid MIP-05 token length")]
    InvalidTokenLength,
    /// Encrypted token is not the required 280-byte size.
    #[error("invalid encrypted token length")]
    InvalidEncryptedTokenLength,
    /// Encrypted token base64 is malformed.
    #[error("invalid encrypted token base64")]
    InvalidEncryptedTokenBase64,
    /// Embedded ephemeral public key is malformed.
    #[error("invalid encrypted token public key")]
    InvalidEncryptedTokenPublicKey,
    /// Embedded nonce is malformed.
    #[error("invalid encrypted token nonce")]
    InvalidEncryptedTokenNonce,
    /// Exact MIP-05 key derivation failed.
    #[error("failed to derive MIP-05 encryption key")]
    KeyDerivationFailed,
    /// Push-token encryption failed.
    #[error("failed to encrypt push token")]
    EncryptionFailed,
    /// Push-token decryption failed.
    #[error("failed to decrypt encrypted token")]
    DecryptionFailed,
    /// Ciphertext size did not match the required wire format.
    #[error("invalid encrypted token ciphertext length")]
    InvalidCiphertextLength,
    /// Rumor kind was not one of the supported MIP-05 kinds.
    #[error("unsupported MIP-05 rumor kind")]
    UnexpectedRumorKind,
    /// MIP-05 rumors must carry empty content.
    #[error("MIP-05 rumors must have empty content")]
    NonEmptyContent,
    /// `kind:447` must include at least one token tag.
    #[error("token request must include at least one token")]
    TokenRequestMustIncludeToken,
    /// `kind:447` contained unsupported tags.
    #[error("token request contains unsupported tags")]
    UnsupportedTokenRequestTags,
    /// `kind:448` must include at least one token tag.
    #[error("token list response must include at least one token")]
    TokenListResponseMustIncludeToken,
    /// `kind:448` must contain exactly one event reference tag.
    #[error("token list response must contain exactly one event reference")]
    TokenListResponseMustContainSingleEventReference,
    /// `kind:448` contained unsupported tags.
    #[error("token list response contains unsupported tags")]
    UnsupportedTokenListResponseTags,
    /// `kind:449` must not contain any tags.
    #[error("token removal rumors must not contain tags")]
    TokenRemovalMustNotContainTags,
    /// A `token` tag was malformed.
    #[error("invalid token tag shape")]
    InvalidTokenTagShape,
    /// Notification server pubkey inside a `token` tag was invalid.
    #[error("invalid notification server public key")]
    InvalidNotificationServerPublicKey,
    /// Relay hint inside a `token` tag was invalid.
    #[error("invalid notification relay hint")]
    InvalidNotificationRelayHint,
    /// Leaf index inside a `token` tag was invalid.
    #[error("invalid MIP-05 leaf index")]
    InvalidLeafIndex,
    /// Multiple token tags claimed the same leaf index.
    #[error("duplicate MIP-05 leaf index")]
    DuplicateLeafIndex,
    /// Required event reference tag was missing.
    #[error("missing event reference")]
    MissingEventReference,
    /// Event reference tag was malformed.
    #[error("invalid event reference")]
    InvalidEventReference,
    /// `kind:446` must include at least one encrypted token.
    #[error("notification request must include at least one token")]
    NotificationRequestMustIncludeToken,
    /// `kind:446` content was not valid base64.
    #[error("invalid notification request base64 content")]
    InvalidNotificationRequestBase64,
    /// `kind:446` content did not split cleanly into encrypted tokens.
    #[error("invalid notification request content length")]
    InvalidNotificationRequestContentLength,
    /// `kind:446` was missing the required version tag.
    #[error("missing notification request version tag")]
    MissingNotificationRequestVersionTag,
    /// `kind:446` used an unsupported version tag value.
    #[error("invalid notification request version tag")]
    InvalidNotificationRequestVersionTag,
    /// `kind:446` contained more than one version tag.
    #[error("duplicate notification request version tag")]
    DuplicateNotificationRequestVersionTag,
    /// `kind:446` was missing the required encoding tag.
    #[error("missing notification request encoding tag")]
    MissingNotificationRequestEncodingTag,
    /// `kind:446` used an unsupported encoding tag value.
    #[error("invalid notification request encoding tag")]
    InvalidNotificationRequestEncodingTag,
    /// `kind:446` contained more than one encoding tag.
    #[error("duplicate notification request encoding tag")]
    DuplicateNotificationRequestEncodingTag,
    /// `kind:446` contained unsupported tags.
    #[error("notification request contains unsupported tags")]
    UnsupportedNotificationRequestTags,
    /// A notification request batch contained duplicate encrypted tokens.
    #[error("duplicate encrypted token in notification request batch")]
    DuplicateEncryptedToken,
    /// NIP-44 encryption for the notification request failed.
    #[error("failed to encrypt notification request")]
    NotificationRequestEncryptionFailed,
    /// The intermediate NIP-59 seal could not be signed.
    #[error("failed to sign notification request seal")]
    NotificationRequestSealFailed,
    /// The outer gift wrap event could not be constructed.
    #[error("failed to build notification request gift wrap")]
    NotificationRequestGiftWrapFailed,
}
