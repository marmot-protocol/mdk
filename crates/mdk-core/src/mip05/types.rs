use std::fmt;

use base64::Engine;
use nostr::{Event, EventId, PublicKey, RelayUrl};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{ENCRYPTED_TOKEN_LEN, Mip05Error, TOKEN_PLAINTEXT_LEN};

/// Supported push-notification platforms for MIP-05.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotificationPlatform {
    /// Apple Push Notification service.
    Apns,
    /// Firebase Cloud Messaging.
    Fcm,
}

impl NotificationPlatform {
    /// Convert the platform to the wire-format byte value.
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Apns => 0x01,
            Self::Fcm => 0x02,
        }
    }

    /// Parse a platform from its wire-format byte value.
    pub fn from_byte(value: u8) -> Result<Self, Mip05Error> {
        match value {
            0x01 => Ok(Self::Apns),
            0x02 => Ok(Self::Fcm),
            _ => Err(Mip05Error::InvalidNotificationPlatform),
        }
    }

    pub(crate) fn validate_device_token_len(self, len: usize) -> Result<(), Mip05Error> {
        match self {
            Self::Apns if len == 32 => Ok(()),
            Self::Fcm if (1..=200).contains(&len) => Ok(()),
            Self::Apns => Err(Mip05Error::InvalidApnsTokenLength),
            Self::Fcm => Err(Mip05Error::InvalidFcmTokenLength),
        }
    }
}

/// Parsed MIP-05 token plaintext.
#[derive(Clone, PartialEq, Eq, Hash, Zeroize, ZeroizeOnDrop)]
pub struct PushTokenPlaintext {
    #[zeroize(skip)]
    platform: NotificationPlatform,
    device_token: Vec<u8>,
}

impl PushTokenPlaintext {
    /// Construct a validated token plaintext.
    pub fn new(platform: NotificationPlatform, device_token: Vec<u8>) -> Result<Self, Mip05Error> {
        platform.validate_device_token_len(device_token.len())?;
        Ok(Self {
            platform,
            device_token,
        })
    }

    /// Get the platform identifier.
    pub const fn platform(&self) -> NotificationPlatform {
        self.platform
    }

    /// Get the raw device token bytes.
    pub fn device_token(&self) -> &[u8] {
        &self.device_token
    }

    pub(crate) fn encode_padded(
        &self,
        padding: &[u8],
    ) -> Result<[u8; TOKEN_PLAINTEXT_LEN], Mip05Error> {
        let padding_len = TOKEN_PLAINTEXT_LEN
            .checked_sub(3 + self.device_token.len())
            .ok_or(Mip05Error::InvalidTokenPaddingLength)?;
        if padding.len() != padding_len {
            return Err(Mip05Error::InvalidTokenPaddingLength);
        }

        let token_len_u16 =
            u16::try_from(self.device_token.len()).map_err(|_| Mip05Error::DeviceTokenTooLarge)?;
        let mut bytes = [0u8; TOKEN_PLAINTEXT_LEN];
        bytes[0] = self.platform.as_byte();
        bytes[1..3].copy_from_slice(&token_len_u16.to_be_bytes());
        bytes[3..3 + self.device_token.len()].copy_from_slice(&self.device_token);
        bytes[3 + self.device_token.len()..].copy_from_slice(padding);
        Ok(bytes)
    }

    pub(crate) fn from_padded_slice(bytes: &[u8]) -> Result<Self, Mip05Error> {
        if bytes.len() != TOKEN_PLAINTEXT_LEN {
            return Err(Mip05Error::InvalidTokenPlaintextLength);
        }

        let platform = NotificationPlatform::from_byte(bytes[0])?;
        let token_len = usize::from(u16::from_be_bytes([bytes[1], bytes[2]]));
        platform.validate_device_token_len(token_len)?;

        let token_end = 3 + token_len;
        if token_end > TOKEN_PLAINTEXT_LEN {
            return Err(Mip05Error::InvalidTokenLength);
        }

        Self::new(platform, bytes[3..token_end].to_vec())
    }
}

impl fmt::Debug for PushTokenPlaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushTokenPlaintext")
            .field("platform", &self.platform)
            .field("device_token_len", &self.device_token.len())
            .finish()
    }
}

/// Fixed-size encrypted MIP-05 token.
#[derive(Clone, PartialEq, Eq, Hash, Zeroize, ZeroizeOnDrop)]
pub struct EncryptedToken([u8; ENCRYPTED_TOKEN_LEN]);

impl EncryptedToken {
    /// Parse an encrypted token from raw bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Mip05Error> {
        let token: [u8; ENCRYPTED_TOKEN_LEN] = bytes
            .try_into()
            .map_err(|_| Mip05Error::InvalidEncryptedTokenLength)?;
        Ok(Self(token))
    }

    /// Parse an encrypted token from RFC 4648 base64.
    pub fn from_base64(value: &str) -> Result<Self, Mip05Error> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|_| Mip05Error::InvalidEncryptedTokenBase64)?;
        Self::from_slice(&bytes)
    }

    /// Return the token as raw bytes.
    pub fn as_bytes(&self) -> &[u8; ENCRYPTED_TOKEN_LEN] {
        &self.0
    }

    /// Encode the token as RFC 4648 base64.
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }
}

impl From<[u8; ENCRYPTED_TOKEN_LEN]> for EncryptedToken {
    fn from(value: [u8; ENCRYPTED_TOKEN_LEN]) -> Self {
        Self(value)
    }
}

impl fmt::Debug for EncryptedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedToken")
            .field("len", &ENCRYPTED_TOKEN_LEN)
            .finish()
    }
}

/// Shared `token` tag payload for MIP-05 token exchange events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenTag {
    /// The encrypted token payload.
    pub encrypted_token: EncryptedToken,
    /// The notification server public key used for encryption.
    pub server_pubkey: PublicKey,
    /// A relay hint where the server's `kind:10050` event can be found.
    pub relay_hint: RelayUrl,
}

/// A `token` tag payload with an explicit MLS leaf index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafTokenTag {
    /// The common token-tag payload.
    pub token_tag: TokenTag,
    /// The owning MLS leaf index.
    pub leaf_index: u32,
}

/// Typed representation of a `kind:447` token request rumor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRequest {
    /// Tokens advertised by the requesting device.
    pub tokens: Vec<TokenTag>,
}

/// Typed representation of a `kind:448` token list response rumor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenListResponse {
    /// The `kind:447` rumor this response references.
    pub request_event_id: EventId,
    /// Known tokens for active group leaves.
    pub tokens: Vec<LeafTokenTag>,
}

/// Typed representation of a `kind:449` token removal rumor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct TokenRemoval;

/// Typed representation of MIP-05 MLS application-message rumors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mip05GroupMessage {
    /// A `kind:447` token request.
    TokenRequest(TokenRequest),
    /// A `kind:448` token list response.
    TokenListResponse(TokenListResponse),
    /// A `kind:449` token removal.
    TokenRemoval(TokenRemoval),
}

/// Typed representation of a `kind:446` notification request rumor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationRequest {
    /// Concatenated encrypted push tokens carried by the rumor.
    pub tokens: Vec<EncryptedToken>,
}

/// Ready-to-publish notification requests for a single notification server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationEventBatch {
    /// The notification server receiving these requests.
    pub server_pubkey: PublicKey,
    /// Relay hints seen on the source token tags for this server.
    pub relay_hints: Vec<RelayUrl>,
    /// Gift-wrapped `kind:1059` events ready to publish.
    pub events: Vec<Event>,
}

#[cfg(test)]
mod tests {
    use nostr::Keys;

    use super::*;

    #[test]
    fn test_push_token_plaintext_validates_platform_lengths() {
        assert!(PushTokenPlaintext::new(NotificationPlatform::Apns, vec![0u8; 32]).is_ok());
        assert!(PushTokenPlaintext::new(NotificationPlatform::Fcm, vec![0u8; 1]).is_ok());
        assert!(PushTokenPlaintext::new(NotificationPlatform::Fcm, vec![0u8; 200]).is_ok());

        assert!(PushTokenPlaintext::new(NotificationPlatform::Apns, vec![0u8; 31]).is_err());
        assert!(PushTokenPlaintext::new(NotificationPlatform::Fcm, vec![]).is_err());
        assert!(PushTokenPlaintext::new(NotificationPlatform::Fcm, vec![0u8; 201]).is_err());
    }

    #[test]
    fn test_push_token_plaintext_roundtrip_from_padded_slice() {
        let plaintext = PushTokenPlaintext::new(NotificationPlatform::Fcm, vec![7u8; 10]).unwrap();
        let padding = vec![9u8; TOKEN_PLAINTEXT_LEN - 13];
        let encoded = plaintext.encode_padded(&padding).unwrap();
        let decoded = PushTokenPlaintext::from_padded_slice(&encoded).unwrap();

        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn test_encrypted_token_base64_roundtrip() {
        let token = EncryptedToken::from([5u8; ENCRYPTED_TOKEN_LEN]);
        let encoded = token.to_base64();
        let decoded = EncryptedToken::from_base64(&encoded).unwrap();

        assert_eq!(decoded, token);
    }

    #[test]
    fn test_token_tag_types_are_constructible() {
        let server_keys = Keys::generate();
        let relay_hint = RelayUrl::parse("wss://relay.example.com").unwrap();
        let token_tag = TokenTag {
            encrypted_token: EncryptedToken::from([1u8; ENCRYPTED_TOKEN_LEN]),
            server_pubkey: server_keys.public_key(),
            relay_hint,
        };

        let leaf_token_tag = LeafTokenTag {
            token_tag: token_tag.clone(),
            leaf_index: 4,
        };

        assert_eq!(leaf_token_tag.token_tag, token_tag);
        assert_eq!(leaf_token_tag.leaf_index, 4);
    }

    #[test]
    fn test_push_token_plaintext_zeroize_clears_device_token() {
        let mut plaintext =
            PushTokenPlaintext::new(NotificationPlatform::Fcm, vec![7u8; 10]).unwrap();

        plaintext.zeroize();

        assert!(plaintext.device_token().is_empty());
    }

    #[test]
    fn test_encrypted_token_zeroize_clears_bytes() {
        let mut token = EncryptedToken::from([5u8; ENCRYPTED_TOKEN_LEN]);

        token.zeroize();

        assert_eq!(token.as_bytes(), &[0u8; ENCRYPTED_TOKEN_LEN]);
    }
}
