//! MIP-05 push-token exchange primitives and helpers.
//!
//! This module provides the protocol-level MIP-05 building blocks that clients
//! need for interoperable token exchange.

mod crypto;
mod error;
mod notifications;
mod rumors;
mod types;

pub use self::crypto::{decrypt_push_token, encrypt_push_token};
pub use self::error::Mip05Error;
pub use self::notifications::{
    build_notification_batches, build_notification_request_rumor, parse_notification_request_rumor,
};
pub use self::rumors::{
    build_token_list_response_rumor, build_token_removal_rumor, build_token_request_rumor,
    parse_group_message, parse_group_message_rumor,
};
pub use self::types::{
    EncryptedToken, LeafTokenTag, Mip05GroupMessage, NotificationEventBatch, NotificationPlatform,
    NotificationRequest, PushTokenPlaintext, TokenListResponse, TokenRemoval, TokenRequest,
    TokenTag,
};

/// MIP-05 `kind:446` notification request rumor.
pub const NOTIFICATION_REQUEST_KIND: u16 = 446;
/// MIP-05 `kind:447` token request rumor.
pub const TOKEN_REQUEST_KIND: u16 = 447;
/// MIP-05 `kind:448` token list response rumor.
pub const TOKEN_LIST_RESPONSE_KIND: u16 = 448;
/// MIP-05 `kind:449` token removal rumor.
pub const TOKEN_REMOVAL_KIND: u16 = 449;

/// Recommended maximum number of encrypted tokens per notification request.
pub const MAX_NOTIFICATION_REQUEST_TOKENS: usize = 100;

/// MIP-05 padded token plaintext length.
pub const TOKEN_PLAINTEXT_LEN: usize = 220;
/// MIP-05 encrypted token length.
pub const ENCRYPTED_TOKEN_LEN: usize = 280;

pub(crate) const EPHEMERAL_PUBKEY_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 12;
// ChaCha20-Poly1305 authentication tag length.
pub(crate) const AEAD_TAG_LEN: usize = 16;
pub(crate) const TOKEN_CIPHERTEXT_LEN: usize = TOKEN_PLAINTEXT_LEN + AEAD_TAG_LEN;

const _: [(); ENCRYPTED_TOKEN_LEN] = [(); EPHEMERAL_PUBKEY_LEN + NONCE_LEN + TOKEN_CIPHERTEXT_LEN];

pub(crate) const TOKEN_TAG_NAME: &str = "token";
pub(crate) const TOKEN_ENCRYPTION_SALT: &[u8] = b"mip05-v1";
pub(crate) const TOKEN_ENCRYPTION_INFO: &[u8] = b"mip05-token-encryption";
pub(crate) const NOTIFICATION_REQUEST_VERSION: &str = "mip05-v1";
pub(crate) const VERSION_TAG_NAME: &str = "v";
pub(crate) const ENCODING_TAG_NAME: &str = "encoding";
pub(crate) const BASE64_ENCODING: &str = "base64";
