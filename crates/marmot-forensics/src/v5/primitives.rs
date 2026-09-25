//! Typed diagnostic identities and precision-preserving numbers.
use super::ContractError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn lower_hex(value: &str, lengths: &[usize]) -> bool {
    lengths.contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

macro_rules! text_type {
    ($name:ident, $valid:expr) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl TryFrom<String> for $name {
            type Error = ContractError;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                if ($valid)(&value) {
                    Ok(Self(value))
                } else {
                    Err(ContractError::new("invalid ", stringify!($name)))
                }
            }
        }
        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}
text_type!(SourceRef, |s: &str| lower_hex(s, &[32]));
text_type!(SessionId, |s: &str| lower_hex(s, &[32]));
text_type!(LocalId, |s: &str| lower_hex(s, &[32]));
text_type!(GroupRef, |s: &str| lower_hex(s, &[64]));
text_type!(MemberRef, |s: &str| lower_hex(s, &[64]));
text_type!(NostrEventRef, |s: &str| lower_hex(s, &[64]));
text_type!(EngineMessageRef, |s: &str| lower_hex(s, &[64]));
text_type!(EndpointRef, |s: &str| lower_hex(s, &[64]));
text_type!(Revision, |s: &str| lower_hex(s, &[40, 64]));
text_type!(BuildToken, |s: &str| !s.is_empty()
    && s.len() <= 64
    && s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)));
text_type!(U64String, |s: &str| s
    .parse::<u64>()
    .is_ok_and(|v| v.to_string() == s));
text_type!(I64String, |s: &str| s
    .parse::<i64>()
    .is_ok_and(|v| v.to_string() == s));

impl U64String {
    pub fn get(&self) -> u64 {
        self.0.parse().expect("validated u64")
    }
}
impl From<u64> for U64String {
    fn from(value: u64) -> Self {
        Self(value.to_string())
    }
}
impl From<i64> for I64String {
    fn from(value: i64) -> Self {
        Self(value.to_string())
    }
}

fn reference(kind: &str, bytes: &[u8]) -> Result<String, ContractError> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| ContractError::rule("reference input exceeds u32"))?;
    if bytes.is_empty() {
        return Err(ContractError::rule("empty reference input"));
    }
    let mut hash = Sha256::new();
    hash.update(b"marmot-audit-ref/v5\0");
    hash.update(kind.as_bytes());
    hash.update([0]);
    hash.update(length.to_be_bytes());
    hash.update(bytes);
    Ok(hex::encode(hash.finalize()))
}
impl GroupRef {
    /// Caller supplies the MLS group ID, which is variable-length (not a Nostr route ID).
    pub fn from_group_id(bytes: &[u8]) -> Result<Self, ContractError> {
        reference("group", bytes).map(Self)
    }
}
impl MemberRef {
    /// Caller supplies a validated public member identity, never key material.
    pub fn from_member_identity(bytes: &[u8]) -> Result<Self, ContractError> {
        reference("member", bytes).map(Self)
    }
}
impl NostrEventRef {
    /// Caller must validate the event hash first. This helper does not authenticate an event.
    pub fn from_validated_event_id(bytes: &[u8; 32]) -> Self {
        Self(reference("nostr_event", bytes).expect("fixed length"))
    }
}
impl EngineMessageRef {
    pub fn from_message_id(bytes: &[u8]) -> Result<Self, ContractError> {
        reference("engine_message", bytes).map(Self)
    }
}
impl EndpointRef {
    /// Hash a caller-normalized endpoint. No URL parser/transport dependency lives here.
    /// The Nostr owner must use RelayUrl -> url::Url -> to_string, preserving path/query.
    pub fn from_normalized_url(url: &str) -> Result<Self, ContractError> {
        reference("endpoint", url.as_bytes()).map(Self)
    }
}
