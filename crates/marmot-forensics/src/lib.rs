use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const FORENSICS_SCHEMA_VERSION: &str = "marmot-forensics/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForensicsDumpMode {
    Public,
    Sensitive,
}

impl ForensicsDumpMode {
    pub fn is_sensitive(self) -> bool {
        matches!(self, Self::Sensitive)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForensicsExportOptions {
    pub mode: ForensicsDumpMode,
    pub redaction_salt: Vec<u8>,
}

impl ForensicsExportOptions {
    pub fn public(redaction_salt: impl Into<Vec<u8>>) -> Self {
        let redaction_salt = redaction_salt.into();
        assert!(
            !redaction_salt.is_empty(),
            "public forensics exports require a non-empty redaction salt"
        );
        Self {
            mode: ForensicsDumpMode::Public,
            redaction_salt,
        }
    }

    pub fn sensitive() -> Self {
        Self {
            mode: ForensicsDumpMode::Sensitive,
            redaction_salt: Vec::new(),
        }
    }

    pub fn protect_hex(&self, value_hex: &str) -> String {
        protect_hex(self.mode, &self.redaction_salt, value_hex)
    }

    pub fn protect_text(&self, value: &str) -> String {
        if self.mode.is_sensitive() {
            value.to_owned()
        } else {
            format!(
                "hash:{}",
                salted_hash_hex(&self.redaction_salt, value.as_bytes())
            )
        }
    }

    pub fn redaction_salt_id(&self) -> Option<String> {
        (!self.mode.is_sensitive())
            .then(|| salted_hash_hex(b"marmot-forensics-salt-id", &self.redaction_salt))
    }

    pub fn protect_digest_hex(&self, digest_hex: &str) -> String {
        if self.mode.is_sensitive() {
            format!("sha256:{digest_hex}")
        } else {
            format!(
                "salted_sha256:{}",
                salted_hash_hex(&self.redaction_salt, digest_hex.as_bytes())
            )
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicsBundle {
    pub schema_version: String,
    pub mode: ForensicsDumpMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_salt_id: Option<String>,
    pub exported_at_ms: u64,
    pub producer: ForensicsProducer,
    pub account: ForensicsAccount,
    pub group: ForensicsGroup,
    pub messages: Vec<ForensicsMessage>,
    pub snapshots: Vec<ForensicsSnapshot>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicsProducer {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicsAccount {
    pub account_ref: String,
    pub account_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicsGroup {
    pub group_id: String,
    pub epoch: u64,
    pub member_count: u32,
    #[serde(default)]
    pub required_app_components: Vec<u16>,
    #[serde(default)]
    pub admins: Vec<String>,
    #[serde(default)]
    pub relays: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nostr_group_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicsEngineGroupState {
    pub group_id: String,
    pub epoch: u64,
    pub member_count: u32,
    #[serde(default)]
    pub required_app_components: Vec<u16>,
    pub messages: Vec<ForensicsMessage>,
    pub snapshots: Vec<ForensicsSnapshot>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicsMessage {
    pub message_id: String,
    pub group_id: String,
    pub epoch: u64,
    pub state: String,
    pub payload_kind: String,
    pub envelope_kind: String,
    pub timestamp: u64,
    pub payload_len: u64,
    #[serde(alias = "payload_sha256")]
    pub payload_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openmls: Option<ForensicsOpenMlsMessage>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicsOpenMlsMessage {
    pub content_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_epoch: Option<u64>,
    pub message_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicsSnapshot {
    pub name: String,
}

pub fn protect_hex(mode: ForensicsDumpMode, salt: &[u8], value_hex: &str) -> String {
    if mode.is_sensitive() {
        value_hex.to_owned()
    } else {
        let decoded = hex::decode(value_hex).unwrap_or_else(|_| value_hex.as_bytes().to_vec());
        format!("hash:{}", salted_hash_hex(salt, &decoded))
    }
}

pub fn capture_payload(
    options: &ForensicsExportOptions,
    bytes: &[u8],
) -> (u64, String, Option<String>) {
    let digest = Sha256::digest(bytes);
    let payload_digest = options.protect_digest_hex(&hex::encode(digest));
    let payload_hex = options.mode.is_sensitive().then(|| hex::encode(bytes));
    (bytes.len() as u64, payload_digest, payload_hex)
}

fn salted_hash_hex(salt: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_options_redact_ids_and_payload_bytes() {
        let options = ForensicsExportOptions::public(b"incident-1");
        let protected = options.protect_hex("aabbcc");
        let (payload_len, payload_digest, payload_hex) =
            capture_payload(&options, &[0xaa, 0xbb, 0xcc]);

        assert!(protected.starts_with("hash:"));
        assert_ne!(protected, "aabbcc");
        assert_eq!(payload_len, 3);
        assert!(payload_digest.starts_with("salted_sha256:"));
        assert_eq!(payload_hex, None);
        assert!(options.redaction_salt_id().is_some());
    }

    #[test]
    #[should_panic(expected = "public forensics exports require a non-empty redaction salt")]
    fn public_options_reject_empty_salt() {
        let _ = ForensicsExportOptions::public(Vec::new());
    }

    #[test]
    fn sensitive_options_preserve_ids_and_payload_bytes() {
        let options = ForensicsExportOptions::sensitive();
        let protected = options.protect_hex("aabbcc");
        let (_, payload_digest, payload_hex) = capture_payload(&options, &[0xaa, 0xbb, 0xcc]);

        assert_eq!(protected, "aabbcc");
        assert_eq!(
            payload_digest,
            "sha256:fa22dfe1da9013b3c1145040acae9089e0c08bc1c1a0719614f4b73add6f6ef5"
        );
        assert_eq!(payload_hex.as_deref(), Some("aabbcc"));
        assert_eq!(options.redaction_salt_id(), None);
    }
}
