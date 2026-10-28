//! The five pairing messages, their app-event kinds and their content.
//!
//! Each message is one app-event kind. Its content is one JSON object with
//! exactly the members shown on its type, every byte string as lowercase
//! hex, and `"v": 1`. A sender writes the members in the order shown with no
//! whitespace. A reader rejects content over [`MAX_CONTENT_LEN`] bytes, an
//! unknown or duplicate member, a missing member, a wrong type, another `v`,
//! and hex that is not lowercase or not the exact length. Nothing a session
//! binds is read from the JSON bytes themselves: the commitment, code and
//! confirmations use the Marmot binary encodings in `sas`.

use cgka_traits::GroupId;
use serde::{Deserialize, Serialize};

use crate::sas::RequestBinding;
use crate::types::{
    AccountKey, ExchangeKey, KeyPackageEventId, KeyPackageRef, SessionId, SlotId,
    valid_group_id_len,
};

/// Kind of a [`PairingRequest`].
pub const KIND_PAIRING_REQUEST: u16 = 452;
/// Kind of a [`PairingAnswer`].
pub const KIND_PAIRING_ANSWER: u16 = 453;
/// Kind of a [`PairingReveal`].
pub const KIND_PAIRING_REVEAL: u16 = 454;
/// Kind of a [`PairingConfirm`].
pub const KIND_PAIRING_CONFIRM: u16 = 455;
/// Kind of a [`PairingCancel`].
pub const KIND_PAIRING_CANCEL: u16 = 456;

/// Every pairing kind, in protocol order.
pub const PAIRING_KINDS: [u16; 5] = [
    KIND_PAIRING_REQUEST,
    KIND_PAIRING_ANSWER,
    KIND_PAIRING_REVEAL,
    KIND_PAIRING_CONFIRM,
    KIND_PAIRING_CANCEL,
];

/// Largest content a reader parses, in bytes. The largest valid message, a
/// confirmation naming a 255-byte group id, is under 800.
pub const MAX_CONTENT_LEN: usize = 1024;

/// The content version every message carries as `v`.
const CONTENT_VERSION: u8 = 1;

/// Longest cancel reason token, in bytes.
const MAX_REASON_LEN: usize = 32;

/// New device to the account: starts a session and commits to its key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingRequest {
    pub session_id: SessionId,
    /// The new device's published KeyPackage.
    pub key_package_event_id: KeyPackageEventId,
    /// That KeyPackage's exact `KeyPackageRef`.
    pub key_package_ref: KeyPackageRef,
    /// [`crate::commitment`] of the new device's key and this request.
    pub commitment: [u8; 32],
}

impl PairingRequest {
    /// What the commitment covers, for a request sent to `account`.
    pub fn binding(&self, account: AccountKey) -> RequestBinding {
        RequestBinding {
            session_id: self.session_id,
            account,
            key_package_event_id: self.key_package_event_id,
            key_package_ref: self.key_package_ref.clone(),
        }
    }
}

/// Existing device to the account: its key, sent after it saw the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingAnswer {
    pub session_id: SessionId,
    /// The answering device's own publication slot.
    pub slot: SlotId,
    pub key: ExchangeKey,
}

/// New device to the account: reveals its key to the one answer it takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingReveal {
    pub session_id: SessionId,
    /// The slot of the answer the new device took. Other answerers drop the
    /// session.
    pub answer_slot: SlotId,
    pub key: ExchangeKey,
}

/// Either side, after its user confirmed that the codes match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingConfirm {
    pub session_id: SessionId,
    pub sender: ConfirmSender,
    /// HMAC-SHA256 over what the sender confirms.
    pub mac: [u8; 32],
}

/// Who sent a confirmation, and what it covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfirmSender {
    /// Covers the new device's exact `KeyPackageRef`, which the receiver
    /// already knows from the request.
    NewDevice,
    /// Covers the device group the existing device adds the new device to.
    ExistingDevice { device_group_id: GroupId },
}

/// Either side: ends a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingCancel {
    pub session_id: SessionId,
    pub reason: CancelReason,
}

/// Why a session was cancelled, as the `reason` token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CancelReason {
    /// The user cancelled. `user`
    User,
    /// The session expired. `timeout`
    Timeout,
    /// The revealed key did not match the request's commitment.
    /// `mismatched_commitment`
    MismatchedCommitment,
    /// The user said the codes differ. `mismatched_code`
    MismatchedCode,
    /// A confirmation did not verify. `mismatched_confirm`
    MismatchedConfirm,
    /// A message arrived that the session's state does not allow.
    /// `unexpected_message`
    UnexpectedMessage,
    /// More than one request was live at once. `competing_requests`
    CompetingRequests,
    /// The answering device reached its session limit. `rate_limited`
    RateLimited,
    /// The new device's KeyPackage can't be linked. `cannot_link`
    CannotLink,
    /// A token this version doesn't know: lowercase ASCII letters, digits and
    /// `_`, 1 to 32 bytes. It still ends the session.
    Other(String),
}

impl CancelReason {
    pub fn as_str(&self) -> &str {
        match self {
            Self::User => "user",
            Self::Timeout => "timeout",
            Self::MismatchedCommitment => "mismatched_commitment",
            Self::MismatchedCode => "mismatched_code",
            Self::MismatchedConfirm => "mismatched_confirm",
            Self::UnexpectedMessage => "unexpected_message",
            Self::CompetingRequests => "competing_requests",
            Self::RateLimited => "rate_limited",
            Self::CannotLink => "cannot_link",
            Self::Other(token) => token,
        }
    }

    fn parse(token: &str) -> Option<Self> {
        Some(match token {
            "user" => Self::User,
            "timeout" => Self::Timeout,
            "mismatched_commitment" => Self::MismatchedCommitment,
            "mismatched_code" => Self::MismatchedCode,
            "mismatched_confirm" => Self::MismatchedConfirm,
            "unexpected_message" => Self::UnexpectedMessage,
            "competing_requests" => Self::CompetingRequests,
            "rate_limited" => Self::RateLimited,
            "cannot_link" => Self::CannotLink,
            other => {
                let valid = (1..=MAX_REASON_LEN).contains(&other.len())
                    && other.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    });
                if !valid {
                    return None;
                }
                Self::Other(other.to_owned())
            }
        })
    }
}

/// One pairing message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairingMessage {
    Request(PairingRequest),
    Answer(PairingAnswer),
    Reveal(PairingReveal),
    Confirm(PairingConfirm),
    Cancel(PairingCancel),
}

/// Why content is not a valid pairing message. Carries no content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PairingMessageError {
    #[error("kind is not a pairing kind")]
    UnknownKind,
    #[error("pairing content is too large")]
    TooLarge,
    #[error("pairing content is malformed")]
    Malformed,
    #[error("pairing content has an unsupported version")]
    UnsupportedVersion,
}

impl PairingMessage {
    pub fn kind(&self) -> u16 {
        match self {
            Self::Request(_) => KIND_PAIRING_REQUEST,
            Self::Answer(_) => KIND_PAIRING_ANSWER,
            Self::Reveal(_) => KIND_PAIRING_REVEAL,
            Self::Confirm(_) => KIND_PAIRING_CONFIRM,
            Self::Cancel(_) => KIND_PAIRING_CANCEL,
        }
    }

    pub fn session_id(&self) -> &SessionId {
        match self {
            Self::Request(message) => &message.session_id,
            Self::Answer(message) => &message.session_id,
            Self::Reveal(message) => &message.session_id,
            Self::Confirm(message) => &message.session_id,
            Self::Cancel(message) => &message.session_id,
        }
    }

    /// The message's content.
    pub fn to_content(&self) -> String {
        let json = match self {
            Self::Request(message) => serde_json::to_string(&RequestJson {
                v: CONTENT_VERSION,
                session: hex::encode(message.session_id.as_bytes()),
                key_package_event: hex::encode(message.key_package_event_id.as_bytes()),
                key_package_ref: hex::encode(message.key_package_ref.as_slice()),
                commitment: hex::encode(message.commitment),
            }),
            Self::Answer(message) => serde_json::to_string(&AnswerJson {
                v: CONTENT_VERSION,
                session: hex::encode(message.session_id.as_bytes()),
                slot: hex::encode(message.slot.as_bytes()),
                key: hex::encode(message.key.as_bytes()),
            }),
            Self::Reveal(message) => serde_json::to_string(&RevealJson {
                v: CONTENT_VERSION,
                session: hex::encode(message.session_id.as_bytes()),
                answer_slot: hex::encode(message.answer_slot.as_bytes()),
                key: hex::encode(message.key.as_bytes()),
            }),
            Self::Confirm(message) => {
                let (from, device_group) = match &message.sender {
                    ConfirmSender::NewDevice => (CONFIRM_FROM_NEW, None),
                    ConfirmSender::ExistingDevice { device_group_id } => (
                        CONFIRM_FROM_EXISTING,
                        Some(hex::encode(device_group_id.as_slice())),
                    ),
                };
                serde_json::to_string(&ConfirmJson {
                    v: CONTENT_VERSION,
                    session: hex::encode(message.session_id.as_bytes()),
                    from: from.to_owned(),
                    device_group,
                    mac: hex::encode(message.mac),
                })
            }
            Self::Cancel(message) => serde_json::to_string(&CancelJson {
                v: CONTENT_VERSION,
                session: hex::encode(message.session_id.as_bytes()),
                reason: message.reason.as_str().to_owned(),
            }),
        };
        json.expect("pairing content always serializes")
    }

    /// Reads the message of `kind` from `content`.
    pub fn from_content(kind: u16, content: &str) -> Result<Self, PairingMessageError> {
        if !PAIRING_KINDS.contains(&kind) {
            return Err(PairingMessageError::UnknownKind);
        }
        if content.len() > MAX_CONTENT_LEN {
            return Err(PairingMessageError::TooLarge);
        }
        match kind {
            KIND_PAIRING_REQUEST => {
                let json: RequestJson = parse(content)?;
                Ok(Self::Request(PairingRequest {
                    session_id: SessionId::new(hex32(&json.session)?),
                    key_package_event_id: KeyPackageEventId::new(hex32(&json.key_package_event)?),
                    key_package_ref: KeyPackageRef::new(hex_bytes(&json.key_package_ref)?)
                        .ok_or(PairingMessageError::Malformed)?,
                    commitment: hex32(&json.commitment)?,
                }))
            }
            KIND_PAIRING_ANSWER => {
                let json: AnswerJson = parse(content)?;
                Ok(Self::Answer(PairingAnswer {
                    session_id: SessionId::new(hex32(&json.session)?),
                    slot: SlotId::new(hex32(&json.slot)?),
                    key: ExchangeKey::new(hex32(&json.key)?),
                }))
            }
            KIND_PAIRING_REVEAL => {
                let json: RevealJson = parse(content)?;
                Ok(Self::Reveal(PairingReveal {
                    session_id: SessionId::new(hex32(&json.session)?),
                    answer_slot: SlotId::new(hex32(&json.answer_slot)?),
                    key: ExchangeKey::new(hex32(&json.key)?),
                }))
            }
            KIND_PAIRING_CONFIRM => {
                let json: ConfirmJson = parse(content)?;
                let sender = match (json.from.as_str(), json.device_group) {
                    (CONFIRM_FROM_NEW, None) => ConfirmSender::NewDevice,
                    (CONFIRM_FROM_EXISTING, Some(device_group)) => {
                        let bytes = hex_bytes(&device_group)?;
                        if !valid_group_id_len(&bytes) {
                            return Err(PairingMessageError::Malformed);
                        }
                        ConfirmSender::ExistingDevice {
                            device_group_id: GroupId::new(bytes),
                        }
                    }
                    _ => return Err(PairingMessageError::Malformed),
                };
                Ok(Self::Confirm(PairingConfirm {
                    session_id: SessionId::new(hex32(&json.session)?),
                    sender,
                    mac: hex32(&json.mac)?,
                }))
            }
            KIND_PAIRING_CANCEL => {
                let json: CancelJson = parse(content)?;
                Ok(Self::Cancel(PairingCancel {
                    session_id: SessionId::new(hex32(&json.session)?),
                    reason: CancelReason::parse(&json.reason)
                        .ok_or(PairingMessageError::Malformed)?,
                }))
            }
            _ => Err(PairingMessageError::UnknownKind),
        }
    }
}

const CONFIRM_FROM_NEW: &str = "new_device";
const CONFIRM_FROM_EXISTING: &str = "existing_device";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestJson {
    v: u8,
    session: String,
    key_package_event: String,
    key_package_ref: String,
    commitment: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnswerJson {
    v: u8,
    session: String,
    slot: String,
    key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevealJson {
    v: u8,
    session: String,
    answer_slot: String,
    key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmJson {
    v: u8,
    session: String,
    from: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_string"
    )]
    device_group: Option<String>,
    mac: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelJson {
    v: u8,
    session: String,
    reason: String,
}

/// A member that may be absent but, when present, must be a string, not
/// `null`.
fn present_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

/// Just the version, read before the members a later version may change.
#[derive(Deserialize)]
struct VersionJson {
    v: u64,
}

fn parse<'a, T: Deserialize<'a>>(content: &'a str) -> Result<T, PairingMessageError> {
    let version: VersionJson =
        serde_json::from_str(content).map_err(|_| PairingMessageError::Malformed)?;
    if version.v != u64::from(CONTENT_VERSION) {
        return Err(PairingMessageError::UnsupportedVersion);
    }
    serde_json::from_str(content).map_err(|_| PairingMessageError::Malformed)
}

fn hex_bytes(value: &str) -> Result<Vec<u8>, PairingMessageError> {
    let lowercase = value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !lowercase {
        return Err(PairingMessageError::Malformed);
    }
    hex::decode(value).map_err(|_| PairingMessageError::Malformed)
}

fn hex32(value: &str) -> Result<[u8; 32], PairingMessageError> {
    hex_bytes(value)?
        .try_into()
        .map_err(|_| PairingMessageError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_of(byte: u8, len: usize) -> String {
        hex::encode(vec![byte; len])
    }

    fn request_content() -> String {
        PairingMessage::Request(PairingRequest {
            session_id: SessionId::new([1; 32]),
            key_package_event_id: KeyPackageEventId::new([2; 32]),
            key_package_ref: KeyPackageRef::new([3; 32]).expect("ref"),
            commitment: [4; 32],
        })
        .to_content()
    }

    fn confirm_json(from: &str, device_group: Option<&str>) -> String {
        let session = hex_of(1, 32);
        let mac = hex_of(5, 32);
        match device_group {
            Some(group) => format!(
                r#"{{"v":1,"session":"{session}","from":"{from}","device_group":{group},"mac":"{mac}"}}"#
            ),
            None => format!(r#"{{"v":1,"session":"{session}","from":"{from}","mac":"{mac}"}}"#),
        }
    }

    fn cancel_json(reason: &str) -> String {
        format!(
            r#"{{"v":1,"session":"{}","reason":"{reason}"}}"#,
            hex_of(1, 32)
        )
    }

    #[test]
    fn message_round_trips_every_kind() {
        let session_id = SessionId::new([1; 32]);
        let messages = [
            PairingMessage::from_content(KIND_PAIRING_REQUEST, &request_content())
                .expect("request"),
            PairingMessage::Answer(PairingAnswer {
                session_id,
                slot: SlotId::new([6; 32]),
                key: ExchangeKey::new([7; 32]),
            }),
            PairingMessage::Reveal(PairingReveal {
                session_id,
                answer_slot: SlotId::new([6; 32]),
                key: ExchangeKey::new([8; 32]),
            }),
            PairingMessage::Confirm(PairingConfirm {
                session_id,
                sender: ConfirmSender::NewDevice,
                mac: [5; 32],
            }),
            PairingMessage::Confirm(PairingConfirm {
                session_id,
                sender: ConfirmSender::ExistingDevice {
                    device_group_id: GroupId::new(vec![9; 16]),
                },
                mac: [5; 32],
            }),
            PairingMessage::Cancel(PairingCancel {
                session_id,
                reason: CancelReason::Other("later_reason".to_owned()),
            }),
        ];
        for message in messages {
            let content = message.to_content();
            assert_eq!(
                PairingMessage::from_content(message.kind(), &content),
                Ok(message.clone()),
                "{content}"
            );
            assert_eq!(message.session_id(), &session_id);
        }
    }

    #[test]
    fn message_rejects_other_kinds() {
        for kind in [0, 451, 457, 1059, u16::MAX] {
            assert_eq!(
                PairingMessage::from_content(kind, &request_content()),
                Err(PairingMessageError::UnknownKind)
            );
        }
        // Content of one kind is not content of another.
        assert_eq!(
            PairingMessage::from_content(KIND_PAIRING_ANSWER, &request_content()),
            Err(PairingMessageError::Malformed)
        );
    }

    #[test]
    fn message_rejects_oversize_content() {
        let padded = format!("{}{}", request_content(), " ".repeat(MAX_CONTENT_LEN));
        assert_eq!(
            PairingMessage::from_content(KIND_PAIRING_REQUEST, &padded),
            Err(PairingMessageError::TooLarge)
        );
        // The largest valid message fits with room to spare.
        let largest = PairingMessage::Confirm(PairingConfirm {
            session_id: SessionId::new([1; 32]),
            sender: ConfirmSender::ExistingDevice {
                device_group_id: GroupId::new(vec![9; crate::types::GROUP_ID_MAX_LEN]),
            },
            mac: [5; 32],
        });
        assert!(largest.to_content().len() < 800);
    }

    #[test]
    fn message_rejects_other_versions() {
        let content = request_content();
        for version in ["0", "2", "255", "256"] {
            assert_eq!(
                PairingMessage::from_content(
                    KIND_PAIRING_REQUEST,
                    &content.replacen(r#""v":1"#, &format!(r#""v":{version}"#), 1)
                ),
                Err(PairingMessageError::UnsupportedVersion),
                "{version}"
            );
        }
        for version in [r#""1""#, "1.0", "-1", "null"] {
            assert_eq!(
                PairingMessage::from_content(
                    KIND_PAIRING_REQUEST,
                    &content.replacen(r#""v":1"#, &format!(r#""v":{version}"#), 1)
                ),
                Err(PairingMessageError::Malformed),
                "{version}"
            );
        }
        // A later version may change the members: it is unsupported, not
        // malformed.
        let later = format!(
            r#"{{"v":2,"session":"{}","new_member":true}}"#,
            hex_of(1, 32)
        );
        assert_eq!(
            PairingMessage::from_content(KIND_PAIRING_REQUEST, &later),
            Err(PairingMessageError::UnsupportedVersion)
        );
    }

    #[test]
    fn message_rejects_wrong_members() {
        let content = request_content();
        let session = format!(r#""session":"{}","#, hex_of(1, 32));
        let cases = [
            // An unknown member.
            content.replacen("{", r#"{"extra":1,"#, 1),
            // A duplicate member.
            content.replacen(&session, &format!("{session}{session}"), 1),
            // A missing member.
            content.replacen(&session, "", 1),
            // A wrong type.
            content.replacen(&session, r#""session":1,"#, 1),
            // Not an object.
            "[]".to_owned(),
            String::new(),
        ];
        for case in cases {
            assert_eq!(
                PairingMessage::from_content(KIND_PAIRING_REQUEST, &case),
                Err(PairingMessageError::Malformed),
                "{case}"
            );
        }
    }

    #[test]
    fn message_rejects_wrong_hex() {
        let content = request_content();
        let session = hex_of(1, 32);
        for wrong in [
            session.to_uppercase().replacen("01", "0A", 1),
            hex_of(1, 31),
            hex_of(1, 33),
            format!("{session}0"),
            format!("0x{}", hex_of(1, 31)),
            session.replacen("01", "0g", 1),
        ] {
            assert_eq!(
                PairingMessage::from_content(
                    KIND_PAIRING_REQUEST,
                    &content.replacen(&session, &wrong, 1)
                ),
                Err(PairingMessageError::Malformed),
                "{wrong}"
            );
        }
        let key_package_ref = hex_of(3, 32);
        for wrong in [
            String::new(),
            hex_of(3, crate::types::KEY_PACKAGE_REF_MAX_LEN + 1),
        ] {
            assert_eq!(
                PairingMessage::from_content(
                    KIND_PAIRING_REQUEST,
                    &content.replacen(&key_package_ref, &wrong, 1)
                ),
                Err(PairingMessageError::Malformed),
                "ref of {} hex digits",
                wrong.len()
            );
        }
    }

    #[test]
    fn message_confirm_names_a_group_only_from_the_existing_device() {
        let group = format!(r#""{}""#, hex_of(9, 16));
        for (content, valid) in [
            (confirm_json("new_device", None), true),
            (confirm_json("existing_device", Some(&group)), true),
            (confirm_json("new_device", Some(&group)), false),
            (confirm_json("existing_device", None), false),
            (confirm_json("existing_device", Some("null")), false),
            (confirm_json("existing_device", Some(r#""""#)), false),
            (
                confirm_json(
                    "existing_device",
                    Some(&format!(
                        r#""{}""#,
                        hex_of(9, crate::types::GROUP_ID_MAX_LEN + 1)
                    )),
                ),
                false,
            ),
            (confirm_json("someone_else", None), false),
        ] {
            assert_eq!(
                PairingMessage::from_content(KIND_PAIRING_CONFIRM, &content).is_ok(),
                valid,
                "{content}"
            );
        }
    }

    #[test]
    fn message_cancel_reason_tokens() {
        for reason in [
            CancelReason::User,
            CancelReason::Timeout,
            CancelReason::MismatchedCommitment,
            CancelReason::MismatchedCode,
            CancelReason::MismatchedConfirm,
            CancelReason::UnexpectedMessage,
            CancelReason::CompetingRequests,
            CancelReason::RateLimited,
            CancelReason::CannotLink,
        ] {
            assert_eq!(CancelReason::parse(reason.as_str()), Some(reason));
        }
        let longest = "a".repeat(MAX_REASON_LEN);
        assert_eq!(
            CancelReason::parse(&longest),
            Some(CancelReason::Other(longest.clone()))
        );
        for invalid in [
            String::new(),
            "a".repeat(MAX_REASON_LEN + 1),
            "Timeout".to_owned(),
            "two words".to_owned(),
            "dash-ed".to_owned(),
            "caf\u{e9}".to_owned(),
        ] {
            assert_eq!(CancelReason::parse(&invalid), None, "{invalid}");
            assert_eq!(
                PairingMessage::from_content(KIND_PAIRING_CANCEL, &cancel_json(&invalid)),
                Err(PairingMessageError::Malformed),
                "{invalid}"
            );
        }
    }
}
