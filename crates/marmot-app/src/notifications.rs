use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use nostr::{
    EventBuilder, Keys, Kind, PublicKey, Tag, TagKind, UnsignedEvent,
    base64::Engine as _,
    base64::engine::general_purpose::STANDARD as BASE64_STANDARD,
    secp256k1::{Parity, PublicKey as SecpPublicKey, SecretKey, XOnlyPublicKey, ecdh},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use transport_nostr_peeler::NostrTransportEvent;

use cgka_traits::app_event::{
    EVENT_REF_TAG, MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_REACTION,
};

use crate::{
    AppError, AppGroupRecord, MarmotApp, MarmotAppEvent, ReceivedMessage, RuntimeMessageReceived,
    tag_value,
};
use storage_sqlite::TimelineMessageTarget;

pub const MARMOT_APP_EVENT_KIND_PUSH_TOKEN_UPDATE: u64 = 447;
pub const MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST: u64 = 448;
pub const MARMOT_APP_EVENT_KIND_PUSH_TOKEN_REMOVAL: u64 = 449;
pub const KIND_MARMOT_NOTIFICATION_RUMOR: u64 = 446;
pub const KIND_MARMOT_NOTIFICATION_SERVER_RELAYS: u64 = 10050;
pub const MIP05_VERSION: &str = "mip05-v1";
pub const MIP05_ENCRYPTED_TOKEN_LEN: usize = 1084;
const MIP05_TOKEN_PLAINTEXT_LEN: usize = 1024;
const MIP05_MAX_PROVIDER_TOKEN_LEN: usize = MIP05_TOKEN_PLAINTEXT_LEN - 3;
const MIP05_CIPHERTEXT_LEN: usize = MIP05_TOKEN_PLAINTEXT_LEN + 16;
const MIP05_HKDF_SALT: &[u8] = b"mip05-v1";
const MIP05_HKDF_INFO: &[u8] = b"mip05-token-encryption";
const NOTIFICATION_VERSION_TAG: &str = "v";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PushPlatform {
    Apns,
    Fcm,
}

impl PushPlatform {
    pub fn platform_byte(self) -> u8 {
        match self {
            Self::Apns => 0x01,
            Self::Fcm => 0x02,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Apns => "apns",
            Self::Fcm => "fcm",
        }
    }

    pub fn from_platform_byte(value: u8) -> Result<Self, AppError> {
        match value {
            0x01 => Ok(Self::Apns),
            0x02 => Ok(Self::Fcm),
            _ => Err(AppError::InvalidPushToken(
                "unsupported push platform".into(),
            )),
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Result<Self, AppError> {
        // Lowercase-only per spec/features/push-notifications.md ("platform is the
        // string apns or fcm") and the no-case-fold canonical-decoding rule. Do NOT
        // accept "Apns"/"APNS"/"Fcm"/"FCM": a case-folding decoder would store and
        // match push-token state differently from a strict peer.
        match value {
            "apns" => Ok(Self::Apns),
            "fcm" => Ok(Self::Fcm),
            _ => Err(AppError::InvalidPushToken(
                "unsupported push platform".into(),
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationWakeSource {
    ApnsNse,
    FcmDataMessage,
    AndroidForegroundService,
    ManualCatchUp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationCollectionStatus {
    NewData,
    NoData,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationTrigger {
    NewMessage,
    GroupInvite,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationSettings {
    pub account_ref: String,
    pub account_id_hex: String,
    pub local_notifications_enabled: bool,
    pub native_push_enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRegistration {
    pub account_ref: String,
    pub account_id_hex: String,
    pub platform: PushPlatform,
    pub token_fingerprint: String,
    pub server_pubkey_hex: String,
    pub relay_hint: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub last_shared_at_ms: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoredPushRegistration {
    pub registration: PushRegistration,
    pub token_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPushTokenRecord {
    pub group_id_hex: String,
    pub member_id_hex: String,
    pub leaf_index: u32,
    pub platform: PushPlatform,
    pub token_fingerprint: String,
    pub server_pubkey_hex: String,
    pub relay_hint: Option<String>,
    pub encrypted_token: Vec<u8>,
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationUser {
    pub account_id_hex: String,
    pub display_name: Option<String>,
    pub picture_url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationUpdate {
    pub notification_key: String,
    pub conversation_key: String,
    pub trigger: NotificationTrigger,
    pub account_ref: String,
    pub account_id_hex: String,
    pub group_id_hex: String,
    pub group_name: Option<String>,
    pub is_dm: bool,
    pub message_id_hex: Option<String>,
    pub sender: NotificationUser,
    pub receiver: NotificationUser,
    pub preview_text: Option<String>,
    /// Reaction emoji (Nostr kind 7 content); `None` for non-reactions. Additive
    /// at the DTO level (no `trigger`/`preview_text` change), but it changes the
    /// generated UniFFI record: consumers must regenerate bindings and ship the
    /// matching native library to receive it.
    pub reaction_emoji: Option<String>,
    /// Preview of the reacted-to message (resolved via the `e` tag against the
    /// timeline). `None` for non-reactions, an unresolvable target, or a
    /// deleted/invalidated one — removed text must never reach the preview.
    pub reacted_to_preview: Option<String>,
    pub timestamp_ms: i64,
    pub is_from_self: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackgroundNotificationCollection {
    pub status: NotificationCollectionStatus,
    pub notifications: Vec<NotificationUpdate>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalPushRegistrationDebug {
    pub registered: bool,
    pub shareable: bool,
    pub local_notifications_enabled: bool,
    pub native_push_enabled: bool,
    pub local_leaf_index: Option<u32>,
    pub local_token_cached: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPushTokenDebugEntry {
    pub member_id_hex: String,
    pub leaf_index: u32,
    pub platform: PushPlatform,
    pub token_fingerprint: String,
    pub server_pubkey_hex: String,
    pub has_relay_hint: bool,
    pub active_leaf: bool,
    pub member_matches_active_leaf: bool,
    pub is_local_member: bool,
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPushDebugInfo {
    pub total_token_count: u32,
    pub active_token_count: u32,
    pub stale_token_count: u32,
    pub missing_relay_hint_count: u32,
    pub last_token_list_updated_at_ms: Option<i64>,
    pub local_registration: LocalPushRegistrationDebug,
    pub tokens: Vec<GroupPushTokenDebugEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PushTokenGossipPayload {
    pub v: String,
    #[serde(default)]
    pub tokens: Vec<PushTokenGossipEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PushTokenGossipEntry {
    pub member_id_hex: String,
    pub leaf_index: u32,
    pub platform: String,
    pub token_fingerprint: String,
    pub server_pubkey_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_hint: Option<String>,
    pub encrypted_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PushTokenRemovalPayload {
    pub v: String,
    #[serde(default)]
    pub removals: Vec<PushTokenRemovalEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PushTokenRemovalEntry {
    pub member_id_hex: String,
    pub platform: String,
    pub token_fingerprint: String,
    pub server_pubkey_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PushGossipAction {
    Upsert(Vec<GroupPushTokenRecord>),
    Remove(Vec<PushTokenRemovalRecord>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PushTokenRemovalRecord {
    pub member_id_hex: String,
    pub platform: PushPlatform,
    pub token_fingerprint: String,
    pub server_pubkey_hex: String,
}

pub fn parse_provider_token(platform: PushPlatform, raw_token: &str) -> Result<Vec<u8>, AppError> {
    let token = match platform {
        PushPlatform::Apns => parse_apns_hex_token(raw_token)?,
        PushPlatform::Fcm => raw_token.as_bytes().to_vec(),
    };
    validate_provider_token_len(&token)?;
    Ok(token)
}

fn parse_apns_hex_token(raw_token: &str) -> Result<Vec<u8>, AppError> {
    if raw_token.is_empty()
        || !raw_token.len().is_multiple_of(2)
        || !raw_token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AppError::InvalidPushToken(
            "APNS token must be lowercase hex".into(),
        ));
    }
    hex::decode(raw_token)
        .map_err(|_| AppError::InvalidPushToken("APNS token must be lowercase hex".into()))
}

fn validate_provider_token_len(token: &[u8]) -> Result<(), AppError> {
    if token.is_empty() {
        return Err(AppError::InvalidPushToken(
            "push token must not be empty".into(),
        ));
    }
    if token.len() > MIP05_MAX_PROVIDER_TOKEN_LEN {
        return Err(AppError::InvalidPushToken(
            "push token is too long for mip05-v1".into(),
        ));
    }
    Ok(())
}

pub fn push_token_fingerprint(platform: PushPlatform, token_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update([platform.platform_byte()]);
    hasher.update(token_bytes);
    let digest = hex::encode(hasher.finalize());
    format!("sha256:{}", &digest[..24])
}

pub fn encrypted_mip05_token(
    platform: PushPlatform,
    token_bytes: &[u8],
    server_pubkey_hex: &str,
) -> Result<Vec<u8>, AppError> {
    validate_provider_token_len(token_bytes)?;
    let server_pubkey_bytes = hex::decode(server_pubkey_hex)
        .map_err(|_| AppError::InvalidPushServer("server pubkey must be 32-byte hex".into()))?;
    if server_pubkey_bytes.len() != 32 {
        return Err(AppError::InvalidPushServer(
            "server pubkey must be 32-byte hex".into(),
        ));
    }
    let server_xonly = XOnlyPublicKey::from_slice(&server_pubkey_bytes).map_err(|_| {
        AppError::InvalidPushServer("server pubkey is not valid x-only secp256k1".into())
    })?;
    let server_pubkey = SecpPublicKey::from_x_only_public_key(server_xonly, Parity::Even);

    let ephemeral_secret = random_secret_key();
    let ephemeral_pubkey = SecpPublicKey::from_secret_key_global(&ephemeral_secret);
    let (ephemeral_xonly, _) = ephemeral_pubkey.x_only_public_key();
    let shared_x = secp256k1_ecdh_x(&server_pubkey, &ephemeral_secret);
    let key = mip05_encryption_key(&shared_x)?;

    let mut plaintext = [0_u8; MIP05_TOKEN_PLAINTEXT_LEN];
    plaintext[0] = platform.platform_byte();
    let token_len = u16::try_from(token_bytes.len())
        .map_err(|_| AppError::InvalidPushToken("push token is too long for mip05-v1".into()))?;
    plaintext[1..3].copy_from_slice(&token_len.to_be_bytes());
    plaintext[3..3 + token_bytes.len()].copy_from_slice(token_bytes);
    OsRng.fill_bytes(&mut plaintext[3 + token_bytes.len()..]);

    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| AppError::InvalidPushToken("mip05-v1 key setup failed".into()))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &[],
            },
        )
        .map_err(|_| AppError::InvalidPushToken("mip05-v1 token encryption failed".into()))?;
    if ciphertext.len() != MIP05_CIPHERTEXT_LEN {
        return Err(AppError::InvalidPushToken(
            "mip05-v1 token encryption produced invalid length".into(),
        ));
    }

    let mut out = Vec::with_capacity(MIP05_ENCRYPTED_TOKEN_LEN);
    out.extend_from_slice(&ephemeral_xonly.serialize());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    debug_assert_eq!(out.len(), MIP05_ENCRYPTED_TOKEN_LEN);
    Ok(out)
}

fn random_secret_key() -> SecretKey {
    loop {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        if let Ok(secret) = SecretKey::from_slice(&bytes) {
            return secret;
        }
    }
}

fn secp256k1_ecdh_x(point: &SecpPublicKey, scalar: &SecretKey) -> [u8; 32] {
    let shared_point = ecdh::shared_secret_point(point, scalar);
    shared_point[..32]
        .try_into()
        .expect("shared point X coordinate is 32 bytes")
}

fn mip05_encryption_key(shared_x: &[u8; 32]) -> Result<[u8; 32], AppError> {
    let hkdf = Hkdf::<Sha256>::new(Some(MIP05_HKDF_SALT), shared_x);
    let mut key = [0_u8; 32];
    hkdf.expand(MIP05_HKDF_INFO, &mut key)
        .map_err(|_| AppError::InvalidPushToken("mip05-v1 token key derivation failed".into()))?;
    Ok(key)
}

pub fn build_notification_rumor_content(tokens: &[Vec<u8>]) -> Result<String, AppError> {
    if tokens.is_empty()
        || tokens
            .iter()
            .any(|token| token.len() != MIP05_ENCRYPTED_TOKEN_LEN)
    {
        return Err(AppError::InvalidPushToken(
            "notification rumor requires mip05-v1 encrypted tokens".into(),
        ));
    }
    let mut joined = Vec::with_capacity(tokens.len() * MIP05_ENCRYPTED_TOKEN_LEN);
    for token in tokens {
        joined.extend_from_slice(token);
    }
    Ok(BASE64_STANDARD.encode(joined))
}

pub async fn build_notification_gift_wrap(
    server_pubkey_hex: &str,
    tokens: &[Vec<u8>],
) -> Result<NostrTransportEvent, AppError> {
    let server_pubkey = PublicKey::parse(server_pubkey_hex).map_err(|_| {
        AppError::InvalidPushServer("server pubkey must be a valid Nostr public key".into())
    })?;
    let content = build_notification_rumor_content(tokens)?;
    let seal_keys = Keys::generate();
    let rumor: UnsignedEvent =
        EventBuilder::new(Kind::Custom(KIND_MARMOT_NOTIFICATION_RUMOR as u16), content)
            .tags([Tag::custom(
                TagKind::custom(NOTIFICATION_VERSION_TAG),
                [MIP05_VERSION],
            )])
            .build(seal_keys.public_key());
    let gift_wrap = EventBuilder::gift_wrap(&seal_keys, &server_pubkey, rumor, [])
        .await
        .map_err(|err| AppError::Publish(format!("notification gift wrap: {err}")))?;
    NostrTransportEvent::from_nostr_event(&gift_wrap)
        .map_err(|err| AppError::Publish(format!("notification event: {err}")))
}

pub(crate) fn local_token_gossip_payload(
    group_id_hex: String,
    member_id_hex: String,
    leaf_index: u32,
    registration: &StoredPushRegistration,
) -> Result<(PushTokenGossipPayload, GroupPushTokenRecord), AppError> {
    let encrypted_token = encrypted_mip05_token(
        registration.registration.platform,
        &registration.token_bytes,
        &registration.registration.server_pubkey_hex,
    )?;
    let record = GroupPushTokenRecord {
        group_id_hex,
        member_id_hex: member_id_hex.clone(),
        leaf_index,
        platform: registration.registration.platform,
        token_fingerprint: registration.registration.token_fingerprint.clone(),
        server_pubkey_hex: registration.registration.server_pubkey_hex.clone(),
        relay_hint: registration.registration.relay_hint.clone(),
        encrypted_token: encrypted_token.clone(),
        updated_at_ms: unix_now_ms(),
    };
    let payload = PushTokenGossipPayload {
        v: MIP05_VERSION.to_owned(),
        tokens: vec![PushTokenGossipEntry::from_record(&record)],
    };
    Ok((payload, record))
}

pub(crate) fn local_token_removal_payload(
    member_id_hex: String,
    registration: &PushRegistration,
) -> PushTokenRemovalPayload {
    PushTokenRemovalPayload {
        v: MIP05_VERSION.to_owned(),
        removals: vec![PushTokenRemovalEntry {
            member_id_hex,
            platform: registration.platform.as_str().to_owned(),
            token_fingerprint: registration.token_fingerprint.clone(),
            server_pubkey_hex: registration.server_pubkey_hex.clone(),
        }],
    }
}

pub(crate) fn parse_push_gossip(
    kind: u64,
    group_id_hex: &str,
    content: &str,
) -> Result<PushGossipAction, AppError> {
    match kind {
        MARMOT_APP_EVENT_KIND_PUSH_TOKEN_UPDATE | MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST => {
            let payload: PushTokenGossipPayload = serde_json::from_str(content)
                .map_err(|_| AppError::InvalidPushGossip("malformed push token gossip".into()))?;
            if payload.v != MIP05_VERSION {
                return Err(AppError::InvalidPushGossip(
                    "unsupported push token gossip version".into(),
                ));
            }
            let records = payload
                .tokens
                .into_iter()
                .map(|entry| entry.into_record(group_id_hex))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(PushGossipAction::Upsert(records))
        }
        MARMOT_APP_EVENT_KIND_PUSH_TOKEN_REMOVAL => {
            let payload: PushTokenRemovalPayload = serde_json::from_str(content)
                .map_err(|_| AppError::InvalidPushGossip("malformed push token removal".into()))?;
            if payload.v != MIP05_VERSION {
                return Err(AppError::InvalidPushGossip(
                    "unsupported push token removal version".into(),
                ));
            }
            let removals = payload
                .removals
                .into_iter()
                .map(PushTokenRemovalEntry::into_record)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(PushGossipAction::Remove(removals))
        }
        _ => Err(AppError::InvalidPushGossip(
            "unsupported push token gossip kind".into(),
        )),
    }
}

impl PushTokenGossipEntry {
    fn from_record(record: &GroupPushTokenRecord) -> Self {
        Self {
            member_id_hex: record.member_id_hex.clone(),
            leaf_index: record.leaf_index,
            platform: record.platform.as_str().to_owned(),
            token_fingerprint: record.token_fingerprint.clone(),
            server_pubkey_hex: record.server_pubkey_hex.clone(),
            relay_hint: record.relay_hint.clone(),
            encrypted_token: BASE64_STANDARD.encode(&record.encrypted_token),
        }
    }

    fn into_record(self, group_id_hex: &str) -> Result<GroupPushTokenRecord, AppError> {
        let platform = PushPlatform::from_str(&self.platform)?;
        let encrypted_token = BASE64_STANDARD
            .decode(self.encrypted_token)
            .map_err(|_| AppError::InvalidPushGossip("invalid encrypted token base64".into()))?;
        if encrypted_token.len() != MIP05_ENCRYPTED_TOKEN_LEN {
            return Err(AppError::InvalidPushGossip(
                "invalid encrypted token length".into(),
            ));
        }
        validate_account_hex(&self.member_id_hex, "member id")?;
        validate_account_hex(&self.server_pubkey_hex, "server pubkey")?;
        validate_fingerprint(&self.token_fingerprint)?;
        Ok(GroupPushTokenRecord {
            group_id_hex: group_id_hex.to_owned(),
            member_id_hex: self.member_id_hex,
            leaf_index: self.leaf_index,
            platform,
            token_fingerprint: self.token_fingerprint,
            server_pubkey_hex: self.server_pubkey_hex,
            relay_hint: self.relay_hint.filter(|relay| !relay.trim().is_empty()),
            encrypted_token,
            updated_at_ms: unix_now_ms(),
        })
    }
}

impl PushTokenRemovalEntry {
    fn into_record(self) -> Result<PushTokenRemovalRecord, AppError> {
        validate_account_hex(&self.member_id_hex, "member id")?;
        validate_account_hex(&self.server_pubkey_hex, "server pubkey")?;
        validate_fingerprint(&self.token_fingerprint)?;
        Ok(PushTokenRemovalRecord {
            member_id_hex: self.member_id_hex,
            platform: PushPlatform::from_str(&self.platform)?,
            token_fingerprint: self.token_fingerprint,
            server_pubkey_hex: self.server_pubkey_hex,
        })
    }
}

fn validate_account_hex(value: &str, name: &str) -> Result<(), AppError> {
    let decoded = hex::decode(value).map_err(|_| {
        AppError::InvalidPushGossip(format!("{name} must be 32-byte lowercase hex"))
    })?;
    if decoded.len() != 32 || value.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(AppError::InvalidPushGossip(format!(
            "{name} must be 32-byte lowercase hex"
        )));
    }
    Ok(())
}

fn validate_fingerprint(value: &str) -> Result<(), AppError> {
    let Some(rest) = value.strip_prefix("sha256:") else {
        return Err(AppError::InvalidPushGossip(
            "token fingerprint must be redacted sha256".into(),
        ));
    };
    if rest.len() != 24 || !rest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::InvalidPushGossip(
            "token fingerprint must be redacted sha256".into(),
        ));
    }
    Ok(())
}

pub(crate) fn is_push_gossip_kind(kind: u64) -> bool {
    matches!(
        kind,
        MARMOT_APP_EVENT_KIND_PUSH_TOKEN_UPDATE
            | MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST
            | MARMOT_APP_EVENT_KIND_PUSH_TOKEN_REMOVAL
    )
}

pub(crate) fn notification_update_from_event(
    app: &MarmotApp,
    event: &MarmotAppEvent,
) -> Result<Option<NotificationUpdate>, AppError> {
    match event {
        MarmotAppEvent::MessageReceived(message) => notification_update_from_message(app, message),
        MarmotAppEvent::GroupJoined {
            account_id_hex,
            account_label,
            group_id,
        } => notification_update_from_group_join(app, account_label, account_id_hex, group_id)
            .map(Some),
        MarmotAppEvent::GroupStateUpdated { .. }
        | MarmotAppEvent::ProjectionUpdated(_)
        | MarmotAppEvent::AgentStreamStarted(_)
        | MarmotAppEvent::GroupEvent(_)
        | MarmotAppEvent::AccountError(_) => Ok(None),
    }
}

/// Whether a received app-event kind should ever surface as a notification.
/// Only chat messages and reactions alert; deletes, edits, agent-stream control
/// events, and group-system rows are state changes, not new user messages.
fn is_notifiable_message_kind(kind: u64) -> bool {
    kind == MARMOT_APP_EVENT_KIND_CHAT || kind == MARMOT_APP_EVENT_KIND_REACTION
}

fn notification_update_from_message(
    app: &MarmotApp,
    event: &RuntimeMessageReceived,
) -> Result<Option<NotificationUpdate>, AppError> {
    let settings = app.notification_settings(&event.account_label)?;
    if !settings.local_notifications_enabled {
        return Err(AppError::NotificationsDisabled);
    }
    // Only chat messages and reactions alert. Deletes, edits, agent-stream
    // control events, and group-system rows are not new user-facing messages,
    // so they never produce a notification (e.g. deleting a message must not
    // push a "Deleted a message" alert).
    if !is_notifiable_message_kind(event.message.kind) {
        return Ok(None);
    }
    let group_id_hex = hex::encode(event.message.group_id.as_slice());
    let group = app.group(&event.account_label, &group_id_hex)?;
    let receiver = notification_user(app, &event.account_id_hex)?;
    let sender = notification_user_from_message(app, &event.message)?;
    let is_from_self = event.message.sender == event.account_id_hex;
    // Resolve the reacted-to row from the materialized timeline by id (not raw
    // app_events): the timeline reflects deletion/invalidation and never carries
    // removed text, so a reaction can't leak it into a preview. Notify only the
    // target's author; if this account didn't author it, or the target is gone
    // (authorship unverifiable), emit nothing.
    let reaction_target = if event.message.kind == MARMOT_APP_EVENT_KIND_REACTION {
        match tag_value(&event.message.tags, EVENT_REF_TAG) {
            Some(target_id) => {
                app.reaction_target(&event.account_label, &group_id_hex, target_id)?
            }
            None => None,
        }
    } else {
        None
    };
    if event.message.kind == MARMOT_APP_EVENT_KIND_REACTION
        && reaction_target
            .as_ref()
            .map(|target| target.sender.as_str())
            != Some(event.account_id_hex.as_str())
    {
        return Ok(None);
    }
    let (reaction_emoji, reacted_to_preview) =
        reaction_notification_fields(&event.message, reaction_target.as_ref());
    Ok(Some(NotificationUpdate {
        notification_key: format!(
            "message:{}:{}",
            event.account_id_hex, event.message.message_id_hex
        ),
        conversation_key: conversation_key(&event.account_id_hex, &group_id_hex),
        trigger: NotificationTrigger::NewMessage,
        account_ref: event.account_label.clone(),
        account_id_hex: event.account_id_hex.clone(),
        group_id_hex,
        group_name: group_name(group.as_ref()),
        is_dm: false,
        message_id_hex: Some(event.message.message_id_hex.clone()),
        sender,
        receiver,
        preview_text: preview_text_for_message(&event.message),
        reaction_emoji,
        reacted_to_preview,
        timestamp_ms: unix_now_ms(),
        is_from_self,
    }))
}

fn notification_update_from_group_join(
    app: &MarmotApp,
    account_label: &str,
    account_id_hex: &str,
    group_id: &cgka_traits::GroupId,
) -> Result<NotificationUpdate, AppError> {
    let settings = app.notification_settings(account_label)?;
    if !settings.local_notifications_enabled {
        return Err(AppError::NotificationsDisabled);
    }
    let group_id_hex = hex::encode(group_id.as_slice());
    let group = app.group(account_label, &group_id_hex)?;
    let receiver = notification_user(app, account_id_hex)?;
    let sender_id = group
        .as_ref()
        .and_then(|group| group.welcomer_account_id_hex.clone())
        .unwrap_or_else(|| account_id_hex.to_owned());
    let sender = notification_user(app, &sender_id)?;
    let invite_ref = group
        .as_ref()
        .and_then(|group| group.via_welcome_message_id_hex.clone())
        .unwrap_or_else(|| group_id_hex.clone());
    Ok(NotificationUpdate {
        notification_key: format!("invite:{account_id_hex}:{invite_ref}"),
        conversation_key: conversation_key(account_id_hex, &group_id_hex),
        trigger: NotificationTrigger::GroupInvite,
        account_ref: account_label.to_owned(),
        account_id_hex: account_id_hex.to_owned(),
        group_id_hex,
        group_name: group_name(group.as_ref()),
        is_dm: false,
        message_id_hex: None,
        sender,
        receiver,
        preview_text: None,
        reaction_emoji: None,
        reacted_to_preview: None,
        timestamp_ms: unix_now_ms(),
        is_from_self: sender_id == account_id_hex,
    })
}

fn group_name(group: Option<&AppGroupRecord>) -> Option<String> {
    group
        .map(|group| group.profile.name.trim().to_owned())
        .filter(|name| !name.is_empty())
}

fn preview_text_for_message(message: &ReceivedMessage) -> Option<String> {
    preview_text_for_kind(message.kind, &message.plaintext)
}

/// Shared preview rule for an inner app event's kind/plaintext. Push-gossip
/// kinds and blank text never produce a preview.
fn preview_text_for_kind(kind: u64, plaintext: &str) -> Option<String> {
    if is_push_gossip_kind(kind) || plaintext.trim().is_empty() {
        None
    } else {
        Some(plaintext.to_owned())
    }
}

/// Shape the (emoji, preview) pair for a reaction from its already-resolved
/// timeline target. Emoji is the trimmed event content. Preview is `None` for a
/// `deleted`/`invalidated` target so removed text never reaches a preview;
/// otherwise the normal preview rule applies. Pure; returns display text only.
fn reaction_notification_fields(
    message: &ReceivedMessage,
    target: Option<&TimelineMessageTarget>,
) -> (Option<String>, Option<String>) {
    if message.kind != MARMOT_APP_EVENT_KIND_REACTION {
        return (None, None);
    }
    let reaction_emoji = {
        let trimmed = message.plaintext.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    };
    let reacted_to_preview = target.and_then(|target| {
        if target.deleted || target.invalidated {
            None
        } else {
            preview_text_for_kind(target.kind, &target.plaintext)
        }
    });
    (reaction_emoji, reacted_to_preview)
}

fn notification_user_from_message(
    app: &MarmotApp,
    message: &ReceivedMessage,
) -> Result<NotificationUser, AppError> {
    let mut user = notification_user(app, &message.sender)?;
    if user.display_name.is_none() {
        user.display_name = message.sender_display_name.clone();
    }
    Ok(user)
}

fn notification_user(app: &MarmotApp, account_id_hex: &str) -> Result<NotificationUser, AppError> {
    let profile = app.directory_entry_for_account_id(account_id_hex)?;
    Ok(NotificationUser {
        account_id_hex: account_id_hex.to_owned(),
        display_name: app.display_name_for_account_id(account_id_hex)?,
        picture_url: profile.and_then(|entry| entry.profile.and_then(|profile| profile.picture)),
    })
}

pub(crate) fn conversation_key(account_id_hex: &str, group_id_hex: &str) -> String {
    format!("conversation:{account_id_hex}:{group_id_hex}")
}

pub(crate) fn dedupe_notification_updates(
    updates: Vec<NotificationUpdate>,
) -> Vec<NotificationUpdate> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for update in updates {
        if seen.insert(update.notification_key.clone()) {
            out.push(update);
        }
    }
    out
}

pub(crate) fn group_debug_info(
    settings: NotificationSettings,
    registration: Option<StoredPushRegistration>,
    tokens: Vec<GroupPushTokenRecord>,
    local_account_id_hex: &str,
    active_members: &[String],
) -> GroupPushDebugInfo {
    let active_by_member = active_members
        .iter()
        .enumerate()
        .map(|(index, member)| (member.clone(), index as u32))
        .collect::<BTreeMap<_, _>>();
    let local_leaf_index = active_by_member.get(local_account_id_hex).copied();
    let local_token_cached = registration.is_some();
    let mut latest = None;
    let mut active_count = 0_u32;
    let mut missing_relay_hint_count = 0_u32;
    let mut entries = Vec::with_capacity(tokens.len());
    for token in &tokens {
        latest = Some(latest.map_or(token.updated_at_ms, |value: i64| {
            value.max(token.updated_at_ms)
        }));
        if token.relay_hint.is_none() {
            missing_relay_hint_count += 1;
        }
        let active_leaf = active_by_member.contains_key(&token.member_id_hex);
        let member_matches_active_leaf = active_by_member
            .get(&token.member_id_hex)
            .is_some_and(|leaf_index| *leaf_index == token.leaf_index);
        if active_leaf && member_matches_active_leaf {
            active_count += 1;
        }
        entries.push(GroupPushTokenDebugEntry {
            member_id_hex: token.member_id_hex.clone(),
            leaf_index: token.leaf_index,
            platform: token.platform,
            token_fingerprint: token.token_fingerprint.clone(),
            server_pubkey_hex: token.server_pubkey_hex.clone(),
            has_relay_hint: token.relay_hint.is_some(),
            active_leaf,
            member_matches_active_leaf,
            is_local_member: token.member_id_hex == local_account_id_hex,
            updated_at_ms: token.updated_at_ms,
        });
    }
    entries.sort_by(|a, b| {
        a.member_id_hex
            .cmp(&b.member_id_hex)
            .then_with(|| a.platform.as_str().cmp(b.platform.as_str()))
            .then_with(|| a.server_pubkey_hex.cmp(&b.server_pubkey_hex))
    });
    GroupPushDebugInfo {
        total_token_count: entries.len() as u32,
        active_token_count: active_count,
        stale_token_count: (entries.len() as u32).saturating_sub(active_count),
        missing_relay_hint_count,
        last_token_list_updated_at_ms: latest,
        local_registration: LocalPushRegistrationDebug {
            registered: registration.is_some(),
            shareable: settings.native_push_enabled && registration.is_some(),
            local_notifications_enabled: settings.local_notifications_enabled,
            native_push_enabled: settings.native_push_enabled,
            local_leaf_index,
            local_token_cached,
        },
        tokens: entries,
    }
}

pub(crate) fn token_records_by_server(
    tokens: Vec<GroupPushTokenRecord>,
    local_account_id_hex: &str,
) -> BTreeMap<String, Vec<GroupPushTokenRecord>> {
    let mut grouped: BTreeMap<String, Vec<GroupPushTokenRecord>> = BTreeMap::new();
    let mut keys = BTreeSet::new();
    for token in tokens {
        // Keep records without a relay hint: the trigger publisher falls back to
        // the server account's published kind-10050 inbox relays, so a missing
        // hint is not an immediate drop (per features/push-notifications.md).
        if token.member_id_hex == local_account_id_hex {
            continue;
        }
        let key = (
            token.member_id_hex.clone(),
            token.platform.as_str().to_owned(),
            token.server_pubkey_hex.clone(),
        );
        if keys.insert(key) {
            grouped
                .entry(token.server_pubkey_hex.clone())
                .or_default()
                .push(token);
        }
    }
    grouped
}

/// Choose the relays to publish a notification trigger to for one server.
///
/// Per features/push-notifications.md the relay hints carried in stored token
/// records are preferred; when none exist the fallback is the notification
/// server account's published kind-10050 NIP-17 inbox relays. If neither is
/// available the server is unreachable and the result is empty (the caller
/// skips it as the genuine last resort). Blank entries are dropped and the
/// result is de-duplicated with a stable order.
pub(crate) fn select_notification_trigger_relays(
    record_relay_hints: &[String],
    server_inbox_relays: &[String],
) -> Vec<String> {
    let hints = dedup_non_empty_relays(record_relay_hints);
    if !hints.is_empty() {
        return hints;
    }
    dedup_non_empty_relays(server_inbox_relays)
}

fn dedup_non_empty_relays(relays: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    relays
        .iter()
        .map(|relay| relay.trim())
        .filter(|relay| !relay.is_empty())
        .filter(|relay| seen.insert(relay.to_owned()))
        .map(str::to_owned)
        .collect()
}

pub(crate) fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
pub(crate) fn decrypt_mip05_token_for_test(
    blob: &[u8],
    server_secret: &SecretKey,
) -> Result<(PushPlatform, Vec<u8>), AppError> {
    if blob.len() != MIP05_ENCRYPTED_TOKEN_LEN {
        return Err(AppError::InvalidPushToken(
            "invalid encrypted token length".into(),
        ));
    }
    let ephemeral_xonly = XOnlyPublicKey::from_slice(&blob[..32])
        .map_err(|_| AppError::InvalidPushToken("invalid encrypted token ephemeral key".into()))?;
    let ephemeral_pubkey = SecpPublicKey::from_x_only_public_key(ephemeral_xonly, Parity::Even);
    let shared_x = secp256k1_ecdh_x(&ephemeral_pubkey, server_secret);
    let key = mip05_encryption_key(&shared_x)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| AppError::InvalidPushToken("mip05-v1 key setup failed".into()))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&blob[32..44]),
            Payload {
                msg: &blob[44..],
                aad: &[],
            },
        )
        .map_err(|_| AppError::InvalidPushToken("mip05-v1 token decrypt failed".into()))?;
    if plaintext.len() != MIP05_TOKEN_PLAINTEXT_LEN {
        return Err(AppError::InvalidPushToken(
            "invalid token plaintext length".into(),
        ));
    }
    let platform = PushPlatform::from_platform_byte(plaintext[0])?;
    let token_len = u16::from_be_bytes([plaintext[1], plaintext[2]]) as usize;
    validate_provider_token_len(&plaintext[3..3 + token_len])?;
    Ok((platform, plaintext[3..3 + token_len].to_vec()))
}

#[cfg(test)]
mod tests;
