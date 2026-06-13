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

use crate::{
    AppError, AppGroupRecord, MarmotApp, MarmotAppEvent, ReceivedMessage, RuntimeMessageReceived,
};

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
        MarmotAppEvent::MessageReceived(message) => {
            notification_update_from_message(app, message).map(Some)
        }
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

fn notification_update_from_message(
    app: &MarmotApp,
    event: &RuntimeMessageReceived,
) -> Result<NotificationUpdate, AppError> {
    let settings = app.notification_settings(&event.account_label)?;
    if !settings.local_notifications_enabled {
        return Err(AppError::NotificationsDisabled);
    }
    let group_id_hex = hex::encode(event.message.group_id.as_slice());
    let group = app.group(&event.account_label, &group_id_hex)?;
    let receiver = notification_user(app, &event.account_id_hex)?;
    let sender = notification_user_from_message(app, &event.message)?;
    let is_from_self = event.message.sender == event.account_id_hex;
    Ok(NotificationUpdate {
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
        timestamp_ms: unix_now_ms(),
        is_from_self,
    })
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
    if is_push_gossip_kind(message.kind) || message.plaintext.trim().is_empty() {
        None
    } else {
        Some(message.plaintext.clone())
    }
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
mod tests {
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
        assert!(
            select_notification_trigger_relays(&["   ".to_owned()], &["".to_owned()]).is_empty()
        );
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
            let err = parse_push_gossip(kind, &group_id_hex, garbage)
                .expect_err("garbage gossip must error");
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
}
