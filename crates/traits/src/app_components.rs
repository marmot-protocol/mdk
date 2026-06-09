//! Marmot MLS app component ids and small byte helpers.
//!
//! Component state itself lives in the MLS `app_data_dictionary` extension.
//! These helpers deliberately stay OpenMLS-free so the public trait surface can
//! talk about component ids without exposing engine internals.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use url::{Host, Url};

/// MLS ComponentID.
pub type AppComponentId = u16;

/// Upstream MLS extensions draft component that carries supported/required
/// application component ids in an `AppDataDictionary` entry.
pub const APP_COMPONENTS_COMPONENT_ID: AppComponentId = 0x0001;

pub const GROUP_PROFILE_COMPONENT_ID: AppComponentId = 0x8001;
pub const GROUP_BLOSSOM_IMAGE_COMPONENT_ID: AppComponentId = 0x8002;
pub const GROUP_ADMIN_POLICY_COMPONENT_ID: AppComponentId = 0x8003;
pub const NOSTR_ROUTING_COMPONENT_ID: AppComponentId = 0x8004;
pub const GROUP_MESSAGE_RETENTION_COMPONENT_ID: AppComponentId = 0x8005;
pub const AGENT_TEXT_STREAM_QUIC_COMPONENT_ID: AppComponentId = 0x8006;
pub const GROUP_AVATAR_URL_COMPONENT_ID: AppComponentId = 0x8007;
pub const GROUP_ENCRYPTED_MEDIA_COMPONENT_ID: AppComponentId = 0x8008;
/// Lookup key for the encrypted-media secret in the
/// [`crate::group_context::GroupContextSnapshot`] secrets map. This is an
/// internal cache key, NOT the MLS exporter label/context: the secret is derived
/// as `MLS-Exporter("marmot", "encrypted-media", 32)` — label `"marmot"`,
/// context `"encrypted-media"` — per the Marmot spec.
pub const GROUP_ENCRYPTED_MEDIA_EXPORTER_CACHE_KEY: &str = "marmot/encrypted-media";

pub const GROUP_PROFILE_COMPONENT: &str = "marmot.group.profile.v1";
pub const GROUP_BLOSSOM_IMAGE_COMPONENT: &str = "marmot.group.blossom.image.v1";
pub const GROUP_ADMIN_POLICY_COMPONENT: &str = "marmot.group.admin-policy.v1";
pub const NOSTR_ROUTING_COMPONENT: &str = "marmot.transport.nostr.routing.v1";
pub const GROUP_MESSAGE_RETENTION_COMPONENT: &str = "marmot.group.message-retention.v1";
pub const AGENT_TEXT_STREAM_QUIC_COMPONENT: &str = "marmot.group.agent-text-stream.quic.v1";
pub const GROUP_AVATAR_URL_COMPONENT: &str = "marmot.group.avatar-url.v1";
pub const GROUP_ENCRYPTED_MEDIA_COMPONENT: &str = "marmot.group.encrypted-media.v1";
pub const ENCRYPTED_MEDIA_FORMAT_V1: &str = "encrypted-media-v1";
pub const BLOSSOM_LOCATOR_KIND_V1: &str = "blossom-v1";

/// Maximum encoded length of a group avatar URL, in bytes.
pub const GROUP_AVATAR_URL_MAX_LEN: usize = 2048;
/// Maximum encoded length of the optional `dim` / `thumbhash` render hints.
pub const GROUP_AVATAR_HINT_MAX_LEN: usize = 256;
pub const ENCRYPTED_MEDIA_LOCATOR_KIND_MAX_LEN: usize = 64;
pub const ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN: usize = 2048;
pub const ENCRYPTED_MEDIA_MAX_LOCATOR_KINDS: usize = 16;
pub const ENCRYPTED_MEDIA_MAX_BLOB_ENDPOINTS: usize = 16;
// Upper bounds for nested var-bytes vectors before decoding them into owned buffers.
const ENCRYPTED_MEDIA_LOCATOR_KINDS_VECTOR_MAX_LEN: usize =
    ENCRYPTED_MEDIA_MAX_LOCATOR_KINDS * (ENCRYPTED_MEDIA_LOCATOR_KIND_MAX_LEN + 2);
const ENCRYPTED_MEDIA_ENDPOINT_ENTRY_MAX_LEN: usize =
    (ENCRYPTED_MEDIA_LOCATOR_KIND_MAX_LEN + 2) + (ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN + 2);
const ENCRYPTED_MEDIA_BLOB_ENDPOINTS_VECTOR_MAX_LEN: usize =
    ENCRYPTED_MEDIA_MAX_BLOB_ENDPOINTS * (ENCRYPTED_MEDIA_ENDPOINT_ENTRY_MAX_LEN + 2);

/// Initial app-component state supplied by the app layer at group creation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppComponentData {
    pub component_id: AppComponentId,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NostrRoutingV1 {
    pub nostr_group_id: [u8; 32],
    pub relays: Vec<String>,
}

impl NostrRoutingV1 {
    pub fn new(nostr_group_id: [u8; 32], mut relays: Vec<String>) -> Result<Self, String> {
        relays.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        relays.dedup();
        let value = Self {
            nostr_group_id,
            relays,
        };
        validate_nostr_routing(&value)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobStoreEndpointV1 {
    pub locator_kind: String,
    pub base_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMediaPolicyV1 {
    pub media_format: String,
    pub allowed_locator_kinds: Vec<String>,
    pub default_blob_endpoints: Vec<BlobStoreEndpointV1>,
}

impl EncryptedMediaPolicyV1 {
    pub fn blossom_default(
        endpoints: impl IntoIterator<Item = String>,
        allow_loopback_http: bool,
    ) -> Result<Self, String> {
        Self::new(
            ENCRYPTED_MEDIA_FORMAT_V1.to_owned(),
            vec![BLOSSOM_LOCATOR_KIND_V1.to_owned()],
            endpoints.into_iter().map(|base_url| BlobStoreEndpointV1 {
                locator_kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
                base_url,
            }),
            allow_loopback_http,
        )
    }

    pub fn new(
        media_format: String,
        allowed_locator_kinds: Vec<String>,
        endpoints: impl IntoIterator<Item = BlobStoreEndpointV1>,
        allow_loopback_http: bool,
    ) -> Result<Self, String> {
        let media_format = media_format.trim().to_owned();
        if media_format != ENCRYPTED_MEDIA_FORMAT_V1 {
            return Err(format!(
                "encrypted media format must be {ENCRYPTED_MEDIA_FORMAT_V1}"
            ));
        }
        let allowed_locator_kinds =
            normalize_locator_kinds(allowed_locator_kinds, "allowed locator kind")?;
        if allowed_locator_kinds.is_empty() {
            return Err("encrypted media policy must allow at least one locator kind".into());
        }
        if allowed_locator_kinds.len() > ENCRYPTED_MEDIA_MAX_LOCATOR_KINDS {
            return Err(format!(
                "encrypted media policy allows more than {ENCRYPTED_MEDIA_MAX_LOCATOR_KINDS} locator kinds"
            ));
        }

        let mut normalized_endpoints = Vec::new();
        for endpoint in endpoints {
            let locator_kind =
                normalize_locator_kind(&endpoint.locator_kind, "endpoint locator kind")?;
            if !allowed_locator_kinds
                .iter()
                .any(|kind| kind == &locator_kind)
            {
                return Err("encrypted media endpoint locator kind is not allowed".into());
            }
            let base_url =
                validate_and_normalize_blob_endpoint_url(&endpoint.base_url, allow_loopback_http)?;
            let endpoint = BlobStoreEndpointV1 {
                locator_kind,
                base_url,
            };
            if !normalized_endpoints
                .iter()
                .any(|existing| existing == &endpoint)
            {
                normalized_endpoints.push(endpoint);
            }
        }
        if normalized_endpoints.is_empty() {
            return Err(
                "encrypted media policy must include at least one default blob endpoint".into(),
            );
        }
        if normalized_endpoints.len() > ENCRYPTED_MEDIA_MAX_BLOB_ENDPOINTS {
            return Err(format!(
                "encrypted media policy includes more than {ENCRYPTED_MEDIA_MAX_BLOB_ENDPOINTS} default blob endpoints"
            ));
        }

        Ok(Self {
            media_format,
            allowed_locator_kinds,
            default_blob_endpoints: normalized_endpoints,
        })
    }
}

/// The group-state components this implementation creates by default when
/// every founding member advertises support for them.
pub fn default_group_components() -> BTreeSet<AppComponentId> {
    [GROUP_PROFILE_COMPONENT_ID, GROUP_ADMIN_POLICY_COMPONENT_ID]
        .into_iter()
        .collect()
}

/// Sorted set of app component ids.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppComponentSet {
    pub ids: BTreeSet<AppComponentId>,
}

impl AppComponentSet {
    pub fn new(ids: impl IntoIterator<Item = AppComponentId>) -> Self {
        Self {
            ids: ids.into_iter().collect(),
        }
    }

    pub fn contains(&self, id: AppComponentId) -> bool {
        self.ids.contains(&id)
    }

    pub fn insert(&mut self, id: AppComponentId) {
        self.ids.insert(id);
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn missing_from(&self, other: &Self) -> Self {
        Self {
            ids: self.ids.difference(&other.ids).copied().collect(),
        }
    }

    pub fn intersection(&self, other: &Self) -> Self {
        Self {
            ids: self.ids.intersection(&other.ids).copied().collect(),
        }
    }
}

impl From<BTreeSet<AppComponentId>> for AppComponentSet {
    fn from(ids: BTreeSet<AppComponentId>) -> Self {
        Self { ids }
    }
}

/// Encode the extensions-draft `ComponentsList`:
///
/// ```text
/// struct {
///   ComponentID component_ids<V>;
/// } ComponentsList;
/// ```
///
/// The vector payload is a concatenated sequence of big-endian `uint16`
/// component ids, prefixed by a canonical QUIC variable-length byte length.
pub fn encode_components_list(ids: &BTreeSet<AppComponentId>) -> Vec<u8> {
    let mut out = Vec::new();
    encode_quic_varint((ids.len() * 2) as u64, &mut out);
    for id in ids {
        out.extend_from_slice(&id.to_be_bytes());
    }
    out
}

pub fn decode_components_list(bytes: &[u8]) -> Result<BTreeSet<AppComponentId>, String> {
    let (len, prefix_len) = decode_quic_varint(bytes)?;
    let len = usize::try_from(len).map_err(|_| "component list length is too large")?;
    let end = prefix_len
        .checked_add(len)
        .ok_or("component list length overflow")?;
    if end != bytes.len() {
        return Err("component list has trailing bytes".into());
    }
    if len % 2 != 0 {
        return Err("component list byte length must be even".into());
    }
    let mut ids = BTreeSet::new();
    for chunk in bytes[prefix_len..end].chunks_exact(2) {
        let id = u16::from_be_bytes([chunk[0], chunk[1]]);
        if !ids.insert(id) {
            return Err("component list contains duplicate ids".into());
        }
    }
    Ok(ids)
}

pub fn encode_component_vectors(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        encode_quic_varint(part.len() as u64, &mut out);
        out.extend_from_slice(part);
    }
    out
}

pub fn encode_nostr_routing_v1(routing: &NostrRoutingV1) -> Result<Vec<u8>, String> {
    validate_nostr_routing(routing)?;
    let mut relay_entries = Vec::new();
    for relay in &routing.relays {
        encode_quic_varint(relay.len() as u64, &mut relay_entries);
        relay_entries.extend_from_slice(relay.as_bytes());
    }

    let mut out = Vec::with_capacity(32 + relay_entries.len() + 8);
    out.extend_from_slice(&routing.nostr_group_id);
    encode_quic_varint(relay_entries.len() as u64, &mut out);
    out.extend_from_slice(&relay_entries);
    Ok(out)
}

pub fn decode_nostr_routing_v1(bytes: &[u8]) -> Result<NostrRoutingV1, String> {
    if bytes.len() < 32 {
        return Err("Nostr routing component is missing nostr_group_id".into());
    }
    let mut nostr_group_id = [0_u8; 32];
    nostr_group_id.copy_from_slice(&bytes[..32]);
    let mut cursor = &bytes[32..];
    let relay_vector = decode_var_bytes(&mut cursor, usize::MAX, "Nostr relay vector")?;
    if !cursor.is_empty() {
        return Err("Nostr routing component has trailing bytes".into());
    }
    let mut relay_cursor = relay_vector.as_slice();
    let mut relays = Vec::new();
    while !relay_cursor.is_empty() {
        let relay = decode_var_bytes(&mut relay_cursor, 512, "Nostr relay URL")?;
        if relay.is_empty() {
            return Err("Nostr relay URL must not be empty".into());
        }
        let relay =
            String::from_utf8(relay).map_err(|e| format!("Nostr relay URL is not UTF-8: {e}"))?;
        relays.push(relay);
    }
    let routing = NostrRoutingV1 {
        nostr_group_id,
        relays,
    };
    validate_nostr_routing(&routing)?;
    Ok(routing)
}

pub fn encode_encrypted_media_policy_v1(
    policy: &EncryptedMediaPolicyV1,
) -> Result<Vec<u8>, String> {
    let policy = EncryptedMediaPolicyV1::new(
        policy.media_format.clone(),
        policy.allowed_locator_kinds.clone(),
        policy.default_blob_endpoints.clone(),
        true,
    )?;
    let mut allowed = Vec::new();
    for kind in &policy.allowed_locator_kinds {
        encode_var_bytes(kind.as_bytes(), &mut allowed);
    }
    let mut endpoints = Vec::new();
    for endpoint in &policy.default_blob_endpoints {
        let mut encoded_endpoint = Vec::new();
        encode_var_bytes(endpoint.locator_kind.as_bytes(), &mut encoded_endpoint);
        encode_var_bytes(endpoint.base_url.as_bytes(), &mut encoded_endpoint);
        encode_var_bytes(&encoded_endpoint, &mut endpoints);
    }
    Ok(encode_component_vectors(&[
        policy.media_format.as_bytes(),
        allowed.as_slice(),
        endpoints.as_slice(),
    ]))
}

pub fn decode_encrypted_media_policy_v1(bytes: &[u8]) -> Result<EncryptedMediaPolicyV1, String> {
    let mut cursor = bytes;
    let media_format = decode_var_bytes(&mut cursor, 64, "encrypted media format")?;
    let allowed_bytes = decode_var_bytes(
        &mut cursor,
        ENCRYPTED_MEDIA_LOCATOR_KINDS_VECTOR_MAX_LEN,
        "encrypted media locator kinds",
    )?;
    let endpoints_bytes = decode_var_bytes(
        &mut cursor,
        ENCRYPTED_MEDIA_BLOB_ENDPOINTS_VECTOR_MAX_LEN,
        "encrypted media default blob endpoints",
    )?;
    if !cursor.is_empty() {
        return Err("encrypted media policy has trailing bytes".into());
    }
    let media_format = String::from_utf8(media_format)
        .map_err(|e| format!("encrypted media format is not UTF-8: {e}"))?;

    let mut allowed_cursor = allowed_bytes.as_slice();
    let mut allowed_locator_kinds = Vec::new();
    while !allowed_cursor.is_empty() {
        let kind = decode_var_bytes(
            &mut allowed_cursor,
            ENCRYPTED_MEDIA_LOCATOR_KIND_MAX_LEN,
            "encrypted media locator kind",
        )?;
        allowed_locator_kinds.push(
            String::from_utf8(kind)
                .map_err(|e| format!("encrypted media locator kind is not UTF-8: {e}"))?,
        );
    }

    let mut endpoints_cursor = endpoints_bytes.as_slice();
    let mut default_blob_endpoints = Vec::new();
    while !endpoints_cursor.is_empty() {
        let endpoint_bytes = decode_var_bytes(
            &mut endpoints_cursor,
            ENCRYPTED_MEDIA_LOCATOR_KIND_MAX_LEN + ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN + 8,
            "encrypted media endpoint",
        )?;
        let mut endpoint_cursor = endpoint_bytes.as_slice();
        let locator_kind = decode_var_bytes(
            &mut endpoint_cursor,
            ENCRYPTED_MEDIA_LOCATOR_KIND_MAX_LEN,
            "encrypted media endpoint locator kind",
        )?;
        let base_url = decode_var_bytes(
            &mut endpoint_cursor,
            ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN,
            "encrypted media endpoint base URL",
        )?;
        if !endpoint_cursor.is_empty() {
            return Err("encrypted media endpoint has trailing bytes".into());
        }
        default_blob_endpoints.push(BlobStoreEndpointV1 {
            locator_kind: String::from_utf8(locator_kind)
                .map_err(|e| format!("encrypted media endpoint locator kind is not UTF-8: {e}"))?,
            base_url: String::from_utf8(base_url)
                .map_err(|e| format!("encrypted media endpoint base URL is not UTF-8: {e}"))?,
        });
    }

    EncryptedMediaPolicyV1::new(
        media_format,
        allowed_locator_kinds,
        default_blob_endpoints,
        true,
    )
}

/// Decoded `marmot.group.avatar-url.v1` state. An absent avatar is an empty `url`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupAvatarUrlV1 {
    pub url: String,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
}

/// Encode `marmot.group.avatar-url.v1` state. The URL is validated and normalized;
/// an empty `url` encodes the absent/cleared avatar (all fields empty).
pub fn encode_group_avatar_url_v1(avatar: &GroupAvatarUrlV1) -> Result<Vec<u8>, String> {
    if avatar.url.is_empty() && (avatar.dim.is_some() || avatar.thumbhash.is_some()) {
        return Err("group avatar absent state must not include hints".into());
    }
    let url = if avatar.url.is_empty() {
        String::new()
    } else {
        validate_and_normalize_group_avatar_url(&avatar.url)?
    };
    let dim = avatar.dim.as_deref().unwrap_or("");
    let thumbhash = avatar.thumbhash.as_deref().unwrap_or("");
    if dim.len() > GROUP_AVATAR_HINT_MAX_LEN {
        return Err(format!(
            "group avatar dim exceeds {GROUP_AVATAR_HINT_MAX_LEN} bytes"
        ));
    }
    if thumbhash.len() > GROUP_AVATAR_HINT_MAX_LEN {
        return Err(format!(
            "group avatar thumbhash exceeds {GROUP_AVATAR_HINT_MAX_LEN} bytes"
        ));
    }
    let mut out = Vec::with_capacity(url.len() + dim.len() + thumbhash.len() + 6);
    encode_var_bytes(url.as_bytes(), &mut out);
    encode_var_bytes(dim.as_bytes(), &mut out);
    encode_var_bytes(thumbhash.as_bytes(), &mut out);
    Ok(out)
}

/// Decode `marmot.group.avatar-url.v1` state, re-validating a present URL.
pub fn decode_group_avatar_url_v1(bytes: &[u8]) -> Result<GroupAvatarUrlV1, String> {
    let mut cursor = bytes;
    let url = decode_var_bytes(&mut cursor, GROUP_AVATAR_URL_MAX_LEN, "group avatar URL")?;
    let dim = decode_var_bytes(&mut cursor, GROUP_AVATAR_HINT_MAX_LEN, "group avatar dim")?;
    let thumbhash = decode_var_bytes(
        &mut cursor,
        GROUP_AVATAR_HINT_MAX_LEN,
        "group avatar thumbhash",
    )?;
    if !cursor.is_empty() {
        return Err("group avatar component has trailing bytes".into());
    }
    let url = String::from_utf8(url).map_err(|e| format!("group avatar URL is not UTF-8: {e}"))?;
    let dim = String::from_utf8(dim).map_err(|e| format!("group avatar dim is not UTF-8: {e}"))?;
    let thumbhash = String::from_utf8(thumbhash)
        .map_err(|e| format!("group avatar thumbhash is not UTF-8: {e}"))?;
    if url.is_empty() && (!dim.is_empty() || !thumbhash.is_empty()) {
        return Err("group avatar absent state must not include hints".into());
    }
    if !url.is_empty() {
        // Compare against normalized bytes so a non-normalized stored URL is rejected.
        let normalized = validate_and_normalize_group_avatar_url(&url)?;
        if normalized != url {
            return Err("group avatar URL is not normalized".into());
        }
    }
    Ok(GroupAvatarUrlV1 {
        url,
        dim: (!dim.is_empty()).then_some(dim),
        thumbhash: (!thumbhash.is_empty()).then_some(thumbhash),
    })
}

/// Validate and normalize a group avatar URL: `https` only, length-bounded, no
/// credentials or fragment, and not pointing at localhost or a non-routable IP.
/// Returns the normalized URL string.
pub fn validate_and_normalize_group_avatar_url(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("group avatar URL must not be empty".into());
    }
    if raw.len() > GROUP_AVATAR_URL_MAX_LEN {
        return Err(format!(
            "group avatar URL exceeds {GROUP_AVATAR_URL_MAX_LEN} bytes"
        ));
    }
    let url = Url::parse(raw).map_err(|e| format!("group avatar URL is invalid: {e}"))?;
    if url.scheme() != "https" {
        return Err("group avatar URL scheme must be https".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("group avatar URL must not include credentials".into());
    }
    if url.fragment().is_some() {
        return Err("group avatar URL must not include a fragment".into());
    }
    match url.host().ok_or("group avatar URL must include a host")? {
        Host::Domain(domain) => {
            let lowered = domain.to_ascii_lowercase();
            if lowered == "localhost" || lowered.ends_with(".localhost") {
                return Err("group avatar URL must not point at localhost".into());
            }
        }
        Host::Ipv4(addr) => reject_non_routable_ipv4(addr)?,
        Host::Ipv6(addr) => reject_non_routable_ipv6(addr)?,
    }
    let normalized = url.as_str();
    if normalized.len() > GROUP_AVATAR_URL_MAX_LEN {
        return Err(format!(
            "group avatar URL exceeds {GROUP_AVATAR_URL_MAX_LEN} bytes"
        ));
    }
    Ok(normalized.to_owned())
}

pub fn validate_and_normalize_blob_endpoint_url(
    raw: &str,
    allow_loopback_http: bool,
) -> Result<String, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("encrypted media endpoint URL must not be empty".into());
    }
    if raw.len() > ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN {
        return Err(format!(
            "encrypted media endpoint URL exceeds {ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN} bytes"
        ));
    }
    let mut url =
        Url::parse(raw).map_err(|e| format!("encrypted media endpoint URL is invalid: {e}"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("encrypted media endpoint URL must not include credentials".into());
    }
    if url.fragment().is_some() {
        return Err("encrypted media endpoint URL must not include a fragment".into());
    }
    if url.query().is_some() {
        return Err("encrypted media endpoint URL must not include a query".into());
    }
    let host = url
        .host()
        .ok_or("encrypted media endpoint URL must include a host")?;
    match url.scheme() {
        "https" => match host {
            Host::Domain(domain) => {
                let lowered = domain.to_ascii_lowercase();
                if lowered == "localhost" || lowered.ends_with(".localhost") {
                    return Err("encrypted media https endpoint must not point at localhost".into());
                }
            }
            Host::Ipv4(addr) => reject_non_routable_ipv4(addr).map_err(|_| {
                "encrypted media endpoint URL must not point at a non-routable address".to_owned()
            })?,
            Host::Ipv6(addr) => reject_non_routable_ipv6(addr).map_err(|_| {
                "encrypted media endpoint URL must not point at a non-routable address".to_owned()
            })?,
        },
        "http" if allow_loopback_http && is_loopback_host(host) => {}
        "http" => {
            return Err(
                "encrypted media endpoint URL scheme must be https unless loopback http is explicitly allowed"
                    .into(),
            );
        }
        _ => return Err("encrypted media endpoint URL scheme must be https".into()),
    }
    url.set_fragment(None);
    let mut normalized = url.as_str().trim_end_matches('/').to_owned();
    if normalized.is_empty() {
        normalized = url.as_str().to_owned();
    }
    if normalized.len() > ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN {
        return Err(format!(
            "encrypted media endpoint URL exceeds {ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN} bytes"
        ));
    }
    Ok(normalized)
}

fn normalize_locator_kinds(kinds: Vec<String>, label: &'static str) -> Result<Vec<String>, String> {
    let mut normalized = Vec::new();
    for kind in kinds {
        let kind = normalize_locator_kind(&kind, label)?;
        if !normalized.iter().any(|existing| existing == &kind) {
            normalized.push(kind);
        }
    }
    Ok(normalized)
}

fn normalize_locator_kind(value: &str, label: &'static str) -> Result<String, String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value.len() > ENCRYPTED_MEDIA_LOCATOR_KIND_MAX_LEN {
        return Err(format!(
            "{label} exceeds {ENCRYPTED_MEDIA_LOCATOR_KIND_MAX_LEN} bytes"
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(format!(
            "{label} must contain only lowercase ASCII letters, digits, and '-'"
        ));
    }
    Ok(value)
}

fn is_loopback_host(host: Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => {
            let lowered = domain.to_ascii_lowercase();
            lowered == "localhost" || lowered.ends_with(".localhost")
        }
        Host::Ipv4(addr) => addr.is_loopback(),
        Host::Ipv6(addr) => addr.is_loopback(),
    }
}

fn reject_non_routable_ipv4(addr: Ipv4Addr) -> Result<(), String> {
    if addr.is_loopback()
        || addr.is_private()
        || addr.is_link_local()
        || addr.is_broadcast()
        || addr.is_documentation()
        || addr.is_unspecified()
        || addr.is_multicast()
    {
        return Err("group avatar URL must not point at a non-routable address".into());
    }
    Ok(())
}

fn reject_non_routable_ipv6(addr: Ipv6Addr) -> Result<(), String> {
    if let Some(mapped) = addr.to_ipv4_mapped() {
        return reject_non_routable_ipv4(mapped);
    }
    if addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() {
        return Err("group avatar URL must not point at a non-routable address".into());
    }
    // Reject unique-local (fc00::/7) and link-local (fe80::/10) addresses, which
    // the stable std API does not yet classify.
    let first = addr.segments()[0];
    if (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 {
        return Err("group avatar URL must not point at a non-routable address".into());
    }
    Ok(())
}

fn encode_var_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    encode_quic_varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

pub fn encode_quic_varint(value: u64, out: &mut Vec<u8>) {
    if value < 64 {
        out.push(value as u8);
    } else if value < 16_384 {
        let encoded = 0x4000 | value as u16;
        out.extend_from_slice(&encoded.to_be_bytes());
    } else if value < 1_073_741_824 {
        let encoded = 0x8000_0000 | value as u32;
        out.extend_from_slice(&encoded.to_be_bytes());
    } else {
        let encoded = 0xC000_0000_0000_0000 | value;
        out.extend_from_slice(&encoded.to_be_bytes());
    }
}

pub fn decode_quic_varint(bytes: &[u8]) -> Result<(u64, usize), String> {
    let first = *bytes.first().ok_or("missing QUIC varint")?;
    let width = 1usize << (first >> 6);
    if bytes.len() < width {
        return Err("truncated QUIC varint".into());
    }
    let mut value = (first & 0x3f) as u64;
    for byte in &bytes[1..width] {
        value = (value << 8) | u64::from(*byte);
    }
    let minimal_width = if value < 64 {
        1
    } else if value < 16_384 {
        2
    } else if value < 1_073_741_824 {
        4
    } else {
        8
    };
    if width != minimal_width {
        return Err("non-canonical QUIC varint length".into());
    }
    Ok((value, width))
}

fn validate_nostr_routing(routing: &NostrRoutingV1) -> Result<(), String> {
    if routing.relays.is_empty() {
        return Err("Nostr routing component must contain at least one relay".into());
    }
    let mut sorted = routing.relays.clone();
    sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    sorted.dedup();
    if sorted != routing.relays {
        return Err("Nostr relay URLs must be sorted and unique".into());
    }
    for relay in &routing.relays {
        validate_nostr_relay_url(relay)?;
    }
    Ok(())
}

fn validate_nostr_relay_url(relay: &str) -> Result<(), String> {
    if relay.is_empty() {
        return Err("Nostr relay URL must not be empty".into());
    }
    if relay.len() > 512 {
        return Err("Nostr relay URL exceeds 512 bytes".into());
    }
    let url = Url::parse(relay).map_err(|e| format!("Nostr relay URL is invalid: {e}"))?;
    if !matches!(url.scheme(), "wss" | "ws") {
        return Err("Nostr relay URL scheme must be wss or ws".into());
    }
    if url.host().is_none() {
        return Err("Nostr relay URL must include a host".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Nostr relay URL must not include credentials".into());
    }
    if url.fragment().is_some() {
        return Err("Nostr relay URL must not include a fragment".into());
    }
    Ok(())
}

fn decode_var_bytes(cursor: &mut &[u8], max_len: usize, label: &str) -> Result<Vec<u8>, String> {
    let (len, prefix_len) =
        decode_quic_varint(cursor).map_err(|e| format!("{label} length decode failed: {e}"))?;
    let len = usize::try_from(len).map_err(|_| format!("{label} length is too large"))?;
    if len > max_len {
        return Err(format!("{label} exceeds maximum length"));
    }
    let end = prefix_len
        .checked_add(len)
        .ok_or_else(|| format!("{label} length overflow"))?;
    if cursor.len() < end {
        return Err(format!("{label} is truncated"));
    }
    let bytes = cursor[prefix_len..end].to_vec();
    *cursor = &cursor[end..];
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_list_round_trips_sorted_ids() {
        let ids = BTreeSet::from([
            GROUP_ADMIN_POLICY_COMPONENT_ID,
            GROUP_PROFILE_COMPONENT_ID,
            NOSTR_ROUTING_COMPONENT_ID,
        ]);

        let encoded = encode_components_list(&ids);

        assert_eq!(decode_components_list(&encoded).unwrap(), ids);
    }

    #[test]
    fn component_list_rejects_duplicate_or_trailing_bytes() {
        let duplicate_profile = vec![4, 0x80, 0x01, 0x80, 0x01];
        assert_eq!(
            decode_components_list(&duplicate_profile),
            Err("component list contains duplicate ids".into())
        );

        let mut trailing = encode_components_list(&BTreeSet::from([GROUP_PROFILE_COMPONENT_ID]));
        trailing.push(0);
        assert_eq!(
            decode_components_list(&trailing),
            Err("component list has trailing bytes".into())
        );
    }

    #[test]
    fn quic_varint_decoder_rejects_non_canonical_lengths() {
        assert_eq!(
            decode_quic_varint(&[0x40, 0x3f]),
            Err("non-canonical QUIC varint length".into())
        );
    }

    #[test]
    fn nostr_routing_round_trips_canonical_state() {
        let routing = NostrRoutingV1::new(
            [0x42; 32],
            vec![
                "wss://relay-b.example".into(),
                "wss://relay-a.example".into(),
            ],
        )
        .unwrap();

        let encoded = encode_nostr_routing_v1(&routing).unwrap();
        let decoded = decode_nostr_routing_v1(&encoded).unwrap();

        assert_eq!(
            decoded.relays,
            vec!["wss://relay-a.example", "wss://relay-b.example"]
        );
        assert_eq!(decoded.nostr_group_id, [0x42; 32]);
    }

    #[test]
    fn encrypted_media_policy_round_trips_ordered_endpoints() {
        let policy = EncryptedMediaPolicyV1::blossom_default(
            vec![
                "https://blossom-a.example/upload-root/".to_owned(),
                "https://blossom-b.example".to_owned(),
            ],
            false,
        )
        .unwrap();

        let encoded = encode_encrypted_media_policy_v1(&policy).unwrap();
        let decoded = decode_encrypted_media_policy_v1(&encoded).unwrap();

        assert_eq!(decoded.media_format, ENCRYPTED_MEDIA_FORMAT_V1);
        assert_eq!(decoded.allowed_locator_kinds, vec![BLOSSOM_LOCATOR_KIND_V1]);
        assert_eq!(
            decoded.default_blob_endpoints,
            vec![
                BlobStoreEndpointV1 {
                    locator_kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
                    base_url: "https://blossom-a.example/upload-root".to_owned(),
                },
                BlobStoreEndpointV1 {
                    locator_kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
                    base_url: "https://blossom-b.example".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn encrypted_media_policy_decode_rejects_oversized_top_level_vectors() {
        let mut oversized_allowed = Vec::new();
        encode_var_bytes(ENCRYPTED_MEDIA_FORMAT_V1.as_bytes(), &mut oversized_allowed);
        encode_quic_varint(
            (ENCRYPTED_MEDIA_LOCATOR_KINDS_VECTOR_MAX_LEN + 1) as u64,
            &mut oversized_allowed,
        );
        assert_eq!(
            decode_encrypted_media_policy_v1(&oversized_allowed),
            Err("encrypted media locator kinds exceeds maximum length".into())
        );

        let mut oversized_endpoints = Vec::new();
        encode_var_bytes(
            ENCRYPTED_MEDIA_FORMAT_V1.as_bytes(),
            &mut oversized_endpoints,
        );
        encode_var_bytes(&[], &mut oversized_endpoints);
        encode_quic_varint(
            (ENCRYPTED_MEDIA_BLOB_ENDPOINTS_VECTOR_MAX_LEN + 1) as u64,
            &mut oversized_endpoints,
        );
        assert_eq!(
            decode_encrypted_media_policy_v1(&oversized_endpoints),
            Err("encrypted media default blob endpoints exceeds maximum length".into())
        );
    }

    #[test]
    fn encrypted_media_policy_rejects_non_https_except_loopback_dev_http() {
        assert!(
            EncryptedMediaPolicyV1::blossom_default(
                vec!["http://media.example".to_owned()],
                false,
            )
            .is_err()
        );
        assert!(
            EncryptedMediaPolicyV1::blossom_default(
                vec!["http://127.0.0.1:3000".to_owned()],
                false,
            )
            .is_err()
        );
        let local = EncryptedMediaPolicyV1::blossom_default(
            vec!["http://127.0.0.1:3000/".to_owned()],
            true,
        )
        .unwrap();
        assert_eq!(
            local.default_blob_endpoints[0].base_url,
            "http://127.0.0.1:3000"
        );
        assert_eq!(
            validate_and_normalize_blob_endpoint_url("https://10.0.0.1", false),
            Err("encrypted media endpoint URL must not point at a non-routable address".into())
        );
    }

    #[test]
    fn nostr_routing_rejects_non_canonical_relay_list() {
        let routing = NostrRoutingV1 {
            nostr_group_id: [0x42; 32],
            relays: vec![
                "wss://relay-b.example".into(),
                "wss://relay-a.example".into(),
            ],
        };

        assert_eq!(
            encode_nostr_routing_v1(&routing),
            Err("Nostr relay URLs must be sorted and unique".into())
        );
    }

    #[test]
    fn nostr_routing_rejects_invalid_relay_urls() {
        for relay in [
            "https://relay.example",
            "wss://user@relay.example",
            "wss://relay.example#fragment",
            "wss://",
        ] {
            let routing = NostrRoutingV1 {
                nostr_group_id: [0x42; 32],
                relays: vec![relay.to_owned()],
            };
            assert!(
                encode_nostr_routing_v1(&routing).is_err(),
                "{relay} should be rejected"
            );
        }
    }

    #[test]
    fn group_avatar_url_round_trips_all_fields() {
        let avatar = GroupAvatarUrlV1 {
            url: "https://cdn.example.com/avatar.png".to_owned(),
            dim: Some("512x512".to_owned()),
            thumbhash: Some("abc123".to_owned()),
        };
        let bytes = encode_group_avatar_url_v1(&avatar).unwrap();
        assert_eq!(decode_group_avatar_url_v1(&bytes).unwrap(), avatar);
    }

    #[test]
    fn group_avatar_url_round_trips_url_only() {
        let avatar = GroupAvatarUrlV1 {
            url: "https://cdn.example.com/avatar.png".to_owned(),
            dim: None,
            thumbhash: None,
        };
        let bytes = encode_group_avatar_url_v1(&avatar).unwrap();
        assert_eq!(decode_group_avatar_url_v1(&bytes).unwrap(), avatar);
    }

    #[test]
    fn group_avatar_url_empty_state_round_trips_as_absent() {
        let absent = GroupAvatarUrlV1::default();
        let bytes = encode_group_avatar_url_v1(&absent).unwrap();
        assert_eq!(decode_group_avatar_url_v1(&bytes).unwrap(), absent);
    }

    #[test]
    fn group_avatar_url_absent_state_rejects_hints() {
        let absent_with_hint = GroupAvatarUrlV1 {
            url: String::new(),
            dim: Some("512x512".to_owned()),
            thumbhash: None,
        };

        assert!(encode_group_avatar_url_v1(&absent_with_hint).is_err());
    }

    #[test]
    fn group_avatar_url_requires_https() {
        for raw in [
            "http://cdn.example.com/a.png",
            "ftp://cdn.example.com/a.png",
            "ws://cdn.example.com/a.png",
        ] {
            assert!(
                validate_and_normalize_group_avatar_url(raw).is_err(),
                "{raw} should be rejected"
            );
        }
    }

    #[test]
    fn group_avatar_url_rejects_localhost_and_non_routable_hosts() {
        for raw in [
            "https://localhost/a.png",
            "https://app.localhost/a.png",
            "https://127.0.0.1/a.png",
            "https://10.0.0.5/a.png",
            "https://192.168.1.2/a.png",
            "https://172.16.0.1/a.png",
            "https://169.254.1.1/a.png",
            "https://[::1]/a.png",
            "https://[::ffff:127.0.0.1]/a.png",
            "https://[::ffff:10.0.0.1]/a.png",
            "https://[fc00::1]/a.png",
            "https://[fe80::1]/a.png",
        ] {
            assert!(
                validate_and_normalize_group_avatar_url(raw).is_err(),
                "{raw} should be rejected"
            );
        }
    }

    #[test]
    fn group_avatar_url_rejects_credentials_and_fragment() {
        assert!(
            validate_and_normalize_group_avatar_url("https://user:pass@cdn.example.com/a").is_err()
        );
        assert!(validate_and_normalize_group_avatar_url("https://cdn.example.com/a#frag").is_err());
    }

    #[test]
    fn group_avatar_url_enforces_max_length() {
        let long = format!(
            "https://cdn.example.com/{}",
            "a".repeat(GROUP_AVATAR_URL_MAX_LEN)
        );
        assert!(validate_and_normalize_group_avatar_url(&long).is_err());
    }

    #[test]
    fn group_avatar_url_normalizes_on_ingest() {
        let normalized =
            validate_and_normalize_group_avatar_url("https://CDN.Example.COM:443/a.png").unwrap();
        // Host lowercased and default https port dropped.
        assert_eq!(normalized, "https://cdn.example.com/a.png");
    }

    #[test]
    fn group_avatar_url_decode_rejects_non_normalized_url() {
        // Hand-build bytes carrying a non-normalized (uppercase host) URL.
        let mut bytes = Vec::new();
        let raw = "https://CDN.EXAMPLE.COM/a.png";
        encode_var_bytes(raw.as_bytes(), &mut bytes);
        encode_var_bytes(b"", &mut bytes);
        encode_var_bytes(b"", &mut bytes);
        assert!(decode_group_avatar_url_v1(&bytes).is_err());
    }

    #[test]
    fn group_avatar_url_decode_rejects_absent_state_with_hints() {
        let mut bytes = Vec::new();
        encode_var_bytes(b"", &mut bytes);
        encode_var_bytes(b"512x512", &mut bytes);
        encode_var_bytes(b"", &mut bytes);

        assert!(decode_group_avatar_url_v1(&bytes).is_err());
    }

    #[test]
    fn group_avatar_url_decode_rejects_trailing_bytes() {
        let avatar = GroupAvatarUrlV1 {
            url: "https://cdn.example.com/a.png".to_owned(),
            dim: None,
            thumbhash: None,
        };
        let mut bytes = encode_group_avatar_url_v1(&avatar).unwrap();
        bytes.push(0);
        assert!(decode_group_avatar_url_v1(&bytes).is_err());
    }

    #[test]
    fn group_avatar_hint_length_is_bounded() {
        let avatar = GroupAvatarUrlV1 {
            url: "https://cdn.example.com/a.png".to_owned(),
            dim: Some("a".repeat(GROUP_AVATAR_HINT_MAX_LEN + 1)),
            thumbhash: None,
        };
        assert!(encode_group_avatar_url_v1(&avatar).is_err());
    }
}
