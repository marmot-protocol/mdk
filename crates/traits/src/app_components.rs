//! Marmot MLS app component ids and small byte helpers.
//!
//! Component state itself lives in the MLS `app_data_dictionary` extension.
//! These helpers deliberately stay OpenMLS-free so the public trait surface can
//! talk about component ids without exposing engine internals.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use url::Url;

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

pub const GROUP_PROFILE_COMPONENT: &str = "marmot.group.profile.v1";
pub const GROUP_BLOSSOM_IMAGE_COMPONENT: &str = "marmot.group.blossom.image.v1";
pub const GROUP_ADMIN_POLICY_COMPONENT: &str = "marmot.group.admin-policy.v1";
pub const NOSTR_ROUTING_COMPONENT: &str = "marmot.transport.nostr.routing.v1";
pub const GROUP_MESSAGE_RETENTION_COMPONENT: &str = "marmot.group.message-retention.v1";
pub const AGENT_TEXT_STREAM_QUIC_COMPONENT: &str = "marmot.group.agent-text-stream.quic.v1";

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
}
