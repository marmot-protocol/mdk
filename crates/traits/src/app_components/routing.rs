//! `marmot.transport.nostr.routing.v1` component state and codec.

use serde::{Deserialize, Serialize};
use url::Url;

use super::codec::{decode_var_bytes, encode_quic_varint};

pub const NOSTR_ROUTING_MAX_RELAYS: usize = 16;
pub const NOSTR_RELAY_URL_MAX_LEN: usize = 512;
const NOSTR_RELAY_VECTOR_MAX_LEN: usize = NOSTR_ROUTING_MAX_RELAYS * (NOSTR_RELAY_URL_MAX_LEN + 2);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NostrRoutingV1 {
    pub nostr_group_id: [u8; 32],
    pub relays: Vec<String>,
}

impl NostrRoutingV1 {
    pub fn new(nostr_group_id: [u8; 32], mut relays: Vec<String>) -> Result<Self, String> {
        validate_nostr_relay_count(relays.len())?;
        for relay in &relays {
            validate_nostr_relay_url(relay)?;
        }
        relays.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        relays.dedup();
        Ok(Self {
            nostr_group_id,
            relays,
        })
    }
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
    let relay_vector = decode_var_bytes(
        &mut cursor,
        NOSTR_RELAY_VECTOR_MAX_LEN,
        "Nostr relay vector",
    )?;
    if !cursor.is_empty() {
        return Err("Nostr routing component has trailing bytes".into());
    }
    let mut relay_cursor = relay_vector.as_slice();
    let mut relays = Vec::new();
    while !relay_cursor.is_empty() {
        if relays.len() == NOSTR_ROUTING_MAX_RELAYS {
            return Err(format!(
                "Nostr routing component must contain at most {NOSTR_ROUTING_MAX_RELAYS} relays"
            ));
        }
        let relay = decode_var_bytes(
            &mut relay_cursor,
            NOSTR_RELAY_URL_MAX_LEN,
            "Nostr relay URL",
        )?;
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

fn validate_nostr_routing(routing: &NostrRoutingV1) -> Result<(), String> {
    validate_nostr_relay_count(routing.relays.len())?;
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

fn validate_nostr_relay_count(count: usize) -> Result<(), String> {
    if count == 0 {
        return Err("Nostr routing component must contain at least one relay".into());
    }
    if count > NOSTR_ROUTING_MAX_RELAYS {
        return Err(format!(
            "Nostr routing component must contain at most {NOSTR_ROUTING_MAX_RELAYS} relays"
        ));
    }
    Ok(())
}

fn validate_nostr_relay_url(relay: &str) -> Result<(), String> {
    if relay.is_empty() {
        return Err("Nostr relay URL must not be empty".into());
    }
    if relay.len() > NOSTR_RELAY_URL_MAX_LEN {
        return Err(format!(
            "Nostr relay URL exceeds {NOSTR_RELAY_URL_MAX_LEN} bytes"
        ));
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
