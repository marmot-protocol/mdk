//! QUIC-varint and var-bytes primitives plus the extensions-draft
//! `ComponentsList` / component-vector encoders shared across the per-schema
//! component codecs.

use super::*;

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

pub(crate) fn encode_var_bytes(bytes: &[u8], out: &mut Vec<u8>) {
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

pub(crate) fn decode_var_bytes(
    cursor: &mut &[u8],
    max_len: usize,
    label: &str,
) -> Result<Vec<u8>, String> {
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
