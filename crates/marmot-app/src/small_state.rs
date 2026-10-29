//! Small state between this account's devices (mdk#2628 item 4.3): the wire
//! form of updates, snapshot requests and snapshots, and the rule that picks
//! a winner between two values of one item.
//!
//! Storage keeps the items and applies winners (`storage_sqlite`'s small-state
//! module); `client::small_state` drives a pass and talks to the siblings.

use std::collections::BTreeSet;
use std::fmt;

use cgka_traits::app_components::DeviceSlotId;
use rand::{RngCore, rngs::OsRng};
use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use storage_sqlite::{
    MAX_SMALL_STATE_NUMBER, MuteSetting, ReadPosition, SmallStateItem, SmallStateItemName,
    SmallStateRule, SmallStateValue, SmallStateVersion,
};

use crate::AppError;

/// An update: items whose value this device's user changed.
pub(crate) const KIND_SMALL_STATE_UPDATE: u64 = 475;
/// A snapshot request, naming the sibling asked.
pub(crate) const KIND_SMALL_STATE_SNAPSHOT_REQUEST: u64 = 476;
/// A snapshot: part of every item the sender holds.
pub(crate) const KIND_SMALL_STATE_SNAPSHOT: u64 = 477;
/// The longest content any of them carries, in bytes.
pub(crate) const MAX_SMALL_STATE_CONTENT_BYTES: usize = 32_768;

const UPDATE_START: &str = "{\"v\":1,\"items\":[";
const PAGE_END: &str = "]}";

/// The rule every device applies, so every device picks the same winner.
pub(crate) struct SmallStateMergeRule;

impl SmallStateRule for SmallStateMergeRule {
    fn wins(&self, incoming: &SmallStateItem, held: &SmallStateItem) -> bool {
        match (&incoming.value, &held.value, incoming.version, held.version) {
            (SmallStateValue::Read(incoming), SmallStateValue::Read(held), _, _) => incoming > held,
            (_, _, Some(incoming_version), Some(held_version)) => {
                incoming_version.version > held_version.version
                    || (incoming_version.version == held_version.version
                        && tie_break(
                            (&incoming_version.change_id, &incoming.value),
                            (&held_version.change_id, &held.value),
                        ))
            }
            _ => false,
        }
    }

    fn new_change_id(&self) -> [u8; 16] {
        random_id()
    }

    fn pin_index(&self, pinned: &[String]) -> usize {
        new_pin_index(pinned)
    }
}

/// At an equal version, whether `incoming`'s change and value beat `held`'s:
/// the lower change id wins, then the lower value encoding, which only a
/// device that breaks the rules makes matter. The only place the tie-break is
/// decided.
fn tie_break(
    (incoming_change, incoming_value): (&[u8; 16], &SmallStateValue),
    (held_change, held_value): (&[u8; 16], &SmallStateValue),
) -> bool {
    (incoming_change, encode_value(incoming_value)) < (held_change, encode_value(held_value))
}

/// Where a chat pinned through small state goes among this device's pinned
/// chats: first, where this device's own pin command puts it. The only place
/// that placement is decided.
fn new_pin_index(_pinned: &[String]) -> usize {
    0
}

/// 16 bytes from the operating system's secure random source: a change id or
/// a snapshot request id.
pub(crate) fn random_id() -> [u8; 16] {
    let mut id = [0; 16];
    OsRng.fill_bytes(&mut id);
    id
}

/// `items` as update contents, as few as fit in
/// [`MAX_SMALL_STATE_CONTENT_BYTES`] each, with each content's items. An item
/// too long to fit alone is left out.
pub(crate) fn encode_small_state_update(
    items: &[SmallStateItem],
) -> Vec<(String, Vec<SmallStateItem>)> {
    let room = MAX_SMALL_STATE_CONTENT_BYTES - UPDATE_START.len() - PAGE_END.len();
    item_pages(items, room)
        .into_iter()
        .map(|(body, carried)| (format!("{UPDATE_START}{body}{PAGE_END}"), carried))
        .collect()
}

/// `items` as the snapshots answering `request`: every part numbered, and one
/// empty part when there is no item.
pub(crate) fn encode_small_state_snapshot(
    request: &[u8; 16],
    items: &[SmallStateItem],
) -> Vec<String> {
    let longest_start = snapshot_start(request, MAX_SMALL_STATE_NUMBER, MAX_SMALL_STATE_NUMBER);
    let room = MAX_SMALL_STATE_CONTENT_BYTES - longest_start.len() - PAGE_END.len();
    let mut bodies = item_pages(items, room)
        .into_iter()
        .map(|(body, _)| body)
        .collect::<Vec<_>>();
    if bodies.is_empty() {
        bodies.push(String::new());
    }
    let parts = bodies.len() as u64;
    bodies
        .into_iter()
        .zip(1..)
        .map(|(body, part)| format!("{}{body}{PAGE_END}", snapshot_start(request, part, parts)))
        .collect()
}

fn snapshot_start(request: &[u8; 16], part: u64, parts: u64) -> String {
    format!(
        "{{\"v\":1,\"request\":\"{}\",\"part\":{part},\"parts\":{parts},\"items\":[",
        hex::encode(request)
    )
}

/// Valid items as comma-separated bodies of at most `room` bytes each, with
/// each body's items.
fn item_pages(items: &[SmallStateItem], room: usize) -> Vec<(String, Vec<SmallStateItem>)> {
    let mut pages = Vec::new();
    let mut body = String::new();
    let mut carried = Vec::new();
    for item in items.iter().filter(|item| item.is_valid()) {
        let encoded = encode_item(item);
        if encoded.len() > room {
            continue;
        }
        let separator = usize::from(!body.is_empty());
        if body.len() + separator + encoded.len() > room {
            pages.push((std::mem::take(&mut body), std::mem::take(&mut carried)));
        }
        if !body.is_empty() {
            body.push(',');
        }
        body.push_str(&encoded);
        carried.push(item.clone());
    }
    if !body.is_empty() {
        pages.push((body, carried));
    }
    pages
}

/// One item, members in the order the wire form gives them.
fn encode_item(item: &SmallStateItem) -> String {
    let mut encoded = format!(
        "{{\"chat\":\"{}\",\"item\":\"{}\",\"value\":{}",
        item.group_id_hex,
        item.name().as_str(),
        encode_value(&item.value)
    );
    if let Some(version) = item.version {
        encoded.push_str(&format!(
            ",\"version\":{},\"change\":\"{}\"",
            version.version,
            hex::encode(version.change_id)
        ));
    }
    encoded.push('}');
    encoded
}

fn encode_value(value: &SmallStateValue) -> String {
    match value {
        SmallStateValue::Read(position) => format!(
            "{{\"epoch\":{},\"at\":{},\"id\":\"{}\"}}",
            position.epoch, position.at, position.message_id_hex
        ),
        SmallStateValue::Pin(flag) | SmallStateValue::Archive(flag) => flag.to_string(),
        SmallStateValue::Mute(MuteSetting::Unmuted) => "false".to_owned(),
        SmallStateValue::Mute(MuteSetting::Muted) => "true".to_owned(),
        SmallStateValue::Mute(MuteSetting::MutedUntil(until)) => until.to_string(),
    }
}

/// An update's items. Refuses content that is not an update; skips an item
/// whose name it does not know or that breaks the item rules.
pub(crate) fn decode_small_state_update(content: &str) -> Result<Vec<SmallStateItem>, AppError> {
    let object = small_state_object(content, &["v", "items"])?;
    let items = decode_items(&object)?;
    if items.is_empty() {
        return Err(malformed());
    }
    Ok(items.iter().filter_map(decode_item).collect())
}

/// One snapshot of an answer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SmallStateSnapshot {
    pub(crate) request: [u8; 16],
    pub(crate) part: u64,
    pub(crate) parts: u64,
    pub(crate) items: Vec<SmallStateItem>,
}

/// A snapshot's request, part and items, under the same rules as an update;
/// its items may be empty.
pub(crate) fn decode_small_state_snapshot(content: &str) -> Result<SmallStateSnapshot, AppError> {
    let object = small_state_object(content, &["v", "request", "part", "parts", "items"])?;
    let request = object
        .get("request")
        .and_then(Value::as_str)
        .and_then(sixteen_bytes)
        .ok_or_else(malformed)?;
    let part = object.get("part").and_then(number).ok_or_else(malformed)?;
    let parts = object.get("parts").and_then(number).ok_or_else(malformed)?;
    if part == 0 || part > parts {
        return Err(malformed());
    }
    let items = decode_items(&object)?;
    Ok(SmallStateSnapshot {
        request,
        part,
        parts,
        items: items.iter().filter_map(decode_item).collect(),
    })
}

/// The raw items, refusing two with the same chat and item.
fn decode_items(object: &Map<String, Value>) -> Result<&Vec<Value>, AppError> {
    let items = object
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(malformed)?;
    let mut seen = BTreeSet::new();
    for item in items {
        let key = item
            .get("chat")
            .and_then(Value::as_str)
            .zip(item.get("item").and_then(Value::as_str));
        if key.is_some_and(|key| !seen.insert(key)) {
            return Err(malformed());
        }
    }
    Ok(items)
}

fn decode_item(item: &Value) -> Option<SmallStateItem> {
    let item = item.as_object()?;
    let name = SmallStateItemName::parse(item.get("item")?.as_str()?)?;
    let members: &[&str] = match name {
        SmallStateItemName::Read => &["chat", "item", "value"],
        _ => &["chat", "item", "value", "version", "change"],
    };
    if item.len() != members.len() || !members.iter().all(|member| item.contains_key(*member)) {
        return None;
    }
    let group_id_hex = item.get("chat")?.as_str()?.to_owned();
    let value = item.get("value")?;
    let value = match name {
        SmallStateItemName::Read => {
            let position = value.as_object()?;
            if position.len() != 3 {
                return None;
            }
            SmallStateValue::Read(ReadPosition {
                epoch: number(position.get("epoch")?)?,
                at: number(position.get("at")?)?,
                message_id_hex: position.get("id")?.as_str()?.to_owned(),
            })
        }
        SmallStateItemName::Pin => SmallStateValue::Pin(value.as_bool()?),
        SmallStateItemName::Archive => SmallStateValue::Archive(value.as_bool()?),
        SmallStateItemName::Mute => SmallStateValue::Mute(match value {
            Value::Bool(false) => MuteSetting::Unmuted,
            Value::Bool(true) => MuteSetting::Muted,
            until => MuteSetting::MutedUntil(number(until)?),
        }),
    };
    let version = match name {
        SmallStateItemName::Read => None,
        _ => Some(SmallStateVersion {
            version: number(item.get("version")?)?,
            change_id: sixteen_bytes(item.get("change")?.as_str()?)?,
        }),
    };
    let decoded = SmallStateItem {
        group_id_hex,
        value,
        version,
    };
    decoded.is_valid().then_some(decoded)
}

fn number(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .filter(|number| *number <= MAX_SMALL_STATE_NUMBER)
}

/// 16 bytes written as 32 lowercase hexadecimal characters.
fn sixteen_bytes(text: &str) -> Option<[u8; 16]> {
    if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    hex::decode(text).ok()?.try_into().ok()
}

/// A snapshot request's content, asking `to` with the id `request`.
pub(crate) fn encode_snapshot_request(to: &DeviceSlotId, request: &[u8; 16]) -> String {
    format!(
        "{{\"v\":1,\"to\":\"{}\",\"request\":\"{}\"}}",
        hex::encode(to),
        hex::encode(request)
    )
}

/// The slot a snapshot request asks, and its id.
pub(crate) fn decode_snapshot_request(content: &str) -> Result<(DeviceSlotId, [u8; 16]), AppError> {
    let object = small_state_object(content, &["v", "to", "request"])?;
    let to = object
        .get("to")
        .and_then(Value::as_str)
        .filter(|to| !to.bytes().any(|byte| byte.is_ascii_uppercase()))
        .and_then(|to| hex::decode(to).ok())
        .and_then(|to| DeviceSlotId::try_from(to).ok())
        .ok_or_else(malformed)?;
    let request = object
        .get("request")
        .and_then(Value::as_str)
        .and_then(sixteen_bytes)
        .ok_or_else(malformed)?;
    Ok((to, request))
}

/// The content's object, when it is one with exactly `members`, no object in
/// it repeating a member name, no longer than the limit, at version 1.
fn small_state_object(content: &str, members: &[&str]) -> Result<Map<String, Value>, AppError> {
    if content.len() > MAX_SMALL_STATE_CONTENT_BYTES {
        return Err(malformed());
    }
    match serde_json::from_str::<Distinct>(content) {
        Ok(Distinct(Value::Object(object)))
            if object.get("v").and_then(Value::as_u64) == Some(1)
                && object.len() == members.len()
                && members.iter().all(|member| object.contains_key(*member)) =>
        {
            Ok(object)
        }
        _ => Err(malformed()),
    }
}

fn malformed() -> AppError {
    AppError::DeviceGroupRefused("malformed_small_state")
}

/// JSON read with every object's member names distinct.
struct Distinct(Value);

impl<'de> Deserialize<'de> for Distinct {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(DistinctVisitor).map(Distinct)
    }
}

struct DistinctVisitor;

impl<'de> Visitor<'de> for DistinctVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
        Ok(serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(Distinct(value)) = seq.next_element()? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = Map::new();
        while let Some(member) = map.next_key::<String>()? {
            if object.contains_key(&member) {
                return Err(A::Error::custom("repeated member name"));
            }
            let Distinct(value) = map.next_value()?;
            object.insert(member, value);
        }
        Ok(Value::Object(object))
    }
}

#[cfg(test)]
mod tests;
