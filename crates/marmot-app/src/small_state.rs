//! Small state between this account's devices (mdk#2628 item 4.3): the wire
//! form of updates, snapshot requests and snapshots, and the rule that picks
//! a winner between two values of one item.
//!
//! Storage keeps the items and applies winners (`storage_sqlite`'s small-state
//! module); `client::small_state` drives a pass and talks to the siblings.

use cgka_traits::app_components::DeviceSlotId;
use rand::{RngCore, rngs::OsRng};
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

const PAGE_START: &str = "{\"v\":1,\"items\":[";
const PAGE_END: &str = "]}";

/// The rule every device applies, so every device picks the same winner.
pub(crate) struct SmallStateMergeRule;

impl SmallStateRule for SmallStateMergeRule {
    fn wins(&self, incoming: &SmallStateItem, held: &SmallStateItem) -> bool {
        match (&incoming.value, &held.value, incoming.version, held.version) {
            (SmallStateValue::Read(incoming), SmallStateValue::Read(held), _, _) => incoming > held,
            (_, _, Some(incoming), Some(held)) => {
                incoming.version > held.version
                    || (incoming.version == held.version
                        && tie_break(&incoming.change_id, &held.change_id))
            }
            _ => false,
        }
    }

    fn new_change_id(&self) -> [u8; 16] {
        let mut change_id = [0; 16];
        OsRng.fill_bytes(&mut change_id);
        change_id
    }

    fn pin_index(&self, pinned: &[String]) -> usize {
        new_pin_index(pinned)
    }
}

/// At an equal version, whether `incoming`'s change beats `held`'s: the lower
/// change id wins. The only place the tie-break is decided.
fn tie_break(incoming: &[u8; 16], held: &[u8; 16]) -> bool {
    incoming < held
}

/// Where a chat pinned through small state goes among this device's pinned
/// chats: first, where this device's own pin command puts it. The only place
/// that placement is decided.
fn new_pin_index(_pinned: &[String]) -> usize {
    0
}

/// `items` as update or snapshot contents, as few as fit in
/// [`MAX_SMALL_STATE_CONTENT_BYTES`] each, with each content's items. An item
/// too long to fit alone is left out.
pub(crate) fn encode_small_state_items(
    items: &[SmallStateItem],
) -> Vec<(String, Vec<SmallStateItem>)> {
    let room = MAX_SMALL_STATE_CONTENT_BYTES - PAGE_START.len() - PAGE_END.len();
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
            pages.push(finish_page(&mut body, &mut carried));
        }
        if !body.is_empty() {
            body.push(',');
        }
        body.push_str(&encoded);
        carried.push(item.clone());
    }
    if !body.is_empty() {
        pages.push(finish_page(&mut body, &mut carried));
    }
    pages
}

fn finish_page(
    body: &mut String,
    carried: &mut Vec<SmallStateItem>,
) -> (String, Vec<SmallStateItem>) {
    (
        format!("{PAGE_START}{}{PAGE_END}", std::mem::take(body)),
        std::mem::take(carried),
    )
}

/// One item, members in the order the wire form gives them.
fn encode_item(item: &SmallStateItem) -> String {
    let value = match &item.value {
        SmallStateValue::Read(position) => format!(
            "{{\"epoch\":{},\"at\":{},\"id\":\"{}\"}}",
            position.epoch, position.at, position.message_id_hex
        ),
        SmallStateValue::Pin(flag) | SmallStateValue::Archive(flag) => flag.to_string(),
        SmallStateValue::Mute(MuteSetting::Unmuted) => "false".to_owned(),
        SmallStateValue::Mute(MuteSetting::Muted) => "true".to_owned(),
        SmallStateValue::Mute(MuteSetting::MutedUntil(until)) => until.to_string(),
    };
    let mut encoded = format!(
        "{{\"chat\":\"{}\",\"item\":\"{}\",\"value\":{value}",
        item.group_id_hex,
        item.name().as_str()
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

/// The items of an update's or a snapshot's content. Refuses content that is
/// not of that shape; skips an item whose name it does not know or that
/// breaks the item rules.
pub(crate) fn decode_small_state_items(content: &str) -> Result<Vec<SmallStateItem>, AppError> {
    let object = small_state_object(content)?;
    let items = object
        .get("items")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or_else(malformed)?;
    Ok(items.iter().filter_map(decode_item).collect())
}

fn decode_item(item: &Value) -> Option<SmallStateItem> {
    let item = item.as_object()?;
    let group_id_hex = item.get("chat")?.as_str()?.to_owned();
    let name = SmallStateItemName::parse(item.get("item")?.as_str()?)?;
    let value = item.get("value")?;
    let value = match name {
        SmallStateItemName::Read => {
            let position = value.as_object()?;
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
        _ => {
            let change = hex::decode(item.get("change")?.as_str()?).ok()?;
            Some(SmallStateVersion {
                version: number(item.get("version")?)?,
                change_id: change.try_into().ok()?,
            })
        }
    };
    let decoded = SmallStateItem {
        group_id_hex,
        value,
        version,
    };
    // A change id read back must be written the same way, lowercase.
    let canonical_change = item
        .get("change")
        .and_then(Value::as_str)
        .is_none_or(|change| !change.bytes().any(|byte| byte.is_ascii_uppercase()));
    (canonical_change && decoded.is_valid()).then_some(decoded)
}

fn number(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .filter(|number| *number <= MAX_SMALL_STATE_NUMBER)
}

/// A snapshot request's content, asking `to`.
pub(crate) fn encode_snapshot_request(to: &DeviceSlotId) -> String {
    format!("{{\"v\":1,\"to\":\"{}\"}}", hex::encode(to))
}

/// The slot a snapshot request asks.
pub(crate) fn decode_snapshot_request(content: &str) -> Result<DeviceSlotId, AppError> {
    let object = small_state_object(content)?;
    let to = object
        .get("to")
        .and_then(Value::as_str)
        .filter(|to| !to.bytes().any(|byte| byte.is_ascii_uppercase()))
        .ok_or_else(malformed)?;
    hex::decode(to)
        .ok()
        .and_then(|to| DeviceSlotId::try_from(to).ok())
        .ok_or_else(malformed)
}

/// The content's object, when it is one, no longer than the limit, at
/// version 1.
fn small_state_object(content: &str) -> Result<Map<String, Value>, AppError> {
    if content.len() > MAX_SMALL_STATE_CONTENT_BYTES {
        return Err(malformed());
    }
    match serde_json::from_str(content) {
        Ok(Value::Object(object)) if object.get("v").and_then(Value::as_u64) == Some(1) => {
            Ok(object)
        }
        _ => Err(malformed()),
    }
}

fn malformed() -> AppError {
    AppError::DeviceGroupRefused("malformed_small_state")
}

#[cfg(test)]
mod tests;
