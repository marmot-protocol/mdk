//! History bundles (mdk#2628 4.2a, decision D60): one stretch of one chat's
//! history, packed for one sibling device.
//!
//! A bundle is one UTF-8 JSON object written without whitespace, members in
//! the order below, no member repeated, and every integer a decimal from 0 to
//! 2^53 - 1:
//!
//! ```text
//! {"v":1,"chat":"<MLS group id hex>","from":P,"to":P,"events":[E,...]}
//! P = {"epoch":e,"at":t,"id":"<64 hex>"}
//! E = {"event":<inner app event>,"epoch":e,"retention":s?,"grant":b?,"keys":[K,...]?}
//! K = {"ciphertext_sha256":"<64 hex>","key":"<64 hex>"}
//! ```
//!
//! `from` and `to` are the ends of the stretch the sender vouches for, both
//! included, in chat order (epoch, `created_at`, id). `retention` appears when
//! the sender holds a retention decision, and `grant` only on the two
//! moderation kinds that need authority. `keys` holds per-file attachment
//! keys, never an epoch's media exporter secret. A bundle's plaintext is at
//! most [`HISTORY_BUNDLE_MAX_PLAINTEXT`] bytes. It is encrypted with
//! ChaCha20-Poly1305 under a fresh one-use key, an all-zero nonce, and
//! [`HISTORY_BUNDLE_AAD`].
//!
//! Nothing sends bundles until the transport through the device group lands;
//! until then only the `test-policy-overrides` hooks reach this module.
#![cfg_attr(not(feature = "test-policy-overrides"), allow(dead_code))]

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use cgka_traits::MarmotAppEvent;
use cgka_traits::app_event::AppMessageRetentionDecision;
use cgka_traits::reporting::requires_source_authority;
use storage_sqlite::{HistoryExportEvent, HistoryExportRow, ImportedAppEvent};

use crate::AppError;

/// The most plaintext one bundle holds; a longer history is several bundles
/// over consecutive stretches. It matches the Blossom chunk size, so a bundle
/// too large to send inline is one blob.
pub(crate) const HISTORY_BUNDLE_MAX_PLAINTEXT: usize = 8 * 1024 * 1024;
/// The AEAD's associated data.
pub(crate) const HISTORY_BUNDLE_AAD: &[u8] = b"marmot history bundle v1";
const HISTORY_BUNDLE_VERSION: u64 = 1;
/// The largest integer a bundle carries, as in spec A's messages.
const MAX_INTEGER: u64 = 9_007_199_254_740_991;
/// The longest MLS group id a bundle names, as for small state.
const MAX_CHAT_ID_BYTES: usize = 256;
const TAG_LEN: usize = 16;
const TRACE_TARGET: &str = "marmot_app::history_bundle";

/// A message's place in chat order: its epoch, its `created_at`, then its id.
/// Field order is the comparison order.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChatPosition {
    pub(crate) epoch: u64,
    pub(crate) at: u64,
    pub(crate) id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HistoryBundle {
    pub(crate) v: u64,
    pub(crate) chat: String,
    pub(crate) from: ChatPosition,
    pub(crate) to: ChatPosition,
    pub(crate) events: Vec<BundledEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BundledEvent {
    pub(crate) event: MarmotAppEvent,
    pub(crate) epoch: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub(crate) retention: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub(crate) grant: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub(crate) keys: Option<Vec<FileKey>>,
}

/// One attachment's `file_key`, named by the `ciphertext_sha256` of the media
/// reference it opens. The key depends on the file's type and name as well as
/// its content, so the plaintext hash alone cannot name it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileKey {
    pub(crate) ciphertext_sha256: String,
    pub(crate) key: String,
}

/// An optional member is absent or holds a value, never `null`.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl HistoryBundle {
    pub(crate) fn new(chat: &[u8], from: ChatPosition, to: ChatPosition) -> Self {
        Self {
            v: HISTORY_BUNDLE_VERSION,
            chat: hex::encode(chat),
            from,
            to,
            events: Vec::new(),
        }
    }

    /// The most bytes this bundle's encoding can take before any event is
    /// added, whatever its ends turn out to be.
    pub(crate) fn header_bound(chat: &[u8]) -> usize {
        let widest = ChatPosition {
            epoch: MAX_INTEGER,
            at: MAX_INTEGER,
            id: "0".repeat(64),
        };
        encoded_len(&Self::new(chat, widest.clone(), widest))
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, AppError> {
        serde_json::to_vec(self).map_err(|_| bundle_error("history_bundle_encoding"))
    }

    /// Decode a bundle, refusing it whole when anything in it breaks the
    /// format, its version is not 1, or its `from` is after its `to`. An event
    /// that keeps the format can still be dropped on its own by
    /// [`BundledEvent::in_stretch`].
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.len() > HISTORY_BUNDLE_MAX_PLAINTEXT {
            return Err(bundle_error("history_bundle_too_large"));
        }
        let bundle: Self =
            serde_json::from_slice(bytes).map_err(|_| bundle_error("history_bundle_encoding"))?;
        if bundle.v != HISTORY_BUNDLE_VERSION {
            return Err(bundle_error("history_bundle_version"));
        }
        let chat_ok = bundle.chat.len() <= 2 * MAX_CHAT_ID_BYTES
            && !bundle.chat.is_empty()
            && bundle.chat.len().is_multiple_of(2)
            && is_lower_hex(&bundle.chat);
        if !chat_ok
            || !bundle.from.is_well_formed()
            || !bundle.to.is_well_formed()
            || !bundle.events.iter().all(BundledEvent::is_well_formed)
        {
            return Err(bundle_error("history_bundle_encoding"));
        }
        if bundle.from > bundle.to {
            return Err(bundle_error("history_bundle_stretch"));
        }
        Ok(bundle)
    }

    /// Whether this bundle names the chat with MLS group id `group_id`.
    pub(crate) fn names_chat(&self, group_id: &[u8]) -> bool {
        self.chat == hex::encode(group_id)
    }
}

impl ChatPosition {
    pub(crate) fn of(event: &MarmotAppEvent, epoch: u64) -> Self {
        Self {
            epoch,
            at: event.created_at,
            id: event.id.clone(),
        }
    }

    pub(crate) fn of_row(row: &HistoryExportRow) -> Self {
        Self {
            epoch: row.source_epoch,
            at: row.created_at,
            id: row.message_id_hex.clone(),
        }
    }

    fn is_well_formed(&self) -> bool {
        self.epoch <= MAX_INTEGER && self.at <= MAX_INTEGER && is_hash_hex(&self.id)
    }
}

/// Fills one bundle with a chat's rows in chat order, closing it before the
/// next event would take its plaintext past the budget.
pub(crate) struct HistoryBundleBuilder {
    bundle: HistoryBundle,
    started: bool,
    taken: bool,
    capacity: usize,
    used: usize,
}

impl HistoryBundleBuilder {
    /// A bundle for `chat` whose stretch starts at `after`, the previous
    /// bundle's `to`, or else at the first row it takes.
    pub(crate) fn new(chat: &[u8], after: Option<ChatPosition>, budget: usize) -> Self {
        let start = after.clone().unwrap_or(ChatPosition {
            epoch: 0,
            at: 0,
            id: String::new(),
        });
        Self {
            bundle: HistoryBundle::new(chat, start.clone(), start),
            started: after.is_some(),
            taken: false,
            capacity: budget.saturating_sub(HistoryBundle::header_bound(chat)),
            used: 0,
        }
    }

    /// Takes the next row after the last one taken, with what the bundle
    /// carries for it, or none for a row that stays out but still lies in the
    /// stretch. Returns false, taking nothing, when the event does not fit.
    /// An event no bundle can carry, too large or outside the format, stays
    /// out, so a receiver never refuses a whole bundle for it. The size check
    /// reserves room for the widest ends, so an event within that reserve of
    /// the budget stays out too; none comes close, as relays cap an event at
    /// 2 MiB.
    pub(crate) fn take(&mut self, position: ChatPosition, event: Option<BundledEvent>) -> bool {
        if !position.is_well_formed() {
            return true;
        }
        if let Some(event) = event {
            let len = event.encoded_len();
            if !event.is_well_formed() || len > self.capacity {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "take",
                    "leaving out an event no history bundle can carry",
                );
            } else if self.used + len > self.capacity {
                return false;
            } else {
                self.used += len;
                self.bundle.events.push(event);
            }
        }
        if !self.started {
            self.bundle.from = position.clone();
            self.started = true;
        }
        self.bundle.to = position;
        self.taken = true;
        true
    }

    /// The bundle, or none when it took no row.
    pub(crate) fn finish(self) -> Option<HistoryBundle> {
        self.taken.then_some(self.bundle)
    }
}

impl BundledEvent {
    pub(crate) fn exported(event: HistoryExportEvent, epoch: u64) -> Self {
        Self {
            event: event.event,
            epoch,
            retention: event.retention_seconds,
            grant: event.moderation_grant,
            keys: None,
        }
    }

    pub(crate) fn imported(self) -> ImportedAppEvent {
        let event = self.event;
        ImportedAppEvent {
            message_id_hex: event.id,
            source_epoch: self.epoch,
            sender: event.pubkey,
            plaintext: event.content,
            kind: event.kind,
            tags: event.tags,
            created_at: event.created_at,
            retention: self
                .retention
                .map(|seconds| AppMessageRetentionDecision::new(event.created_at, seconds)),
            moderation_grant: self.grant,
        }
    }

    /// The encoded size this event adds to a bundle, its separating comma
    /// included.
    pub(crate) fn encoded_len(&self) -> usize {
        encoded_len(self) + 1
    }

    /// Whether this event lies in `bundle`'s stretch and carries `grant` only
    /// on a kind that needs authority. An event that does not is dropped on
    /// its own; its id and content are the importer's to check.
    pub(crate) fn in_stretch(&self, bundle: &HistoryBundle) -> bool {
        let position = ChatPosition::of(&self.event, self.epoch);
        (self.grant.is_none() || requires_source_authority(self.event.kind))
            && bundle.from <= position
            && position <= bundle.to
    }

    fn is_well_formed(&self) -> bool {
        let event = &self.event;
        is_hash_hex(&event.id)
            && is_hash_hex(&event.pubkey)
            && event.created_at <= MAX_INTEGER
            && event.kind <= MAX_INTEGER
            && self.epoch <= MAX_INTEGER
            && self.retention.is_none_or(|seconds| seconds <= MAX_INTEGER)
            && self.keys.as_ref().is_none_or(|keys| {
                !keys.is_empty()
                    && keys
                        .iter()
                        .all(|key| is_hash_hex(&key.ciphertext_sha256) && is_hash_hex(&key.key))
            })
    }
}

/// A bundle encrypted under its own key. `key` and `ciphertext_sha256` are
/// what the carrying message seals to the receiving device.
pub(crate) struct SealedHistoryBundle {
    pub(crate) key: Zeroizing<[u8; 32]>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) ciphertext_sha256: [u8; 32],
}

pub(crate) fn seal_history_bundle(bundle: &HistoryBundle) -> Result<SealedHistoryBundle, AppError> {
    let plaintext = Zeroizing::new(bundle.encode()?);
    if plaintext.len() > HISTORY_BUNDLE_MAX_PLAINTEXT {
        return Err(bundle_error("history_bundle_too_large"));
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(key.as_mut());
    let ciphertext = cipher(&key)?
        .encrypt(
            &Nonce::default(),
            Payload {
                msg: &plaintext,
                aad: HISTORY_BUNDLE_AAD,
            },
        )
        .map_err(|_| bundle_error("history_bundle_seal"))?;
    let ciphertext_sha256 = Sha256::digest(&ciphertext).into();
    Ok(SealedHistoryBundle {
        key,
        ciphertext,
        ciphertext_sha256,
    })
}

/// Open a bundle the carrying message vouched for with `key` and
/// `ciphertext_sha256`.
pub(crate) fn open_history_bundle(
    key: &[u8; 32],
    ciphertext_sha256: &[u8; 32],
    ciphertext: &[u8],
) -> Result<HistoryBundle, AppError> {
    if ciphertext.len() > HISTORY_BUNDLE_MAX_PLAINTEXT + TAG_LEN {
        return Err(bundle_error("history_bundle_too_large"));
    }
    if Sha256::digest(ciphertext).as_slice() != ciphertext_sha256 {
        return Err(bundle_error("history_bundle_hash"));
    }
    let plaintext = Zeroizing::new(
        cipher(key)?
            .decrypt(
                &Nonce::default(),
                Payload {
                    msg: ciphertext,
                    aad: HISTORY_BUNDLE_AAD,
                },
            )
            .map_err(|_| bundle_error("history_bundle_decrypt"))?,
    );
    HistoryBundle::decode(&plaintext)
}

fn cipher(key: &[u8; 32]) -> Result<ChaCha20Poly1305, AppError> {
    ChaCha20Poly1305::new_from_slice(key).map_err(|_| bundle_error("history_bundle_decrypt"))
}

fn encoded_len<T: Serialize>(value: &T) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

fn is_hash_hex(value: &str) -> bool {
    value.len() == 64 && is_lower_hex(value)
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn bundle_error(reason: &'static str) -> AppError {
    AppError::DeviceGroupRefused(reason)
}

#[cfg(test)]
mod tests;
