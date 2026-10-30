//! Private KeyPackages (mdk#2628 item 3.4b): single-use KeyPackages a device
//! issues to one sibling in its device group. They travel only inside the
//! device group and are never published.
//!
//! - The issuer keeps one [`IssuedPrivateKeyPackage`] per KeyPackage, written
//!   and deleted in the same transaction as its OpenMLS private bundle, so a
//!   bundle never outlives its record or the reverse.
//! - A private KeyPackage has the public one's lifetime and capabilities but
//!   is not last-resort, so OpenMLS deletes its bundle when a Welcome consumes
//!   it. Only a sibling Welcome from the device group may consume one (3.5):
//!   an ordinary Welcome naming it is refused as not addressed to this device,
//!   which leaves its content eligible for that sibling Welcome.
//! - A request (kind 459) and a hand-off (kind 460) carry the sender's and the
//!   addressee's slots in their content. This module owns their wire codecs;
//!   the app sends and receives them.
//! - A sibling Welcome (kind 461) carries the Welcome for an add that consumed
//!   the addressee's private KeyPackage, with that KeyPackage's ref and the
//!   chat's relays (marmot#471). This module owns its codec too.

use crate::engine::Engine;
use crate::key_package::{
    KeyPackageMetadata, key_package_device_tag_claim, key_package_metadata, key_package_ref,
};
use cgka_traits::app_components::{DeviceRosterV1, DeviceSlotId, DeviceTagClaim};
use cgka_traits::engine::KeyPackage;
use cgka_traits::error::EngineError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::ingest::{IngestOutcome, PeeledContent, PeeledMessage};
use cgka_traits::storage::{
    IssuedPrivateKeyPackage, PrivateKeyPackageStorage, StorageProvider, private_key_package_halfway,
};
use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
use cgka_traits::{MemberId, MessageId};
use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn};
use openmls_traits::storage::StorageProvider as OpenMlsStorageProvider;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use tls_codec::{Deserialize as _, Serialize as _, VLBytes};

/// Kind of a request for private KeyPackages, sent inside the device group.
pub const KIND_PRIVATE_KEY_PACKAGE_REQUEST: u64 = 459;
/// Kind of a hand-off of private KeyPackages, sent inside the device group.
pub const KIND_PRIVATE_KEY_PACKAGE_HAND_OFF: u64 = 460;
/// Kind of a sibling Welcome, sent inside the device group.
pub const KIND_SIBLING_WELCOME: u64 = 461;
/// How many usable private KeyPackages an issuer keeps with each sibling.
pub const PRIVATE_KEY_PACKAGE_STOCK_TARGET: usize = 10;
/// Below this many usable ones, the issuer tops a sibling up to the target.
pub const PRIVATE_KEY_PACKAGE_STOCK_LOW: usize = 5;
/// The most private KeyPackages one request may ask for.
pub const MAX_PRIVATE_KEY_PACKAGE_WANT: u32 = 100;
/// The most private KeyPackages one hand-off carries.
pub const MAX_HAND_OFF_KEY_PACKAGES: usize = 20;
/// Unexpired records an issuer keeps per sibling, three full requests' worth.
/// Issuing stops there until some are used or expire, so repeated requests
/// cannot grow storage, and no key goes before its `not_after`. A request
/// that finds the cap reached is answered with KeyPackages the sibling was
/// already given, handed over again (mdk#2628 D42).
pub const MAX_RETAINED_PRIVATE_KEY_PACKAGES: usize = 3 * MAX_PRIVATE_KEY_PACKAGE_WANT as usize;
const HAND_OFF_VERSION: u8 = 1;
const REQUEST_VERSION: u64 = 1;
const SIBLING_WELCOME_VERSION: u8 = 1;
/// The longest `KeyPackageRefV1` the roster's encoding allows.
const MAX_KEY_PACKAGE_REF_LEN: usize = 64;
/// The longest relay URL a sibling Welcome carries.
const MAX_SIBLING_WELCOME_RELAY_LEN: usize = 512;

/// A sibling asks the addressee for `want` new private KeyPackages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateKeyPackageRequest {
    pub from: DeviceSlotId,
    pub to: DeviceSlotId,
    /// 1 to [`MAX_PRIVATE_KEY_PACKAGE_WANT`].
    pub want: u32,
}

impl PrivateKeyPackageRequest {
    /// The request's content: canonical JSON
    /// `{"v":1,"from":"<slot>","to":"<slot>","want":n}`.
    pub fn encode(&self) -> String {
        format!(
            r#"{{"v":{REQUEST_VERSION},"from":"{}","to":"{}","want":{}}}"#,
            hex::encode(self.from),
            hex::encode(self.to),
            self.want
        )
    }

    /// Decode a request's content, accepting only the canonical form.
    pub fn decode(content: &str) -> Result<Self, EngineError> {
        let invalid = || EngineError::Serialize("invalid private KeyPackage request".into());
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            v: u64,
            from: String,
            to: String,
            want: u32,
        }
        let wire: Wire = serde_json::from_str(content).map_err(|_| invalid())?;
        let slot = |hex_slot: &str| -> Result<DeviceSlotId, EngineError> {
            hex::decode(hex_slot)
                .ok()
                .and_then(|bytes| DeviceSlotId::try_from(bytes).ok())
                .ok_or_else(invalid)
        };
        let request = Self {
            from: slot(&wire.from)?,
            to: slot(&wire.to)?,
            want: wire.want,
        };
        if wire.v != REQUEST_VERSION
            || !(1..=MAX_PRIVATE_KEY_PACKAGE_WANT).contains(&request.want)
            || request.encode() != content
        {
            return Err(invalid());
        }
        Ok(request)
    }
}

/// An issuer hands private KeyPackages to the addressee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateKeyPackageHandOff {
    pub from: DeviceSlotId,
    pub to: DeviceSlotId,
    /// 1 to [`MAX_HAND_OFF_KEY_PACKAGES`] `mls_key_package` MLSMessages.
    pub key_packages: Vec<KeyPackage>,
}

impl PrivateKeyPackageHandOff {
    /// The binary `PrivateKeyPackageHandOffV1 { uint8 version; SlotId from;
    /// SlotId to; MLSMessage key_packages<V> }`. The message content is its
    /// standard base64.
    pub fn encode(&self) -> Result<Vec<u8>, EngineError> {
        if !(1..=MAX_HAND_OFF_KEY_PACKAGES).contains(&self.key_packages.len()) {
            return Err(EngineError::Serialize(
                "a hand-off carries 1 to 20 KeyPackages".into(),
            ));
        }
        let mut bytes = Vec::new();
        bytes.push(HAND_OFF_VERSION);
        bytes.extend_from_slice(&self.from);
        bytes.extend_from_slice(&self.to);
        let key_packages: Vec<u8> = self
            .key_packages
            .iter()
            .flat_map(|key_package| key_package.bytes().iter().copied())
            .collect();
        VLBytes::new(key_packages)
            .tls_serialize(&mut bytes)
            .map_err(|error| EngineError::Serialize(format!("hand-off encode: {error:?}")))?;
        Ok(bytes)
    }

    /// Decode a hand-off. Every element must be an `mls_key_package`
    /// MLSMessage; it is not validated here
    /// ([`validate_received_private_key_package`] does that).
    pub fn decode(bytes: &[u8]) -> Result<Self, EngineError> {
        let invalid = || EngineError::Serialize("invalid private KeyPackage hand-off".into());
        let (&version, rest) = bytes.split_first().ok_or_else(invalid)?;
        if version != HAND_OFF_VERSION || rest.len() < 64 {
            return Err(invalid());
        }
        let (from, rest) = rest.split_at(32);
        let (to, mut rest) = rest.split_at(32);
        let list = VLBytes::tls_deserialize(&mut rest).map_err(|_| invalid())?;
        if !rest.is_empty() {
            return Err(invalid());
        }
        let mut remaining = list.as_slice();
        let mut key_packages = Vec::new();
        while !remaining.is_empty() {
            let before = remaining;
            let message = MlsMessageIn::tls_deserialize(&mut remaining).map_err(|_| invalid())?;
            if !matches!(message.extract(), MlsMessageBodyIn::KeyPackage(_)) {
                return Err(invalid());
            }
            // Only current-profile devices hold device groups.
            key_packages.push(
                KeyPackage::new(before[..before.len() - remaining.len()].to_vec())
                    .with_protocol_profile(ProtocolProfile::Current),
            );
            if key_packages.len() > MAX_HAND_OFF_KEY_PACKAGES {
                return Err(invalid());
            }
        }
        if key_packages.is_empty() {
            return Err(invalid());
        }
        Ok(Self {
            from: from.try_into().map_err(|_| invalid())?,
            to: to.try_into().map_err(|_| invalid())?,
            key_packages,
        })
    }
}

/// A Welcome that consumes the addressee's private KeyPackage, sent by the
/// sibling whose Commit added it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiblingWelcome {
    pub from: DeviceSlotId,
    pub to: DeviceSlotId,
    /// The consumed private KeyPackage's `KeyPackageRef`, 1 to 64 bytes.
    pub key_package_ref: Vec<u8>,
    /// One `mls_welcome` MLSMessage, as MLS encodes it.
    pub welcome: Vec<u8>,
    /// Where the new member fetches the chat's group messages.
    pub relays: Vec<String>,
}

impl SiblingWelcome {
    /// The binary `SiblingWelcomeV1 { uint8 version; SlotId from; SlotId to;
    /// KeyPackageRefV1 key_package_ref; MLSMessage welcome;
    /// SiblingWelcomeRelayV1 relays<V> }`, each relay an `opaque url<1..512>`.
    /// The message content is its standard base64.
    pub fn encode(&self) -> Result<Vec<u8>, EngineError> {
        let invalid = |reason: &str| EngineError::Serialize(format!("sibling Welcome: {reason}"));
        if !(1..=MAX_KEY_PACKAGE_REF_LEN).contains(&self.key_package_ref.len()) {
            return Err(invalid("a KeyPackageRef is 1 to 64 bytes"));
        }
        if !is_one_welcome(&self.welcome) {
            return Err(invalid("not one mls_welcome MLSMessage"));
        }
        let mut relays = Vec::new();
        for relay in &self.relays {
            if !(1..=MAX_SIBLING_WELCOME_RELAY_LEN).contains(&relay.len()) {
                return Err(invalid("a relay URL is 1 to 512 bytes"));
            }
            VLBytes::new(relay.as_bytes().to_vec())
                .tls_serialize(&mut relays)
                .map_err(|error| invalid(&format!("{error:?}")))?;
        }
        let mut bytes = vec![SIBLING_WELCOME_VERSION];
        bytes.extend_from_slice(&self.from);
        bytes.extend_from_slice(&self.to);
        VLBytes::new(self.key_package_ref.clone())
            .tls_serialize(&mut bytes)
            .map_err(|error| invalid(&format!("{error:?}")))?;
        bytes.extend_from_slice(&self.welcome);
        VLBytes::new(relays)
            .tls_serialize(&mut bytes)
            .map_err(|error| invalid(&format!("{error:?}")))?;
        Ok(bytes)
    }

    /// Decode a sibling Welcome, accepting only the exact encoding: version
    /// 1, a ref of 1 to 64 bytes, one `mls_welcome` MLSMessage, relay URLs of
    /// 1 to 512 bytes of UTF-8, and nothing left over. The Welcome itself is
    /// not processed here.
    pub fn decode(bytes: &[u8]) -> Result<Self, EngineError> {
        let invalid = || EngineError::Serialize("invalid sibling Welcome".into());
        let (&version, rest) = bytes.split_first().ok_or_else(invalid)?;
        if version != SIBLING_WELCOME_VERSION || rest.len() < 64 {
            return Err(invalid());
        }
        let (from, rest) = rest.split_at(32);
        let (to, mut rest) = rest.split_at(32);
        let key_package_ref = VLBytes::tls_deserialize(&mut rest).map_err(|_| invalid())?;
        if !(1..=MAX_KEY_PACKAGE_REF_LEN).contains(&key_package_ref.as_slice().len()) {
            return Err(invalid());
        }
        let before = rest;
        let message = MlsMessageIn::tls_deserialize(&mut rest).map_err(|_| invalid())?;
        if !matches!(message.extract(), MlsMessageBodyIn::Welcome(_)) {
            return Err(invalid());
        }
        let welcome = before[..before.len() - rest.len()].to_vec();
        let list = VLBytes::tls_deserialize(&mut rest).map_err(|_| invalid())?;
        if !rest.is_empty() {
            return Err(invalid());
        }
        let mut remaining = list.as_slice();
        let mut relays = Vec::new();
        while !remaining.is_empty() {
            let relay = VLBytes::tls_deserialize(&mut remaining).map_err(|_| invalid())?;
            if !(1..=MAX_SIBLING_WELCOME_RELAY_LEN).contains(&relay.as_slice().len()) {
                return Err(invalid());
            }
            relays.push(String::from_utf8(relay.as_slice().to_vec()).map_err(|_| invalid())?);
        }
        Ok(Self {
            from: from.try_into().map_err(|_| invalid())?,
            to: to.try_into().map_err(|_| invalid())?,
            key_package_ref: key_package_ref.as_slice().to_vec(),
            welcome,
            relays,
        })
    }
}

/// The id a sibling Welcome's join is recorded under, derived from the id of
/// the device-group message that carried it, which keeps its own record.
pub(crate) fn sibling_welcome_id(message_id: &MessageId) -> MessageId {
    let mut hasher = Sha256::new();
    hasher.update(b"marmot sibling welcome v1");
    hasher.update(message_id.as_slice());
    MessageId::new(hasher.finalize().to_vec())
}

/// Whether `bytes` are exactly one `mls_welcome` MLSMessage.
fn is_one_welcome(mut bytes: &[u8]) -> bool {
    MlsMessageIn::tls_deserialize(&mut bytes)
        .is_ok_and(|message| matches!(message.extract(), MlsMessageBodyIn::Welcome(_)))
        && bytes.is_empty()
}

/// Validate a KeyPackage a sibling handed over, as decoded: a current-profile
/// KeyPackage of `account`, single-use, unexpired at `now`, whose leaf
/// carries a device tag that reads as `from`'s in `roster`, the device
/// group's current roster (mdk#2628 D33). The tag binds the KeyPackage to the
/// sibling that handed it over. It is the device group's rule for accepting
/// a hand-off, not a validity rule: an untagged KeyPackage stays valid
/// everywhere else.
pub fn validate_received_private_key_package(
    key_package: &KeyPackage,
    account: &MemberId,
    roster: &DeviceRosterV1,
    from: &DeviceSlotId,
    now: u64,
) -> Result<KeyPackageMetadata, EngineError> {
    let refused =
        |reason: &str| EngineError::Other(format!("private KeyPackage refused: {reason}"));
    let metadata = key_package_metadata(key_package)?;
    if metadata.credential_identity_hex != hex::encode(account.as_slice()) {
        return Err(refused("another account"));
    }
    if key_package_device_tag_claim(key_package, roster)? != DeviceTagClaim::Device(*from) {
        return Err(refused("not tagged as the sender's"));
    }
    if metadata.last_resort {
        return Err(refused("last resort"));
    }
    if metadata.not_after <= now {
        return Err(refused("expired"));
    }
    Ok(metadata)
}

/// The refs of every private KeyPackage this device issued.
pub(crate) fn issued_references<S: StorageProvider>(
    storage: &S,
) -> Result<BTreeSet<Vec<u8>>, EngineError> {
    Ok(match storage.private_key_package_storage() {
        Some(private) => private
            .list_issued_private_key_packages()?
            .into_iter()
            .map(|record| record.key_package_ref)
            .collect(),
        None => BTreeSet::new(),
    })
}

/// The record of the private KeyPackage `key_package_ref` names, if this
/// device issued it.
pub(crate) fn issued_record<S: StorageProvider>(
    storage: &S,
    key_package_ref: &[u8],
) -> Result<Option<IssuedPrivateKeyPackage>, EngineError> {
    Ok(match storage.private_key_package_storage() {
        Some(private) => private.issued_private_key_package(key_package_ref)?,
        None => None,
    })
}

fn private_storage<S: StorageProvider>(
    storage: &S,
) -> Result<&dyn PrivateKeyPackageStorage, EngineError> {
    storage
        .private_key_package_storage()
        .ok_or_else(|| EngineError::Backend("private KeyPackage storage is unavailable".into()))
}

/// Delete a record and its private bundle.
pub(crate) fn delete_issued<S: StorageProvider>(
    storage: &S,
    record: &IssuedPrivateKeyPackage,
) -> Result<(), EngineError> {
    // OpenMLS builds a ref from bytes only by decoding its TLS form.
    let reference = openmls::prelude::KeyPackageRef::tls_deserialize_exact(
        VLBytes::new(record.key_package_ref.clone())
            .tls_serialize_detached()
            .map_err(|error| EngineError::Serialize(format!("key_package ref: {error:?}")))?,
    )
    .map_err(|error| EngineError::Serialize(format!("key_package ref: {error:?}")))?;
    OpenMlsStorageProvider::delete_key_package(storage.mls_storage(), &reference)
        .map_err(|error| EngineError::Backend(format!("key_package delete: {error:?}")))?;
    private_storage(storage)?.delete_issued_private_key_package(&record.key_package_ref)?;
    Ok(())
}

/// How many of `records` count toward `recipient`'s stock at `now`: counted
/// and before halfway.
pub fn private_key_package_stock(
    records: &[IssuedPrivateKeyPackage],
    recipient: &DeviceSlotId,
    now: u64,
) -> usize {
    records
        .iter()
        .filter(|record| {
            &record.recipient_slot == recipient
                && record.counted
                && now < private_key_package_halfway(record.not_before, record.not_after)
        })
        .count()
}

impl<S: StorageProvider> Engine<S> {
    /// Issue `count` private KeyPackages to the sibling in `recipient`, each
    /// recorded in the same transaction as its private bundle, its hand-off
    /// not yet queued. Returns how many answer it: fewer once the sibling
    /// holds [`MAX_RETAINED_PRIVATE_KEY_PACKAGES`] unexpired records.
    ///
    /// With `request`, they answer that request from the sibling: every
    /// earlier record for it stops counting, since their hand-offs may have
    /// been lost, but keeps its key until used or expired, since the sibling
    /// may still hold it. A request already answered issues nothing. At the
    /// cap, the newest unexpired records for the sibling make up the rest:
    /// they count again and their hand-offs go out again, so a sibling whose
    /// hand-offs were all lost still gets some, and nothing is deleted before
    /// `not_after` (mdk#2628 D42). The sibling ignores one it has used.
    pub fn issue_private_key_packages(
        &mut self,
        recipient: &DeviceSlotId,
        count: usize,
        request: Option<&MessageId>,
        now: u64,
    ) -> Result<usize, EngineError> {
        let count = count.min(MAX_PRIVATE_KEY_PACKAGE_WANT as usize);
        self.storage.with_transaction(|storage| {
            let private = private_storage(storage)?;
            let records = private.list_issued_private_key_packages()?;
            if let Some(request) = request {
                if records
                    .iter()
                    .any(|record| record.request_id.as_ref() == Some(request))
                {
                    return Ok(0);
                }
                for record in records
                    .iter()
                    .filter(|record| &record.recipient_slot == recipient && record.counted)
                {
                    private.put_issued_private_key_package(&IssuedPrivateKeyPackage {
                        counted: false,
                        ..record.clone()
                    })?;
                }
            }
            let retained = records
                .iter()
                .filter(|record| &record.recipient_slot == recipient && now < record.not_after)
                .count();
            let fresh = count.min(MAX_RETAINED_PRIVATE_KEY_PACKAGES.saturating_sub(retained));
            for _ in 0..fresh {
                let (wire, key_package) = self.build_key_package(storage, false)?;
                private.put_issued_private_key_package(&IssuedPrivateKeyPackage {
                    key_package_ref: key_package_ref(&key_package)?.as_slice().to_vec(),
                    recipient_slot: *recipient,
                    not_before: key_package.life_time().not_before(),
                    not_after: key_package.life_time().not_after(),
                    key_package: wire.bytes().to_vec(),
                    issued_at: now,
                    hand_off_queued: false,
                    counted: true,
                    request_id: request.cloned(),
                })?;
            }
            let Some(request) = request else {
                return Ok::<_, EngineError>(fresh);
            };
            let mut held: Vec<_> = records
                .iter()
                .filter(|record| &record.recipient_slot == recipient && now < record.not_after)
                .collect();
            held.sort_by(|a, b| {
                (b.issued_at, b.not_after, &b.key_package_ref).cmp(&(
                    a.issued_at,
                    a.not_after,
                    &a.key_package_ref,
                ))
            });
            let again = held.into_iter().take(count - fresh);
            let mut answered = fresh;
            for record in again {
                private.put_issued_private_key_package(&IssuedPrivateKeyPackage {
                    hand_off_queued: false,
                    counted: true,
                    request_id: Some(request.clone()),
                    ..record.clone()
                })?;
                answered += 1;
            }
            Ok(answered)
        })
    }

    /// Join a chat from a sibling Welcome (mdk#2628 3.5), carried by the
    /// device-group message `message_id`, which `created_at` dates as its
    /// sender wrote it. The caller admits it first: it arrived in the trusted
    /// device group, `to` is this device's slot, `from` is another device of
    /// the roster, and the sending leaf's tag reads as `from`'s.
    ///
    /// The join consumes only the private KeyPackage the Welcome names, and
    /// only one this device issued to `from` and still holds; it then deletes
    /// that KeyPackage's issued record. Every other check is a Welcome join's.
    /// Outcomes are an ingested Welcome's: a refusal names its reason, and
    /// only storage and internal failures are errors.
    pub async fn join_sibling_welcome(
        &mut self,
        message_id: &MessageId,
        welcome: &SiblingWelcome,
        created_at: Option<Timestamp>,
    ) -> Result<IngestOutcome, EngineError> {
        let msg = TransportMessage {
            id: sibling_welcome_id(message_id),
            payload: welcome.welcome.clone(),
            timestamp: created_at.unwrap_or_default(),
            causal_deps: Vec::new(),
            source: TransportSource("device-group".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: self.identity.self_id().clone(),
            },
        };
        let peeled = PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            // Every device of the account is a sibling's sender.
            sender: Some(self.identity.self_id().clone()),
            content: PeeledContent::Welcome {
                bytes: welcome.welcome.clone(),
                created_at,
                key_package_event_id: None,
            },
            origin: msg.clone(),
        };
        let content_id = crate::group_lifecycle::welcome_content_dedup_id(&peeled)?;
        let joined = self
            .do_join_welcome(
                msg.clone(),
                Some((peeled, content_id.clone())),
                crate::group_lifecycle::WelcomeRoute::Sibling {
                    from: welcome.from,
                    key_package_ref: welcome.key_package_ref.clone(),
                },
            )
            .await;
        self.welcome_join_outcome(&msg, Some(content_id), joined)
    }

    /// Every private KeyPackage this device issued, oldest first.
    pub fn issued_private_key_packages(&self) -> Result<Vec<IssuedPrivateKeyPackage>, EngineError> {
        Ok(private_storage(&self.storage)?.list_issued_private_key_packages()?)
    }

    /// Record whether the hand-offs of `references` are queued: before they
    /// are sent, and undone when their publication reaches no one.
    pub fn set_private_key_package_hand_offs_queued(
        &mut self,
        references: &[Vec<u8>],
        queued: bool,
    ) -> Result<(), EngineError> {
        self.storage.with_transaction(|storage| {
            let private = private_storage(storage)?;
            for reference in references {
                if let Some(record) = private.issued_private_key_package(reference)? {
                    private.put_issued_private_key_package(&IssuedPrivateKeyPackage {
                        hand_off_queued: queued,
                        ..record
                    })?;
                }
            }
            Ok::<_, EngineError>(())
        })
    }

    /// Stop counting every private KeyPackage that no longer advertises what
    /// one built now would, so upkeep issues replacements, as a published
    /// KeyPackage is replaced when the capabilities change. Their keys stay
    /// until a Welcome consumes them or they expire. Returns how many.
    pub fn uncount_outdated_private_key_packages(&mut self) -> Result<usize, EngineError> {
        let mut outdated = Vec::new();
        for record in self.issued_private_key_packages()? {
            let key_package = KeyPackage::new(record.key_package.clone())
                .with_protocol_profile(ProtocolProfile::Current);
            // One this device cannot read is left to expire.
            if record.counted
                && !self
                    .key_package_advertises_current_capabilities(&key_package)
                    .unwrap_or(true)
            {
                outdated.push(IssuedPrivateKeyPackage {
                    counted: false,
                    ..record
                });
            }
        }
        self.storage.with_transaction(|storage| {
            let private = private_storage(storage)?;
            for record in &outdated {
                private.put_issued_private_key_package(record)?;
            }
            Ok::<_, EngineError>(outdated.len())
        })
    }

    /// Delete private KeyPackages with their keys: those expired at `now`,
    /// and with `recipient`, every one issued to that sibling. Returns how
    /// many went.
    pub fn discard_private_key_packages(
        &mut self,
        now: u64,
        recipient: Option<&DeviceSlotId>,
    ) -> Result<usize, EngineError> {
        self.storage.with_transaction(|storage| {
            let mut discarded = 0;
            for record in private_storage(storage)?.list_issued_private_key_packages()? {
                if record.not_after <= now || recipient == Some(&record.recipient_slot) {
                    delete_issued(storage, &record)?;
                    discarded += 1;
                }
            }
            Ok::<_, EngineError>(discarded)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_is_canonical_json() {
        let request = PrivateKeyPackageRequest {
            from: [0xab; 32],
            to: [0x01; 32],
            want: 10,
        };
        let content = request.encode();
        assert_eq!(
            content,
            format!(
                r#"{{"v":1,"from":"{}","to":"{}","want":10}}"#,
                "ab".repeat(32),
                "01".repeat(32)
            )
        );
        assert_eq!(PrivateKeyPackageRequest::decode(&content).unwrap(), request);
        for refused in [
            content.replace(r#""want":10"#, r#""want":0"#),
            content.replace(r#""want":10"#, r#""want":101"#),
            content.replace(r#""v":1"#, r#""v":2"#),
            content.replace("ab", "AB"),
            content.replace(r#","want""#, r#", "want""#),
            content.replace('}', r#","extra":1}"#),
            content.replace(&"01".repeat(32), &"01".repeat(31)),
        ] {
            assert!(
                PrivateKeyPackageRequest::decode(&refused).is_err(),
                "{refused}"
            );
        }
    }

    #[test]
    fn a_hand_off_refuses_an_empty_list_and_trailing_bytes() {
        let empty = PrivateKeyPackageHandOff {
            from: [1; 32],
            to: [2; 32],
            key_packages: Vec::new(),
        };
        assert!(empty.encode().is_err());
        let mut bytes = vec![HAND_OFF_VERSION];
        bytes.extend_from_slice(&[1; 32]);
        bytes.extend_from_slice(&[2; 32]);
        VLBytes::new(Vec::new()).tls_serialize(&mut bytes).unwrap();
        assert!(PrivateKeyPackageHandOff::decode(&bytes).is_err());
        bytes.push(0);
        assert!(PrivateKeyPackageHandOff::decode(&bytes).is_err());
        bytes[0] = 2;
        assert!(PrivateKeyPackageHandOff::decode(&bytes).is_err());
    }
}
