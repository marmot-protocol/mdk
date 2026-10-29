//! Marmot MLS app component ids and small byte helpers.
//!
//! Component state itself lives in the MLS `app_data_dictionary` extension.
//! These helpers deliberately stay OpenMLS-free so the public trait surface can
//! talk about component ids without exposing engine internals.
//!
//! This module is split into:
//!
//! - shared component ids, schema-name strings, and length limits (this file),
//! - [`codec`]: QUIC-varint / var-bytes primitives and the `ComponentsList`
//!   encoder,
//! - [`host_safety`]: public-IP / loopback host classifiers,
//! - per-schema component state and codecs: [`routing`], [`profile`],
//!   [`blossom_image`], [`encrypted_media`], [`encrypted_media_v2`], and
//!   [`avatar_url`].
//!
//! Everything public is re-exported here, so every `cgka_traits::app_components::*`
//! path is unchanged.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

mod avatar_url;
mod blossom_image;
mod codec;
mod device_roster;
mod encrypted_media;
mod encrypted_media_v2;
mod host_safety;
mod lifecycle;
mod profile;
mod routing;

#[cfg(test)]
mod tests;

pub use avatar_url::{
    GroupAvatarUrlV1, decode_group_avatar_url_v1, encode_group_avatar_url_v1,
    reject_unsafe_group_avatar_contact_url, validate_and_normalize_group_avatar_url,
};
pub use blossom_image::{
    GroupBlossomImageV1, canonicalize_marmot_media_type, decode_group_blossom_image_v1,
    encode_group_blossom_image_v1,
};
pub use codec::{
    decode_components_list, decode_quic_varint, encode_component_vectors, encode_components_list,
    encode_quic_varint,
};
pub use device_roster::{
    AccountEntryV1, DEVICE_ROSTER_KEY_PACKAGE_REF_MAX_LEN, DEVICE_ROSTER_RESERVED_KEY_MAX_LEN,
    DEVICE_ROSTER_TAG_SIGNATURE_KEY_MAX_LEN, DEVICE_ROSTER_TEXT_MAX_LEN, DeviceEntryV1,
    DeviceRosterOperationV1, DeviceRosterUpdateV1, DeviceRosterV1, DeviceSettingsV1, DeviceSlotId,
    DeviceStatusV1, RejectedKeyPackageV1, RejectedSlotReasonV1, RejectedSlotV1,
    apply_device_roster_update_v1, decode_device_roster_update_v1, decode_device_roster_v1,
    encode_device_roster_update_v1, encode_device_roster_v1,
};
pub use encrypted_media::{
    BlobStoreEndpointV1, EncryptedMediaPolicyV1, decode_encrypted_media_policy_v1,
    encode_encrypted_media_policy_v1, validate_and_normalize_blob_endpoint_url,
};
pub use encrypted_media_v2::{
    BlobStoreEndpointV2, EncryptedMediaPolicyV2, decode_encrypted_media_policy_v2,
    encode_encrypted_media_policy_v2, validate_and_normalize_blob_endpoint_url_v2,
};
pub use host_safety::{
    is_loopback_candidate_host, is_loopback_host, is_loopback_ip, is_public_ip, is_public_ipv4,
    is_public_ipv6, reject_non_public_ip, reject_non_public_socket_addr,
};
pub use lifecycle::{GroupLifecycleV1, decode_group_lifecycle_v1, encode_group_lifecycle_v1};
pub use profile::{
    GROUP_PROFILE_DESCRIPTION_MAX_LEN, GROUP_PROFILE_NAME_MAX_LEN, GroupProfileV1,
    decode_group_profile_v1, encode_group_profile_v1,
};
pub use routing::{
    NOSTR_RELAY_URL_MAX_LEN, NOSTR_ROUTING_MAX_RELAYS, NostrRoutingV1, decode_nostr_routing_v1,
    encode_nostr_routing_v1,
};

/// MLS ComponentID.
pub type AppComponentId = u16;

/// First application-component id in the private-use range.
///
/// Kind-30443 KeyPackage events publish only private-use application
/// components; upstream standardized component ids below this boundary remain
/// discoverable from the decoded MLS capabilities.
pub const PRIVATE_USE_APP_COMPONENT_ID_START: AppComponentId = 0x8000;

/// Upstream MLS extensions draft component that carries supported/required
/// application component ids in an `AppDataDictionary` entry.
pub const APP_COMPONENTS_COMPONENT_ID: AppComponentId = 0x0001;
/// Upstream MLS extensions draft component that advertises SafeAAD component
/// usage in LeafNodes and requires SafeAAD framing in GroupContexts.
pub const SAFE_AAD_COMPONENT_ID: AppComponentId = 0x0002;

pub const GROUP_PROFILE_COMPONENT_ID: AppComponentId = 0x8001;
pub const GROUP_BLOSSOM_IMAGE_COMPONENT_ID: AppComponentId = 0x8002;
pub const GROUP_ADMIN_POLICY_COMPONENT_ID: AppComponentId = 0x8003;
pub const NOSTR_ROUTING_COMPONENT_ID: AppComponentId = 0x8004;
pub const GROUP_MESSAGE_RETENTION_COMPONENT_ID: AppComponentId = 0x8005;
pub const AGENT_TEXT_STREAM_QUIC_COMPONENT_ID: AppComponentId = 0x8006;
pub const GROUP_AVATAR_URL_COMPONENT_ID: AppComponentId = 0x8007;
pub const GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID: AppComponentId = 0x8008;
/// Backward-compatible name for the frozen V1 component. New code should use
/// the explicit V1/V2 constants so a group cannot silently change formats.
#[deprecated(
    note = "use GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID or GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID"
)]
pub const GROUP_ENCRYPTED_MEDIA_COMPONENT_ID: AppComponentId =
    GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID;
/// LeafNode-only account identity proof binding the Marmot account key to the
/// MLS signature key. The proof bytes live in the LeafNode
/// `app_data_dictionary`; GroupContext dictionaries only require the id via
/// `app_components`.
pub const ACCOUNT_IDENTITY_PROOF_COMPONENT_ID: AppComponentId = 0x8009;
// 0x800a was the draft multi-device join authorization. The registry
// withdrew it (marmot#427), so MDK treats it like any id the registry does
// not assign.
pub const GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID: AppComponentId = 0x800b;
pub const GROUP_LIFECYCLE_COMPONENT_ID: AppComponentId = 0x800c;
/// `marmot.group.account-devices.v1`: lets a member add and remove leaves of
/// its own account without admin authority once a group requires it. It has
/// no data at any location; its id appears only in `app_components` support
/// and required lists.
pub const ACCOUNT_DEVICES_COMPONENT_ID: AppComponentId = 0x800d;

/// `max_leaves_per_account` of `marmot.group.account-devices.v1`: while a
/// group requires the component, no account holds more current leaves than
/// this. Fixed for the component id; a different cap needs a new id.
pub const MAX_LEAVES_PER_ACCOUNT: usize = 20;

/// `marmot.account.device-roster.v1`: the roster of an account's device
/// group (mdk#2628 D16). Requiring it marks a group as a device group; the
/// marker alone never makes a group trusted. Its update is a diff of keyed
/// entries ([`DeviceRosterUpdateV1`]). The wire format is unreleased until
/// its spec lands, so the engine advertises it only in test-policy builds.
pub const DEVICE_ROSTER_COMPONENT_ID: AppComponentId = 0x800e;

/// First component id applications may allocate for themselves.
///
/// The protocol registry allocates upward from `0x8001` and is at `0x800e`
/// today, so "any private-use id the registry has not taken yet" is not a
/// safe rule for applications: an id chosen that way can be assigned by a
/// later registry entry, stranding state already committed in live groups.
/// Applications allocate at or above this boundary instead, which the
/// protocol never reaches, so the two spaces cannot collide.
pub const APP_OWNED_APP_COMPONENT_ID_START: AppComponentId = 0xf000;

/// Largest application-owned component payload accepted for a group.
///
/// Component state is re-encoded into the GroupContext of every later commit
/// and into the GroupInfo of every Welcome, so an oversized value inflates
/// each commit and can push a Welcome past a relay's event-size limit, where
/// it fails after the commit is already staged. Matches
/// [`GROUP_PROFILE_DESCRIPTION_MAX_LEN`]: enough for settings, not a blob
/// store.
pub const APP_COMPONENT_DATA_MAX_LEN: usize = 4096;

/// Every component id the protocol owns, in registry assignment order.
///
/// Add every new protocol component constant here, including draft ones: the
/// engine's GroupContext format validation reads
/// this list, so an id left out is never format-checked. Applications are
/// kept away from all of these by the separate
/// [`APP_OWNED_APP_COMPONENT_ID_START`] boundary rather than by this list, so
/// a new entry here cannot collide with an id an application already uses.
pub const PROTOCOL_OWNED_APP_COMPONENT_IDS: &[AppComponentId] = &[
    APP_COMPONENTS_COMPONENT_ID,
    SAFE_AAD_COMPONENT_ID,
    GROUP_PROFILE_COMPONENT_ID,
    GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
    GROUP_ADMIN_POLICY_COMPONENT_ID,
    NOSTR_ROUTING_COMPONENT_ID,
    GROUP_MESSAGE_RETENTION_COMPONENT_ID,
    AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
    GROUP_AVATAR_URL_COMPONENT_ID,
    GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID,
    ACCOUNT_IDENTITY_PROOF_COMPONENT_ID,
    GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
    GROUP_LIFECYCLE_COMPONENT_ID,
    ACCOUNT_DEVICES_COMPONENT_ID,
    DEVICE_ROSTER_COMPONENT_ID,
];

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
pub const GROUP_ENCRYPTED_MEDIA_V1_COMPONENT: &str = "marmot.group.encrypted-media.v1";
/// Backward-compatible name for the frozen V1 component.
#[deprecated(note = "use GROUP_ENCRYPTED_MEDIA_V1_COMPONENT or GROUP_ENCRYPTED_MEDIA_V2_COMPONENT")]
pub const GROUP_ENCRYPTED_MEDIA_COMPONENT: &str = GROUP_ENCRYPTED_MEDIA_V1_COMPONENT;
pub const ACCOUNT_IDENTITY_PROOF_COMPONENT: &str = "marmot.member.account-identity-proof.v2";
pub const GROUP_ENCRYPTED_MEDIA_V2_COMPONENT: &str = "marmot.group.encrypted-media.v2";
pub const GROUP_LIFECYCLE_COMPONENT: &str = "marmot.group.lifecycle.v1";
pub const ACCOUNT_DEVICES_COMPONENT: &str = "marmot.group.account-devices.v1";
pub const DEVICE_ROSTER_COMPONENT: &str = "marmot.account.device-roster.v1";
pub const ENCRYPTED_MEDIA_FORMAT_V1: &str = "encrypted-media-v1";
pub const ENCRYPTED_MEDIA_FORMAT_V2: &str = "encrypted-media-v2";
pub const BLOSSOM_LOCATOR_KIND_V1: &str = "blossom-v1";

/// Maximum encoded length of a group avatar URL, in bytes.
pub const GROUP_AVATAR_URL_MAX_LEN: usize = 2048;
/// Maximum encoded length of the optional `dim` / `thumbhash` render hints.
pub const GROUP_AVATAR_HINT_MAX_LEN: usize = 256;
pub const ENCRYPTED_MEDIA_LOCATOR_KIND_MAX_LEN: usize = 64;
pub const ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN: usize = 2048;
pub const ENCRYPTED_MEDIA_MAX_LOCATOR_KINDS: usize = 16;
pub const ENCRYPTED_MEDIA_MAX_BLOB_ENDPOINTS: usize = 16;

/// Initial app-component state supplied by the app layer at group creation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppComponentData {
    pub component_id: AppComponentId,
    pub data: Vec<u8>,
}

/// The group-state components this implementation creates by default when
/// every founding member advertises support for them.
pub fn default_group_components() -> BTreeSet<AppComponentId> {
    [
        GROUP_PROFILE_COMPONENT_ID,
        GROUP_ADMIN_POLICY_COMPONENT_ID,
        GROUP_LIFECYCLE_COMPONENT_ID,
    ]
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
