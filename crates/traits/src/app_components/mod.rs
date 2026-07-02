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
//! - per-schema component state and codecs: [`routing`], [`encrypted_media`],
//!   and [`avatar_url`].
//!
//! Everything public is re-exported here, so every `cgka_traits::app_components::*`
//! path is unchanged.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

mod avatar_url;
mod codec;
mod encrypted_media;
mod host_safety;
mod routing;

#[cfg(test)]
mod tests;

pub use avatar_url::{
    GroupAvatarUrlV1, decode_group_avatar_url_v1, encode_group_avatar_url_v1,
    validate_and_normalize_group_avatar_url,
};
pub use codec::{
    decode_components_list, decode_quic_varint, encode_component_vectors, encode_components_list,
    encode_quic_varint,
};
pub use encrypted_media::{
    BlobStoreEndpointV1, EncryptedMediaPolicyV1, decode_encrypted_media_policy_v1,
    encode_encrypted_media_policy_v1, validate_and_normalize_blob_endpoint_url,
};
pub use host_safety::{
    is_loopback_host, is_loopback_ip, is_public_ip, is_public_ipv4, is_public_ipv6,
};
pub use routing::{NostrRoutingV1, decode_nostr_routing_v1, encode_nostr_routing_v1};

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

/// Initial app-component state supplied by the app layer at group creation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppComponentData {
    pub component_id: AppComponentId,
    pub data: Vec<u8>,
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
