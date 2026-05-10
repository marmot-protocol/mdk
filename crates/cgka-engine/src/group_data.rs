//! MIP-01 `marmot_group_data` extension (`0xF2EE`).
//!
//! Faithful TLS-codec serialization of the monolithic `NostrGroupData`
//! struct from MIP-01 v3. Most fields are transport-agnostic infrastructure
//! that the engine treats as opaque placeholders for 0.1.0 — only
//! `admin_pubkeys` is actively consulted by the engine (for MIP-03
//! §149/§150 guards).
//!
//! Per the user's direction (2026-04-25): we keep the monolithic
//! `marmot_group_data` extension as-is rather than splitting into
//! components. A future component-based split will retire this module.

use tls_codec::{
    Deserialize as TlsDeserialize, Serialize as TlsSerialize, TlsDeserialize, TlsSerialize,
    TlsSize, VLBytes,
};

use cgka_traits::error::EngineError;
use cgka_traits::types::MemberId;
use openmls::extensions::Extension;
use openmls::group::MlsGroup;
use openmls::prelude::ExtensionType;

/// The MIP-01 extension identifier.
pub const MARMOT_GROUP_DATA_EXT_TYPE: u16 = 0xF2EE;

/// Current version per MIP-01 v3.
pub const NOSTR_GROUP_DATA_VERSION: u16 = 3;

/// MIP-01 NostrGroupData (version 3) — TLS-presentation-language struct.
///
/// All variable-length fields use QUIC varint length prefixes via
/// `tls_codec::VLBytes`.
///
/// `nostr_group_id` is generated from a CSPRNG at create time so it is
/// not derivable from any member identity. Deriving the routing tag from
/// a member identity would let a relay-side observer (or any group
/// member, since this field is in the signed group context) correlate
/// every group created by that identity.
#[derive(Clone, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct NostrGroupData {
    /// Version field. MUST be ≥ 1; 0 is rejected. Currently 3.
    pub version: u16,
    /// 32-byte transport-visible group id (Nostr `h`-tag value). For the
    /// engine layer's purposes this is opaque — the transport adapter
    /// would normally generate this. We populate with random bytes at
    /// create time so the wire format is valid.
    pub nostr_group_id: [u8; 32],
    /// UTF-8 group name. From `CreateGroupRequest::name`.
    pub name: VLBytes,
    /// UTF-8 group description.
    pub description: VLBytes,
    /// Concatenated 32-byte x-only secp256k1 admin pubkeys. Length must
    /// be a multiple of 32. **The only field the engine actively reads.**
    pub admin_pubkeys: VLBytes,
    /// Concatenated length-prefixed UTF-8 relay URLs. Empty at engine
    /// layer; transport adapters fill this in on the way out.
    pub relays: VLBytes,
    /// Optional 32-byte SHA-256 of the encrypted group image. Empty here.
    pub image_hash: VLBytes,
    /// Optional 32-byte image-encryption seed.
    pub image_key: VLBytes,
    /// Optional 12-byte image nonce.
    pub image_nonce: VLBytes,
    /// Optional 32-byte image-upload-keypair seed.
    pub image_upload_key: VLBytes,
    /// Optional 8-byte big-endian disappearing-message duration in seconds.
    pub disappearing_message_secs: VLBytes,
}

impl NostrGroupData {
    /// Build a fresh extension for `create_group`. `creator_admin_pubkey`
    /// MUST be 32 bytes per MIP-01.
    pub fn fresh(
        name: &str,
        description: &str,
        nostr_group_id: [u8; 32],
        creator_admin_pubkey: [u8; 32],
    ) -> Self {
        Self {
            version: NOSTR_GROUP_DATA_VERSION,
            nostr_group_id,
            name: VLBytes::new(name.as_bytes().to_vec()),
            description: VLBytes::new(description.as_bytes().to_vec()),
            admin_pubkeys: VLBytes::new(creator_admin_pubkey.to_vec()),
            relays: VLBytes::new(Vec::new()),
            image_hash: VLBytes::new(Vec::new()),
            image_key: VLBytes::new(Vec::new()),
            image_nonce: VLBytes::new(Vec::new()),
            image_upload_key: VLBytes::new(Vec::new()),
            disappearing_message_secs: VLBytes::new(Vec::new()),
        }
    }

    /// Decode the admin set into a list of 32-byte pubkeys.
    pub fn admins(&self) -> Vec<[u8; 32]> {
        let bytes = self.admin_pubkeys.as_slice();
        if bytes.is_empty() || !bytes.len().is_multiple_of(32) {
            return Vec::new();
        }
        bytes
            .chunks_exact(32)
            .map(|c| {
                let mut out = [0u8; 32];
                out.copy_from_slice(c);
                out
            })
            .collect()
    }

    /// Re-pack the admin list into the wire-format opaque vector.
    pub fn set_admins(&mut self, admins: &[[u8; 32]]) {
        let mut bytes = Vec::with_capacity(admins.len() * 32);
        for k in admins {
            bytes.extend_from_slice(k);
        }
        self.admin_pubkeys = VLBytes::new(bytes);
    }

    pub fn to_extension(&self) -> Result<Extension, EngineError> {
        let bytes = self
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("nostr_group_data: {e:?}")))?;
        // OpenMLS exposes UnknownExtension via `Extension::Unknown(type, data)`.
        Ok(Extension::Unknown(
            MARMOT_GROUP_DATA_EXT_TYPE,
            openmls::extensions::UnknownExtension(bytes),
        ))
    }
}

/// Pull the `marmot_group_data` extension out of an MlsGroup, if present,
/// and return it parsed.
pub fn read_from_group(mls_group: &MlsGroup) -> Result<Option<NostrGroupData>, EngineError> {
    for ext in mls_group.extensions().iter() {
        if let Extension::Unknown(
            MARMOT_GROUP_DATA_EXT_TYPE,
            openmls::extensions::UnknownExtension(bytes),
        ) = ext
        {
            let parsed = NostrGroupData::tls_deserialize_exact(bytes)
                .map_err(|e| EngineError::Serialize(format!("nostr_group_data parse: {e:?}")))?;
            if parsed.version == 0 {
                return Err(EngineError::Serialize(
                    "nostr_group_data version 0 is reserved".into(),
                ));
            }
            return Ok(Some(parsed));
        }
    }
    Ok(None)
}

/// Convenience: read just the admin set from the group's extension.
/// Returns empty Vec if the extension isn't present (unusual; MIP-01 makes
/// it mandatory but tests for older flows might construct groups without).
pub fn admins_of_group(mls_group: &MlsGroup) -> Result<Vec<[u8; 32]>, EngineError> {
    Ok(read_from_group(mls_group)?
        .map(|d| d.admins())
        .unwrap_or_default())
}

/// Convert a [`MemberId`] into a 32-byte admin pubkey. MIP-01 admin pubkeys
/// MUST be raw 32-byte x-only secp256k1 keys; engine identities flowing
/// through `EngineBuilder::identity` are expected to satisfy this. Returns
/// an error on length mismatch — production callers that produce a
/// non-32-byte identity have a bug, not a degraded behavior to silently
/// paper over.
pub fn admin_pubkey_from_member_id(id: &MemberId) -> Result<[u8; 32], EngineError> {
    let bytes = id.as_slice();
    if bytes.len() != 32 {
        return Err(EngineError::Backend(format!(
            "MIP-01 requires 32-byte member identities for admin tracking; got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Used by `ExtensionType` registration in MlsGroupCreateConfig. The engine
/// must declare `marmot_group_data` as a known/required leaf-capability +
/// group-context-required extension at create time.
pub fn extension_type() -> ExtensionType {
    ExtensionType::Unknown(MARMOT_GROUP_DATA_EXT_TYPE)
}

/// Snapshot of the routing-relevant fields inside `marmot_group_data`,
/// pulled out by integration tests that need to assert on the wire shape
/// of the extension. Production callers should not use this — the engine
/// owns interpretation of `marmot_group_data`.
#[derive(Clone, Debug)]
pub struct MarmotGroupDataSnapshot {
    pub nostr_group_id: [u8; 32],
    pub admins: Vec<[u8; 32]>,
    pub name: String,
    pub description: String,
}

/// Test-only helper: load the named group from storage, read its
/// `marmot_group_data` extension, and return a copy of its routing-
/// relevant fields. Returns `None` if the group has no extension or the
/// extension fails to parse.
///
/// This is exported under a `_for_test` suffix so production code does
/// not accidentally reach for it; storage-side direct reads should go
/// through the engine API.
pub fn read_marmot_group_data_for_test<S: cgka_traits::storage::StorageProvider>(
    storage: &S,
    group_id: &cgka_traits::types::GroupId,
) -> Option<MarmotGroupDataSnapshot> {
    use openmls::group::{GroupId as MlsGroupId, MlsGroup};
    use openmls_rust_crypto::RustCrypto;

    let crypto = RustCrypto::default();
    let provider = crate::provider::EngineOpenMlsProvider::<S>::new(&crypto, storage.mls_storage());
    let mls_gid = MlsGroupId::from_slice(group_id.as_slice());
    let mls_group = MlsGroup::load(
        <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
            &provider,
        ),
        &mls_gid,
    )
    .ok()
    .flatten()?;
    let data = read_from_group(&mls_group).ok().flatten()?;
    Some(MarmotGroupDataSnapshot {
        nostr_group_id: data.nostr_group_id,
        admins: data.admins(),
        name: String::from_utf8_lossy(data.name.as_slice()).into_owned(),
        description: String::from_utf8_lossy(data.description.as_slice()).into_owned(),
    })
}
