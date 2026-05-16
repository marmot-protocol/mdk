//! Marmot app-component state carried in OpenMLS `app_data_dictionary`.

use cgka_traits::app_components::{
    APP_COMPONENTS_COMPONENT_ID, AppComponentData, AppComponentId, AppComponentSet,
    GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_BLOSSOM_IMAGE_COMPONENT_ID, GROUP_PROFILE_COMPONENT_ID,
    NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, decode_components_list, decode_nostr_routing_v1,
    decode_quic_varint, encode_component_vectors, encode_components_list,
};
use cgka_traits::error::EngineError;
use cgka_traits::types::{GroupId, MemberId};
use openmls::extensions::{AppDataDictionary, AppDataDictionaryExtension, Extension};
use openmls::group::MlsGroup;
use openmls::prelude::LeafNode;
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InitialComponentState {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) admins: Vec<[u8; 32]>,
    pub(crate) app_components: Vec<AppComponentData>,
}

pub(crate) fn leaf_app_components_extension(
    supported: &AppComponentSet,
) -> Result<Extension, EngineError> {
    let mut dict = AppDataDictionary::new();
    dict.insert(
        APP_COMPONENTS_COMPONENT_ID,
        encode_components_list(&supported.ids),
    );
    Ok(Extension::AppDataDictionary(
        AppDataDictionaryExtension::new(dict),
    ))
}

pub(crate) fn app_components_of_leaf(leaf: &LeafNode) -> Result<AppComponentSet, EngineError> {
    let Some(ext) = leaf.extensions().app_data_dictionary() else {
        return Ok(AppComponentSet::default());
    };
    let Some(bytes) = ext.dictionary().get(&APP_COMPONENTS_COMPONENT_ID) else {
        return Ok(AppComponentSet::default());
    };
    let ids = decode_components_list(bytes)
        .map_err(|e| EngineError::Serialize(format!("leaf app_components decode failed: {e}")))?;
    Ok(AppComponentSet::from(ids))
}

pub(crate) fn app_data_dictionary_extension_for_group(
    required: &AppComponentSet,
    initial: &InitialComponentState,
) -> Result<Extension, EngineError> {
    let mut dict = AppDataDictionary::new();
    dict.insert(
        APP_COMPONENTS_COMPONENT_ID,
        encode_components_list(&required.ids),
    );
    if required.contains(GROUP_PROFILE_COMPONENT_ID) {
        dict.insert(
            GROUP_PROFILE_COMPONENT_ID,
            encode_group_profile(&initial.name, &initial.description)?,
        );
    }
    if required.contains(GROUP_BLOSSOM_IMAGE_COMPONENT_ID) {
        dict.insert(
            GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
            encode_component_vectors(&[]),
        );
    }
    if required.contains(GROUP_ADMIN_POLICY_COMPONENT_ID) {
        dict.insert(
            GROUP_ADMIN_POLICY_COMPONENT_ID,
            encode_admin_policy(&initial.admins)?,
        );
    }
    let mut seen_initial = BTreeSet::new();
    for component in &initial.app_components {
        if !seen_initial.insert(component.component_id) {
            return Err(EngineError::Other(
                "group creation request contains duplicate app components".into(),
            ));
        }
        validate_initial_app_component(component)?;
        if required.contains(component.component_id) {
            dict.insert(component.component_id, component.data.clone());
        }
    }
    Ok(Extension::AppDataDictionary(
        AppDataDictionaryExtension::new(dict),
    ))
}

pub(crate) fn required_app_components_of_group(
    mls_group: &MlsGroup,
) -> Result<AppComponentSet, EngineError> {
    let Some(bytes) = app_component_bytes(mls_group, APP_COMPONENTS_COMPONENT_ID) else {
        return Ok(AppComponentSet::default());
    };
    let ids = decode_components_list(bytes)
        .map_err(|e| EngineError::Serialize(format!("group app_components decode failed: {e}")))?;
    Ok(AppComponentSet::from(ids))
}

pub(crate) fn group_profile_of_group(
    mls_group: &MlsGroup,
) -> Result<Option<(String, String)>, EngineError> {
    let Some(bytes) = app_component_bytes(mls_group, GROUP_PROFILE_COMPONENT_ID) else {
        return Ok(None);
    };
    let mut cursor = bytes;
    let name = decode_var_bytes(&mut cursor, 256, "profile name")?;
    let description = decode_var_bytes(&mut cursor, 4096, "profile description")?;
    if !cursor.is_empty() {
        return Err(EngineError::Serialize(
            "profile component has trailing bytes".into(),
        ));
    }
    let name = String::from_utf8(name)
        .map_err(|e| EngineError::Serialize(format!("profile name is not UTF-8: {e}")))?;
    let description = String::from_utf8(description)
        .map_err(|e| EngineError::Serialize(format!("profile description is not UTF-8: {e}")))?;
    Ok(Some((name, description)))
}

pub(crate) fn admins_of_group(mls_group: &MlsGroup) -> Result<Vec<[u8; 32]>, EngineError> {
    let Some(bytes) = app_component_bytes(mls_group, GROUP_ADMIN_POLICY_COMPONENT_ID) else {
        return Ok(Vec::new());
    };
    decode_admin_policy(bytes)
}

pub(crate) fn app_component_data_of_group(
    mls_group: &MlsGroup,
    component_id: AppComponentId,
) -> Option<Vec<u8>> {
    app_component_bytes(mls_group, component_id).map(ToOwned::to_owned)
}

pub(crate) fn nostr_routing_of_group(
    mls_group: &MlsGroup,
) -> Result<Option<NostrRoutingV1>, EngineError> {
    let Some(bytes) = app_component_bytes(mls_group, NOSTR_ROUTING_COMPONENT_ID) else {
        return Ok(None);
    };
    decode_nostr_routing_v1(bytes)
        .map(Some)
        .map_err(|e| EngineError::Serialize(format!("Nostr routing component decode failed: {e}")))
}

pub(crate) fn transport_group_id_of_group(mls_group: &MlsGroup) -> Result<Vec<u8>, EngineError> {
    if let Some(routing) = nostr_routing_of_group(mls_group)? {
        return Ok(routing.nostr_group_id.to_vec());
    }
    Ok(mls_group.group_id().as_slice().to_vec())
}

pub(crate) fn require_admin(
    mls_group: &MlsGroup,
    group_id: &GroupId,
    member_id: &MemberId,
) -> Result<(), EngineError> {
    let member_pubkey = admin_pubkey_from_member_id(member_id)?;
    let admins = admins_of_group(mls_group)?;
    if admins.iter().any(|admin| admin == &member_pubkey) {
        return Ok(());
    }
    Err(EngineError::NotGroupAdmin {
        group_id: group_id.clone(),
    })
}

pub(crate) fn admin_pubkey_from_member_id(id: &MemberId) -> Result<[u8; 32], EngineError> {
    let bytes = id.as_slice();
    if bytes.len() != 32 {
        return Err(EngineError::Backend(format!(
            "Marmot admin policy requires 32-byte member identities; got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

pub(crate) fn encode_group_profile(name: &str, description: &str) -> Result<Vec<u8>, EngineError> {
    if name.len() > 256 {
        return Err(EngineError::Other(
            "group profile name must be at most 256 UTF-8 bytes".into(),
        ));
    }
    if description.len() > 4096 {
        return Err(EngineError::Other(
            "group profile description must be at most 4096 UTF-8 bytes".into(),
        ));
    }
    Ok(encode_component_vectors(&[
        name.as_bytes(),
        description.as_bytes(),
    ]))
}

pub(crate) fn encode_admin_policy(admins: &[[u8; 32]]) -> Result<Vec<u8>, EngineError> {
    let mut admins = admins.to_vec();
    admins.sort();
    admins.dedup();
    if admins.is_empty() {
        return Err(EngineError::Other(
            "admin policy must contain at least one admin".into(),
        ));
    }
    let mut admin_bytes = Vec::with_capacity(admins.len() * 32);
    for admin in &admins {
        admin_bytes.extend_from_slice(admin);
    }
    let mut out = Vec::new();
    cgka_traits::app_components::encode_quic_varint(admin_bytes.len() as u64, &mut out);
    out.extend_from_slice(&admin_bytes);
    Ok(out)
}

pub(crate) fn decode_admin_policy(bytes: &[u8]) -> Result<Vec<[u8; 32]>, EngineError> {
    let (len, prefix_len) = decode_quic_varint(bytes)
        .map_err(|e| EngineError::Serialize(format!("admin policy length decode failed: {e}")))?;
    let len = usize::try_from(len)
        .map_err(|_| EngineError::Serialize("admin policy length is too large".into()))?;
    let end = prefix_len
        .checked_add(len)
        .ok_or_else(|| EngineError::Serialize("admin policy length overflow".into()))?;
    if end != bytes.len() {
        return Err(EngineError::Serialize(
            "admin policy has trailing bytes".into(),
        ));
    }
    if len == 0 || len % 32 != 0 {
        return Err(EngineError::Serialize(
            "admin policy must contain one or more 32-byte keys".into(),
        ));
    }
    let mut admins = Vec::with_capacity(len / 32);
    for chunk in bytes[prefix_len..end].chunks_exact(32) {
        let mut admin = [0u8; 32];
        admin.copy_from_slice(chunk);
        admins.push(admin);
    }
    let mut sorted = admins.clone();
    sorted.sort();
    sorted.dedup();
    if sorted != admins {
        return Err(EngineError::Serialize(
            "admin policy keys must be sorted and unique".into(),
        ));
    }
    Ok(admins)
}

fn app_component_bytes(mls_group: &MlsGroup, component_id: AppComponentId) -> Option<&[u8]> {
    mls_group
        .extensions()
        .app_data_dictionary()?
        .dictionary()
        .get(&component_id)
}

fn validate_initial_app_component(component: &AppComponentData) -> Result<(), EngineError> {
    match component.component_id {
        APP_COMPONENTS_COMPONENT_ID
        | GROUP_PROFILE_COMPONENT_ID
        | GROUP_ADMIN_POLICY_COMPONENT_ID => Err(EngineError::Other(
            "group creation request cannot override engine-owned app components".into(),
        )),
        NOSTR_ROUTING_COMPONENT_ID => decode_nostr_routing_v1(&component.data)
            .map(|_| ())
            .map_err(|e| EngineError::Serialize(format!("invalid Nostr routing component: {e}"))),
        _ => Ok(()),
    }
}

fn decode_var_bytes(
    cursor: &mut &[u8],
    max_len: usize,
    label: &str,
) -> Result<Vec<u8>, EngineError> {
    let (len, prefix_len) = decode_quic_varint(cursor)
        .map_err(|e| EngineError::Serialize(format!("{label} length decode failed: {e}")))?;
    let len = usize::try_from(len)
        .map_err(|_| EngineError::Serialize(format!("{label} length is too large")))?;
    if len > max_len {
        return Err(EngineError::Serialize(format!(
            "{label} exceeds maximum length"
        )));
    }
    let end = prefix_len
        .checked_add(len)
        .ok_or_else(|| EngineError::Serialize(format!("{label} length overflow")))?;
    if cursor.len() < end {
        return Err(EngineError::Serialize(format!("{label} is truncated")));
    }
    let bytes = cursor[prefix_len..end].to_vec();
    *cursor = &cursor[end..];
    Ok(bytes)
}
