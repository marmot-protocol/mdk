//! `marmot.group.profile.v1` component state and codec.

use serde::{Deserialize, Serialize};

use super::codec::{decode_var_bytes, encode_component_vectors};

pub const GROUP_PROFILE_NAME_MAX_LEN: usize = 256;
pub const GROUP_PROFILE_DESCRIPTION_MAX_LEN: usize = 4096;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupProfileV1 {
    pub name: String,
    pub description: String,
}

pub fn encode_group_profile_v1(profile: &GroupProfileV1) -> Result<Vec<u8>, String> {
    if profile.name.len() > GROUP_PROFILE_NAME_MAX_LEN {
        return Err(format!(
            "group profile name exceeds {GROUP_PROFILE_NAME_MAX_LEN} bytes"
        ));
    }
    if profile.description.len() > GROUP_PROFILE_DESCRIPTION_MAX_LEN {
        return Err(format!(
            "group profile description exceeds {GROUP_PROFILE_DESCRIPTION_MAX_LEN} bytes"
        ));
    }
    Ok(encode_component_vectors(&[
        profile.name.as_bytes(),
        profile.description.as_bytes(),
    ]))
}

pub fn decode_group_profile_v1(bytes: &[u8]) -> Result<GroupProfileV1, String> {
    let mut cursor = bytes;
    let name = decode_var_bytes(
        &mut cursor,
        GROUP_PROFILE_NAME_MAX_LEN,
        "group profile name",
    )?;
    let description = decode_var_bytes(
        &mut cursor,
        GROUP_PROFILE_DESCRIPTION_MAX_LEN,
        "group profile description",
    )?;
    if !cursor.is_empty() {
        return Err("group profile component has trailing bytes".into());
    }
    Ok(GroupProfileV1 {
        name: String::from_utf8(name)
            .map_err(|e| format!("group profile name is not UTF-8: {e}"))?,
        description: String::from_utf8(description)
            .map_err(|e| format!("group profile description is not UTF-8: {e}"))?,
    })
}
