use serde::{Deserialize, Serialize};

/// Authenticated terminal lifecycle state carried by
/// `marmot.group.lifecycle.v1`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupLifecycleV1 {
    #[default]
    Active,
    Disbanded,
}

/// Encode the v1 lifecycle as exactly one byte.
pub fn encode_group_lifecycle_v1(state: GroupLifecycleV1) -> Vec<u8> {
    vec![match state {
        GroupLifecycleV1::Active => 0,
        GroupLifecycleV1::Disbanded => 1,
    }]
}

/// Decode the exact one-byte v1 lifecycle representation.
pub fn decode_group_lifecycle_v1(bytes: &[u8]) -> Result<GroupLifecycleV1, &'static str> {
    match bytes {
        [0] => Ok(GroupLifecycleV1::Active),
        [1] => Ok(GroupLifecycleV1::Disbanded),
        [] => Err("group lifecycle state is empty"),
        [_] => Err("group lifecycle state is unknown"),
        _ => Err("group lifecycle state has trailing bytes"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_codec_is_exactly_one_byte() {
        assert_eq!(encode_group_lifecycle_v1(GroupLifecycleV1::Active), [0]);
        assert_eq!(encode_group_lifecycle_v1(GroupLifecycleV1::Disbanded), [1]);
        assert_eq!(
            decode_group_lifecycle_v1(&[0]),
            Ok(GroupLifecycleV1::Active)
        );
        assert_eq!(
            decode_group_lifecycle_v1(&[1]),
            Ok(GroupLifecycleV1::Disbanded)
        );
        assert!(decode_group_lifecycle_v1(&[]).is_err());
        assert!(decode_group_lifecycle_v1(&[2]).is_err());
        assert!(decode_group_lifecycle_v1(&[0, 0]).is_err());
    }
}
