//! Thin selected-title extraction after the existing bounded typed validation.
//! No avatar-bearing object escapes this function. The transient <=64KiB
//! envelope decoder still allocates typed avatar fields to preserve its exact
//! acceptance contract; it performs no asset/profile acquisition or SQL.
use super::{PresentationText, decode_envelope};
use cgka_traits::storage::StorageResult;

#[derive(Clone, PartialEq, Eq)]
pub struct SelectionPresentation {
    pub title: PresentationText,
    pub peer_id: Option<String>,
}
impl std::fmt::Debug for SelectionPresentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectionPresentation")
            .finish_non_exhaustive()
    }
}

/// Readiness/current-source checks belong to the capture transaction. Do not
/// call this on the default/no-presentation path or retain the input envelope.
pub(crate) fn decode_selection_presentation(bytes: &[u8]) -> StorageResult<SelectionPresentation> {
    let presentation = decode_envelope(bytes)?.value.presentation;
    Ok(SelectionPresentation {
        title: presentation.title,
        peer_id: presentation.peer_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::chat_presentation::{MAX_BYTES, decode_envelope};
    fn envelope() -> serde_json::Value {
        serde_json::json!({
            "format":1,"value":{
                "presentation":{
                    "title":{"Literal":"private-title-sentinel"},
                    "avatar":{"EncryptedGroupImage":{
                        "image":{"image_hash_hex":"hash","image_key_hex":"private-key-sentinel","image_nonce_hex":"nonce","image_upload_key_hex":"private-upload-sentinel","media_type":null},
                        "cache_key":"private-avatar-sentinel"
                    }},
                    "title_source":"Group","avatar_source":"Group","peer_id":"private-peer-sentinel","resolution":"Cached"
                },"profile_version":null
            }
        })
    }
    #[test]
    fn exact_typed_acceptance_drops_avatar_and_redacts_text() {
        let bytes = serde_json::to_vec(&envelope()).unwrap();
        let expected = decode_envelope(&bytes).unwrap().value.presentation;
        let selected = decode_selection_presentation(&bytes).unwrap();
        assert!(selected.title == expected.title);
        assert_eq!(selected.peer_id, expected.peer_id);
        let debug = format!("{selected:?}");
        assert!(!debug.contains("sentinel"));
        // All three shipped title variants use the same decoder path.
        for title in [
            serde_json::json!({"UnnamedGroup":{"member_count":2}}),
            serde_json::json!("UnavailableConversation"),
        ] {
            let mut value = envelope();
            value["value"]["presentation"]["title"] = title;
            let bytes = serde_json::to_vec(&value).unwrap();
            assert!(
                decode_selection_presentation(&bytes).unwrap().title
                    == decode_envelope(&bytes).unwrap().value.presentation.title
            );
        }
    }
    #[test]
    fn malformed_avatar_is_not_ignored_by_thin_extraction() {
        for replacement in [
            serde_json::json!(null),
            serde_json::json!({"EncryptedGroupImage":{"image":{"image_key_hex":3},"cache_key":"x"}}),
            serde_json::json!({"UnknownVariant":{}}),
        ] {
            let mut value = envelope();
            value["value"]["presentation"]["avatar"] = replacement;
            let bytes = serde_json::to_vec(&value).unwrap();
            assert!(decode_envelope(&bytes).is_err());
            assert!(decode_selection_presentation(&bytes).is_err());
        }
    }
    #[test]
    fn exact_byte_gate_matches_existing_decoder() {
        let mut bytes = serde_json::to_vec(&envelope()).unwrap();
        assert!(bytes.len() < MAX_BYTES);
        bytes.resize(MAX_BYTES, b' ');
        assert!(decode_envelope(&bytes).is_ok());
        assert!(decode_selection_presentation(&bytes).is_ok());
        bytes.push(b' ');
        assert!(decode_envelope(&bytes).is_err());
        assert!(decode_selection_presentation(&bytes).is_err());
    }
}
