//! Shared FFI helpers used across the conversion sub-modules.

use cgka_traits::{GroupId, app_event::MARMOT_APP_EVENT_KIND_CHAT};
use marmot_app::SelfMembership;

use crate::markdown::{MarkdownDocumentFfi, parse_markdown_document};

// MLS group ids are opaque bytes. OpenMLS-generated ids are 16 bytes today,
// but protocol surfaces that bind raw MLS group ids treat them as variable
// length and cap them at 1024 bytes.
const MLS_GROUP_ID_MAX_LEN: usize = 1024;

/// The local account's own membership in a group: an active `Member`, or a
/// terminal state describing how it left — `Left` (a voluntary self-removal or
/// declined invite) or `Removed` (evicted by another member). Surfaced on both
/// the chat-list row and the group-detail record.
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum SelfMembershipFfi {
    Member,
    Left,
    Removed,
}

impl From<SelfMembership> for SelfMembershipFfi {
    fn from(value: SelfMembership) -> Self {
        match value {
            SelfMembership::Member => SelfMembershipFfi::Member,
            SelfMembership::Left => SelfMembershipFfi::Left,
            SelfMembership::Removed => SelfMembershipFfi::Removed,
        }
    }
}

/// One Nostr tag from an inner Marmot app event, e.g. `["e", "<id>"]` or an
/// `["imeta", …]` media descriptor. Host apps branch on the inner event `kind`
/// plus these tags instead of a fixed payload enum.
#[derive(Clone, Debug, uniffi::Record)]
pub struct MessageTagFfi {
    pub values: Vec<String>,
}

pub(crate) fn message_tags_ffi(tags: Vec<Vec<String>>) -> Vec<MessageTagFfi> {
    tags.into_iter()
        .map(|values| MessageTagFfi { values })
        .collect()
}

pub(crate) fn markdown_content_tokens(kind: u64, plaintext: &str) -> MarkdownDocumentFfi {
    if kind == MARMOT_APP_EVENT_KIND_CHAT {
        parse_markdown_document(plaintext)
    } else {
        MarkdownDocumentFfi::default()
    }
}

/// Decode a hex-encoded group id back into the engine's byte newtype.
pub fn group_id_from_hex(group_id_hex: &str) -> Result<GroupId, crate::errors::MarmotKitError> {
    let group_id_hex = group_id_hex.trim();
    if group_id_hex.len() > MLS_GROUP_ID_MAX_LEN * 2 {
        return Err(crate::errors::MarmotKitError::InvalidHex {
            details: format!("group id exceeds {MLS_GROUP_ID_MAX_LEN} bytes"),
        });
    }
    let bytes =
        hex::decode(group_id_hex).map_err(|err| crate::errors::MarmotKitError::InvalidHex {
            details: err.to_string(),
        })?;
    if bytes.is_empty() {
        return Err(crate::errors::MarmotKitError::InvalidHex {
            details: "group id must not be empty".into(),
        });
    }
    Ok(GroupId::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::markdown::{MarkdownBlockFfi, MarkdownInlineFfi};

    #[test]
    fn chat_tokens_include_details_blocks() {
        let tokens = markdown_content_tokens(
            MARMOT_APP_EVENT_KIND_CHAT,
            "<details>\n<summary>More</summary>\nbody\n</details>",
        );
        assert!(matches!(tokens.blocks[0], MarkdownBlockFfi::Details { .. }));
        let other =
            markdown_content_tokens(1, "<details>\n<summary>More</summary>\nbody\n</details>");
        assert!(other.blocks.is_empty());
        let fallback = markdown_content_tokens(
            MARMOT_APP_EVENT_KIND_CHAT,
            "<details>\n<summary>KEEP_THIS_SUMMARY</summary>\nbody",
        );
        assert!(
            !fallback
                .blocks
                .iter()
                .any(|block| matches!(block, MarkdownBlockFfi::Details { .. }))
        );
        assert!(fallback.blocks.iter().any(|block| match block {
            MarkdownBlockFfi::Paragraph { inlines } => inlines.iter().any(|inline| matches!(
                inline,
                MarkdownInlineFfi::Text { content } if content.contains("KEEP_THIS_SUMMARY")
            )),
            _ => false,
        }));
        let later = markdown_content_tokens(
            MARMOT_APP_EVENT_KIND_CHAT,
            "<details>\n    code\n<summary>ordinary later text</summary>\nbody\n</details>",
        );
        let MarkdownBlockFfi::Details { summary, body, .. } = &later.blocks[0] else {
            panic!("expected details");
        };
        assert!(summary.is_empty());
        assert!(body.iter().any(|block| match block {
            MarkdownBlockFfi::Paragraph { inlines } => inlines.iter().any(|inline| matches!(
                inline,
                MarkdownInlineFfi::Text { content }
                    if content.contains("<summary>ordinary later text</summary>")
            )),
            _ => false,
        }));
        let tokens = markdown_content_tokens(
            MARMOT_APP_EVENT_KIND_CHAT,
            "<details>\n<summary>`one\n</summary>\ntwo`</summary>\nbody\n</details>",
        );
        let MarkdownBlockFfi::Details { summary, .. } = &tokens.blocks[0] else {
            panic!("expected details tokens");
        };
        assert!(
            summary
                .iter()
                .any(|inline| matches!(inline, MarkdownInlineFfi::Code { .. }))
        );
        let hard = markdown_content_tokens(
            MARMOT_APP_EVENT_KIND_CHAT,
            "<details>\n<summary>one  \ntwo</summary>\nbody\n</details>",
        );
        let MarkdownBlockFfi::Details { summary, .. } = &hard.blocks[0] else {
            panic!("expected hard-break tokens");
        };
        assert!(
            summary
                .iter()
                .any(|inline| matches!(inline, MarkdownInlineFfi::HardBreak))
        );
    }
}
