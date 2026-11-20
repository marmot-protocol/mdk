//! Marmot profile of NIP-22 thread messages carried in MLS app messages.
//!
//! A thread message is a kind-1111 comment whose first lowercase `e` tag names
//! the message it answers, its parent. Uppercase `E`/`K`/`P` tags name the
//! thread root. An inline reply is kind 9 with `e` + `q` and is never a thread
//! message. The contract, including the older forms MDK still reads, is in
//! `docs/marmot-architecture/overview/thread-messages.md`.

/// NIP-22 comment kind; Marmot uses it for thread messages.
pub const NIP22_COMMENT_KIND: u64 = 1111;

/// True when a kind-1111 event is a comment MDK projects like chat (parent
/// link, media, author edits, mentions). It needs a numeric `k` tag or a
/// lowercase `e` tag: White Noise Linux sent thread messages without `k` until
/// 2026-11-17, and those stay readable.
pub fn is_nip22_comment(kind: u64, tags: &[Vec<String>]) -> bool {
    kind == NIP22_COMMENT_KIND
        && tags
            .iter()
            .any(|tag| match tag.first().map(String::as_str) {
                Some("k") => tag.get(1).is_some_and(|kind| kind.parse::<u64>().is_ok()),
                Some("e") => true,
                _ => false,
            })
}

/// The parent a thread message answers: the value of a comment's first
/// lowercase `e` tag. That first `e` is authoritative even without a value,
/// and `q` is a body quote that never names the parent. `None` when the event
/// is not a thread message.
pub fn thread_message_parent(kind: u64, tags: &[Vec<String>]) -> Option<&str> {
    // A lowercase `e` alone makes a kind-1111 event a comment, so finding it
    // is the whole recognition check.
    if kind != NIP22_COMMENT_KIND {
        return None;
    }
    first_tag(tags, "e")
        .and_then(|tag| tag.get(1))
        .map(String::as_str)
}

/// A chat message in the Marmot sense: kind 9, or a thread message. Both
/// carry Markdown text and mentions, and both are chat activity.
pub fn is_chat_message(kind: u64, tags: &[Vec<String>]) -> bool {
    kind == crate::app_event::MARMOT_APP_EVENT_KIND_CHAT
        || thread_message_parent(kind, tags).is_some()
}

/// The thread root an event names with its first uppercase `E` tag.
pub fn thread_root_tag(tags: &[Vec<String>]) -> Option<&str> {
    first_tag(tags, "E")
        .and_then(|tag| tag.get(1))
        .map(String::as_str)
}

fn first_tag<'a>(tags: &'a [Vec<String>], name: &str) -> Option<&'a Vec<String>> {
    tags.iter()
        .find(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(rows: &[&[&str]]) -> Vec<Vec<String>> {
        rows.iter()
            .map(|row| row.iter().map(|value| (*value).to_owned()).collect())
            .collect()
    }

    #[test]
    fn recognizes_comments_by_numeric_k_or_lowercase_e() {
        assert!(is_nip22_comment(1111, &tags(&[&["k", "9"]])));
        assert!(is_nip22_comment(1111, &tags(&[&["e", "parent"]])));
        assert!(!is_nip22_comment(1111, &tags(&[&["k", "nine"]])));
        assert!(!is_nip22_comment(
            1111,
            &tags(&[&["E", "root"], &["q", "x"]])
        ));
        assert!(!is_nip22_comment(
            9,
            &tags(&[&["e", "parent"], &["k", "9"]])
        ));
    }

    #[test]
    fn parent_is_the_first_lowercase_e_even_without_a_value() {
        let full = tags(&[
            &["q", "quote"],
            &["E", "root"],
            &["e", "parent"],
            &["e", "other"],
        ]);
        assert_eq!(thread_message_parent(1111, &full), Some("parent"));
        assert_eq!(thread_root_tag(&full), Some("root"));
        let empty_first = tags(&[&["k", "9"], &["e"], &["e", "later"]]);
        assert_eq!(thread_message_parent(1111, &empty_first), None);
        assert_eq!(thread_message_parent(9, &full), None);
    }

    #[test]
    fn chat_messages_are_kind_9_and_thread_messages() {
        assert!(is_chat_message(9, &[]));
        assert!(is_chat_message(1111, &tags(&[&["e", "parent"]])));
        assert!(!is_chat_message(1111, &tags(&[&["k", "9"]])));
        assert!(!is_chat_message(1068, &tags(&[&["e", "parent"]])));
    }
}
