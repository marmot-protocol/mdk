//! Nostr secret-key shape classification shared across CLI, UniFFI, and runtime.

/// Returns true when `value` has the reserved Nostr secret-key prefix.
///
/// The four-character `nsec` prefix is matched case-insensitively so argv and
/// FFI inputs cannot bypass secret rejection by varying ASCII case. This is a
/// conservative secret-shape classifier, not full bech32 validation.
pub fn is_nostr_secret(value: &str) -> bool {
    value
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("nsec"))
}

#[cfg(test)]
mod tests {
    use super::is_nostr_secret;

    #[test]
    fn rejects_non_nsec_prefix() {
        assert!(!is_nostr_secret("npub1example"));
        assert!(!is_nostr_secret("nse"));
        assert!(!is_nostr_secret(""));
    }

    #[test]
    fn accepts_nsec_prefix_case_insensitively() {
        assert!(is_nostr_secret("nsec1example"));
        assert!(is_nostr_secret("NSEC1EXAMPLE"));
        assert!(is_nostr_secret("NsEc1example"));
    }
}
