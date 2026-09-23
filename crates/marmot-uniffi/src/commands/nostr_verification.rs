//! Stateless public-event verification for Swift and Kotlin hosts.

/// Verify a BIP-340 signature over an already computed 32-byte digest.
/// Invalid hex, lengths, keys, and signatures return false.
#[uniffi::export]
pub fn verify_bip340_signature(
    public_key_hex: String,
    message_hex: String,
    signature_hex: String,
) -> bool {
    marmot_app::verify_bip340_signature(&public_key_hex, &message_hex, &signature_hex)
}

/// Verify both the canonical ID and BIP-340 signature of a public Nostr event.
/// This requires no account, runtime, or secret key. Callers remain responsible
/// for author, kind, and tag policy and for bounding untrusted JSON input.
#[uniffi::export]
pub fn verify_public_nostr_event_json(event_json: String) -> bool {
    marmot_app::verify_public_nostr_event_json(&event_json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, JsonUtil, Keys, Kind};

    #[test]
    fn binding_accepts_valid_public_event_and_rejects_tampering() {
        let event = EventBuilder::new(Kind::TextNote, "public event")
            .sign_with_keys(&Keys::generate())
            .unwrap();
        let json = event.as_json();
        assert!(verify_public_nostr_event_json(json.clone()));
        let mut changed: serde_json::Value = serde_json::from_str(&json).unwrap();
        changed["content"] = "tampered".into();
        assert!(!verify_public_nostr_event_json(changed.to_string()));
    }

    #[test]
    fn malformed_inputs_fail_closed() {
        assert!(!verify_bip340_signature(
            "bad".into(),
            "00".into(),
            "bad".into()
        ));
        assert!(!verify_public_nostr_event_json("{}".into()));
    }
}
