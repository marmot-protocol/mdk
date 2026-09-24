//! Stateless public-event verification for Swift and Kotlin hosts.

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
    use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind};

    #[test]
    fn binding_accepts_valid_public_event_and_rejects_tampering() {
        let event = EventBuilder::new(Kind::TextNote, "public event")
            .finalize(&Keys::generate())
            .unwrap();
        let json = event.as_json();
        assert!(verify_public_nostr_event_json(json.clone()));
        let mut changed: serde_json::Value = serde_json::from_str(&json).unwrap();
        changed["content"] = "tampered".into();
        assert!(!verify_public_nostr_event_json(changed.to_string()));
    }

    #[test]
    fn malformed_inputs_fail_closed() {
        assert!(!verify_public_nostr_event_json("{}".into()));
    }
}
