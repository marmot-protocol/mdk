//! Stateless verification for public Nostr events consumed outside MDK relay ingestion.
//!
//! This uses the same Rust Nostr/libsecp256k1 stack as MDK's transport path.
//! It does not require an account, runtime, relay connection, or secret key.

use nostr::prelude::Event;

// The digest-only verifier is retained for the BIP-340 reference vectors, not
// exported to hosts: public-event consumers must also verify the canonical ID.
#[cfg(test)]
fn verify_bip340_signature(public_key_hex: &str, message_hex: &str, signature_hex: &str) -> bool {
    use secp256k1::{Secp256k1, XOnlyPublicKey, schnorr::Signature};

    let (mut public_key, mut message, mut signature) = ([0u8; 32], [0u8; 32], [0u8; 64]);
    if hex::decode_to_slice(public_key_hex, &mut public_key).is_err()
        || hex::decode_to_slice(message_hex, &mut message).is_err()
        || hex::decode_to_slice(signature_hex, &mut signature).is_err()
    {
        return false;
    }
    let (Ok(public_key), Ok(signature)) = (
        XOnlyPublicKey::from_slice(&public_key),
        Signature::from_slice(&signature),
    ) else {
        return false;
    };
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &public_key)
        .is_ok()
}

/// Verify a public Nostr event's canonical ID and BIP-340 signature.
/// Parsing never grants trust: both checks run after deserialization. The
/// caller remains responsible for application-specific kind, author, and tag
/// policy, and should bound any untrusted network body before passing it here.
pub fn verify_public_nostr_event_json(event_json: &str) -> bool {
    serde_json::from_str::<Event>(event_json).is_ok_and(|event| event.verify().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind};

    #[test]
    fn bip340_reference_vectors_and_malformed_inputs_fail_closed() {
        let mut tested = 0;
        for line in include_str!("../tests/fixtures/bip340_vectors_0_14.csv").lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split(',').collect();
            assert_eq!(fields.len(), 5);
            assert_eq!(
                verify_bip340_signature(fields[1], fields[2], fields[3]),
                fields[4] == "TRUE",
                "BIP-340 vector {}",
                fields[0]
            );
            tested += 1;
        }
        assert_eq!(tested, 15, "all fixed-width official vectors must run");
        let positive = include_str!("../tests/fixtures/bip340_vectors_0_14.csv")
            .lines()
            .find(|line| line.starts_with("0,"))
            .unwrap();
        let fields: Vec<&str> = positive.split(',').collect();
        assert!(!verify_bip340_signature("zz", fields[2], fields[3]));
        assert!(!verify_bip340_signature(fields[1], "00", fields[3]));
        assert!(!verify_bip340_signature(fields[1], fields[2], "gg"));
        assert!(!verify_bip340_signature(
            &fields[1][..fields[1].len() - 2],
            fields[2],
            fields[3]
        ));
        assert!(!verify_bip340_signature(
            fields[1],
            fields[2],
            &fields[3][..fields[3].len() - 2]
        ));
    }

    #[test]
    fn public_event_verification_checks_id_and_signature() {
        let event = EventBuilder::new(Kind::TextNote, "public event")
            .finalize(&Keys::generate())
            .unwrap();
        let json = serde_json::to_string(&event).unwrap();
        assert!(verify_public_nostr_event_json(&json));

        let mut changed: serde_json::Value = serde_json::from_str(&json).unwrap();
        changed["content"] = "mutated".into();
        assert!(!verify_public_nostr_event_json(&changed.to_string()));

        let mut changed: serde_json::Value = serde_json::from_str(&json).unwrap();
        changed["id"] = "00".repeat(32).into();
        assert!(!verify_public_nostr_event_json(&changed.to_string()));

        let mut changed: serde_json::Value = serde_json::from_str(&json).unwrap();
        changed["sig"] = "00".repeat(64).into();
        assert!(!verify_public_nostr_event_json(&changed.to_string()));

        let mut changed: serde_json::Value = serde_json::from_str(&json).unwrap();
        changed["pubkey"] = "00".repeat(32).into();
        assert!(!verify_public_nostr_event_json(&changed.to_string()));

        assert!(!verify_public_nostr_event_json("not json"));
        assert!(!verify_public_nostr_event_json("{}"));
        assert!(!verify_public_nostr_event_json(""));
    }
}
