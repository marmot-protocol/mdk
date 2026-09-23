//! Stateless verification for public Nostr events consumed outside MDK relay ingestion.
//!
//! This uses the same Rust Nostr/libsecp256k1 stack as MDK's transport path.
//! It does not require an account, runtime, relay connection, or secret key.

use nostr::secp256k1::{Message, SECP256K1, XOnlyPublicKey, schnorr::Signature};
use nostr::{Event, JsonUtil};

/// Verify a BIP-340 signature over an already computed 32-byte message digest.
/// Malformed hex, lengths, public keys, and signatures fail closed.
pub fn verify_bip340_signature(
    public_key_hex: &str,
    message_hex: &str,
    signature_hex: &str,
) -> bool {
    if public_key_hex.len() != 64 || message_hex.len() != 64 || signature_hex.len() != 128 {
        return false;
    }
    let Ok(public_key) = hex::decode(public_key_hex) else {
        return false;
    };
    let Ok(message) = hex::decode(message_hex) else {
        return false;
    };
    let Ok(signature) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(message) = <[u8; 32]>::try_from(message.as_slice()) else {
        return false;
    };
    let Ok(public_key) = XOnlyPublicKey::from_slice(&public_key) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&signature) else {
        return false;
    };
    SECP256K1
        .verify_schnorr(&signature, &Message::from_digest(message), &public_key)
        .is_ok()
}

/// Verify a public Nostr event's canonical ID and BIP-340 signature.
/// Parsing never grants trust: both checks run after deserialization. The
/// caller remains responsible for application-specific kind, author, and tag
/// policy, and should bound any untrusted network body before passing it here.
pub fn verify_public_nostr_event_json(event_json: &str) -> bool {
    Event::from_json(event_json).is_ok_and(|event| event.verify().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Kind};

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
            .sign_with_keys(&Keys::generate())
            .unwrap();
        let json = event.as_json();
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
