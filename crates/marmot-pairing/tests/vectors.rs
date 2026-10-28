//! Known-answer vectors from `testdata/pairing_vectors.py`, an independent
//! implementation of the derivations, run through both state machines.

use cgka_traits::GroupId;
use marmot_pairing::{
    AccountKey, ConfirmSender, ExistingDeviceEvent, ExistingDevicePairing, KIND_PAIRING_ANSWER,
    KIND_PAIRING_CONFIRM, KIND_PAIRING_REQUEST, KIND_PAIRING_REVEAL, KeyPackageEventId,
    KeyPackageRef, NewDeviceConfirmation, NewDeviceEvent, NewDevicePairing, PairingMessage,
    PublishedKeyPackage, SAS_EMOJI, SessionId, SlotId, commitment,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("../testdata/pairing-v1.json");
const T0: u64 = 1_800_000_000;

fn bytes(vector: &Value, field: &str) -> Vec<u8> {
    hex::decode(vector[field].as_str().expect("hex field")).expect("valid hex")
}

fn array(vector: &Value, field: &str) -> [u8; 32] {
    bytes(vector, field).try_into().expect("32 bytes")
}

fn content(vector: &Value, message: &str) -> String {
    vector["content"][message]
        .as_str()
        .expect("content string")
        .to_owned()
}

#[test]
fn pairing_vectors_match_both_state_machines() {
    let file: Value = serde_json::from_str(VECTORS).expect("vector file parses");
    let vectors = file["vectors"].as_array().expect("vector list");
    assert!(!vectors.is_empty());
    for vector in vectors {
        let name = vector["name"].as_str().expect("name");
        let account = AccountKey::new(array(vector, "account"));
        let session_id = SessionId::new(array(vector, "session_id"));
        let key_package_event_id = KeyPackageEventId::new(array(vector, "key_package_event_id"));
        let key_package_ref =
            KeyPackageRef::new(bytes(vector, "key_package_ref")).expect("valid ref");
        let slot = SlotId::new(array(vector, "existing_device_slot"));
        let device_group_id = GroupId::new(bytes(vector, "device_group_id"));

        let (mut new, request) = NewDevicePairing::start_pinned(
            session_id,
            array(vector, "new_device_secret"),
            account,
            key_package_event_id,
            key_package_ref.clone(),
            T0,
        );
        assert_eq!(request.commitment, array(vector, "commitment"), "{name}");
        let request_message = PairingMessage::Request(request.clone());
        assert_eq!(
            request_message.to_content(),
            content(vector, "request"),
            "{name}"
        );
        assert_eq!(
            PairingMessage::from_content(KIND_PAIRING_REQUEST, &content(vector, "request")),
            Ok(request_message.clone()),
            "{name}"
        );
        assert_eq!(new.code(T0), None, "{name}: no code before an answer");

        let mut existing = ExistingDevicePairing::new(account, slot);
        assert_eq!(
            existing.receive(&request_message, T0, T0),
            ExistingDeviceEvent::Requested {
                session_id,
                competing: false
            },
            "{name}"
        );
        let answer = existing
            .answer_pinned(
                &session_id,
                &PublishedKeyPackage {
                    event_id: key_package_event_id,
                    key_package_ref: key_package_ref.clone(),
                },
                array(vector, "existing_device_secret"),
                T0,
            )
            .expect("answer");
        assert_eq!(
            answer.key.as_bytes(),
            &array(vector, "existing_device_key"),
            "{name}"
        );
        let answer_message = PairingMessage::Answer(answer);
        assert_eq!(
            answer_message.to_content(),
            content(vector, "answer"),
            "{name}"
        );
        assert_eq!(
            PairingMessage::from_content(KIND_PAIRING_ANSWER, &content(vector, "answer")),
            Ok(answer_message.clone()),
        );

        let NewDeviceEvent::Reveal(reveal) = new.receive(&answer_message, T0) else {
            panic!("{name}: expected a reveal");
        };
        assert_eq!(
            reveal.key.as_bytes(),
            &array(vector, "new_device_key"),
            "{name}"
        );
        assert_eq!(
            commitment(&reveal.key, &request.binding(account)),
            array(vector, "commitment"),
            "{name}"
        );
        let reveal_message = PairingMessage::Reveal(reveal);
        assert_eq!(
            reveal_message.to_content(),
            content(vector, "reveal"),
            "{name}"
        );
        assert_eq!(
            PairingMessage::from_content(KIND_PAIRING_REVEAL, &content(vector, "reveal")),
            Ok(reveal_message.clone()),
        );

        let code = new.code(T0).expect("code after the answer").clone();
        assert_eq!(
            code.bytes().as_slice(),
            bytes(vector, "sas_bytes"),
            "{name}"
        );
        let emoji: Vec<u64> = code.emoji_numbers().iter().map(|n| u64::from(*n)).collect();
        let expected_emoji: Vec<u64> = vector["emoji_numbers"]
            .as_array()
            .expect("emoji numbers")
            .iter()
            .map(|n| n.as_u64().expect("number"))
            .collect();
        assert_eq!(emoji, expected_emoji, "{name}");

        assert_eq!(
            existing.receive(&reveal_message, T0, T0),
            ExistingDeviceEvent::CodeReady { session_id },
            "{name}"
        );
        assert_eq!(
            existing.code(&session_id, T0),
            Some(&code),
            "{name}: same code"
        );

        // The new device's user taps first; its confirmation waits for the
        // existing device's.
        assert_eq!(
            new.confirm_match(T0),
            Ok(NewDeviceConfirmation::Waiting),
            "{name}"
        );
        let existing_confirm = existing
            .confirm_link(&session_id, device_group_id.clone(), T0)
            .expect("existing device confirms");
        assert_eq!(
            existing_confirm.mac,
            array(vector, "existing_device_mac"),
            "{name}"
        );
        assert_eq!(
            existing_confirm.sender,
            ConfirmSender::ExistingDevice {
                device_group_id: device_group_id.clone()
            }
        );
        let existing_confirm_message = PairingMessage::Confirm(existing_confirm);
        assert_eq!(
            existing_confirm_message.to_content(),
            content(vector, "existing_device_confirm"),
            "{name}"
        );

        let NewDeviceEvent::Linked {
            confirm: new_confirm,
            link: new_link,
        } = new.receive(&existing_confirm_message, T0)
        else {
            panic!("{name}: new device links");
        };
        assert_eq!(new_confirm.mac, array(vector, "new_device_mac"), "{name}");
        let new_confirm_message = PairingMessage::Confirm(new_confirm);
        assert_eq!(
            new_confirm_message.to_content(),
            content(vector, "new_device_confirm"),
            "{name}"
        );
        for (message, field) in [
            (&new_confirm_message, "new_device_confirm"),
            (&existing_confirm_message, "existing_device_confirm"),
        ] {
            assert_eq!(
                PairingMessage::from_content(KIND_PAIRING_CONFIRM, &content(vector, field))
                    .as_ref(),
                Ok(message),
                "{name}: {field}"
            );
        }

        let ExistingDeviceEvent::Linked(existing_link) =
            existing.receive(&new_confirm_message, T0, T0)
        else {
            panic!("{name}: existing device links");
        };
        assert_eq!(existing_link, new_link, "{name}: both hold the same link");
        assert_eq!(new_link.key_package_ref, key_package_ref, "{name}");
        assert_eq!(
            new_link.key_package_event_id, key_package_event_id,
            "{name}"
        );
        assert_eq!(new_link.device_group_id, device_group_id, "{name}");
        assert_eq!(new_link.existing_device_slot, slot, "{name}");
        assert!(new.accepts_welcome_for(&device_group_id), "{name}");
    }
}

/// The table equals Matrix's `sas-emoji.json`, by the digest the generator
/// computed from that file.
#[test]
fn pairing_emoji_table_matches_matrix_source() {
    let file: Value = serde_json::from_str(VECTORS).expect("vector file parses");
    let lines: String = SAS_EMOJI
        .iter()
        .map(|entry| {
            format!(
                "{}\t{}\t{}\t{}\n",
                entry.number, entry.emoji, entry.description, entry.unicode
            )
        })
        .collect();
    assert_eq!(
        hex::encode(Sha256::digest(lines.as_bytes())),
        file["emoji_table_sha256"].as_str().expect("digest")
    );
    for (index, entry) in SAS_EMOJI.iter().enumerate() {
        assert_eq!(usize::from(entry.number), index);
    }
    assert_eq!(SAS_EMOJI[0].description, "Dog");
    assert_eq!(SAS_EMOJI[63].description, "Pin");
}
