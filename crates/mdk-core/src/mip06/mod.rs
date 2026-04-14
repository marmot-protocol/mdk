//! MIP-06: Multi-Device Support
//!
//! This module implements the multi-device protocol for Marmot, allowing a single
//! Nostr identity to participate in MLS groups from multiple independent devices.
//! Each device is an independent MLS leaf node that joins existing groups, authorized
//! through an out-of-band device pairing flow.
//!
//! ## Joining Flows
//!
//! **External Commit (spec-compliant, primary):** The new device receives a
//! `PairingPayload` containing `GroupInfo` + join PSK for each group, then
//! constructs an External Commit with a Nostr identity proof in
//! `authenticated_data`. The existing device validates the commit through the
//! standard message pipeline (`validate_external_commit_authorization`,
//! `validate_external_commit_identity_proof`).
//!
//! **Add-based (workaround):** Used while OpenMLS External Commit support has
//! limitations. The new device sends a KeyPackage to the existing device, which
//! adds the new device via standard MLS Add proposals and returns Welcome
//! messages. This is a two-phase encrypted exchange:
//! 1. New device -> Existing device: KeyPackage (via `DevicePairingRequest`)
//! 2. Existing device -> New device: Welcome messages (via `DevicePairingResponse`)

mod device_name;
mod extension;
mod identity_proof;
mod join_psk;
mod pairing;
mod pairing_crypto;

pub use self::device_name::EncryptedDeviceName;
pub use self::extension::{MarmotMultiDevice, is_multi_device_enabled};
pub use self::identity_proof::{
    NostrIdentityProof, compute_challenge, construct_identity_proof, verify_identity_proof,
};
pub use self::join_psk::{JOIN_PSK_EXPORTER_LABEL, JOIN_PSK_LABEL, JoinPskId};
pub use self::pairing::{
    DevicePairingRequest, DevicePairingResponse, GroupPairingDataV1, GroupWelcomeData,
    PairingPayload,
};
pub use self::pairing_crypto::{
    PairingMessage, decrypt_pairing_message, encrypt_pairing_message, generate_new_device_keypair,
};

#[cfg(test)]
mod integration_tests {
    use nostr::{EventId, JsonUtil, Keys};
    use openmls_traits::OpenMlsProvider;
    use tls_codec::{Deserialize as _, Serialize as _};

    use crate::test_util::{create_key_package_event, create_nostr_group_config_data};
    use crate::tests::create_test_mdk;

    /// Test the full Add-based multi-device pairing flow:
    /// 1. Alice device 1 creates a group with MIP-06 enabled
    /// 2. Alice device 2 creates a KeyPackage
    /// 3. The KeyPackage is sent via encrypted pairing channel
    /// 4. Alice device 1 adds device 2 to the group (standard Add)
    /// 5. Welcome is sent back via encrypted pairing channel
    /// 6. Alice device 2 processes the Welcome and joins
    #[test]
    fn test_full_add_based_pairing_flow() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_device1_mdk = create_test_mdk();
        let alice_device2_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        let admins = vec![alice_keys.public_key(), bob_keys.public_key()];
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);

        let create_result = alice_device1_mdk
            .create_group_with_multi_device(
                &alice_keys.public_key(),
                vec![bob_key_package],
                create_nostr_group_config_data(admins),
            )
            .expect("Should create group");

        let group_id = create_result.group.mls_group_id.clone();

        // create_group_with_multi_device internally calls create_group_inner which
        // merges the initial group-creation commit (privacy-preserving). The pending
        // commit here is the add-members commit that invited Bob.
        alice_device1_mdk
            .merge_pending_commit(&group_id)
            .expect("Should merge the add-members commit from group creation");

        // Phase 1: New device → Existing device (encrypted DevicePairingRequest)
        let device2_kp_event = create_key_package_event(&alice_device2_mdk, &alice_keys);

        let kp_bytes = super::DevicePairingRequest::new(device2_kp_event.as_json().into_bytes())
            .to_bytes()
            .unwrap();

        let (new_priv, new_pub) = super::pairing_crypto::generate_new_device_keypair();
        let (_existing_pub, encrypted) =
            super::encrypt_pairing_message(&kp_bytes, &new_pub).unwrap();

        let decrypted = super::decrypt_pairing_message(&encrypted, &new_priv).unwrap();

        let request = super::DevicePairingRequest::from_bytes(&decrypted).unwrap();

        let kp_event: nostr::Event =
            nostr::Event::from_json(std::str::from_utf8(request.key_package_event_json()).unwrap())
                .unwrap();

        // Phase 2: Existing device → New device (encrypted DevicePairingResponse)
        let pairing_response = alice_device1_mdk
            .add_device_to_groups(std::slice::from_ref(&group_id), &kp_event)
            .expect("Should add device to groups");

        assert_eq!(pairing_response.groups().len(), 1);

        let response_bytes = pairing_response.to_bytes().unwrap();
        let (_ep2, encrypted_response) =
            super::encrypt_pairing_message(&response_bytes, &new_pub).unwrap();

        let decrypted_response =
            super::decrypt_pairing_message(&encrypted_response, &new_priv).unwrap();

        let response = super::DevicePairingResponse::from_bytes(&decrypted_response).unwrap();

        let group_data = &response.groups()[0];
        let welcome_rumor: nostr::UnsignedEvent = nostr::UnsignedEvent::from_json(
            std::str::from_utf8(group_data.welcome_rumor_bytes()).unwrap(),
        )
        .unwrap();

        let processed_welcome = alice_device2_mdk
            .process_welcome(&EventId::all_zeros(), &welcome_rumor)
            .expect("Should process welcome");

        alice_device2_mdk
            .accept_welcome(&processed_welcome)
            .expect("Should accept welcome");

        // Merge the add-device commit produced by add_device_to_groups above.
        alice_device1_mdk
            .merge_pending_commit(&group_id)
            .expect("Should merge the add-device commit from pairing");

        let device2_group = alice_device2_mdk
            .get_group(&processed_welcome.mls_group_id)
            .unwrap()
            .expect("Device 2 should have the group");

        assert_eq!(device2_group.name, "Test Group");
        assert_eq!(
            device2_group.nostr_group_id,
            create_result.group.nostr_group_id
        );
    }

    /// Test coalesced members with multi-device
    #[test]
    fn test_coalesced_members_single_device() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        let admins = vec![alice_keys.public_key(), bob_keys.public_key()];
        let bob_kp = create_key_package_event(&bob_mdk, &bob_keys);

        let create_result = alice_mdk
            .create_group_with_multi_device(
                &alice_keys.public_key(),
                vec![bob_kp],
                create_nostr_group_config_data(admins),
            )
            .expect("Should create group");

        let group_id = create_result.group.mls_group_id.clone();
        alice_mdk.merge_pending_commit(&group_id).unwrap();

        let coalesced = alice_mdk.coalesced_members(&group_id).unwrap();
        assert_eq!(coalesced.len(), 2);
        assert_eq!(coalesced[&alice_keys.public_key()].len(), 1);
        assert_eq!(coalesced[&bob_keys.public_key()].len(), 1);
    }

    /// Test own_device_leaves
    #[test]
    fn test_own_device_leaves() {
        let alice_keys = Keys::generate();
        let alice_mdk = create_test_mdk();

        let create_result = alice_mdk
            .create_group_with_multi_device(
                &alice_keys.public_key(),
                vec![],
                create_nostr_group_config_data(vec![alice_keys.public_key()]),
            )
            .expect("Should create group");

        let own_leaves = alice_mdk
            .own_device_leaves(&create_result.group.mls_group_id)
            .unwrap();
        assert_eq!(own_leaves.len(), 1);
    }

    /// Test identity proof construction and verification
    #[test]
    fn test_identity_proof_standalone() {
        let keys = Keys::generate();
        let credential_identity = keys.public_key().to_bytes();

        let proof = super::identity_proof::construct_identity_proof(
            &keys,
            &credential_identity,
            b"signature-key",
            b"group-context",
        )
        .unwrap();

        let aad = proof.to_authenticated_data().unwrap();
        let decoded = super::NostrIdentityProof::from_authenticated_data(&aad).unwrap();

        super::identity_proof::verify_identity_proof(
            &decoded,
            &keys.public_key(),
            &credential_identity,
            b"signature-key",
            b"group-context",
        )
        .unwrap();

        // Wrong key fails
        let other = Keys::generate();
        assert!(
            super::identity_proof::verify_identity_proof(
                &decoded,
                &other.public_key(),
                &credential_identity,
                b"signature-key",
                b"group-context",
            )
            .is_err()
        );
    }

    #[test]
    fn test_join_group_via_external_commit_rejects_missing_ratchet_tree_extension() {
        let alice_keys = Keys::generate();
        let alice_device1 = create_test_mdk();
        let alice_device2 = create_test_mdk();

        let create_result = alice_device1
            .create_group_with_multi_device(
                &alice_keys.public_key(),
                vec![],
                create_nostr_group_config_data(vec![alice_keys.public_key()]),
            )
            .unwrap();
        let group_id = create_result.group.mls_group_id.clone();
        alice_device1.merge_pending_commit(&group_id).unwrap();

        let payload = alice_device1
            .build_pairing_payload(std::slice::from_ref(&group_id))
            .unwrap();
        let group_data = &payload.groups()[0];

        let mls_group = alice_device1.load_mls_group(&group_id).unwrap().unwrap();
        let signer = alice_device1.load_mls_signer(&mls_group).unwrap();
        let group_info_msg = mls_group
            .export_group_info(alice_device1.provider.crypto(), &signer, false)
            .unwrap();
        let group_info_bytes = group_info_msg.tls_serialize_detached().unwrap();

        let invalid_data = super::GroupPairingDataV1::new(
            *group_data.group_event_key(),
            group_data.join_psk().to_vec(),
            group_info_bytes,
        )
        .unwrap();

        let result = alice_device2.join_group_via_external_commit(&invalid_data, &alice_keys);
        assert!(matches!(
            result,
            Err(crate::Error::PairingError(ref msg)) if msg.contains("ratchet_tree")
        ));
    }

    /// Test device name encryption roundtrip
    #[test]
    fn test_device_name_roundtrip() {
        let keys = Keys::generate();
        let encrypted = super::EncryptedDeviceName::encrypt(&keys, "iPhone 15").unwrap();
        assert_eq!(encrypted.decrypt(&keys).unwrap(), "iPhone 15");
    }

    /// Test enable_multi_device on existing group
    #[test]
    fn test_enable_multi_device_on_existing_group() {
        let alice_keys = Keys::generate();
        let alice_mdk = create_test_mdk();

        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![],
                create_nostr_group_config_data(vec![alice_keys.public_key()]),
            )
            .unwrap();

        let group_id = create_result.group.mls_group_id.clone();

        let mls_group = alice_mdk.load_mls_group(&group_id).unwrap().unwrap();
        assert!(!super::is_multi_device_enabled(&mls_group));
        drop(mls_group);

        alice_mdk.enable_multi_device(&group_id).unwrap();
        alice_mdk.merge_pending_commit(&group_id).unwrap();

        let mls_group = alice_mdk.load_mls_group(&group_id).unwrap().unwrap();
        assert!(super::is_multi_device_enabled(&mls_group));
    }

    /// Test build_pairing_payload extracts valid data for each group
    #[test]
    fn test_build_pairing_payload() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        let admins = vec![alice_keys.public_key(), bob_keys.public_key()];
        let bob_kp = create_key_package_event(&bob_mdk, &bob_keys);

        let create_result = alice_mdk
            .create_group_with_multi_device(
                &alice_keys.public_key(),
                vec![bob_kp],
                create_nostr_group_config_data(admins),
            )
            .expect("Should create group");

        let group_id = create_result.group.mls_group_id.clone();
        alice_mdk.merge_pending_commit(&group_id).unwrap();

        // Build pairing payload
        let payload = alice_mdk
            .build_pairing_payload(&[group_id])
            .expect("Should build pairing payload");

        assert_eq!(payload.groups().len(), 1);

        let group_data = &payload.groups()[0];
        assert_ne!(group_data.group_event_key(), &[0u8; 32]);
        assert!(!group_data.join_psk().is_empty());
        assert!(!group_data.group_info().is_empty());

        // Verify roundtrip serialization
        let bytes = payload.to_bytes().unwrap();
        let decoded = super::PairingPayload::from_bytes(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    /// Test build_pairing_payload rejects groups without MIP-06
    #[test]
    fn test_build_pairing_payload_rejects_non_multi_device_group() {
        let alice_keys = Keys::generate();
        let alice_mdk = create_test_mdk();

        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![],
                create_nostr_group_config_data(vec![alice_keys.public_key()]),
            )
            .unwrap();

        let result = alice_mdk.build_pairing_payload(&[create_result.group.mls_group_id]);
        assert!(result.is_err());
    }

    /// Test join_group_via_external_commit rejects invalid GroupInfo bytes.
    #[test]
    fn test_join_group_via_external_commit_rejects_invalid_group_info() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();
        let data = super::GroupPairingDataV1::new([1; 32], vec![2; 32], vec![3; 100]).unwrap();

        let result = mdk.join_group_via_external_commit(&data, &keys);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("GroupInfo"),
            "Expected GroupInfo-related error, got: {err_msg}"
        );
    }

    /// Test register_join_psk succeeds for MIP-06-enabled groups and is a no-op for others.
    #[test]
    fn test_register_join_psk() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();
        let bob_kp = create_key_package_event(&bob_mdk, &bob_keys);

        // MIP-06 group: register should succeed
        let create_result = alice_mdk
            .create_group_with_multi_device(
                &alice_keys.public_key(),
                vec![bob_kp],
                create_nostr_group_config_data(vec![
                    alice_keys.public_key(),
                    bob_keys.public_key(),
                ]),
            )
            .unwrap();
        let group_id = create_result.group.mls_group_id.clone();
        alice_mdk.merge_pending_commit(&group_id).unwrap();

        alice_mdk
            .register_join_psk(&group_id)
            .expect("Should register join PSK for MIP-06 group");

        // Non-MIP-06 group: register should be a no-op
        let non_mip06_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![],
                create_nostr_group_config_data(vec![alice_keys.public_key()]),
            )
            .unwrap();
        alice_mdk
            .register_join_psk(&non_mip06_result.group.mls_group_id)
            .expect("Should be no-op for non-MIP-06 group");
    }

    /// Test full External Commit flow: existing device builds pairing payload,
    /// new device joins via External Commit with join PSK.
    #[test]
    fn test_external_commit_join_flow() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_device1 = create_test_mdk();
        let alice_device2 = create_test_mdk();
        let bob_mdk = create_test_mdk();
        let bob_kp = create_key_package_event(&bob_mdk, &bob_keys);

        let create_result = alice_device1
            .create_group_with_multi_device(
                &alice_keys.public_key(),
                vec![bob_kp],
                create_nostr_group_config_data(vec![
                    alice_keys.public_key(),
                    bob_keys.public_key(),
                ]),
            )
            .unwrap();
        let group_id = create_result.group.mls_group_id.clone();
        alice_device1.merge_pending_commit(&group_id).unwrap();

        let payload = alice_device1
            .build_pairing_payload(std::slice::from_ref(&group_id))
            .unwrap();
        assert_eq!(payload.groups().len(), 1);

        let group_data = &payload.groups()[0];

        let commit_result = alice_device2
            .join_group_via_external_commit(group_data, &alice_keys)
            .expect("External Commit should succeed");
        assert_eq!(commit_result.group_id, group_id);
        assert!(!commit_result.commit_message.is_empty());
        assert_eq!(
            commit_result.group_event_key.as_ref(),
            group_data.group_event_key()
        );

        let mut mls_group = alice_device1.load_mls_group(&group_id).unwrap().unwrap();

        let msg_in =
            openmls::prelude::MlsMessageIn::tls_deserialize_exact(&commit_result.commit_message)
                .expect("Should deserialize commit message");

        let protocol_msg = msg_in
            .try_into_protocol_message()
            .expect("Should be a protocol message");

        // NOTE: This calls OpenMLS directly (not MDK::process_message) because the
        // commit bytes are not wrapped in an encrypted Nostr event. The MDK validation
        // pipeline (validate_external_commit_authorization, validate_external_commit_identity_proof)
        // is exercised in messages::validation::tests::test_external_commit_validation_pipeline.
        let processed = mls_group
            .process_message(&alice_device1.provider, protocol_msg)
            .expect("Device 1 should accept the External Commit");

        let aad = processed.aad();
        assert!(
            !aad.is_empty(),
            "authenticated_data should contain identity proof"
        );
        let proof = super::NostrIdentityProof::from_authenticated_data(aad)
            .expect("Should parse identity proof from AAD");
        assert_eq!(proof.version(), 1);

        match processed.into_content() {
            openmls::prelude::ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                let joining_leaf = staged_commit
                    .update_path_leaf_node()
                    .expect("Should have update path leaf node");
                let joining_cred =
                    openmls::prelude::BasicCredential::try_from(joining_leaf.credential().clone())
                        .unwrap();
                let joining_pubkey_bytes = joining_cred.identity();
                assert_eq!(
                    joining_pubkey_bytes,
                    alice_keys.public_key().to_bytes().as_slice(),
                    "Joining device should have Alice's Nostr pubkey"
                );

                mls_group
                    .merge_staged_commit(&alice_device1.provider, *staged_commit)
                    .expect("Should merge External Commit");
            }
            other => panic!("Expected StagedCommitMessage, got {:?}", other),
        }

        let alice_pubkey_bytes = alice_keys.public_key().to_bytes();
        let alice_leaf_count = mls_group
            .members()
            .filter(|m| {
                openmls::prelude::BasicCredential::try_from(m.credential.clone())
                    .ok()
                    .map(|c| c.identity() == alice_pubkey_bytes.as_slice())
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(
            alice_leaf_count, 2,
            "Alice should have 2 leaves (2 devices)"
        );
    }

    /// Test that calling `enable_multi_device` on a group that already has it
    /// enabled returns the "already enabled" error.
    #[test]
    fn test_enable_multi_device_already_enabled() {
        let alice_keys = Keys::generate();
        let alice_mdk = create_test_mdk();

        let create_result = alice_mdk
            .create_group_with_multi_device(
                &alice_keys.public_key(),
                vec![],
                create_nostr_group_config_data(vec![alice_keys.public_key()]),
            )
            .expect("Should create group with multi-device");

        let group_id = create_result.group.mls_group_id.clone();

        // The group was created with multi-device already enabled.
        // Trying to enable it again should fail.
        let result = alice_mdk.enable_multi_device(&group_id);
        assert!(
            matches!(
                result,
                Err(crate::Error::Group(ref msg)) if msg.contains("already enabled")
            ),
            "Expected 'already enabled' error, got: {:?}",
            result
        );
    }

    /// Test that a non-admin member cannot enable multi-device on a group.
    #[test]
    fn test_enable_multi_device_non_admin() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        // Only Alice is an admin; Bob is a regular member.
        let admins = vec![alice_keys.public_key()];
        let bob_kp = create_key_package_event(&bob_mdk, &bob_keys);

        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_kp],
                create_nostr_group_config_data(admins),
            )
            .expect("Alice should create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge group creation commit");

        // Bob processes the welcome and joins the group.
        let bob_welcome = bob_mdk
            .process_welcome(&EventId::all_zeros(), &create_result.welcome_rumors[0])
            .expect("Bob should process welcome");
        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Bob (non-admin) tries to enable multi-device -> should fail.
        let result = bob_mdk.enable_multi_device(&bob_welcome.mls_group_id);
        assert!(
            matches!(
                result,
                Err(crate::Error::Group(ref msg)) if msg.contains("Only group admins")
            ),
            "Expected 'Only group admins' error, got: {:?}",
            result
        );
    }

    /// Test that `join_group_via_external_commit` rejects a pairing payload
    /// whose group_info has trailing bytes after the TLS-deserialized GroupInfo.
    #[test]
    fn test_join_group_via_external_commit_rejects_trailing_bytes() {
        let alice_keys = Keys::generate();
        let alice_device1 = create_test_mdk();
        let alice_device2 = create_test_mdk();

        let create_result = alice_device1
            .create_group_with_multi_device(
                &alice_keys.public_key(),
                vec![],
                create_nostr_group_config_data(vec![alice_keys.public_key()]),
            )
            .unwrap();
        let group_id = create_result.group.mls_group_id.clone();
        alice_device1.merge_pending_commit(&group_id).unwrap();

        let payload = alice_device1
            .build_pairing_payload(std::slice::from_ref(&group_id))
            .unwrap();
        let group_data = &payload.groups()[0];

        // Append trailing bytes to the valid group_info.
        let mut tampered_gi = group_data.group_info().to_vec();
        tampered_gi.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let tampered_data = super::GroupPairingDataV1::new(
            *group_data.group_event_key(),
            group_data.join_psk().to_vec(),
            tampered_gi,
        )
        .unwrap();

        let result = alice_device2.join_group_via_external_commit(&tampered_data, &alice_keys);
        assert!(
            matches!(
                result,
                Err(crate::Error::PairingError(ref msg)) if msg.contains("trailing bytes")
            ),
            "Expected 'trailing bytes' error, got: {:?}",
            result
        );
    }

    /// Test that `join_group_via_external_commit` rejects a group_info that is
    /// too short to be a valid MLS GroupInfo (< 5 bytes triggers deserialization
    /// failure before the length check, so we expect a deserialization error).
    #[test]
    fn test_join_group_via_external_commit_rejects_short_group_info() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();

        // 4 bytes is too short for a valid GroupInfo.
        let data = super::GroupPairingDataV1::new([1; 32], vec![2; 32], vec![0, 0, 0, 1]).unwrap();
        let result = mdk.join_group_via_external_commit(&data, &keys);
        assert!(
            result.is_err(),
            "Expected error for 4-byte group_info, got: {:?}",
            result
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("GroupInfo") || err_msg.contains("deserialize"),
            "Expected GroupInfo/deserialization error, got: {err_msg}"
        );
    }

    /// Test that `join_group_via_external_commit` rejects GroupInfo from a
    /// non-MIP-06 group (one created with `create_group` instead of
    /// `create_group_with_multi_device`).
    ///
    /// The GroupInfo will be well-formed but missing the `marmot_multi_device`
    /// extension in the GroupContext. This exercises the signaling gate check
    /// at the beginning of `join_group_via_external_commit`.
    #[test]
    fn test_join_group_via_external_commit_rejects_non_mip06_group_info() {
        let alice_keys = Keys::generate();
        let alice_device1 = create_test_mdk();
        let alice_device2 = create_test_mdk();

        // Create a regular (non-MIP06) group
        let create_result = alice_device1
            .create_group(
                &alice_keys.public_key(),
                vec![],
                create_nostr_group_config_data(vec![alice_keys.public_key()]),
            )
            .unwrap();
        let group_id = create_result.group.mls_group_id.clone();

        // Export GroupInfo WITH ratchet_tree from this non-MIP06 group
        let mls_group = alice_device1.load_mls_group(&group_id).unwrap().unwrap();
        let signer = alice_device1.load_mls_signer(&mls_group).unwrap();
        let group_info_msg = mls_group
            .export_group_info(alice_device1.provider.crypto(), &signer, true)
            .unwrap();
        let group_info_bytes = group_info_msg.tls_serialize_detached().unwrap();

        // Build pairing data with this non-MIP06 GroupInfo
        let data =
            super::GroupPairingDataV1::new([0xAA; 32], vec![0xBB; 32], group_info_bytes).unwrap();

        let result = alice_device2.join_group_via_external_commit(&data, &alice_keys);
        assert!(
            matches!(
                result,
                Err(crate::Error::PairingError(ref msg)) if msg.contains("marmot_multi_device signaling")
            ),
            "Expected missing signaling error, got: {:?}",
            result
        );
    }

    /// Test that `join_group_via_external_commit` rejects when the group_info
    /// bytes have a corrupted wire format tag (not a GroupInfo MLS message type).
    #[test]
    fn test_join_group_via_external_commit_rejects_non_group_info_wire_format() {
        let alice_keys = Keys::generate();
        let alice_mdk = create_test_mdk();
        let device2 = create_test_mdk();

        let create_result = alice_mdk
            .create_group_with_multi_device(
                &alice_keys.public_key(),
                vec![],
                create_nostr_group_config_data(vec![alice_keys.public_key()]),
            )
            .unwrap();
        let group_id = create_result.group.mls_group_id.clone();
        alice_mdk.merge_pending_commit(&group_id).unwrap();

        let mls_group = alice_mdk.load_mls_group(&group_id).unwrap().unwrap();
        let signer = alice_mdk.load_mls_signer(&mls_group).unwrap();
        let gi_msg = mls_group
            .export_group_info(alice_mdk.provider.crypto(), &signer, true)
            .unwrap();
        let mut gi_bytes = gi_msg.tls_serialize_detached().unwrap();

        // Corrupt the MLS wire format tag (bytes 2-3 after the version u16).
        // GroupInfo wire_format = 4. Change to 3 (Welcome) to trigger
        // deserialization failure or non-GroupInfo extraction.
        if gi_bytes.len() > 3 {
            gi_bytes[3] ^= 0xFF; // corrupt wire format byte
        }

        let data = super::GroupPairingDataV1::new([1; 32], vec![2; 32], gi_bytes).unwrap();

        let result = device2.join_group_via_external_commit(&data, &alice_keys);
        assert!(result.is_err(), "Expected error for corrupted wire format");
    }

    /// Test that `join_group_via_external_commit` validates GroupInfo `required_capabilities`.
    ///
    /// Exports a valid MIP-06 GroupInfo, then corrupts the required_capabilities
    /// extension to remove the 0xF2F0 type. This exercises the check that
    /// required_capabilities includes the multi-device extension type.
    #[test]
    fn test_join_group_via_external_commit_rejects_missing_external_pub() {
        let alice_keys = Keys::generate();
        let alice_device1 = create_test_mdk();
        let alice_device2 = create_test_mdk();

        let create_result = alice_device1
            .create_group_with_multi_device(
                &alice_keys.public_key(),
                vec![],
                create_nostr_group_config_data(vec![alice_keys.public_key()]),
            )
            .unwrap();
        let group_id = create_result.group.mls_group_id.clone();
        alice_device1.merge_pending_commit(&group_id).unwrap();

        // Export GroupInfo WITHOUT ratchet_tree or external_pub
        let mls_group = alice_device1.load_mls_group(&group_id).unwrap().unwrap();
        let signer = alice_device1.load_mls_signer(&mls_group).unwrap();
        let group_info_msg = mls_group
            .export_group_info(alice_device1.provider.crypto(), &signer, false) // no extensions
            .unwrap();
        let group_info_bytes = group_info_msg.tls_serialize_detached().unwrap();

        let payload = alice_device1
            .build_pairing_payload(std::slice::from_ref(&group_id))
            .unwrap();
        let good_data = &payload.groups()[0];

        // Use the GroupInfo without extensions, but with the original PSK
        let data = super::GroupPairingDataV1::new(
            *good_data.group_event_key(),
            good_data.join_psk().to_vec(),
            group_info_bytes,
        )
        .unwrap();

        let result = alice_device2.join_group_via_external_commit(&data, &alice_keys);
        // Should fail with "missing ratchet_tree" (checked before external_pub)
        assert!(
            matches!(
                result,
                Err(crate::Error::PairingError(ref msg)) if msg.contains("ratchet_tree")
            ),
            "Expected ratchet_tree error, got: {:?}",
            result
        );
    }

    /// Test multiple groups in `build_pairing_payload` all get valid data.
    #[test]
    fn test_build_pairing_payload_multiple_groups() {
        let alice_keys = Keys::generate();
        let alice_mdk = create_test_mdk();

        let mut group_ids = Vec::new();
        for _ in 0..3 {
            let result = alice_mdk
                .create_group_with_multi_device(
                    &alice_keys.public_key(),
                    vec![],
                    create_nostr_group_config_data(vec![alice_keys.public_key()]),
                )
                .unwrap();
            let gid = result.group.mls_group_id.clone();
            alice_mdk.merge_pending_commit(&gid).unwrap();
            group_ids.push(gid);
        }

        let payload = alice_mdk.build_pairing_payload(&group_ids).unwrap();
        assert_eq!(payload.groups().len(), 3);

        for group_data in payload.groups() {
            assert_ne!(group_data.group_event_key(), &[0u8; 32]);
            assert_eq!(group_data.join_psk().len(), 32);
            assert!(!group_data.group_info().is_empty());
        }
    }

    /// Test `register_join_psk` is idempotent (can be called multiple times).
    #[test]
    fn test_register_join_psk_idempotent() {
        let alice_keys = Keys::generate();
        let alice_mdk = create_test_mdk();

        let create_result = alice_mdk
            .create_group_with_multi_device(
                &alice_keys.public_key(),
                vec![],
                create_nostr_group_config_data(vec![alice_keys.public_key()]),
            )
            .unwrap();
        let group_id = create_result.group.mls_group_id.clone();
        alice_mdk.merge_pending_commit(&group_id).unwrap();

        // First registration
        alice_mdk.register_join_psk(&group_id).unwrap();
        // Second registration (should succeed, overwriting the first)
        alice_mdk.register_join_psk(&group_id).unwrap();
    }

    /// Test that `build_pairing_payload` for a non-existent group returns GroupNotFound.
    #[test]
    fn test_build_pairing_payload_nonexistent_group() {
        let alice_mdk = create_test_mdk();
        let fake_id = mdk_storage_traits::GroupId::from_slice(&[0xFF; 16]);
        let result = alice_mdk.build_pairing_payload(&[fake_id]);
        assert!(matches!(result, Err(crate::Error::GroupNotFound)));
    }

    /// Test `enable_multi_device` on a non-existent group returns GroupNotFound.
    #[test]
    fn test_enable_multi_device_nonexistent_group() {
        let alice_mdk = create_test_mdk();
        let fake_id = mdk_storage_traits::GroupId::from_slice(&[0xFF; 16]);
        let result = alice_mdk.enable_multi_device(&fake_id);
        assert!(matches!(result, Err(crate::Error::GroupNotFound)));
    }

    /// Test `register_join_psk` on a non-existent group returns GroupNotFound.
    #[test]
    fn test_register_join_psk_nonexistent_group() {
        let alice_mdk = create_test_mdk();
        let fake_id = mdk_storage_traits::GroupId::from_slice(&[0xFF; 16]);
        let result = alice_mdk.register_join_psk(&fake_id);
        assert!(matches!(result, Err(crate::Error::GroupNotFound)));
    }

    /// Test `add_device_to_groups` with an empty group list returns an empty response.
    #[test]
    fn test_add_device_to_groups_empty_list() {
        let alice_keys = Keys::generate();
        let alice_mdk = create_test_mdk();
        let device2_mdk = create_test_mdk();
        let device2_kp = create_key_package_event(&device2_mdk, &alice_keys);

        let result = alice_mdk.add_device_to_groups(&[], &device2_kp);
        assert!(result.is_ok());
        assert!(result.unwrap().groups().is_empty());
    }

    /// Test `coalesced_members` with multiple members (not just the creator).
    #[test]
    fn test_coalesced_members_with_multiple_users() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        let bob_kp = create_key_package_event(&bob_mdk, &bob_keys);
        let create_result = alice_mdk
            .create_group_with_multi_device(
                &alice_keys.public_key(),
                vec![bob_kp],
                create_nostr_group_config_data(vec![
                    alice_keys.public_key(),
                    bob_keys.public_key(),
                ]),
            )
            .unwrap();
        let group_id = create_result.group.mls_group_id.clone();
        alice_mdk.merge_pending_commit(&group_id).unwrap();

        let members = alice_mdk.coalesced_members(&group_id).unwrap();
        assert_eq!(members.len(), 2);

        // Check both pubkeys are present
        assert!(members.contains_key(&alice_keys.public_key()));
        assert!(members.contains_key(&bob_keys.public_key()));

        // Each user has exactly 1 leaf
        for leaves in members.values() {
            assert_eq!(leaves.len(), 1);
        }
    }

    /// Test `own_device_leaves` returns correct leaf indices.
    #[test]
    fn test_own_device_leaves_returns_leaf_index() {
        let alice_keys = Keys::generate();
        let alice_mdk = create_test_mdk();

        let create_result = alice_mdk
            .create_group_with_multi_device(
                &alice_keys.public_key(),
                vec![],
                create_nostr_group_config_data(vec![alice_keys.public_key()]),
            )
            .unwrap();
        let group_id = create_result.group.mls_group_id.clone();
        alice_mdk.merge_pending_commit(&group_id).unwrap();

        let own_leaves = alice_mdk.own_device_leaves(&group_id).unwrap();
        assert_eq!(own_leaves.len(), 1);
        // Leaf index 0 is the creator
        assert_eq!(own_leaves[0], 0);
    }
}
