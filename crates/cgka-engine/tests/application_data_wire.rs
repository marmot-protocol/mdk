//! OpenMLS integration-contract tests for the MLS application-data carriers
//! Marmot uses.
//!
//! These direct codec tests pin the fork behavior that MDK's engine paths rely
//! on. Engine-boundary coverage for KeyPackage application data lives in
//! `group_creation.rs`; state-transition preservation coverage lives in
//! `update_group_data.rs`.

use openmls::component::ComponentData;
use openmls::extensions::{
    AppDataDictionary, AppDataDictionaryExtension, Extension, ExtensionType, Extensions,
};
use openmls::group::GroupContext;
use openmls::messages::proposals::{AppDataUpdateOperation, AppDataUpdateProposal, ProposalType};
use openmls::prelude::{KeyPackage, LeafNode};
use tls_codec::{Deserialize as _, Serialize as _, VLBytes};

const OPAQUE_COMPONENT_ID: u16 = 0x9001;
const OPAQUE_COMPONENT_BYTES: &[u8] = &[0xde, 0xad, 0xbe, 0xef];

fn app_data_extension() -> Extension {
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(OPAQUE_COMPONENT_ID, OPAQUE_COMPONENT_BYTES.to_vec());
    Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary))
}

fn assert_opaque_component<T>(extensions: &Extensions<T>) {
    let dictionary = extensions
        .app_data_dictionary()
        .expect("app_data_dictionary extension")
        .dictionary();
    assert_eq!(
        dictionary.get(&OPAQUE_COMPONENT_ID),
        Some(OPAQUE_COMPONENT_BYTES)
    );
}

#[test]
fn application_data_dictionary_roundtrips_in_every_extension_carrier_mdk_uses() {
    let key_package = Extensions::<KeyPackage>::single(app_data_extension()).unwrap();
    let decoded = Extensions::<KeyPackage>::tls_deserialize_exact(
        key_package.tls_serialize_detached().unwrap(),
    )
    .unwrap();
    assert_opaque_component(&decoded);

    let leaf_node = Extensions::<LeafNode>::single(app_data_extension()).unwrap();
    let decoded =
        Extensions::<LeafNode>::tls_deserialize_exact(leaf_node.tls_serialize_detached().unwrap())
            .unwrap();
    assert_opaque_component(&decoded);

    let group_context = Extensions::<GroupContext>::single(app_data_extension()).unwrap();
    let decoded = Extensions::<GroupContext>::tls_deserialize_exact(
        group_context.tls_serialize_detached().unwrap(),
    )
    .unwrap();
    assert_opaque_component(&decoded);
}

#[test]
fn application_data_dictionary_serializes_canonically_and_preserves_opaque_bytes() {
    let mut dictionary = AppDataDictionary::new();
    // Insert in descending component-id order. Canonical serialization must
    // still order the wire entries by component id.
    dictionary.insert(OPAQUE_COMPONENT_ID, OPAQUE_COMPONENT_BYTES.to_vec());
    dictionary.insert(0x0001, vec![0x01]);
    let encoded = dictionary.tls_serialize_detached().unwrap();
    let expected = vec![
        ComponentData::from_parts(0x0001, vec![0x01].into()),
        ComponentData::from_parts(OPAQUE_COMPONENT_ID, OPAQUE_COMPONENT_BYTES.to_vec().into()),
    ]
    .tls_serialize_detached()
    .unwrap();
    assert_eq!(encoded, expected);

    let dictionary = AppDataDictionary::tls_deserialize_exact(encoded).unwrap();
    assert_eq!(
        dictionary.get(&OPAQUE_COMPONENT_ID),
        Some(OPAQUE_COMPONENT_BYTES)
    );
}

#[test]
fn application_data_dictionary_rejects_duplicate_and_out_of_order_components() {
    let duplicate = vec![
        ComponentData::from_parts(0x0001, vec![0x01].into()),
        ComponentData::from_parts(0x0001, vec![0x02].into()),
    ]
    .tls_serialize_detached()
    .unwrap();
    assert!(AppDataDictionary::tls_deserialize_exact(duplicate).is_err());

    let out_of_order = vec![
        ComponentData::from_parts(OPAQUE_COMPONENT_ID, vec![0x01].into()),
        ComponentData::from_parts(0x0001, vec![0x02].into()),
    ]
    .tls_serialize_detached()
    .unwrap();
    assert!(AppDataDictionary::tls_deserialize_exact(out_of_order).is_err());
}

#[test]
fn application_data_extension_rejects_malformed_length_framing() {
    let Extension::AppDataDictionary(extension) = app_data_extension() else {
        unreachable!()
    };
    let mut extension_data = extension.tls_serialize_detached().unwrap();
    extension_data.push(0xff);

    let mut malformed = ExtensionType::AppDataDictionary
        .tls_serialize_detached()
        .unwrap();
    malformed.extend_from_slice(
        &VLBytes::from(extension_data)
            .tls_serialize_detached()
            .unwrap(),
    );

    assert!(Extension::tls_deserialize_exact(malformed).is_err());

    let mut truncated = app_data_extension().tls_serialize_detached().unwrap();
    truncated.pop();
    assert!(Extension::tls_deserialize_exact(truncated).is_err());
}

#[test]
fn app_data_update_proposals_roundtrip_and_reject_malformed_operations() {
    assert_eq!(u16::from(ProposalType::AppDataUpdate), 0x0008);

    let update = AppDataUpdateProposal::update(OPAQUE_COMPONENT_ID, OPAQUE_COMPONENT_BYTES);
    let update_bytes = update.tls_serialize_detached().unwrap();
    let decoded = AppDataUpdateProposal::tls_deserialize_exact(update_bytes.clone()).unwrap();
    assert_eq!(decoded.component_id(), OPAQUE_COMPONENT_ID);
    assert!(matches!(
        decoded.operation(),
        AppDataUpdateOperation::Update(data) if data.as_slice() == OPAQUE_COMPONENT_BYTES
    ));

    let remove = AppDataUpdateProposal::remove(OPAQUE_COMPONENT_ID);
    let decoded =
        AppDataUpdateProposal::tls_deserialize_exact(remove.tls_serialize_detached().unwrap())
            .unwrap();
    assert_eq!(decoded.component_id(), OPAQUE_COMPONENT_ID);
    assert_eq!(decoded.operation(), &AppDataUpdateOperation::Remove);

    // AppDataUpdateProposal starts with the explicit u16 component id followed
    // by the operation discriminant. Construct that frame directly instead of
    // mutating a positional byte in an otherwise-valid proposal.
    let mut unknown_operation = OPAQUE_COMPONENT_ID.to_be_bytes().to_vec();
    unknown_operation.push(0xff);
    assert!(AppDataUpdateProposal::tls_deserialize_exact(unknown_operation).is_err());

    let mut truncated = update_bytes;
    truncated.pop();
    assert!(AppDataUpdateProposal::tls_deserialize_exact(truncated).is_err());
}
