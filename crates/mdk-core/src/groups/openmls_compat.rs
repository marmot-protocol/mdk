//! Temporary OpenMLS compatibility helpers.
//!
//! MDK's workspace pins OpenMLS to an upstream git revision that exposes
//! `MlsGroup::treesync().full_leaves()`, but crates.io packages verify against
//! registry dependencies. The OpenMLS 0.8.1 release needed for MDK 0.8.0
//! verification does not have that public API. Delete this module and use the
//! upstream full-leaf iterator directly once a crates.io OpenMLS release
//! includes it.

use std::collections::BTreeMap;

use openmls::prelude::Signature as MlsSignature;
use openmls::prelude::*;
use openmls::treesync::EncryptionKey;
use tls_codec::{
    DeserializeBytes as TlsDeserializeBytes, Serialize as TlsSerialize, Size as TlsSize, VLBytes,
};

const RATCHET_TREE_NODE_TYPE_LEAF: u8 = 1;
const RATCHET_TREE_NODE_TYPE_PARENT: u8 = 2;
const LEAF_NODE_SOURCE_KEY_PACKAGE: u8 = 1;
const LEAF_NODE_SOURCE_UPDATE: u8 = 2;
const LEAF_NODE_SOURCE_COMMIT: u8 = 3;

#[derive(Debug)]
enum ExportedRatchetTreeNode {
    Leaf {
        capabilities: Capabilities,
        serialized_len: usize,
    },
    Parent {
        serialized_len: usize,
    },
}

impl TlsSize for ExportedRatchetTreeNode {
    fn tls_serialized_len(&self) -> usize {
        match self {
            Self::Leaf { serialized_len, .. } | Self::Parent { serialized_len } => *serialized_len,
        }
    }
}

impl TlsDeserializeBytes for ExportedRatchetTreeNode {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error> {
        let original_len = bytes.len();
        let (node_type, remainder) = u8::tls_deserialize_bytes(bytes)?;

        match node_type {
            RATCHET_TREE_NODE_TYPE_LEAF => {
                let remainder = skip_tls_value::<EncryptionKey>(remainder)?;
                let remainder = skip_tls_value::<SignaturePublicKey>(remainder)?;
                let remainder = skip_tls_value::<Credential>(remainder)?;
                let (capabilities, remainder) = Capabilities::tls_deserialize_bytes(remainder)?;
                let (leaf_node_source, remainder) = u8::tls_deserialize_bytes(remainder)?;
                let remainder = match leaf_node_source {
                    LEAF_NODE_SOURCE_KEY_PACKAGE => skip_tls_value::<Lifetime>(remainder)?,
                    LEAF_NODE_SOURCE_UPDATE => remainder,
                    LEAF_NODE_SOURCE_COMMIT => skip_tls_value::<VLBytes>(remainder)?,
                    unknown => {
                        return Err(tls_codec::Error::DecodingError(format!(
                            "unknown leaf node source {unknown}"
                        )));
                    }
                };
                let remainder = skip_tls_value::<Extensions<LeafNode>>(remainder)?;
                let remainder = skip_tls_value::<MlsSignature>(remainder)?;

                Ok((
                    Self::Leaf {
                        capabilities,
                        serialized_len: original_len - remainder.len(),
                    },
                    remainder,
                ))
            }
            RATCHET_TREE_NODE_TYPE_PARENT => {
                let remainder = skip_tls_value::<ParentNode>(remainder)?;
                Ok((
                    Self::Parent {
                        serialized_len: original_len - remainder.len(),
                    },
                    remainder,
                ))
            }
            unknown => Err(tls_codec::Error::DecodingError(format!(
                "unknown ratchet tree node type {unknown}"
            ))),
        }
    }
}

pub(super) fn exported_leaf_capabilities(
    group: &MlsGroup,
) -> Result<BTreeMap<LeafNodeIndex, Capabilities>, tls_codec::Error> {
    let serialized_tree = group.export_ratchet_tree().tls_serialize_detached()?;
    let (nodes, remainder): (Vec<Option<ExportedRatchetTreeNode>>, _) =
        Vec::tls_deserialize_bytes(&serialized_tree)?;

    if !remainder.is_empty() {
        return Err(tls_codec::Error::TrailingData);
    }

    Ok(nodes
        .into_iter()
        .enumerate()
        .filter_map(|(node_index, node)| match node {
            Some(ExportedRatchetTreeNode::Leaf { capabilities, .. }) => {
                Some((LeafNodeIndex::new((node_index / 2) as u32), capabilities))
            }
            Some(ExportedRatchetTreeNode::Parent { .. }) | None => None,
        })
        .collect())
}

fn skip_tls_value<T>(bytes: &[u8]) -> Result<&[u8], tls_codec::Error>
where
    T: TlsDeserializeBytes,
{
    let (_, remainder) = T::tls_deserialize_bytes(bytes)?;
    Ok(remainder)
}
