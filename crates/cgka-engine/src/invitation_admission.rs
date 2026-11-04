//! Invitation generations bind the account to the exact validated admission context.

use cgka_traits::{EngineError, MemberId};
use openmls::group::GroupContext;
use sha2::{Digest, Sha256};
use tls_codec::Serialize;

impl<S: cgka_traits::StorageProvider> crate::engine::Engine<S> {
    /// A locally created solo group has no staged Add. Export its own signed
    /// GroupInfo to obtain the exact upstream context through production APIs.
    pub(crate) fn local_invitation_generation(
        &self,
        group: &openmls::group::MlsGroup,
    ) -> Result<[u8; 32], EngineError> {
        let info = group
            .export_group_info(&self.crypto, &self.identity.signer, false)
            .map_err(|_| EngineError::Serialize("invitation context export".into()))?;
        let openmls::prelude::MlsMessageBodyOut::GroupInfo(info) = info.body() else {
            return Err(EngineError::Serialize("invitation context export".into()));
        };
        invitation_generation(self.identity.self_id(), info.group_context())
    }
}

pub(crate) fn invitation_generation(
    account: &MemberId,
    context: &GroupContext,
) -> Result<[u8; 32], EngineError> {
    if account.as_slice().len() != 32 {
        return Err(EngineError::Serialize("invalid invitation account".into()));
    }
    let context = context
        .tls_serialize_detached()
        .map_err(|_| EngineError::Serialize("invitation context".into()))?;
    let length = u64::try_from(context.len())
        .map_err(|_| EngineError::Serialize("invitation context length".into()))?;
    let mut hash = Sha256::new();
    hash.update(b"marmot.invitation-generation.v1\0");
    hash.update(account.as_slice());
    hash.update(length.to_be_bytes());
    hash.update(context);
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_codec::Deserialize;

    // Independently calculated SHA-256 vector; the 17-byte raw MLS id is
    // deliberately not a 32-byte transport routing handle.
    #[test]
    fn admission_generation_binds_exact_mls_context_account_and_domain() {
        let account =
            hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let context_bytes = hex::decode("0001000111000102030405060708090a0b0c0d0e0f10000000000000000720111111111111111111111111111111111111111111111111111111111111111120222222222222222222222222222222222222222222222222222222222222222200").unwrap();
        let context = GroupContext::tls_deserialize_exact(&context_bytes).unwrap();
        assert_eq!(
            hex::encode(invitation_generation(&MemberId::new(account), &context).unwrap()),
            "6d0ba86f166ff1fc424217574e7a62dbcf9c6d16a54efd61936dbc05a1f8fec2",
        );
    }
}
