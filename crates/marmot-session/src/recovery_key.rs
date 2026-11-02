//! Sealing to a recovery key without a session (mdk#2628 4.4b). A backup is
//! written off the account worker, where no session is at hand. The sealing
//! is the engine's ([`cgka_engine::recovery_key`]), under the stateless
//! crypto provider the engine itself uses.

use openmls_rust_crypto::RustCrypto;

/// `plaintext` sealed to a recovery key's public half, as the roster's
/// account entry holds it, for `context`; `None` when that key is not one a
/// value can be sealed to. See [`cgka_engine::recovery_key::seal_to_recovery_key`].
pub fn seal_to_recovery_key(
    recovery_public_key: &[u8],
    context: &[u8],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    cgka_engine::recovery_key::seal_to_recovery_key(
        &RustCrypto::default(),
        recovery_public_key,
        context,
        plaintext,
    )
}
