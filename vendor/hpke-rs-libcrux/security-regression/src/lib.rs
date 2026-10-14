#[cfg(test)]
mod tests {
    use hpke_rs::{Hpke, Mode};
    use hpke_rs_crypto::{
        types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm},
        HpkeCrypto,
    };
    use hpke_rs_libcrux::HpkeLibcrux;
    use hpke_rs_rust_crypto::HpkeRustCrypto;

    /// Every supported overlapping KEM must encrypt across the unchanged 0.7 provider boundary.
    #[test]
    fn bidirectional_provider_interoperability() {
        let mut kems = vec![
            KemAlgorithm::DhKem25519,
            KemAlgorithm::DhKemP256,
            KemAlgorithm::XWingDraft06,
        ];
        if cfg!(feature = "mlkem") {
            kems.extend([KemAlgorithm::MlKem768, KemAlgorithm::MlKem1024]);
        }
        for kem in kems {
            let mut crux = Hpke::<HpkeLibcrux>::new(
                Mode::Base,
                kem,
                KdfAlgorithm::HkdfSha256,
                AeadAlgorithm::Aes128Gcm,
            );
            let mut rust = Hpke::<HpkeRustCrypto>::new(
                Mode::Base,
                kem,
                KdfAlgorithm::HkdfSha256,
                AeadAlgorithm::Aes128Gcm,
            );
            let crux_keys = crux.generate_key_pair().unwrap();
            let rust_keys = rust.generate_key_pair().unwrap();
            let (enc, ciphertext) = crux
                .seal(
                    rust_keys.public_key(),
                    b"info",
                    b"aad",
                    b"message",
                    None,
                    None,
                    None,
                )
                .unwrap();
            assert_eq!(
                rust.open(
                    &enc,
                    rust_keys.private_key(),
                    b"info",
                    b"aad",
                    &ciphertext,
                    None,
                    None,
                    None
                )
                .unwrap(),
                b"message",
                "libcrux -> RustCrypto: {kem:?}"
            );
            let (enc, ciphertext) = rust
                .seal(
                    crux_keys.public_key(),
                    b"info",
                    b"aad",
                    b"message",
                    None,
                    None,
                    None,
                )
                .unwrap();
            assert_eq!(
                crux.open(
                    &enc,
                    crux_keys.private_key(),
                    b"info",
                    b"aad",
                    &ciphertext,
                    None,
                    None,
                    None
                )
                .unwrap(),
                b"message",
                "RustCrypto -> libcrux: {kem:?}"
            );
        }
    }

    /// Both advisory input classes return errors rather than panicking in the patched KEM.
    #[test]
    fn malformed_hybrid_keys_and_short_seeds_are_rejected() {
        use libcrux_kem::{Algorithm, PrivateKey, PublicKey};
        for alg in [Algorithm::XWingKemDraft06, Algorithm::X25519MlKem768Draft00] {
            let mut rng = HpkeLibcrux::prng();
            let (_, pk) = libcrux_kem::key_gen(alg, &mut rng).unwrap();
            for len in [0, 1, 31] {
                let short = vec![0; len];
                assert!(PrivateKey::decode(alg, &short).is_err());
                assert!(PublicKey::decode(alg, &short).is_err());
                assert!(pk.encapsulate_derand(&short).is_err());
            }
        }
    }
}
