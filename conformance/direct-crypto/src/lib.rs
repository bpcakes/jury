#[cfg(test)]
mod tests {
    use aes_gcm_siv::{
        Aes256GcmSiv, KeyInit,
        aead::{Aead, Payload},
    };
    use argon2::{Algorithm, Argon2, Params, Version};
    use chacha20::ChaCha20Rng;
    use ed25519_dalek::{Signature, VerifyingKey};
    use hkdf::Hkdf;
    use hmac::{Hmac, Mac, digest::KeyInit as MacKeyInit};
    use hpke::{
        Deserializable, Kem, OpModeR, OpModeS,
        aead::ChaCha20Poly1305,
        kdf::HkdfSha256,
        kem::XWing,
        rand_core::{Rng, SeedableRng},
        single_shot_open, single_shot_seal_with_rng,
    };
    use serde_json::Value;
    use sha2::Sha256;
    use std::{cell::Cell, fs, path::Path};
    use zeroize::Zeroize;

    const DIRECT_SLOT_HEADER_LEN: usize = 197;
    const XWING_ENCAPSULATION_LEN: usize = 1_120;

    fn corpus() -> Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/security/vectors/jury-v1-suite.json");
        serde_json::from_slice(&fs::read(path).expect("read corpus")).expect("parse corpus")
    }

    fn decode(value: &Value) -> Vec<u8> {
        hex::decode(value.as_str().expect("hex string")).expect("valid hex")
    }

    #[derive(Debug, Eq, PartialEq)]
    enum EntropyError {
        Unavailable,
    }

    fn with_seeded_rng<T>(
        seed: Result<[u8; 32], EntropyError>,
        provider_called: &Cell<bool>,
        operation: impl FnOnce(&mut ChaCha20Rng) -> T,
    ) -> Result<T, EntropyError> {
        let mut seed = seed?;
        let mut rng = ChaCha20Rng::from_seed(seed);
        seed.zeroize();
        provider_called.set(true);
        Ok(operation(&mut rng))
    }

    fn preimage(corpus: &Value, name: &Value) -> Vec<u8> {
        let name = name.as_str().expect("preimage name");
        decode(&corpus["preimages"][name]["hex"])
    }

    fn hpke_open(
        private_seed: &[u8],
        enc: &[u8],
        ciphertext: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, hpke::HpkeError> {
        let private_key = <<XWing as Kem>::PrivateKey as Deserializable>::from_bytes(private_seed)?;
        let encapsulation = <<XWing as Kem>::EncappedKey as Deserializable>::from_bytes(enc)?;
        single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeR::Base,
            &private_key,
            &encapsulation,
            info,
            ciphertext,
            aad,
        )
    }

    #[test]
    fn fallible_entropy_boundary_returns_before_provider_use() {
        let provider_called = Cell::new(false);
        let failed: Result<[u8; 64], _> =
            with_seeded_rng(Err(EntropyError::Unavailable), &provider_called, |rng| {
                let mut output = [0; 64];
                rng.fill_bytes(&mut output);
                output
            });
        assert_eq!(failed, Err(EntropyError::Unavailable));
        assert!(!provider_called.get());

        let generated = with_seeded_rng(Ok([0x5a; 32]), &provider_called, |rng| {
            let mut output = [0; 64];
            rng.fill_bytes(&mut output);
            output
        })
        .unwrap();
        assert!(provider_called.get());
        assert_ne!(generated, [0; 64]);
    }

    #[test]
    fn frozen_hpke_outputs_open_and_mutations_fail_closed() {
        let corpus = corpus();

        for name in ["descriptor", "body"] {
            let vector = &corpus["encodings"]["direct_slots"][name];
            let slot = decode(&vector["hex"]);
            assert_eq!(slot.len(), 1_365);
            let enc_end = DIRECT_SLOT_HEADER_LEN + XWING_ENCAPSULATION_LEN;
            let enc = &slot[DIRECT_SLOT_HEADER_LEN..enc_end];
            let ciphertext = &slot[enc_end..];
            assert_eq!(ciphertext, decode(&vector["ciphertext_hex"]));

            let private_seed = decode(&vector["recipient_private_seed_hex"]);
            let info = preimage(&corpus, &vector["info_preimage"]);
            let aad = preimage(&corpus, &vector["aad_preimage"]);
            let plaintext = decode(&vector["plaintext_hex"]);
            assert_eq!(
                hpke_open(&private_seed, enc, ciphertext, &info, &aad).unwrap(),
                plaintext
            );

            let mut bad_ciphertext = ciphertext.to_vec();
            bad_ciphertext[0] ^= 1;
            assert!(hpke_open(&private_seed, enc, &bad_ciphertext, &info, &aad).is_err());

            let mut bad_enc = enc.to_vec();
            bad_enc[0] ^= 1;
            assert!(hpke_open(&private_seed, &bad_enc, ciphertext, &info, &aad).is_err());
        }

        let vector = &corpus["encodings"]["registration_challenge_hpke"];
        let private_seed = decode(&vector["recipient_private_seed_hex"]);
        let enc = decode(&vector["enc_hex"]);
        let ciphertext = decode(&vector["ciphertext_hex"]);
        let info = preimage(&corpus, &vector["info_preimage"]);
        let aad = preimage(&corpus, &vector["aad_preimage"]);
        assert_eq!(
            hpke_open(&private_seed, &enc, &ciphertext, &info, &aad).unwrap(),
            decode(&vector["plaintext_hex"])
        );
    }

    #[test]
    fn hpke_with_rng_surface_is_non_exhausting_and_round_trips() {
        let mut rng = ChaCha20Rng::from_seed([0x5a; 32]);
        let (private_key, public_key) = XWing::gen_keypair_with_rng(&mut rng);
        let (enc, ciphertext) = single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeS::Base,
            &public_key,
            b"jury-j01b/provider-surface",
            b"ExampleSecret",
            b"public-aad",
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(
                &OpModeR::Base,
                &private_key,
                &enc,
                b"jury-j01b/provider-surface",
                &ciphertext,
                b"public-aad",
            )
            .unwrap(),
            b"ExampleSecret"
        );
    }

    #[test]
    fn frozen_aes_gcm_siv_outputs_open_and_tamper_fails() {
        let corpus = corpus();
        for name in ["item_descriptor", "item_body"] {
            let vector = &corpus["aead"][name];
            let key = decode(&vector["key_hex"]);
            let nonce: [u8; 12] = decode(&vector["nonce_hex"]).try_into().unwrap();
            let aad = preimage(&corpus, &vector["aad_preimage"]);
            let ciphertext = decode(&vector["ciphertext_hex"]);
            let plaintext_name = vector["plaintext_encoding"].as_str().unwrap();
            let expected_plaintext = decode(&corpus["encodings"][plaintext_name]["hex"]);
            let cipher = Aes256GcmSiv::new_from_slice(&key).unwrap();
            assert_eq!(
                cipher
                    .decrypt(
                        (&nonce).into(),
                        Payload {
                            msg: &ciphertext,
                            aad: &aad
                        }
                    )
                    .unwrap(),
                expected_plaintext
            );

            let mut tampered = ciphertext;
            tampered[0] ^= 1;
            assert!(
                cipher
                    .decrypt(
                        (&nonce).into(),
                        Payload {
                            msg: &tampered,
                            aad: &aad
                        }
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn frozen_hkdf_and_hmac_outputs_match() {
        let corpus = corpus();
        for vector in corpus["hkdf_sha256"].as_object().unwrap().values() {
            let ikm = decode(&vector["ikm_hex"]);
            let salt = decode(&vector["salt_hex"]);
            let info = preimage(&corpus, &vector["info_preimage"]);
            let mut output = vec![0; vector["length"].as_u64().unwrap() as usize];
            Hkdf::<Sha256>::new(Some(&salt), &ikm)
                .expand(&info, &mut output)
                .unwrap();
            assert_eq!(output, decode(&vector["output_hex"]));
        }

        for vector in corpus["hmac_sha256"].as_object().unwrap().values() {
            let key_name = vector["key_vector"].as_str().unwrap();
            let key = decode(&corpus["hkdf_sha256"][key_name]["output_hex"]);
            let input = preimage(&corpus, &vector["input_preimage"]);
            let tag = decode(&vector["tag_hex"]);
            let mut mac = <Hmac<Sha256> as MacKeyInit>::new_from_slice(&key).unwrap();
            mac.update(&input);
            mac.verify_slice(&tag).unwrap();

            let mut bad_tag = tag;
            bad_tag[0] ^= 1;
            let mut bad_mac = <Hmac<Sha256> as MacKeyInit>::new_from_slice(&key).unwrap();
            bad_mac.update(&input);
            assert!(bad_mac.verify_slice(&bad_tag).is_err());
        }
    }

    #[test]
    fn all_frozen_ed25519_signatures_verify_strictly() {
        let corpus = corpus();
        for vector in corpus["ed25519"].as_object().unwrap().values() {
            let signer = vector["signer"].as_str().unwrap();
            let public_bytes: [u8; 32] =
                decode(&corpus["fixture_signing_keys"][signer]["public_key_hex"])
                    .try_into()
                    .unwrap();
            let public_key = VerifyingKey::from_bytes(&public_bytes).unwrap();
            let signature = Signature::from_slice(&decode(&vector["signature_hex"])).unwrap();
            let message = preimage(&corpus, &vector["message_preimage"]);
            public_key.verify_strict(&message, &signature).unwrap();
        }

        let negative = corpus["negative_vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "ed25519_noncanonical_s")
            .unwrap();
        let source = negative["source"].as_str().unwrap();
        let positive = &corpus["ed25519"][source];
        let signer = positive["signer"].as_str().unwrap();
        let public_bytes: [u8; 32] =
            decode(&corpus["fixture_signing_keys"][signer]["public_key_hex"])
                .try_into()
                .unwrap();
        let public_key = VerifyingKey::from_bytes(&public_bytes).unwrap();
        let signature = Signature::from_slice(&decode(&negative["mutated_hex"])).unwrap();
        let message = preimage(&corpus, &positive["message_preimage"]);
        assert!(public_key.verify_strict(&message, &signature).is_err());
    }

    #[test]
    fn both_frozen_argon2id_profiles_match() {
        let corpus = corpus();
        let password = decode(&corpus["argon2id"]["password_hex"]);
        for name in ["portable-v1", "hardened-v1"] {
            let vector = &corpus["argon2id"][name];
            let params = Params::new(
                vector["memory_kib"].as_u64().unwrap() as u32,
                vector["passes"].as_u64().unwrap() as u32,
                vector["lanes"].as_u64().unwrap() as u32,
                Some(vector["length"].as_u64().unwrap() as usize),
            )
            .unwrap();
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut output = vec![0; vector["length"].as_u64().unwrap() as usize];
            argon2
                .hash_password_into(&password, &decode(&vector["salt_hex"]), &mut output)
                .unwrap();
            assert_eq!(output, decode(&vector["output_hex"]));
        }
    }
}
