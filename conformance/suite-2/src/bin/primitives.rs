// Isolated J18 provider conformance, not runtime or gate acceptance.
// Public fixtures only. Retire with this suite.
use chacha20::ChaCha20Rng;
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable,
    aead::{AesGcm256, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::XWing,
    rand_core::{Rng, SeedableRng},
    single_shot_open, single_shot_seal_with_rng,
};
use serde_json::{Value, json};
fn bytes(v: &Value, field: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(hex::decode(
        v[field].as_str().ok_or("missing public fixture field")?,
    )?)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() == 3 && args[1] == "verify" {
        let corpus: Value = serde_json::from_slice(&std::fs::read(&args[2])?)?;
        let vectors = corpus.as_array().ok_or("expected public vector list")?;
        let mut negatives = 0;
        for v in vectors {
            let seed = bytes(v, "private_seed")?;
            let private = <<XWing as Kem>::PrivateKey as Deserializable>::from_bytes(&seed)?;
            let enc = <<XWing as Kem>::EncappedKey as Deserializable>::from_bytes(&bytes(
                v,
                "encapsulation",
            )?)?;
            let info = bytes(v, "info")?;
            let aad = bytes(v, "aad")?;
            let ciphertext = bytes(v, "ciphertext")?;
            let expected = bytes(v, "plaintext")?;
            let opened = single_shot_open::<AesGcm256, HkdfSha256, XWing>(
                &OpModeR::Base,
                &private,
                &enc,
                &info,
                &ciphertext,
                &aad,
            )?;
            assert_eq!(opened, expected);
            assert!(
                single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(
                    &OpModeR::Base,
                    &private,
                    &enc,
                    &info,
                    &ciphertext,
                    &aad
                )
                .is_err()
            );
            negatives += 1;
            for part in 0..5 {
                let mut altered = [
                    seed.clone(),
                    bytes(v, "encapsulation")?,
                    info.clone(),
                    aad.clone(),
                    ciphertext.clone(),
                ];
                altered[part][0] ^= 1;
                let key = <<XWing as Kem>::PrivateKey as Deserializable>::from_bytes(&altered[0])?;
                let enc = <<XWing as Kem>::EncappedKey as Deserializable>::from_bytes(&altered[1])?;
                assert!(
                    single_shot_open::<AesGcm256, HkdfSha256, XWing>(
                        &OpModeR::Base,
                        &key,
                        &enc,
                        &altered[2],
                        &altered[4],
                        &altered[3]
                    )
                    .is_err()
                );
                negatives += 1;
            }
        }
        println!(
            "Rust opened {} alternate-provider vectors; rejected {} key/context/ciphertext/cross-AEAD mutations",
            vectors.len(),
            negatives
        );
        return Ok(());
    }
    if args.len() != 1 {
        return Err("use roundtrip [verify PUBLIC_CORPUS]".into());
    }
    let mut vectors = Vec::new();
    for (marker, length) in [(0x31, 32), (0x32, 33), (0x33, 0), (0x34, 256)] {
        let seed = [marker; 32];
        let private = <<XWing as Kem>::PrivateKey as Deserializable>::from_bytes(&seed)?;
        let public = XWing::sk_to_pk(&private);
        let rng_seed = [marker + 16; 32];
        let mut rng = ChaCha20Rng::from_seed(rng_seed);
        let mut entropy = [0; 64];
        rng.fill_bytes(&mut entropy);
        let mut rng = ChaCha20Rng::from_seed(rng_seed);
        let info = b"ExampleSuite2PrimitiveInfo";
        let aad = b"ExampleSuite2PrimitiveAad";
        let plaintext = vec![marker + 32; length];
        let (enc, ciphertext) = single_shot_seal_with_rng::<AesGcm256, HkdfSha256, XWing>(
            &OpModeS::Base,
            &public,
            info,
            &plaintext,
            aad,
            &mut rng,
        )?;
        let mut encapsulation = vec![0; <XWing as Kem>::EncappedKey::size()];
        enc.write_exact(&mut encapsulation);
        vectors.push(json!({"private_seed":hex::encode(seed),"encapsulation_entropy":hex::encode(entropy),
            "encapsulation":hex::encode(encapsulation),"info":hex::encode(info),"aad":hex::encode(aad),
            "ciphertext":hex::encode(ciphertext),"plaintext":hex::encode(plaintext)}));
    }
    println!("{}", serde_json::to_string_pretty(&vectors)?);
    Ok(())
}
