//! Consume public deterministic BoringSSL vectors with the selected Rust HPKE.
//! This standalone executable cannot be linked into Jury runtime crates.
use std::convert::Infallible;

use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable,
    aead::{AesGcm256, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::XWing,
    rand_core::{TryCryptoRng, TryRng},
    single_shot_open, single_shot_seal_with_rng,
};
use serde_json::Value;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

// The provider test interface requires this marker. These are fixed public
// conformance bytes, never a production generator or secret randomness source.
struct FixtureEntropy {
    bytes: Vec<u8>,
    consumed: usize,
}
impl TryCryptoRng for FixtureEntropy {}
impl TryRng for FixtureEntropy {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> std::result::Result<u32, Infallible> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn try_next_u64(&mut self) -> std::result::Result<u64, Infallible> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> std::result::Result<(), Infallible> {
        let end = self.consumed + output.len();
        assert!(
            end <= self.bytes.len(),
            "provider exceeded fixture entropy contract"
        );
        output.copy_from_slice(&self.bytes[self.consumed..end]);
        self.consumed = end;
        Ok(())
    }
}

fn bytes(value: &Value, key: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(
        value[key].as_str().ok_or("missing public fixture")?,
    )?)
}

fn open(parts: &[Vec<u8>; 5]) -> Result<Vec<u8>> {
    let private = <<XWing as Kem>::PrivateKey as Deserializable>::from_bytes(&parts[0])?;
    let enc = <<XWing as Kem>::EncappedKey as Deserializable>::from_bytes(&parts[1])?;
    Ok(single_shot_open::<AesGcm256, HkdfSha256, XWing>(
        &OpModeR::Base,
        &private,
        &enc,
        &parts[2],
        &parts[4],
        &parts[3],
    )?)
}

fn profile_one(value: &mut [u8]) -> Result {
    let terminator = value
        .iter()
        .position(|byte| *byte == 0)
        .ok_or("missing domain")?;
    if value.get(terminator + 1..terminator + 3) != Some(&[0, 2]) {
        return Err("unexpected suite-2 domain".into());
    }
    value[terminator + 2] = 1;
    Ok(())
}

fn main() -> Result {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: contexts PUBLIC_CORPUS")?;
    let corpus: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let vectors = corpus["vectors"]
        .as_array()
        .ok_or("missing context vectors")?;
    assert_eq!(corpus["suite"], 2);
    assert_eq!(vectors.len(), 7);
    let mut negatives = 0;
    for vector in vectors {
        let parts = [
            bytes(vector, "private_seed")?,
            bytes(vector, "encapsulation")?,
            bytes(vector, "info")?,
            bytes(vector, "aad")?,
            bytes(vector, "ciphertext")?,
        ];
        let expected = bytes(vector, "plaintext")?;
        assert_eq!(open(&parts)?, expected);
        let private = <<XWing as Kem>::PrivateKey as Deserializable>::from_bytes(&parts[0])?;
        let public = XWing::sk_to_pk(&private);
        let mut entropy = FixtureEntropy {
            bytes: bytes(vector, "encapsulation_entropy")?,
            consumed: 0,
        };
        assert_eq!(entropy.bytes.len(), 64);
        let (enc, ciphertext) = single_shot_seal_with_rng::<AesGcm256, HkdfSha256, XWing>(
            &OpModeS::Base,
            &public,
            &parts[2],
            &expected,
            &parts[3],
            &mut entropy,
        )?;
        assert_eq!(entropy.consumed, 64);
        let mut encoded = vec![0; <XWing as Kem>::EncappedKey::size()];
        enc.write_exact(&mut encoded);
        assert_eq!(encoded, parts[1]);
        assert_eq!(ciphertext, parts[4]);
        for field in 0..5 {
            let mut changed = parts.clone();
            changed[field][0] ^= 1;
            assert!(open(&changed).is_err());
            negatives += 1;
        }
        for field in [0, 1, 4] {
            let mut changed = parts.clone();
            changed[field].pop();
            assert!(open(&changed).is_err());
            negatives += 1;
        }
        assert!(
            single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(
                &OpModeR::Base,
                &private,
                &enc,
                &parts[2],
                &parts[4],
                &parts[3]
            )
            .is_err()
        );
        negatives += 1;
        let mut old_profile = parts.clone();
        profile_one(&mut old_profile[2])?;
        profile_one(&mut old_profile[3])?;
        assert!(open(&old_profile).is_err());
        negatives += 1;
    }
    assert_eq!(negatives, 70);
    println!(
        "Rust: seven alternate-provider context opens and exact seals; 70 key/context/ciphertext/truncation/profile/AEAD refusals passed"
    );
    Ok(())
}
