use std::error::Error;

use jury_protected::{ProtectedMemory, ProtectionPolicy};
use jury_protocol::vault_v1::{Encapsulation1120, Nonce12};
use serde_json::Value;

use super::*;

fn corpus() -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_str(include_str!(
        "../../../docs/security/vectors/jury-v1-suite.json"
    ))?)
}

fn decode(value: &Value) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(hex::decode(value.as_str().ok_or("expected hex string")?)?)
}

fn preimage(corpus: &Value, vector: &Value, field: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let name = vector[field].as_str().ok_or("expected preimage name")?;
    decode(&corpus["preimages"][name]["hex"])
}

fn protected(bytes: &[u8]) -> Result<ProtectedMemory, Box<dyn Error>> {
    Ok(ProtectedMemory::initialize(
        bytes.len(),
        ProtectionPolicy::Strict,
        |destination| {
            destination.copy_from_slice(bytes);
            Ok::<usize, ()>(destination.len())
        },
    )?)
}

#[test]
fn frozen_hpke_vector_opens_only_through_protected_output() -> Result<(), Box<dyn Error>> {
    const DIRECT_HEADER_BYTES: usize = 197;
    let corpus = corpus()?;
    let vector = &corpus["encodings"]["direct_slots"]["descriptor"];
    let slot = decode(&vector["hex"])?;
    let encapsulation =
        Encapsulation1120::from_slice(&slot[DIRECT_HEADER_BYTES..DIRECT_HEADER_BYTES + 1_120])?;
    let ciphertext = &slot[DIRECT_HEADER_BYTES + 1_120..];
    let private_seed = protected(&decode(&vector["recipient_private_seed_hex"])?)?;
    let expected = decode(&vector["plaintext_hex"])?;
    let info = preimage(&corpus, vector, "info_preimage")?;
    let aad = preimage(&corpus, vector, "aad_preimage")?;

    let opened = open_hpke(
        &private_seed,
        &encapsulation,
        ciphertext,
        &info,
        &aad,
        expected.len(),
    )?;
    assert!(opened.expose(|bytes| bytes == expected)?);
    assert!(format!("{opened:?}").contains("[REDACTED]"));

    let mut tampered = ciphertext.to_vec();
    tampered[0] ^= 1;
    assert_eq!(
        open_hpke(
            &private_seed,
            &encapsulation,
            &tampered,
            &info,
            &aad,
            expected.len(),
        )
        .map(|_| ()),
        Err(CryptoError::AuthenticationFailed)
    );
    Ok(())
}

#[test]
fn frozen_storage_hkdf_and_signature_vectors_match_wrappers() -> Result<(), Box<dyn Error>> {
    let corpus = corpus()?;
    let hkdf = &corpus["hkdf_sha256"]["kdf_identity_root_wrap"];
    let ikm = protected(&decode(&hkdf["ikm_hex"])?)?;
    let info = preimage(&corpus, hkdf, "info_preimage")?;
    let derived = derive_hkdf_key(&ikm, &info)?;
    let expected_hkdf = decode(&hkdf["output_hex"])?;
    assert!(derived.expose(|bytes| bytes == expected_hkdf)?);

    let aead = &corpus["aead"]["item_descriptor"];
    let key = protected(&decode(&aead["key_hex"])?)?;
    let nonce = Nonce12::from_slice(&decode(&aead["nonce_hex"])?)?;
    let aad = preimage(&corpus, aead, "aad_preimage")?;
    let plaintext_name = aead["plaintext_encoding"]
        .as_str()
        .ok_or("expected plaintext encoding")?;
    let plaintext_bytes = decode(&corpus["encodings"][plaintext_name]["hex"])?;
    let plaintext = protected(&plaintext_bytes)?;
    let ciphertext = seal(&key, &nonce, &aad, &plaintext)?;
    assert_eq!(ciphertext, decode(&aead["ciphertext_hex"])?);
    let opened = open(&key, &nonce, &aad, &ciphertext, plaintext_bytes.len())?;
    assert!(opened.expose(|bytes| bytes == plaintext_bytes)?);

    let signature_vector = &corpus["ed25519"]["item_revision_signature"];
    let signer = signature_vector["signer"]
        .as_str()
        .ok_or("expected signer")?;
    let signing_seed = decode(&corpus["fixture_signing_keys"][signer]["seed_hex"])?;
    let message = preimage(&corpus, signature_vector, "message_preimage")?;
    assert_eq!(
        sign_bytes(&signing_seed, &message)?.as_bytes().as_slice(),
        decode(&signature_vector["signature_hex"])?.as_slice()
    );
    Ok(())
}
