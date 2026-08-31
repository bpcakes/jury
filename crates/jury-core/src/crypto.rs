use std::fmt;

use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce, Tag, aead::AeadInOut};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20::ChaCha20Rng;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::XWing, rand_core::SeedableRng, single_shot_open, single_shot_seal_with_rng,
};
use jury_protected::{
    MemoryErrorKind, ProtectedMemory, ProtectionPolicy, RandomSource,
    capture_after_process_protection, protected_random,
};
use jury_protocol::{
    identity_v1::KdfProfile,
    vault_v1::{
        Encapsulation1120, Nonce12, RecipientPublicKey1216, Signature64, VerificationPublicKey32,
    },
};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CryptoError {
    EntropyUnavailable,
    MemoryProtection,
    ResourceUnavailable,
    ProviderFailure,
    AuthenticationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EntropyUnavailable => "cryptographic entropy was unavailable",
            Self::MemoryProtection => "cryptographic memory protection failed",
            Self::ResourceUnavailable => "cryptographic resources were unavailable",
            Self::ProviderFailure => "cryptographic provider failed",
            Self::AuthenticationFailed => "cryptographic authentication failed",
        })
    }
}

impl std::error::Error for CryptoError {}

pub(crate) fn random_secret(
    length: usize,
    policy: ProtectionPolicy,
    source: &mut impl RandomSource,
) -> Result<ProtectedMemory, CryptoError> {
    protected_random(length, policy, source).map_err(|error| match error {
        jury_protected::ProtectedRandomError::Entropy(_) => CryptoError::EntropyUnavailable,
        jury_protected::ProtectedRandomError::Memory(_) => CryptoError::MemoryProtection,
    })
}

pub(crate) fn generate_recipient_keypair(
    policy: ProtectionPolicy,
    source: &mut impl RandomSource,
) -> Result<(ProtectedMemory, RecipientPublicKey1216), CryptoError> {
    let seed = random_secret(32, policy, source)?;
    let capture = capture_after_process_protection(
        policy,
        seed.status().clone(),
        || -> Result<(ProtectedMemory, RecipientPublicKey1216), CryptoError> {
            seed.expose(|seed_bytes| {
                let seed_bytes: &[u8; 32] = seed_bytes
                    .try_into()
                    .map_err(|_| CryptoError::ProviderFailure)?;
                let mut rng = ChaCha20Rng::from_seed(*seed_bytes);
                let (private_key, public_key) = XWing::gen_keypair_with_rng(&mut rng);
                let private = ProtectedMemory::initialize(32, policy, |destination| {
                    private_key.write_exact(destination);
                    Ok::<usize, ()>(destination.len())
                })
                .map_err(|_| CryptoError::MemoryProtection)?;
                let mut public = [0_u8; 1_216];
                public_key.write_exact(&mut public);
                Ok((private, RecipientPublicKey1216::new(public)))
            })
            .map_err(|_| CryptoError::MemoryProtection)?
        },
    )
    .map_err(|_| CryptoError::MemoryProtection)?;
    capture.value
}

pub(crate) fn recipient_public_key_bytes(
    private_seed: &[u8],
) -> Result<RecipientPublicKey1216, CryptoError> {
    let private_key = <<XWing as Kem>::PrivateKey as Deserializable>::from_bytes(private_seed)
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let public_key = XWing::sk_to_pk(&private_key);
    let mut public = [0_u8; 1_216];
    public_key.write_exact(&mut public);
    Ok(RecipientPublicKey1216::new(public))
}

pub(crate) fn verification_public_key(
    signing_seed: &ProtectedMemory,
) -> Result<VerificationPublicKey32, CryptoError> {
    signing_seed
        .expose(verification_public_key_bytes)
        .map_err(|_| CryptoError::MemoryProtection)?
}

pub(crate) fn verification_public_key_bytes(
    signing_seed: &[u8],
) -> Result<VerificationPublicKey32, CryptoError> {
    let seed: &[u8; 32] = signing_seed
        .try_into()
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok(VerificationPublicKey32::new(
        SigningKey::from_bytes(seed).verifying_key().to_bytes(),
    ))
}

pub(crate) fn sign_bytes(signing_seed: &[u8], message: &[u8]) -> Result<Signature64, CryptoError> {
    let seed: &[u8; 32] = signing_seed
        .try_into()
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok(Signature64::new(
        SigningKey::from_bytes(seed).sign(message).to_bytes(),
    ))
}

pub(crate) fn verify_bytes(
    verification_key: &VerificationPublicKey32,
    message: &[u8],
    signature: &Signature64,
) -> Result<(), CryptoError> {
    let key = VerifyingKey::from_bytes(verification_key.as_bytes())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let signature = Signature::from_bytes(signature.as_bytes());
    key.verify_strict(message, &signature)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

pub(crate) fn derive_argon2_key(
    passphrase: &ProtectedMemory,
    profile: KdfProfile,
    salt: &[u8; 16],
) -> Result<ProtectedMemory, CryptoError> {
    let policy = passphrase.status().policy();
    let params = Params::new(profile.memory_kib(), 3, 4, Some(32))
        .map_err(|_| CryptoError::ProviderFailure)?;
    let block_count = params.block_count();
    let capture = capture_after_process_protection(
        policy,
        passphrase.status().clone(),
        || -> Result<ProtectedMemory, CryptoError> {
            let mut raw_blocks = Vec::new();
            raw_blocks
                .try_reserve_exact(block_count)
                .map_err(|_| CryptoError::ResourceUnavailable)?;
            raw_blocks.resize(block_count, Block::new());
            let mut blocks = Zeroizing::new(raw_blocks);
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            ProtectedMemory::initialize(32, policy, |output| {
                let derived = passphrase
                    .expose(|password| {
                        argon2.hash_password_into_with_memory(
                            password,
                            salt,
                            output,
                            blocks.as_mut_slice(),
                        )
                    })
                    .map_err(|_| ())?;
                derived.map_err(|_| ())?;
                Ok::<usize, ()>(output.len())
            })
            .map_err(|_| CryptoError::MemoryProtection)
        },
    )
    .map_err(|_| CryptoError::MemoryProtection)?;
    capture.value
}

pub(crate) fn derive_hkdf_key(
    secret: &ProtectedMemory,
    info: &[u8],
) -> Result<ProtectedMemory, CryptoError> {
    let policy = secret.status().policy();
    ProtectedMemory::initialize(32, policy, |output| {
        let expanded = secret
            .expose(|input| Hkdf::<Sha256>::new(Some(&[0_u8; 32]), input).expand(info, output))
            .map_err(|_| ())?;
        expanded.map_err(|_| ())?;
        Ok::<usize, ()>(output.len())
    })
    .map_err(|_| CryptoError::MemoryProtection)
}

pub(crate) fn seal(
    key: &ProtectedMemory,
    nonce: &Nonce12,
    aad: &[u8],
    plaintext: &ProtectedMemory,
) -> Result<Vec<u8>, CryptoError> {
    let mut ciphertext = Zeroizing::new(Vec::with_capacity(plaintext.len() + 16));
    plaintext
        .expose(|bytes| ciphertext.extend_from_slice(bytes))
        .map_err(|_| CryptoError::MemoryProtection)?;
    let tag = key
        .expose(|key_bytes| {
            let cipher = Aes256GcmSiv::new_from_slice(key_bytes)
                .map_err(|_| CryptoError::ProviderFailure)?;
            let provider_nonce: &Nonce = nonce
                .as_bytes()
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::ProviderFailure)?;
            cipher
                .encrypt_inout_detached(provider_nonce, aad, ciphertext.as_mut_slice().into())
                .map_err(|_| CryptoError::ProviderFailure)
        })
        .map_err(|_| CryptoError::MemoryProtection)??;
    ciphertext.extend_from_slice(tag.as_slice());
    Ok(ciphertext.to_vec())
}

pub(crate) fn open(
    key: &ProtectedMemory,
    nonce: &Nonce12,
    aad: &[u8],
    ciphertext: &[u8],
    plaintext_length: usize,
) -> Result<ProtectedMemory, CryptoError> {
    if ciphertext.len() != plaintext_length.saturating_add(16) {
        return Err(CryptoError::ProviderFailure);
    }
    let (body, tag_bytes) = ciphertext.split_at(plaintext_length);
    let mut initializer_error = CryptoError::AuthenticationFailed;
    let result =
        ProtectedMemory::initialize(plaintext_length, key.status().policy(), |destination| {
            destination.copy_from_slice(body);
            let opened = match key.expose(|key_bytes| {
                let cipher = Aes256GcmSiv::new_from_slice(key_bytes).map_err(|_| ())?;
                let provider_nonce: &Nonce =
                    nonce.as_bytes().as_slice().try_into().map_err(|_| ())?;
                let tag: &Tag = tag_bytes.try_into().map_err(|_| ())?;
                cipher
                    .decrypt_inout_detached(provider_nonce, aad, destination.into(), tag)
                    .map_err(|_| ())
            }) {
                Ok(opened) => opened,
                Err(_) => {
                    initializer_error = CryptoError::MemoryProtection;
                    return Err(());
                }
            };
            opened?;
            Ok::<usize, ()>(destination.len())
        });
    result.map_err(|error| match error.kind() {
        MemoryErrorKind::Initializer => initializer_error,
        _ => CryptoError::MemoryProtection,
    })
}

pub(crate) fn open_hpke(
    private_seed: &ProtectedMemory,
    encapsulation: &Encapsulation1120,
    ciphertext: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext_length: usize,
) -> Result<ProtectedMemory, CryptoError> {
    let encapsulation =
        <<XWing as Kem>::EncappedKey as Deserializable>::from_bytes(encapsulation.as_bytes())
            .map_err(|_| CryptoError::AuthenticationFailed)?;
    let policy = private_seed.status().policy();
    let capture = capture_after_process_protection(
        policy,
        private_seed.status().clone(),
        || -> Result<ProtectedMemory, CryptoError> {
            private_seed
                .expose(|private_bytes| {
                    let private =
                        <<XWing as Kem>::PrivateKey as Deserializable>::from_bytes(private_bytes)
                            .map_err(|_| CryptoError::AuthenticationFailed)?;
                    let opened = single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(
                        &OpModeR::Base,
                        &private,
                        &encapsulation,
                        info,
                        ciphertext,
                        aad,
                    )
                    .map_err(|_| CryptoError::AuthenticationFailed)?;
                    let opened = Zeroizing::new(opened);
                    if opened.len() != plaintext_length {
                        return Err(CryptoError::AuthenticationFailed);
                    }
                    ProtectedMemory::initialize(plaintext_length, policy, |destination| {
                        destination.copy_from_slice(&opened);
                        Ok::<usize, ()>(destination.len())
                    })
                    .map_err(|_| CryptoError::MemoryProtection)
                })
                .map_err(|_| CryptoError::MemoryProtection)?
        },
    )
    .map_err(|_| CryptoError::MemoryProtection)?;
    capture.value
}

pub(crate) fn seal_hpke(
    public_key: &RecipientPublicKey1216,
    plaintext: &ProtectedMemory,
    info: &[u8],
    aad: &[u8],
    source: &mut impl RandomSource,
) -> Result<(Encapsulation1120, Vec<u8>), CryptoError> {
    let public = <<XWing as Kem>::PublicKey as Deserializable>::from_bytes(public_key.as_bytes())
        .map_err(|_| CryptoError::ProviderFailure)?;
    let mut seed = [0_u8; 32];
    source
        .fill(&mut seed)
        .map_err(|_| CryptoError::EntropyUnavailable)?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    seed.zeroize();
    let policy = plaintext.status().policy();
    let capture = capture_after_process_protection(
        policy,
        plaintext.status().clone(),
        || -> Result<(Encapsulation1120, Vec<u8>), CryptoError> {
            plaintext
                .expose(|bytes| {
                    let (encapsulation, ciphertext) =
                        single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
                            &OpModeS::Base,
                            &public,
                            info,
                            bytes,
                            aad,
                            &mut rng,
                        )
                        .map_err(|_| CryptoError::ProviderFailure)?;
                    if ciphertext.len() != bytes.len().saturating_add(16) {
                        return Err(CryptoError::ProviderFailure);
                    }
                    let encapsulation = Encapsulation1120::from_slice(&encapsulation.to_bytes())
                        .map_err(|_| CryptoError::ProviderFailure)?;
                    Ok((encapsulation, ciphertext))
                })
                .map_err(|_| CryptoError::MemoryProtection)?
        },
    )
    .map_err(|_| CryptoError::MemoryProtection)?;
    capture.value
}

#[cfg(test)]
#[path = "crypto_tests.rs"]
mod tests;
