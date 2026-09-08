//! Single-message HPKE. Plaintext and failure scratch stay in protected memory.
use ::hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable,
    aead::{Aead, AeadTag, AesGcm256, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::XWing,
    rand_core::SeedableRng,
    single_shot_open_inout_detached, single_shot_seal_inout_detached_with_rng,
};
use chacha20::ChaCha20Rng;
use jury_protected::{
    MemoryErrorKind, ProtectedMemory, RandomSource, capture_after_process_protection,
};
use jury_protocol::{
    hpke_context::VaultSuite,
    vault_v1::{Encapsulation1120, RecipientPublicKey1216},
};
use zeroize::Zeroizing;

use super::CryptoError;

/// Identity/registration profile 1 remains fixed across vault suite migration.
pub(crate) fn open_hpke(
    private_seed: &ProtectedMemory,
    encapsulation: &Encapsulation1120,
    ciphertext: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext_length: usize,
) -> Result<ProtectedMemory, CryptoError> {
    open_hpke_for_suite(
        VaultSuite::Suite1,
        private_seed,
        encapsulation,
        ciphertext,
        info,
        aad,
        plaintext_length,
    )
}

pub(crate) fn open_hpke_for_suite(
    suite: VaultSuite,
    private_seed: &ProtectedMemory,
    encapsulation: &Encapsulation1120,
    ciphertext: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext_length: usize,
) -> Result<ProtectedMemory, CryptoError> {
    if !matches!(plaintext_length, 32 | 33) || ciphertext.len() != plaintext_length + 16 {
        return Err(CryptoError::AuthenticationFailed);
    }
    match suite {
        VaultSuite::Suite1 => open::<ChaCha20Poly1305>(
            private_seed,
            encapsulation,
            ciphertext,
            info,
            aad,
            plaintext_length,
        ),
        VaultSuite::Suite2 => open::<AesGcm256>(
            private_seed,
            encapsulation,
            ciphertext,
            info,
            aad,
            plaintext_length,
        ),
    }
}

fn open<A: Aead>(
    private_seed: &ProtectedMemory,
    encapsulation: &Encapsulation1120,
    ciphertext: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext_length: usize,
) -> Result<ProtectedMemory, CryptoError> {
    let encapsulation = <XWing as Kem>::EncappedKey::from_bytes(encapsulation.as_bytes())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let (body, tag) = ciphertext.split_at(plaintext_length);
    let tag = AeadTag::<A>::from_bytes(tag).map_err(|_| CryptoError::AuthenticationFailed)?;
    let policy = private_seed.status().policy();
    capture_after_process_protection(policy, private_seed.status().clone(), || {
        private_seed
            .expose(|bytes| {
                let private = <XWing as Kem>::PrivateKey::from_bytes(bytes)
                    .map_err(|_| CryptoError::AuthenticationFailed)?;
                ProtectedMemory::initialize(plaintext_length, policy, |destination| {
                    destination.copy_from_slice(body);
                    single_shot_open_inout_detached::<A, HkdfSha256, XWing>(
                        &OpModeR::Base,
                        &private,
                        &encapsulation,
                        info,
                        destination.into(),
                        aad,
                        &tag,
                    )
                    .map_err(|_| CryptoError::AuthenticationFailed)?;
                    Ok::<usize, CryptoError>(plaintext_length)
                })
                .map_err(|error| match error.kind() {
                    MemoryErrorKind::Initializer => CryptoError::AuthenticationFailed,
                    _ => CryptoError::MemoryProtection,
                })
            })
            .map_err(|_| CryptoError::MemoryProtection)?
    })
    .map_err(|_| CryptoError::MemoryProtection)?
    .value
}

/// Identity/registration profile 1 remains fixed across vault suite migration.
pub(crate) fn seal_hpke(
    public_key: &RecipientPublicKey1216,
    plaintext: &ProtectedMemory,
    info: &[u8],
    aad: &[u8],
    source: &mut (impl RandomSource + ?Sized),
) -> Result<(Encapsulation1120, Vec<u8>), CryptoError> {
    seal_hpke_for_suite(VaultSuite::Suite1, public_key, plaintext, info, aad, source)
}

pub(crate) fn seal_hpke_for_suite(
    suite: VaultSuite,
    public_key: &RecipientPublicKey1216,
    plaintext: &ProtectedMemory,
    info: &[u8],
    aad: &[u8],
    source: &mut (impl RandomSource + ?Sized),
) -> Result<(Encapsulation1120, Vec<u8>), CryptoError> {
    if !matches!(plaintext.len(), 32 | 33) {
        return Err(CryptoError::ProviderFailure);
    }
    let public = <XWing as Kem>::PublicKey::from_bytes(public_key.as_bytes())
        .map_err(|_| CryptoError::ProviderFailure)?;
    let mut seed = Zeroizing::new([0_u8; 32]);
    source
        .fill(seed.as_mut())
        .map_err(|_| CryptoError::EntropyUnavailable)?;
    let policy = plaintext.status().policy();
    capture_after_process_protection(policy, plaintext.status().clone(), || {
        let mut rng = ChaCha20Rng::from_seed(*seed);
        match suite {
            VaultSuite::Suite1 => seal::<ChaCha20Poly1305>(&public, plaintext, info, aad, &mut rng),
            VaultSuite::Suite2 => seal::<AesGcm256>(&public, plaintext, info, aad, &mut rng),
        }
    })
    .map_err(|_| CryptoError::MemoryProtection)?
    .value
}

fn seal<A: Aead>(
    public: &<XWing as Kem>::PublicKey,
    plaintext: &ProtectedMemory,
    info: &[u8],
    aad: &[u8],
    rng: &mut ChaCha20Rng,
) -> Result<(Encapsulation1120, Vec<u8>), CryptoError> {
    let mut ciphertext = Vec::new();
    ciphertext
        .try_reserve_exact(plaintext.len() + 16)
        .map_err(|_| CryptoError::ResourceUnavailable)?;
    let mut envelope = None;
    // No ordinary Vec ever contains plaintext, including on provider failure.
    let scratch = plaintext
        .expose(|bytes| {
            ProtectedMemory::initialize(bytes.len(), plaintext.status().policy(), |destination| {
                destination.copy_from_slice(bytes);
                envelope = Some(
                    single_shot_seal_inout_detached_with_rng::<A, HkdfSha256, XWing>(
                        &OpModeS::Base,
                        public,
                        info,
                        destination.into(),
                        aad,
                        rng,
                    )
                    .map_err(|_| CryptoError::ProviderFailure)?,
                );
                Ok::<usize, CryptoError>(bytes.len())
            })
            .map_err(|error| match error.kind() {
                MemoryErrorKind::Initializer => CryptoError::ProviderFailure,
                _ => CryptoError::MemoryProtection,
            })
        })
        .map_err(|_| CryptoError::MemoryProtection)??;
    let (encapsulation, tag) = envelope.ok_or(CryptoError::ProviderFailure)?;
    scratch
        .expose(|bytes| ciphertext.extend_from_slice(bytes))
        .map_err(|_| CryptoError::MemoryProtection)?;
    ciphertext.extend_from_slice(&tag.to_bytes());
    let encapsulation = Encapsulation1120::from_slice(&encapsulation.to_bytes())
        .map_err(|_| CryptoError::ProviderFailure)?;
    Ok((encapsulation, ciphertext))
}
