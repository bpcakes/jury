//! Portable passphrase-protected identity lifecycle.
//!
//! Private key bytes stay inside protected memory and are reachable only by
//! role-specific operations implemented in this crate.

use std::fmt;

use jury_protected::{OsRandom, ProtectedMemory, RandomSource};
use jury_protocol::witness_v1::WitnessContributionEnvelopeV1;
use jury_protocol::{
    identity_v1::{
        IdentityFileV1, IdentityFormatError, IdentityHeaderV1, KdfProfile, ProtectionMode,
        ProviderKind, ProviderMetadata,
    },
    vault_v1::{
        Digest32, DirectSlotV1, Encapsulation1120, FixedBytes, IdentityPayloadCiphertext149,
        ItemAccessMode, Nonce12, PrincipalDescriptorV1, PrincipalId as WirePrincipalId,
        PrincipalKind, RecipientPublicKey1216, ResponseId, RootWrapCiphertext48, Salt16,
        ShareCiphertext49, Signature64, WitnessShareCapsuleV1, recipient_public_key_fingerprint,
    },
};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::{
    crypto::{self, CryptoError},
    domain::{IdentifierGenerationError, NativeIdGenerator},
};

const PRIVATE_PAYLOAD_BYTES: usize = 133;
const RECIPIENT_SEED_RANGE: std::ops::Range<usize> = 37..69;
const SIGNING_SEED_RANGE: std::ops::Range<usize> = 69..101;
const LOCAL_SEED_RANGE: std::ops::Range<usize> = 101..133;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityErrorKind {
    Format,
    InvalidPassphrase,
    EntropyUnavailable,
    RetryExhausted,
    ResourceUnavailable,
    ProtectionUnavailable,
    ProviderFailure,
    AuthenticationFailed,
    KeyCollision,
    KdfDowngrade,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct IdentityError {
    kind: IdentityErrorKind,
}

impl IdentityError {
    #[must_use]
    pub const fn kind(self) -> IdentityErrorKind {
        self.kind
    }

    const fn new(kind: IdentityErrorKind) -> Self {
        Self { kind }
    }
}

impl fmt::Debug for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            IdentityErrorKind::Format => "identity format is invalid",
            IdentityErrorKind::InvalidPassphrase => "passphrase does not meet the exact profile",
            IdentityErrorKind::EntropyUnavailable => "operating-system entropy was unavailable",
            IdentityErrorKind::RetryExhausted => "identity generation exhausted its retry bound",
            IdentityErrorKind::ResourceUnavailable => {
                "identity protection resources are unavailable"
            }
            IdentityErrorKind::ProtectionUnavailable => {
                "required private-memory protection is unavailable"
            }
            IdentityErrorKind::ProviderFailure => "identity cryptographic provider failed",
            IdentityErrorKind::AuthenticationFailed => "identity authentication failed",
            IdentityErrorKind::KeyCollision => "identity key generation collided",
            IdentityErrorKind::KdfDowngrade => "identity KDF downgrade requires explicit approval",
        })
    }
}

impl std::error::Error for IdentityError {}

pub struct CreatedIdentity {
    pub file: IdentityFileV1,
    pub descriptor: PrincipalDescriptorV1,
}

pub struct ReplacedIdentity {
    pub previous_principal_id: WirePrincipalId,
    pub replacement: CreatedIdentity,
}

pub struct IdentityCreator<R = OsRandom> {
    source: R,
}

impl IdentityCreator<OsRandom> {
    #[must_use]
    pub const fn new() -> Self {
        Self { source: OsRandom }
    }
}

impl Default for IdentityCreator<OsRandom> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: RandomSource> IdentityCreator<R> {
    #[cfg(test)]
    pub(crate) fn from_source(source: R) -> Self {
        Self { source }
    }

    pub fn create(
        &mut self,
        kind: PrincipalKind,
        profile: KdfProfile,
        created_at_ms: u64,
        passphrase: &ProtectedMemory,
        mut principal_is_known: impl FnMut(&WirePrincipalId) -> bool,
    ) -> Result<CreatedIdentity, IdentityError> {
        validate_passphrase(passphrase)?;
        let principal_id = {
            let mut generator = NativeIdGenerator::from_source(&mut self.source);
            generator
                .generate_principal_id(|candidate| {
                    WirePrincipalId::from_bytes(*candidate.as_bytes())
                        .map_or(true, |wire| principal_is_known(&wire))
                })
                .map_err(map_identifier_error)?
        };
        let principal_id = WirePrincipalId::from_bytes(*principal_id.as_bytes())
            .map_err(|_| IdentityError::new(IdentityErrorKind::Format))?;
        let policy = passphrase.status().policy();
        let (recipient_seed, recipient_public_key) =
            crypto::generate_recipient_keypair(policy, &mut self.source)
                .map_err(map_crypto_error)?;
        let signing_seed =
            crypto::random_secret(32, policy, &mut self.source).map_err(map_crypto_error)?;
        let local_seed =
            crypto::random_secret(32, policy, &mut self.source).map_err(map_crypto_error)?;
        ensure_distinct_secrets(&recipient_seed, &signing_seed, &local_seed)?;
        let verification_public_key =
            crypto::verification_public_key(&signing_seed).map_err(map_crypto_error)?;
        let identity_root =
            crypto::random_secret(32, policy, &mut self.source).map_err(map_crypto_error)?;
        let salt = Salt16::new(fill_public(&mut self.source)?);
        let root_wrap_nonce = Nonce12::new(fill_public(&mut self.source)?);
        let payload_nonce = Nonce12::new(fill_public(&mut self.source)?);
        let mut header = IdentityHeaderV1 {
            identity_format: 1,
            principal_id,
            principal_kind: kind,
            recipient_public_key,
            verification_public_key,
            descriptor_fingerprint: FixedBytes::new([0; 32]),
            created_at_ms,
            kdf_profile: profile,
            argon2_version: 0x13,
            memory_kib: profile.memory_kib(),
            passes: 3,
            lanes: 4,
            salt,
            protection_mode: ProtectionMode::Portable,
            provider_kind: ProviderKind::new(Vec::new())
                .map_err(|_| IdentityError::new(IdentityErrorKind::Format))?,
            provider_metadata: ProviderMetadata::new(Vec::new())
                .map_err(|_| IdentityError::new(IdentityErrorKind::Format))?,
            root_wrap_algorithm: 1,
            root_wrap_nonce,
            payload_algorithm: 1,
            payload_nonce,
        };
        header.descriptor_fingerprint = header
            .recomputed_descriptor_fingerprint()
            .map_err(map_format_error)?;
        let payload = build_payload(&header, &recipient_seed, &signing_seed, &local_seed, policy)?;
        let file = seal_file(header, passphrase, &identity_root, &payload)?;
        let descriptor = descriptor_from_payload(&file.header, &payload)?;
        Ok(CreatedIdentity { file, descriptor })
    }

    pub fn replace(
        &mut self,
        current: &IdentityFileV1,
        profile: KdfProfile,
        created_at_ms: u64,
        passphrase: &ProtectedMemory,
        principal_is_known: impl FnMut(&WirePrincipalId) -> bool,
    ) -> Result<ReplacedIdentity, IdentityError> {
        current.validate().map_err(map_format_error)?;
        let previous_principal_id = current.header.principal_id;
        let replacement = self.create(
            current.header.principal_kind,
            profile,
            created_at_ms,
            passphrase,
            principal_is_known,
        )?;
        Ok(ReplacedIdentity {
            previous_principal_id,
            replacement,
        })
    }

    pub fn change_passphrase(
        &mut self,
        current: &IdentityFileV1,
        old_passphrase: &ProtectedMemory,
        new_passphrase: &ProtectedMemory,
        profile: KdfProfile,
        allow_kdf_downgrade: bool,
    ) -> Result<IdentityFileV1, IdentityError> {
        current.validate().map_err(map_format_error)?;
        if current.header.kdf_profile == KdfProfile::HardenedV1
            && profile == KdfProfile::PortableV1
            && !allow_kdf_downgrade
        {
            return Err(IdentityError::new(IdentityErrorKind::KdfDowngrade));
        }
        validate_passphrase(new_passphrase)?;
        let secrets = unlock_secrets(current, old_passphrase)?;
        let policy = new_passphrase.status().policy();
        let identity_root =
            crypto::random_secret(32, policy, &mut self.source).map_err(map_crypto_error)?;
        let mut header = current.header.clone();
        header.kdf_profile = profile;
        header.memory_kib = profile.memory_kib();
        header.salt = Salt16::new(fill_public(&mut self.source)?);
        header.root_wrap_nonce = Nonce12::new(fill_public(&mut self.source)?);
        header.payload_nonce = Nonce12::new(fill_public(&mut self.source)?);
        seal_file(header, new_passphrase, &identity_root, &secrets.payload)
    }
}

struct IdentitySecrets {
    header: IdentityHeaderV1,
    payload: ProtectedMemory,
}

impl fmt::Debug for IdentitySecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentitySecrets")
            .field("kind", &self.header.principal_kind)
            .field("principal_id", &self.header.principal_id)
            .field("private", &"[REDACTED]")
            .finish()
    }
}

impl IdentitySecrets {
    fn derive_local_state_key(&self, info: &[u8]) -> Result<ProtectedMemory, IdentityError> {
        let seed = payload_component(&self.payload, LOCAL_SEED_RANGE)?;
        crypto::derive_hkdf_key(&seed, info).map_err(map_crypto_error)
    }
}

pub struct VaultPrincipalIdentity(IdentitySecrets);
pub struct ApproverIdentity(IdentitySecrets);
pub struct WitnessIdentity(IdentitySecrets);

/// One revision-scoped direct secret which has no byte-export API.
pub(crate) struct ProtectedRevisionSecret {
    pub(crate) bytes: ProtectedMemory,
}

/// One revision-scoped witness share which has no byte-export API.
pub(crate) struct ProtectedWitnessShare {
    pub(crate) bytes: ProtectedMemory,
    witness_id: WirePrincipalId,
    witness_policy_digest: Digest32,
    share_commitment: Digest32,
    share_index: u8,
    context_digest: Digest32,
}

/// Request-bound context for releasing one encrypted witness share.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WitnessContributionTarget {
    pub request_digest: Digest32,
    pub action_manifest_digest: Digest32,
    pub response_id: ResponseId,
    pub checkpoint_digest: Digest32,
    pub capsule_set_digest: Digest32,
    pub session_public_key: RecipientPublicKey1216,
    pub session_fingerprint: Digest32,
    pub expires_at_ms: u64,
}

/// Exact J19 contribution envelope. Its plaintext share is not exportable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EncryptedWitnessContribution {
    pub response_id: ResponseId,
    pub share_index: u8,
    pub share_commitment: Digest32,
    pub context_digest: Digest32,
    pub capsule_set_digest: Digest32,
    pub session_fingerprint: Digest32,
    pub encapsulation: Encapsulation1120,
    pub ciphertext: ShareCiphertext49,
}

impl ProtectedRevisionSecret {
    pub(crate) fn memory(&self) -> &ProtectedMemory {
        &self.bytes
    }
}

impl ProtectedWitnessShare {
    /// Consumes the share into one request-session encrypted J19 envelope.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the engine uses the injected-randomness variant")
    )]
    pub(crate) fn seal_for_request(
        self,
        target: &WitnessContributionTarget,
    ) -> Result<EncryptedWitnessContribution, IdentityError> {
        self.seal_for_request_with_source(target, &mut OsRandom)
    }

    pub(crate) fn seal_for_request_with_source(
        self,
        target: &WitnessContributionTarget,
        source: &mut impl RandomSource,
    ) -> Result<EncryptedWitnessContribution, IdentityError> {
        if target.expires_at_ms == 0
            || target.session_fingerprint
                != recipient_public_key_fingerprint(&target.session_public_key)
        {
            return Err(IdentityError::new(IdentityErrorKind::Format));
        }
        let mut info = identity_jce("jury-witness-v1/contribution/info");
        info.extend_from_slice(target.request_digest.as_bytes());
        info.extend_from_slice(target.action_manifest_digest.as_bytes());
        info.extend_from_slice(target.response_id.as_bytes());
        info.extend_from_slice(self.witness_id.as_bytes());
        info.extend_from_slice(self.witness_policy_digest.as_bytes());
        info.extend_from_slice(target.checkpoint_digest.as_bytes());
        info.extend_from_slice(self.share_commitment.as_bytes());
        info.push(self.share_index);

        let mut aad = identity_jce("jury-witness-v1/contribution/aad");
        aad.extend_from_slice(target.capsule_set_digest.as_bytes());
        aad.extend_from_slice(self.context_digest.as_bytes());
        aad.extend_from_slice(target.session_fingerprint.as_bytes());
        aad.extend_from_slice(&target.expires_at_ms.to_be_bytes());
        let (encapsulation, ciphertext) =
            crypto::seal_hpke(&target.session_public_key, &self.bytes, &info, &aad, source)
                .map_err(map_crypto_error)?;
        Ok(EncryptedWitnessContribution {
            response_id: target.response_id,
            share_index: self.share_index,
            share_commitment: self.share_commitment,
            context_digest: self.context_digest,
            capsule_set_digest: target.capsule_set_digest.clone(),
            session_fingerprint: target.session_fingerprint.clone(),
            encapsulation,
            ciphertext: ShareCiphertext49::from_slice(&ciphertext)
                .map_err(|_| IdentityError::new(IdentityErrorKind::ProviderFailure))?,
        })
    }
}

impl EncryptedWitnessContribution {
    #[must_use]
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "covered by the public envelope")
    )]
    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(1_332);
        output.extend_from_slice(&1_u16.to_be_bytes());
        output.extend_from_slice(self.response_id.as_bytes());
        output.push(self.share_index);
        output.extend_from_slice(self.share_commitment.as_bytes());
        output.extend_from_slice(self.context_digest.as_bytes());
        output.extend_from_slice(self.capsule_set_digest.as_bytes());
        output.extend_from_slice(self.session_fingerprint.as_bytes());
        output.extend_from_slice(self.encapsulation.as_bytes());
        output.extend_from_slice(self.ciphertext.as_bytes());
        output
    }

    #[must_use]
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "covered by the public envelope")
    )]
    pub(crate) fn digest(&self) -> Digest32 {
        let envelope = self.canonical_bytes();
        let mut preimage = identity_jce("jury-witness-v1/contribution/hash");
        preimage.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
        preimage.extend_from_slice(&envelope);
        Digest32::new(Sha256::digest(preimage).into())
    }

    pub(crate) fn into_protocol(self) -> WitnessContributionEnvelopeV1 {
        WitnessContributionEnvelopeV1 {
            schema: 1,
            response_id: self.response_id,
            share_index: self.share_index,
            share_commitment: self.share_commitment,
            capsule_context_digest: self.context_digest,
            capsule_set_digest: self.capsule_set_digest,
            request_session_key_fingerprint: self.session_fingerprint,
            encapsulation: self.encapsulation,
            ciphertext: self.ciphertext,
        }
    }
}

impl fmt::Debug for ProtectedRevisionSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedRevisionSecret([REDACTED])")
    }
}

impl fmt::Debug for ProtectedWitnessShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedWitnessShare([REDACTED])")
    }
}

pub enum UnlockedIdentity {
    VaultPrincipal(VaultPrincipalIdentity),
    Approver(ApproverIdentity),
    Witness(WitnessIdentity),
}

impl fmt::Debug for UnlockedIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VaultPrincipal(identity) => formatter
                .debug_tuple("VaultPrincipal")
                .field(identity)
                .finish(),
            Self::Approver(identity) => formatter.debug_tuple("Approver").field(identity).finish(),
            Self::Witness(identity) => formatter.debug_tuple("Witness").field(identity).finish(),
        }
    }
}

macro_rules! role_identity {
    ($name:ident) => {
        impl $name {
            pub fn public_descriptor(&self) -> Result<PrincipalDescriptorV1, IdentityError> {
                descriptor_from_payload(&self.0.header, &self.0.payload)
            }

            #[must_use]
            pub const fn principal_id(&self) -> WirePrincipalId {
                self.0.header.principal_id
            }

            pub(crate) fn derive_local_state_key(
                &self,
                info: &[u8],
            ) -> Result<ProtectedMemory, IdentityError> {
                self.0.derive_local_state_key(info)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

role_identity!(VaultPrincipalIdentity);
role_identity!(ApproverIdentity);
role_identity!(WitnessIdentity);

impl VaultPrincipalIdentity {
    pub(crate) fn sign_validated_statement(
        &self,
        preimage: &[u8],
    ) -> Result<Signature64, IdentityError> {
        sign_payload_statement(&self.0.payload, preimage)
    }

    /// Opens one suite-1 direct slot bound to this exact identity.
    pub(crate) fn open_direct_slot(
        &self,
        slot: &DirectSlotV1,
    ) -> Result<ProtectedRevisionSecret, IdentityError> {
        if slot.slot_schema != 1
            || slot.slot_algorithm != 1
            || slot.suite != 1
            || slot.kem != 0x647a
            || slot.kdf != 1
            || slot.aead != 3
            || slot.revision == 0
            || !matches!(
                slot.item_access_mode,
                ItemAccessMode::DirectOnly | ItemAccessMode::Mixed
            )
        {
            return Err(IdentityError::new(IdentityErrorKind::Format));
        }
        if slot.recipient_principal_id != self.0.header.principal_id
            || slot.recipient_public_key_fingerprint
                != recipient_public_key_fingerprint(&self.0.header.recipient_public_key)
        {
            return Err(IdentityError::new(IdentityErrorKind::AuthenticationFailed));
        }
        let private_seed = payload_component(&self.0.payload, RECIPIENT_SEED_RANGE)?;
        let bytes = crypto::open_hpke(
            &private_seed,
            &slot.encapsulation,
            slot.ciphertext.as_bytes(),
            &slot.info_preimage(),
            &slot.aad_preimage(),
            32,
        )
        .map_err(map_crypto_error)?;
        Ok(ProtectedRevisionSecret { bytes })
    }
}

impl WitnessIdentity {
    pub(crate) fn sign_validated_decision(
        &self,
        preimage: &[u8],
    ) -> Result<Signature64, IdentityError> {
        sign_payload_statement(&self.0.payload, preimage)
    }

    /// Opens one exact J19 revision-scoped share without exporting its bytes.
    pub(crate) fn open_contribution_share(
        &self,
        capsule: &WitnessShareCapsuleV1,
    ) -> Result<ProtectedWitnessShare, IdentityError> {
        if capsule.capsule_schema != 1
            || capsule.protocol != 1
            || capsule.construction != 1
            || capsule.revision == 0
            || !(2..=32).contains(&capsule.member_count)
            || !(2..=capsule.member_count).contains(&capsule.threshold)
            || capsule.share_index == 0
            || capsule.share_index > capsule.member_count
            || !matches!(
                capsule.item_access_mode,
                ItemAccessMode::WitnessedOnly | ItemAccessMode::Mixed
            )
            || capsule.recomputed_context_digest() != capsule.context_digest
        {
            return Err(IdentityError::new(IdentityErrorKind::Format));
        }
        if capsule.witness_id != self.0.header.principal_id
            || capsule.contribution_key_fingerprint
                != recipient_public_key_fingerprint(&self.0.header.recipient_public_key)
        {
            return Err(IdentityError::new(IdentityErrorKind::AuthenticationFailed));
        }
        let private_seed = payload_component(&self.0.payload, RECIPIENT_SEED_RANGE)?;
        let share = crypto::open_hpke(
            &private_seed,
            &capsule.encapsulation,
            capsule.ciphertext.as_bytes(),
            &capsule.info_preimage(),
            &capsule.aad_preimage(),
            33,
        )
        .map_err(map_crypto_error)?;
        let commitment_matches = share
            .expose(|bytes| {
                let mut preimage = b"jury-witness-v1/share/commitment\0\0\x01".to_vec();
                preimage.extend_from_slice(capsule.context_digest.as_bytes());
                preimage.extend_from_slice(bytes);
                let digest: [u8; 32] = Sha256::digest(preimage).into();
                bool::from(digest.ct_eq(capsule.share_commitment.as_bytes()))
            })
            .map_err(|_| IdentityError::new(IdentityErrorKind::ProtectionUnavailable))?;
        if !commitment_matches {
            return Err(IdentityError::new(IdentityErrorKind::AuthenticationFailed));
        }
        Ok(ProtectedWitnessShare {
            bytes: share,
            witness_id: capsule.witness_id,
            witness_policy_digest: capsule.witness_policy_digest.clone(),
            share_commitment: capsule.share_commitment.clone(),
            share_index: capsule.share_index,
            context_digest: capsule.context_digest.clone(),
        })
    }
}

impl ApproverIdentity {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "J20 consumes the role-bound signing seam")
    )]
    pub(crate) fn sign_validated_approval(
        &self,
        preimage: &[u8],
    ) -> Result<Signature64, IdentityError> {
        sign_payload_statement(&self.0.payload, preimage)
    }
}

pub fn unlock(
    file: &IdentityFileV1,
    passphrase: &ProtectedMemory,
) -> Result<UnlockedIdentity, IdentityError> {
    let secrets = unlock_secrets(file, passphrase)?;
    Ok(match secrets.header.principal_kind {
        PrincipalKind::Human | PrincipalKind::Machine => {
            UnlockedIdentity::VaultPrincipal(VaultPrincipalIdentity(secrets))
        }
        PrincipalKind::Approver => UnlockedIdentity::Approver(ApproverIdentity(secrets)),
        PrincipalKind::Witness => UnlockedIdentity::Witness(WitnessIdentity(secrets)),
    })
}

pub fn validate_passphrase(passphrase: &ProtectedMemory) -> Result<(), IdentityError> {
    jury_protected::capture_after_process_protection(
        passphrase.status().policy(),
        passphrase.status().clone(),
        || (),
    )
    .map_err(|_| IdentityError::new(IdentityErrorKind::ProtectionUnavailable))?;
    let valid = passphrase
        .expose(|bytes| {
            (12..=1_024).contains(&bytes.len())
                && std::str::from_utf8(bytes).is_ok()
                && !bytes.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
        })
        .map_err(|_| IdentityError::new(IdentityErrorKind::ProtectionUnavailable))?;
    if valid {
        Ok(())
    } else {
        Err(IdentityError::new(IdentityErrorKind::InvalidPassphrase))
    }
}

fn unlock_secrets(
    file: &IdentityFileV1,
    passphrase: &ProtectedMemory,
) -> Result<IdentitySecrets, IdentityError> {
    file.validate().map_err(map_format_error)?;
    validate_passphrase(passphrase)?;
    let derived = crypto::derive_argon2_key(
        passphrase,
        file.header.kdf_profile,
        file.header.salt.as_bytes(),
    )
    .map_err(map_crypto_error)?;
    let wrap_key = crypto::derive_hkdf_key(&derived, &file.header.root_wrap_kdf_info())
        .map_err(map_crypto_error)?;
    let identity_root = crypto::open(
        &wrap_key,
        &file.header.root_wrap_nonce,
        &file.header.root_wrap_aad().map_err(map_format_error)?,
        file.root_wrap_ciphertext.as_bytes(),
        32,
    )
    .map_err(map_crypto_error)?;
    let payload_key = crypto::derive_hkdf_key(&identity_root, &file.header.payload_kdf_info())
        .map_err(map_crypto_error)?;
    let payload = crypto::open(
        &payload_key,
        &file.header.payload_nonce,
        &file.header.payload_aad().map_err(map_format_error)?,
        file.payload_ciphertext.as_bytes(),
        PRIVATE_PAYLOAD_BYTES,
    )
    .map_err(map_crypto_error)?;
    validate_payload(&file.header, &payload)?;
    Ok(IdentitySecrets {
        header: file.header.clone(),
        payload,
    })
}

fn build_payload(
    header: &IdentityHeaderV1,
    recipient_seed: &ProtectedMemory,
    signing_seed: &ProtectedMemory,
    local_seed: &ProtectedMemory,
    policy: jury_protected::ProtectionPolicy,
) -> Result<ProtectedMemory, IdentityError> {
    ProtectedMemory::initialize(PRIVATE_PAYLOAD_BYTES, policy, |output| {
        output[..2].copy_from_slice(&1_u16.to_be_bytes());
        output[2..4].copy_from_slice(&1_u16.to_be_bytes());
        output[4..36].copy_from_slice(header.principal_id.as_bytes());
        output[36] = principal_kind_tag(header.principal_kind);
        recipient_seed.expose(|bytes| output[RECIPIENT_SEED_RANGE].copy_from_slice(bytes))?;
        signing_seed.expose(|bytes| output[SIGNING_SEED_RANGE].copy_from_slice(bytes))?;
        local_seed.expose(|bytes| output[LOCAL_SEED_RANGE].copy_from_slice(bytes))?;
        Ok::<usize, jury_protected::MemoryError>(output.len())
    })
    .map_err(|_| IdentityError::new(IdentityErrorKind::ProtectionUnavailable))
}

fn payload_component(
    payload: &ProtectedMemory,
    range: std::ops::Range<usize>,
) -> Result<ProtectedMemory, IdentityError> {
    let policy = payload.status().policy();
    let length = range.len();
    ProtectedMemory::initialize(length, policy, |output| {
        payload.expose(|bytes| output.copy_from_slice(&bytes[range]))?;
        Ok::<usize, jury_protected::MemoryError>(output.len())
    })
    .map_err(|_| IdentityError::new(IdentityErrorKind::ProtectionUnavailable))
}

fn validate_payload(
    header: &IdentityHeaderV1,
    payload: &ProtectedMemory,
) -> Result<(), IdentityError> {
    let valid = payload
        .expose(|bytes| -> Result<bool, CryptoError> {
            if bytes.len() != PRIVATE_PAYLOAD_BYTES
                || bytes[..2] != 1_u16.to_be_bytes()
                || bytes[2..4] != 1_u16.to_be_bytes()
                || bytes[4..36] != *header.principal_id.as_bytes()
                || bytes[36] != principal_kind_tag(header.principal_kind)
            {
                return Ok(false);
            }
            let recipient = &bytes[RECIPIENT_SEED_RANGE];
            let signing = &bytes[SIGNING_SEED_RANGE];
            let local = &bytes[LOCAL_SEED_RANGE];
            let distinct = !(bool::from(recipient.ct_eq(signing))
                || bool::from(recipient.ct_eq(local))
                || bool::from(signing.ct_eq(local)));
            let recipient_matches =
                crypto::recipient_public_key_bytes(recipient)? == header.recipient_public_key;
            let signing_matches =
                crypto::verification_public_key_bytes(signing)? == header.verification_public_key;
            Ok(distinct && recipient_matches && signing_matches)
        })
        .map_err(|_| IdentityError::new(IdentityErrorKind::ProtectionUnavailable))?
        .map_err(map_crypto_error)?;
    if valid {
        Ok(())
    } else {
        Err(IdentityError::new(IdentityErrorKind::AuthenticationFailed))
    }
}

fn seal_file(
    header: IdentityHeaderV1,
    passphrase: &ProtectedMemory,
    identity_root: &ProtectedMemory,
    payload: &ProtectedMemory,
) -> Result<IdentityFileV1, IdentityError> {
    header
        .validate_for_active_release()
        .map_err(map_format_error)?;
    let derived = crypto::derive_argon2_key(passphrase, header.kdf_profile, header.salt.as_bytes())
        .map_err(map_crypto_error)?;
    let wrap_key = crypto::derive_hkdf_key(&derived, &header.root_wrap_kdf_info())
        .map_err(map_crypto_error)?;
    let root_wrap = crypto::seal(
        &wrap_key,
        &header.root_wrap_nonce,
        &header.root_wrap_aad().map_err(map_format_error)?,
        identity_root,
    )
    .map_err(map_crypto_error)?;
    let payload_key = crypto::derive_hkdf_key(identity_root, &header.payload_kdf_info())
        .map_err(map_crypto_error)?;
    let payload_ciphertext = crypto::seal(
        &payload_key,
        &header.payload_nonce,
        &header.payload_aad().map_err(map_format_error)?,
        payload,
    )
    .map_err(map_crypto_error)?;
    Ok(IdentityFileV1 {
        magic: "jury-identity".to_owned(),
        header,
        root_wrap_ciphertext: RootWrapCiphertext48::from_slice(&root_wrap)
            .map_err(|_| IdentityError::new(IdentityErrorKind::Format))?,
        payload_ciphertext: IdentityPayloadCiphertext149::from_slice(&payload_ciphertext)
            .map_err(|_| IdentityError::new(IdentityErrorKind::Format))?,
    })
}

fn descriptor_from_payload(
    header: &IdentityHeaderV1,
    payload: &ProtectedMemory,
) -> Result<PrincipalDescriptorV1, IdentityError> {
    let mut descriptor = PrincipalDescriptorV1 {
        descriptor_version: 1,
        principal_id: header.principal_id,
        principal_kind: header.principal_kind,
        recipient_public_key: header.recipient_public_key.clone(),
        verification_public_key: header.verification_public_key.clone(),
        self_signature: Signature64::new([0; 64]),
    };
    let preimage = descriptor
        .self_signature_preimage()
        .map_err(|_| IdentityError::new(IdentityErrorKind::Format))?;
    descriptor.self_signature = payload
        .expose(|bytes| crypto::sign_bytes(&bytes[SIGNING_SEED_RANGE], &preimage))
        .map_err(|_| IdentityError::new(IdentityErrorKind::ProtectionUnavailable))?
        .map_err(map_crypto_error)?;
    Ok(descriptor)
}

#[cfg(test)]
pub(crate) fn unlocked_identity_for_test(
    principal_id: WirePrincipalId,
    principal_kind: PrincipalKind,
    source: &mut impl RandomSource,
) -> Result<UnlockedIdentity, IdentityError> {
    let policy = jury_protected::ProtectionPolicy::Strict;
    let (recipient_seed, recipient_public_key) =
        crypto::generate_recipient_keypair(policy, source).map_err(map_crypto_error)?;
    let signing_seed = crypto::random_secret(32, policy, source).map_err(map_crypto_error)?;
    let local_seed = crypto::random_secret(32, policy, source).map_err(map_crypto_error)?;
    ensure_distinct_secrets(&recipient_seed, &signing_seed, &local_seed)?;
    let verification_public_key =
        crypto::verification_public_key(&signing_seed).map_err(map_crypto_error)?;
    let header = IdentityHeaderV1 {
        identity_format: 1,
        principal_id,
        principal_kind,
        recipient_public_key,
        verification_public_key,
        descriptor_fingerprint: Digest32::new([1; 32]),
        created_at_ms: 1,
        kdf_profile: KdfProfile::PortableV1,
        argon2_version: 0x13,
        memory_kib: KdfProfile::PortableV1.memory_kib(),
        passes: 3,
        lanes: 4,
        salt: Salt16::new([1; 16]),
        protection_mode: ProtectionMode::Portable,
        provider_kind: ProviderKind::new(Vec::new())
            .map_err(|_| IdentityError::new(IdentityErrorKind::Format))?,
        provider_metadata: ProviderMetadata::new(Vec::new())
            .map_err(|_| IdentityError::new(IdentityErrorKind::Format))?,
        root_wrap_algorithm: 1,
        root_wrap_nonce: Nonce12::new([1; 12]),
        payload_algorithm: 1,
        payload_nonce: Nonce12::new([2; 12]),
    };
    let payload = build_payload(&header, &recipient_seed, &signing_seed, &local_seed, policy)?;
    let secrets = IdentitySecrets { header, payload };
    Ok(match principal_kind {
        PrincipalKind::Human | PrincipalKind::Machine => {
            UnlockedIdentity::VaultPrincipal(VaultPrincipalIdentity(secrets))
        }
        PrincipalKind::Approver => UnlockedIdentity::Approver(ApproverIdentity(secrets)),
        PrincipalKind::Witness => UnlockedIdentity::Witness(WitnessIdentity(secrets)),
    })
}

fn sign_payload_statement(
    payload: &ProtectedMemory,
    preimage: &[u8],
) -> Result<Signature64, IdentityError> {
    if preimage.is_empty() || preimage.len() > 1024 * 1024 {
        return Err(IdentityError::new(IdentityErrorKind::Format));
    }
    payload
        .expose(|bytes| crypto::sign_bytes(&bytes[SIGNING_SEED_RANGE], preimage))
        .map_err(|_| IdentityError::new(IdentityErrorKind::ProtectionUnavailable))?
        .map_err(map_crypto_error)
}

fn ensure_distinct_secrets(
    recipient: &ProtectedMemory,
    signing: &ProtectedMemory,
    local: &ProtectedMemory,
) -> Result<(), IdentityError> {
    let recipient_signing = protected_equal(recipient, signing)?;
    let recipient_local = protected_equal(recipient, local)?;
    let signing_local = protected_equal(signing, local)?;
    if recipient_signing || recipient_local || signing_local {
        Err(IdentityError::new(IdentityErrorKind::KeyCollision))
    } else {
        Ok(())
    }
}

fn protected_equal(left: &ProtectedMemory, right: &ProtectedMemory) -> Result<bool, IdentityError> {
    left.expose(|left_bytes| right.expose(|right_bytes| bool::from(left_bytes.ct_eq(right_bytes))))
        .map_err(|_| IdentityError::new(IdentityErrorKind::ProtectionUnavailable))?
        .map_err(|_| IdentityError::new(IdentityErrorKind::ProtectionUnavailable))
}

fn fill_public<const N: usize>(source: &mut impl RandomSource) -> Result<[u8; N], IdentityError> {
    let mut output = [0_u8; N];
    source
        .fill(&mut output)
        .map_err(|_| IdentityError::new(IdentityErrorKind::EntropyUnavailable))?;
    Ok(output)
}

const fn principal_kind_tag(kind: PrincipalKind) -> u8 {
    match kind {
        PrincipalKind::Human => 1,
        PrincipalKind::Machine => 2,
        PrincipalKind::Approver => 3,
        PrincipalKind::Witness => 4,
    }
}

const fn map_identifier_error(error: IdentifierGenerationError) -> IdentityError {
    match error {
        IdentifierGenerationError::EntropyUnavailable => {
            IdentityError::new(IdentityErrorKind::EntropyUnavailable)
        }
        IdentifierGenerationError::RetryExhausted => {
            IdentityError::new(IdentityErrorKind::RetryExhausted)
        }
    }
}

const fn map_crypto_error(error: CryptoError) -> IdentityError {
    let kind = match error {
        CryptoError::EntropyUnavailable => IdentityErrorKind::EntropyUnavailable,
        CryptoError::MemoryProtection => IdentityErrorKind::ProtectionUnavailable,
        CryptoError::ResourceUnavailable => IdentityErrorKind::ResourceUnavailable,
        CryptoError::ProviderFailure => IdentityErrorKind::ProviderFailure,
        CryptoError::AuthenticationFailed => IdentityErrorKind::AuthenticationFailed,
    };
    IdentityError::new(kind)
}

const fn map_format_error(_: IdentityFormatError) -> IdentityError {
    IdentityError::new(IdentityErrorKind::Format)
}

fn identity_jce(domain: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(domain.len() + 3);
    output.extend_from_slice(domain.as_bytes());
    output.extend_from_slice(&[0, 0, 1]);
    output
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;
