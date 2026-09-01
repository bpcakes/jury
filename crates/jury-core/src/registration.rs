//! Bounded proof-of-possession artifacts for principal registration.
//!
//! A challenge encrypts one random response independently to the candidate and
//! the acting owner. The proof publishes only an HMAC of the response and a
//! candidate signature. Possessing only the candidate signing key or only the
//! public challenge is therefore insufficient to register the recipient key.

use std::fmt;

use jury_protected::{OsRandom, ProtectedMemory, ProtectionPolicy, RandomSource};
use jury_protocol::vault_v1::{
    Digest32, DirectCiphertext48, Encapsulation1120, PrincipalDescriptorV1, PrincipalId,
    PrincipalKind, Signature64, VaultId, recipient_public_key_fingerprint,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize as _;

use crate::canonical;
use crate::crypto;
use crate::identity::{UnlockedIdentity, VaultPrincipalIdentity};
use crate::policy::{
    ApprovalMode, ApproverPolicyDescriptor, DescriptorStatus, PolicyState, WitnessOperation,
    WitnessPolicyDescriptor, signing_key_fingerprint,
};

const CHALLENGE_VERSION: u16 = 1;
const PROOF_VERSION: u16 = 1;
const MAX_REGISTRATION_ARTIFACT_BYTES: usize = 16 * 1024;
const MAX_CHALLENGE_LIFETIME_MS: u64 = 24 * 60 * 60 * 1_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "role", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RegistrationRoleProfileV1 {
    VaultPrincipal,
    Approver,
    Witness { share_index: u8 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "role", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RegistrationRoleDescriptorV1 {
    VaultPrincipal,
    Approver {
        descriptor: ApproverPolicyDescriptor,
    },
    Witness {
        descriptor: Box<WitnessPolicyDescriptor>,
    },
}

impl RegistrationRoleDescriptorV1 {
    #[must_use]
    pub const fn principal_id(&self) -> Option<PrincipalId> {
        match self {
            Self::VaultPrincipal => None,
            Self::Approver { descriptor } => Some(descriptor.approver_id),
            Self::Witness { descriptor } => Some(descriptor.witness_id),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationErrorKind {
    InvalidArtifact,
    InvalidDescriptor,
    Unauthorized,
    WrongCandidate,
    Expired,
    EntropyUnavailable,
    ProtectionUnavailable,
    AuthenticationFailed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RegistrationError {
    kind: RegistrationErrorKind,
}

impl RegistrationError {
    const fn new(kind: RegistrationErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> RegistrationErrorKind {
        self.kind
    }
}

impl fmt::Debug for RegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistrationError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RegistrationErrorKind::InvalidArtifact => "registration artifact is invalid",
            RegistrationErrorKind::InvalidDescriptor => "principal descriptor is invalid",
            RegistrationErrorKind::Unauthorized => "registration owner is unauthorized",
            RegistrationErrorKind::WrongCandidate => "registration candidate differs",
            RegistrationErrorKind::Expired => "registration challenge expired",
            RegistrationErrorKind::EntropyUnavailable => "registration entropy is unavailable",
            RegistrationErrorKind::ProtectionUnavailable => {
                "registration protected memory is unavailable"
            }
            RegistrationErrorKind::AuthenticationFailed => {
                "registration proof authentication failed"
            }
        })
    }
}

impl std::error::Error for RegistrationError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationChallengeV1 {
    pub version: u16,
    pub vault_id: VaultId,
    pub genesis_fingerprint: Digest32,
    pub owner_principal_id: PrincipalId,
    pub candidate_descriptor: PrincipalDescriptorV1,
    pub role_profile: RegistrationRoleProfileV1,
    pub challenge_id: Digest32,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub candidate_encapsulation: Encapsulation1120,
    pub candidate_ciphertext: DirectCiphertext48,
    pub owner_encapsulation: Encapsulation1120,
    pub owner_ciphertext: DirectCiphertext48,
    pub owner_signature: Signature64,
}

impl RegistrationChallengeV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, RegistrationError> {
        canonical::validate_json_input(bytes, MAX_REGISTRATION_ARTIFACT_BYTES)
            .map_err(|_| RegistrationError::new(RegistrationErrorKind::InvalidArtifact))?;
        let artifact: Self = canonical::deserialize_json(bytes)
            .map_err(|_| RegistrationError::new(RegistrationErrorKind::InvalidArtifact))?;
        if artifact.to_json_bytes()? != bytes {
            return Err(RegistrationError::new(
                RegistrationErrorKind::InvalidArtifact,
            ));
        }
        artifact.validate_shape()?;
        Ok(artifact)
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, RegistrationError> {
        canonical::compact_json_bytes(self, Some(MAX_REGISTRATION_ARTIFACT_BYTES))
            .map_err(|_| RegistrationError::new(RegistrationErrorKind::InvalidArtifact))
    }

    pub fn digest(&self) -> Result<Digest32, RegistrationError> {
        let mut bytes = domain("jury-v1/registration-challenge/digest");
        bytes.extend_from_slice(&self.signed_preimage()?);
        bytes.extend_from_slice(self.owner_signature.as_bytes());
        Ok(Digest32::new(Sha256::digest(bytes).into()))
    }

    fn signed_preimage(&self) -> Result<Vec<u8>, RegistrationError> {
        self.validate_shape()?;
        let mut bytes = domain("jury-v1/registration-challenge/signature");
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(self.vault_id.as_bytes());
        bytes.extend_from_slice(self.genesis_fingerprint.as_bytes());
        bytes.extend_from_slice(self.owner_principal_id.as_bytes());
        bytes.extend_from_slice(&self.candidate_descriptor.canonical_bytes());
        append_bounded_json(&mut bytes, &self.role_profile)?;
        bytes.extend_from_slice(self.challenge_id.as_bytes());
        bytes.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        bytes.extend_from_slice(self.candidate_encapsulation.as_bytes());
        bytes.extend_from_slice(self.candidate_ciphertext.as_bytes());
        bytes.extend_from_slice(self.owner_encapsulation.as_bytes());
        bytes.extend_from_slice(self.owner_ciphertext.as_bytes());
        Ok(bytes)
    }

    fn capsule_context(&self, recipient: u8) -> Result<(Vec<u8>, Vec<u8>), RegistrationError> {
        capsule_context(
            &CapsuleContextBinding {
                vault_id: self.vault_id,
                genesis_fingerprint: &self.genesis_fingerprint,
                owner_principal_id: self.owner_principal_id,
                candidate_descriptor: &self.candidate_descriptor,
                role_profile: &self.role_profile,
                challenge_id: &self.challenge_id,
                issued_at_ms: self.issued_at_ms,
                expires_at_ms: self.expires_at_ms,
            },
            recipient,
        )
    }

    fn validate_shape(&self) -> Result<(), RegistrationError> {
        if self.version != CHALLENGE_VERSION
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms.saturating_sub(self.issued_at_ms) > MAX_CHALLENGE_LIFETIME_MS
        {
            return Err(RegistrationError::new(
                RegistrationErrorKind::InvalidArtifact,
            ));
        }
        validate_descriptor(&self.candidate_descriptor)?;
        match (
            &self.candidate_descriptor.principal_kind,
            &self.role_profile,
        ) {
            (
                PrincipalKind::Human | PrincipalKind::Machine,
                RegistrationRoleProfileV1::VaultPrincipal,
            )
            | (PrincipalKind::Approver, RegistrationRoleProfileV1::Approver)
            | (
                PrincipalKind::Witness,
                RegistrationRoleProfileV1::Witness {
                    share_index: 1..=32,
                },
            ) => Ok(()),
            _ => Err(RegistrationError::new(
                RegistrationErrorKind::InvalidDescriptor,
            )),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationProofV1 {
    pub version: u16,
    pub challenge: RegistrationChallengeV1,
    pub challenge_digest: Digest32,
    pub candidate_principal_id: PrincipalId,
    pub role_descriptor: RegistrationRoleDescriptorV1,
    pub response_mac: Digest32,
    pub created_at_ms: u64,
    pub candidate_signature: Signature64,
}

impl RegistrationProofV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, RegistrationError> {
        canonical::validate_json_input(bytes, MAX_REGISTRATION_ARTIFACT_BYTES)
            .map_err(|_| RegistrationError::new(RegistrationErrorKind::InvalidArtifact))?;
        let artifact: Self = canonical::deserialize_json(bytes)
            .map_err(|_| RegistrationError::new(RegistrationErrorKind::InvalidArtifact))?;
        if artifact.to_json_bytes()? != bytes
            || artifact.version != PROOF_VERSION
            || artifact.challenge.digest()? != artifact.challenge_digest
        {
            return Err(RegistrationError::new(
                RegistrationErrorKind::InvalidArtifact,
            ));
        }
        validate_role_descriptor(
            &artifact.challenge.candidate_descriptor,
            &artifact.challenge.role_profile,
            &artifact.role_descriptor,
        )?;
        Ok(artifact)
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, RegistrationError> {
        canonical::compact_json_bytes(self, Some(MAX_REGISTRATION_ARTIFACT_BYTES))
            .map_err(|_| RegistrationError::new(RegistrationErrorKind::InvalidArtifact))
    }

    pub fn digest(&self) -> Result<Digest32, RegistrationError> {
        let mut bytes = domain("jury-v1/registration-proof/digest");
        bytes.extend_from_slice(&self.signed_preimage()?);
        bytes.extend_from_slice(self.candidate_signature.as_bytes());
        Ok(Digest32::new(Sha256::digest(bytes).into()))
    }

    fn signed_preimage(&self) -> Result<Vec<u8>, RegistrationError> {
        if self.version != PROOF_VERSION {
            return Err(RegistrationError::new(
                RegistrationErrorKind::InvalidArtifact,
            ));
        }
        let mut bytes = domain("jury-v1/registration-proof/signature");
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(self.challenge_digest.as_bytes());
        bytes.extend_from_slice(self.candidate_principal_id.as_bytes());
        append_bounded_json(&mut bytes, &self.role_descriptor)?;
        bytes.extend_from_slice(self.response_mac.as_bytes());
        bytes.extend_from_slice(&self.created_at_ms.to_be_bytes());
        Ok(bytes)
    }
}

pub struct RegistrationCreator<R = OsRandom> {
    source: R,
    protection: ProtectionPolicy,
}

impl RegistrationCreator<OsRandom> {
    #[must_use]
    pub const fn new(protection: ProtectionPolicy) -> Self {
        Self {
            source: OsRandom,
            protection,
        }
    }
}

impl<R: RandomSource> RegistrationCreator<R> {
    pub fn create_challenge(
        &mut self,
        policy: &PolicyState,
        owner: &VaultPrincipalIdentity,
        candidate_descriptor: PrincipalDescriptorV1,
        issued_at_ms: u64,
        lifetime_ms: u64,
        witness_share_index: Option<u8>,
    ) -> Result<RegistrationChallengeV1, RegistrationError> {
        validate_descriptor(&candidate_descriptor)?;
        if !policy.is_owner(&owner.principal_id()) {
            return Err(RegistrationError::new(RegistrationErrorKind::Unauthorized));
        }
        if policy.principal_id_was_used(&candidate_descriptor.principal_id)
            || policy.principals().any(|(_, principal)| {
                principal.descriptor.recipient_public_key
                    == candidate_descriptor.recipient_public_key
                    || principal.descriptor.verification_public_key
                        == candidate_descriptor.verification_public_key
            })
        {
            return Err(RegistrationError::new(
                RegistrationErrorKind::InvalidDescriptor,
            ));
        }
        if lifetime_ms == 0 || lifetime_ms > MAX_CHALLENGE_LIFETIME_MS {
            return Err(RegistrationError::new(
                RegistrationErrorKind::InvalidArtifact,
            ));
        }
        let expires_at_ms = issued_at_ms
            .checked_add(lifetime_ms)
            .ok_or_else(|| RegistrationError::new(RegistrationErrorKind::InvalidArtifact))?;
        let challenge_id = random_nonzero_digest(&mut self.source)?;
        let role_profile = match candidate_descriptor.principal_kind {
            PrincipalKind::Human | PrincipalKind::Machine => {
                if witness_share_index.is_some() {
                    return Err(RegistrationError::new(
                        RegistrationErrorKind::InvalidDescriptor,
                    ));
                }
                RegistrationRoleProfileV1::VaultPrincipal
            }
            PrincipalKind::Approver => {
                if witness_share_index.is_some() {
                    return Err(RegistrationError::new(
                        RegistrationErrorKind::InvalidDescriptor,
                    ));
                }
                RegistrationRoleProfileV1::Approver
            }
            PrincipalKind::Witness => RegistrationRoleProfileV1::Witness {
                share_index: witness_share_index
                    .filter(|index| (1..=32).contains(index))
                    .ok_or_else(|| {
                        RegistrationError::new(RegistrationErrorKind::InvalidDescriptor)
                    })?,
            },
        };
        let response = random_secret(&mut self.source, self.protection)?;
        let owner_descriptor = owner
            .public_descriptor()
            .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
        let binding = CapsuleContextBinding {
            vault_id: policy.vault_id(),
            genesis_fingerprint: policy.genesis_fingerprint(),
            owner_principal_id: owner.principal_id(),
            candidate_descriptor: &candidate_descriptor,
            role_profile: &role_profile,
            challenge_id: &challenge_id,
            issued_at_ms,
            expires_at_ms,
        };
        let (candidate_info, candidate_aad) = capsule_context(&binding, 1)?;
        let (owner_info, owner_aad) = capsule_context(&binding, 2)?;
        let (candidate_encapsulation, candidate_ciphertext) = crypto::seal_hpke(
            &candidate_descriptor.recipient_public_key,
            &response,
            &candidate_info,
            &candidate_aad,
            &mut self.source,
        )
        .map_err(map_crypto_error)?;
        let (owner_encapsulation, owner_ciphertext) = crypto::seal_hpke(
            &owner_descriptor.recipient_public_key,
            &response,
            &owner_info,
            &owner_aad,
            &mut self.source,
        )
        .map_err(map_crypto_error)?;
        let mut challenge = RegistrationChallengeV1 {
            version: CHALLENGE_VERSION,
            vault_id: policy.vault_id(),
            genesis_fingerprint: policy.genesis_fingerprint().clone(),
            owner_principal_id: owner.principal_id(),
            candidate_descriptor,
            role_profile,
            challenge_id,
            issued_at_ms,
            expires_at_ms,
            candidate_encapsulation,
            candidate_ciphertext: DirectCiphertext48::from_slice(&candidate_ciphertext)
                .map_err(|_| RegistrationError::new(RegistrationErrorKind::InvalidArtifact))?,
            owner_encapsulation,
            owner_ciphertext: DirectCiphertext48::from_slice(&owner_ciphertext)
                .map_err(|_| RegistrationError::new(RegistrationErrorKind::InvalidArtifact))?,
            owner_signature: Signature64::new([0; 64]),
        };
        challenge.owner_signature = owner
            .sign_validated_statement(&challenge.signed_preimage()?)
            .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
        Ok(challenge)
    }
}

pub fn answer_challenge(
    policy: &PolicyState,
    identity: &UnlockedIdentity,
    challenge: &RegistrationChallengeV1,
    now_ms: u64,
) -> Result<RegistrationProofV1, RegistrationError> {
    challenge.validate_shape()?;
    if challenge.vault_id != policy.vault_id()
        || challenge.genesis_fingerprint != *policy.genesis_fingerprint()
        || now_ms < challenge.issued_at_ms
        || now_ms > challenge.expires_at_ms
    {
        return Err(RegistrationError::new(RegistrationErrorKind::Expired));
    }
    let owner = policy
        .principal(&challenge.owner_principal_id)
        .filter(|_| policy.is_owner(&challenge.owner_principal_id))
        .ok_or_else(|| RegistrationError::new(RegistrationErrorKind::Unauthorized))?;
    crypto::verify_bytes(
        &owner.descriptor.verification_public_key,
        &challenge.signed_preimage()?,
        &challenge.owner_signature,
    )
    .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
    let descriptor = identity
        .public_descriptor()
        .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
    if descriptor != challenge.candidate_descriptor {
        return Err(RegistrationError::new(
            RegistrationErrorKind::WrongCandidate,
        ));
    }
    let (info, aad) = challenge.capsule_context(1)?;
    let response = identity
        .open_registration_capsule(
            &challenge.candidate_encapsulation,
            challenge.candidate_ciphertext.as_bytes(),
            &info,
            &aad,
        )
        .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
    let challenge_digest = challenge.digest()?;
    let response_mac = response_mac(&response, &challenge_digest)?;
    let role_descriptor = create_role_descriptor(
        identity,
        &descriptor,
        &challenge.role_profile,
        challenge.issued_at_ms,
    )?;
    let mut proof = RegistrationProofV1 {
        version: PROOF_VERSION,
        challenge: challenge.clone(),
        challenge_digest,
        candidate_principal_id: descriptor.principal_id,
        role_descriptor,
        response_mac,
        created_at_ms: now_ms,
        candidate_signature: Signature64::new([0; 64]),
    };
    proof.candidate_signature = identity
        .sign_registration_statement(&proof.signed_preimage()?)
        .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
    Ok(proof)
}

pub fn verify_proof(
    policy: &PolicyState,
    owner: &VaultPrincipalIdentity,
    challenge: &RegistrationChallengeV1,
    proof: &RegistrationProofV1,
    now_ms: u64,
) -> Result<Digest32, RegistrationError> {
    challenge.validate_shape()?;
    if !policy.is_owner(&owner.principal_id())
        || challenge.owner_principal_id != owner.principal_id()
        || challenge.vault_id != policy.vault_id()
        || challenge.genesis_fingerprint != *policy.genesis_fingerprint()
    {
        return Err(RegistrationError::new(RegistrationErrorKind::Unauthorized));
    }
    if now_ms < challenge.issued_at_ms || now_ms > challenge.expires_at_ms {
        return Err(RegistrationError::new(RegistrationErrorKind::Expired));
    }
    let owner_descriptor = owner
        .public_descriptor()
        .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
    crypto::verify_bytes(
        &owner_descriptor.verification_public_key,
        &challenge.signed_preimage()?,
        &challenge.owner_signature,
    )
    .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
    let challenge_digest = challenge.digest()?;
    if proof.version != PROOF_VERSION
        || proof.challenge != *challenge
        || proof.challenge_digest != challenge_digest
        || proof.candidate_principal_id != challenge.candidate_descriptor.principal_id
        || proof.created_at_ms < challenge.issued_at_ms
        || proof.created_at_ms > now_ms
    {
        return Err(RegistrationError::new(
            RegistrationErrorKind::InvalidArtifact,
        ));
    }
    validate_role_descriptor(
        &challenge.candidate_descriptor,
        &challenge.role_profile,
        &proof.role_descriptor,
    )?;
    crypto::verify_bytes(
        &challenge.candidate_descriptor.verification_public_key,
        &proof.signed_preimage()?,
        &proof.candidate_signature,
    )
    .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
    let (info, aad) = challenge.capsule_context(2)?;
    let response = owner
        .open_registration_capsule(
            &challenge.owner_encapsulation,
            challenge.owner_ciphertext.as_bytes(),
            &info,
            &aad,
        )
        .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
    let expected = response_mac(&response, &challenge_digest)?;
    if expected != proof.response_mac {
        return Err(RegistrationError::new(
            RegistrationErrorKind::AuthenticationFailed,
        ));
    }
    proof.digest()
}

fn validate_descriptor(descriptor: &PrincipalDescriptorV1) -> Result<(), RegistrationError> {
    if descriptor.descriptor_version != 1 {
        return Err(RegistrationError::new(
            RegistrationErrorKind::InvalidDescriptor,
        ));
    }
    crypto::verify_bytes(
        &descriptor.verification_public_key,
        &descriptor
            .self_signature_preimage()
            .map_err(|_| RegistrationError::new(RegistrationErrorKind::InvalidDescriptor))?,
        &descriptor.self_signature,
    )
    .map_err(|_| RegistrationError::new(RegistrationErrorKind::InvalidDescriptor))
}

fn create_role_descriptor(
    identity: &UnlockedIdentity,
    principal: &PrincipalDescriptorV1,
    profile: &RegistrationRoleProfileV1,
    created_at_ms: u64,
) -> Result<RegistrationRoleDescriptorV1, RegistrationError> {
    match profile {
        RegistrationRoleProfileV1::VaultPrincipal => {
            Ok(RegistrationRoleDescriptorV1::VaultPrincipal)
        }
        RegistrationRoleProfileV1::Approver => {
            let allowed_operations = vec![
                WitnessOperation::ReadStdout,
                WitnessOperation::WritePrivateFile,
                WitnessOperation::TemplateInjection,
                WitnessOperation::ChildEnvironment,
                WitnessOperation::ChildStdin,
                WitnessOperation::ItemMutation,
                WitnessOperation::Backup,
                WitnessOperation::Recovery,
                WitnessOperation::AdministrativeRekey,
            ];
            let mut descriptor = ApproverPolicyDescriptor {
                schema: 1,
                approver_id: principal.principal_id,
                signing_public_key: principal.verification_public_key.clone(),
                signing_key_fingerprint: signing_key_fingerprint(
                    2,
                    &principal.principal_id,
                    1,
                    &principal.verification_public_key,
                ),
                signing_key_epoch: 1,
                status: DescriptorStatus::Active,
                approval_mode: ApprovalMode::Human,
                allowed_operations,
                created_at_ms,
                self_signature: Signature64::new([0; 64]),
            };
            descriptor.self_signature = identity
                .sign_registration_statement(&descriptor.self_signature_preimage().map_err(
                    |_| RegistrationError::new(RegistrationErrorKind::InvalidDescriptor),
                )?)
                .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
            Ok(RegistrationRoleDescriptorV1::Approver { descriptor })
        }
        RegistrationRoleProfileV1::Witness { share_index } => {
            let mut descriptor = WitnessPolicyDescriptor {
                schema: 1,
                witness_id: principal.principal_id,
                share_index: *share_index,
                signing_public_key: principal.verification_public_key.clone(),
                signing_key_fingerprint: signing_key_fingerprint(
                    3,
                    &principal.principal_id,
                    1,
                    &principal.verification_public_key,
                ),
                signing_key_epoch: 1,
                contribution_public_key: principal.recipient_public_key.clone(),
                contribution_key_fingerprint: recipient_public_key_fingerprint(
                    &principal.recipient_public_key,
                ),
                contribution_key_epoch: 1,
                status: DescriptorStatus::Active,
                created_at_ms,
                self_signature: Signature64::new([0; 64]),
            };
            descriptor.self_signature = identity
                .sign_registration_statement(&descriptor.self_signature_preimage().map_err(
                    |_| RegistrationError::new(RegistrationErrorKind::InvalidDescriptor),
                )?)
                .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
            Ok(RegistrationRoleDescriptorV1::Witness {
                descriptor: Box::new(descriptor),
            })
        }
    }
}

fn validate_role_descriptor(
    principal: &PrincipalDescriptorV1,
    profile: &RegistrationRoleProfileV1,
    role: &RegistrationRoleDescriptorV1,
) -> Result<(), RegistrationError> {
    let valid = match (profile, role) {
        (
            RegistrationRoleProfileV1::VaultPrincipal,
            RegistrationRoleDescriptorV1::VaultPrincipal,
        ) => matches!(
            principal.principal_kind,
            PrincipalKind::Human | PrincipalKind::Machine
        ),
        (
            RegistrationRoleProfileV1::Approver,
            RegistrationRoleDescriptorV1::Approver { descriptor },
        ) => {
            principal.principal_kind == PrincipalKind::Approver
                && descriptor.approver_id == principal.principal_id
                && descriptor.signing_public_key == principal.verification_public_key
                && descriptor.validate().is_ok()
        }
        (
            RegistrationRoleProfileV1::Witness { share_index },
            RegistrationRoleDescriptorV1::Witness { descriptor },
        ) => {
            principal.principal_kind == PrincipalKind::Witness
                && descriptor.witness_id == principal.principal_id
                && descriptor.share_index == *share_index
                && descriptor.signing_public_key == principal.verification_public_key
                && descriptor.contribution_public_key == principal.recipient_public_key
                && descriptor.validate().is_ok()
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(RegistrationError::new(
            RegistrationErrorKind::InvalidDescriptor,
        ))
    }
}

fn append_bounded_json(
    output: &mut Vec<u8>,
    value: &impl Serialize,
) -> Result<(), RegistrationError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| RegistrationError::new(RegistrationErrorKind::InvalidArtifact))?;
    let length = u32::try_from(bytes.len())
        .map_err(|_| RegistrationError::new(RegistrationErrorKind::InvalidArtifact))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(&bytes);
    Ok(())
}

struct CapsuleContextBinding<'a> {
    vault_id: VaultId,
    genesis_fingerprint: &'a Digest32,
    owner_principal_id: PrincipalId,
    candidate_descriptor: &'a PrincipalDescriptorV1,
    role_profile: &'a RegistrationRoleProfileV1,
    challenge_id: &'a Digest32,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

fn capsule_context(
    binding: &CapsuleContextBinding<'_>,
    recipient: u8,
) -> Result<(Vec<u8>, Vec<u8>), RegistrationError> {
    let mut info = domain("jury-v1/registration-challenge/capsule-info");
    info.extend_from_slice(binding.vault_id.as_bytes());
    info.extend_from_slice(binding.genesis_fingerprint.as_bytes());
    info.extend_from_slice(binding.owner_principal_id.as_bytes());
    info.extend_from_slice(binding.candidate_descriptor.principal_id.as_bytes());
    let role_bytes = serde_json::to_vec(binding.role_profile)
        .map_err(|_| RegistrationError::new(RegistrationErrorKind::InvalidArtifact))?;
    let role_length = u32::try_from(role_bytes.len())
        .map_err(|_| RegistrationError::new(RegistrationErrorKind::InvalidArtifact))?;
    info.extend_from_slice(&role_length.to_be_bytes());
    info.extend_from_slice(&role_bytes);
    info.extend_from_slice(binding.challenge_id.as_bytes());
    info.push(recipient);
    let mut aad = domain("jury-v1/registration-challenge/capsule-aad");
    aad.extend_from_slice(&binding.candidate_descriptor.canonical_bytes());
    aad.extend_from_slice(&binding.issued_at_ms.to_be_bytes());
    aad.extend_from_slice(&binding.expires_at_ms.to_be_bytes());
    aad.push(recipient);
    Ok((info, aad))
}

fn response_mac(
    response: &ProtectedMemory,
    challenge_digest: &Digest32,
) -> Result<Digest32, RegistrationError> {
    let mut message = domain("jury-v1/registration-proof/response-mac");
    message.extend_from_slice(challenge_digest.as_bytes());
    Ok(Digest32::new(
        crypto::hmac_sha256(response, &message).map_err(map_crypto_error)?,
    ))
}

fn random_secret(
    source: &mut impl RandomSource,
    protection: ProtectionPolicy,
) -> Result<ProtectedMemory, RegistrationError> {
    let mut bytes = [0_u8; 32];
    source
        .fill(&mut bytes)
        .map_err(|_| RegistrationError::new(RegistrationErrorKind::EntropyUnavailable))?;
    let result = ProtectedMemory::initialize(32, protection, |destination| {
        destination.copy_from_slice(&bytes);
        Ok::<usize, ()>(destination.len())
    })
    .map_err(|_| RegistrationError::new(RegistrationErrorKind::ProtectionUnavailable));
    bytes.zeroize();
    result
}

fn random_nonzero_digest(source: &mut impl RandomSource) -> Result<Digest32, RegistrationError> {
    for _ in 0..8 {
        let mut bytes = [0_u8; 32];
        source
            .fill(&mut bytes)
            .map_err(|_| RegistrationError::new(RegistrationErrorKind::EntropyUnavailable))?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(Digest32::new(bytes));
        }
    }
    Err(RegistrationError::new(
        RegistrationErrorKind::EntropyUnavailable,
    ))
}

fn map_crypto_error(error: crypto::CryptoError) -> RegistrationError {
    match error {
        crypto::CryptoError::EntropyUnavailable => {
            RegistrationError::new(RegistrationErrorKind::EntropyUnavailable)
        }
        crypto::CryptoError::MemoryProtection => {
            RegistrationError::new(RegistrationErrorKind::ProtectionUnavailable)
        }
        _ => RegistrationError::new(RegistrationErrorKind::AuthenticationFailed),
    }
}

fn domain(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut output = b"JCE1".to_vec();
    output.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    output.extend_from_slice(bytes);
    output
}
