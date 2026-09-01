//! Bounded public envelope for portable Jury identity files.
//!
//! Identity ciphertexts are local private state and never belong in a vault
//! artifact, transfer, receipt, or witness message.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::artifact::{self, JsonError};
use crate::canonical::{self, jce_v1 as jce};
use crate::vault_v1::{
    BoundedBytes, Digest32, FixedBytes, IdentityPayloadCiphertext149, Nonce12,
    PrincipalDescriptorV1, PrincipalId, PrincipalKind, RecipientPublicKey1216,
    RootWrapCiphertext48, Salt16, Signature64, VerificationPublicKey32,
};

pub const MAX_IDENTITY_FILE_BYTES: usize = 64 * 1024;
pub const MAX_PROVIDER_KIND_BYTES: usize = 128;
pub const MAX_PROVIDER_METADATA_BYTES: usize = 4 * 1024;

pub type ProviderKind = BoundedBytes<MAX_PROVIDER_KIND_BYTES>;
pub type ProviderMetadata = BoundedBytes<MAX_PROVIDER_METADATA_BYTES>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KdfProfile {
    PortableV1,
    HardenedV1,
}

impl KdfProfile {
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::PortableV1 => 1,
            Self::HardenedV1 => 2,
        }
    }

    #[must_use]
    pub const fn memory_kib(self) -> u32 {
        match self {
            Self::PortableV1 => 131_072,
            Self::HardenedV1 => 524_288,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionMode {
    Portable,
    DeviceBound,
}

impl ProtectionMode {
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Portable => 1,
            Self::DeviceBound => 2,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityHeaderV1 {
    pub identity_format: u16,
    pub principal_id: PrincipalId,
    pub principal_kind: PrincipalKind,
    pub recipient_public_key: RecipientPublicKey1216,
    pub verification_public_key: VerificationPublicKey32,
    pub descriptor_fingerprint: Digest32,
    pub created_at_ms: u64,
    pub kdf_profile: KdfProfile,
    pub argon2_version: u8,
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
    pub salt: Salt16,
    pub protection_mode: ProtectionMode,
    pub provider_kind: ProviderKind,
    pub provider_metadata: ProviderMetadata,
    pub root_wrap_algorithm: u8,
    pub root_wrap_nonce: Nonce12,
    pub payload_algorithm: u8,
    pub payload_nonce: Nonce12,
}

impl IdentityHeaderV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IdentityFormatError> {
        let mut output =
            Vec::with_capacity(1_388 + self.provider_kind.len() + self.provider_metadata.len());
        output.extend_from_slice(&self.identity_format.to_be_bytes());
        output.extend_from_slice(self.principal_id.as_bytes());
        output.push(self.principal_kind.tag());
        output.extend_from_slice(self.recipient_public_key.as_bytes());
        output.extend_from_slice(self.verification_public_key.as_bytes());
        output.extend_from_slice(self.descriptor_fingerprint.as_bytes());
        output.extend_from_slice(&self.created_at_ms.to_be_bytes());
        output.push(self.kdf_profile.tag());
        output.push(self.argon2_version);
        output.extend_from_slice(&self.memory_kib.to_be_bytes());
        output.extend_from_slice(&self.passes.to_be_bytes());
        output.extend_from_slice(&self.lanes.to_be_bytes());
        output.extend_from_slice(self.salt.as_bytes());
        output.push(self.protection_mode.tag());
        bytes_field(&mut output, self.provider_kind.as_bytes())?;
        bytes_field(&mut output, self.provider_metadata.as_bytes())?;
        output.push(self.root_wrap_algorithm);
        output.extend_from_slice(self.root_wrap_nonce.as_bytes());
        output.push(self.payload_algorithm);
        output.extend_from_slice(self.payload_nonce.as_bytes());
        Ok(output)
    }

    pub fn hash_preimage(&self) -> Result<Vec<u8>, IdentityFormatError> {
        let header = self.canonical_bytes()?;
        let mut output = jce("jury-v1/identity-header/hash");
        bytes_field(&mut output, &header)?;
        Ok(output)
    }

    pub fn recomputed_digest(&self) -> Result<Digest32, IdentityFormatError> {
        Ok(FixedBytes::new(
            Sha256::digest(self.hash_preimage()?).into(),
        ))
    }

    #[must_use]
    pub fn root_wrap_kdf_info(&self) -> Vec<u8> {
        let mut output = jce("jury-v1/kdf/identity-root-wrap");
        output.extend_from_slice(&self.identity_format.to_be_bytes());
        output.extend_from_slice(self.principal_id.as_bytes());
        output.push(self.protection_mode.tag());
        output
    }

    #[must_use]
    pub fn payload_kdf_info(&self) -> Vec<u8> {
        let mut output = jce("jury-v1/kdf/identity-payload");
        output.extend_from_slice(&self.identity_format.to_be_bytes());
        output.extend_from_slice(self.principal_id.as_bytes());
        output
    }

    pub fn root_wrap_aad(&self) -> Result<Vec<u8>, IdentityFormatError> {
        self.role_aad("jury-v1/identity-root-wrap/aad", 1)
    }

    pub fn payload_aad(&self) -> Result<Vec<u8>, IdentityFormatError> {
        self.role_aad("jury-v1/identity-payload/aad", 2)
    }

    fn role_aad(&self, domain: &str, role: u8) -> Result<Vec<u8>, IdentityFormatError> {
        let mut output = jce(domain);
        output.extend_from_slice(&self.identity_format.to_be_bytes());
        output.extend_from_slice(self.recomputed_digest()?.as_bytes());
        output.push(role);
        Ok(output)
    }

    pub fn recomputed_descriptor_fingerprint(&self) -> Result<Digest32, IdentityFormatError> {
        let descriptor = PrincipalDescriptorV1 {
            descriptor_version: 1,
            principal_id: self.principal_id,
            principal_kind: self.principal_kind,
            recipient_public_key: self.recipient_public_key.clone(),
            verification_public_key: self.verification_public_key.clone(),
            self_signature: Signature64::new([0; 64]),
        };
        Ok(FixedBytes::new(
            Sha256::digest(descriptor.fingerprint_preimage()?).into(),
        ))
    }

    pub fn validate_for_active_release(&self) -> Result<(), IdentityFormatError> {
        if self.identity_format != 1
            || self.argon2_version != 0x13
            || self.passes != 3
            || self.lanes != 4
            || self.memory_kib != self.kdf_profile.memory_kib()
            || self.protection_mode != ProtectionMode::Portable
            || !self.provider_kind.is_empty()
            || !self.provider_metadata.is_empty()
            || self.root_wrap_algorithm != 1
            || self.payload_algorithm != 1
        {
            return Err(IdentityFormatError::UnsupportedProfile);
        }
        if self.recomputed_descriptor_fingerprint()? != self.descriptor_fingerprint {
            return Err(IdentityFormatError::DescriptorMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityFileV1 {
    pub magic: String,
    pub header: IdentityHeaderV1,
    pub root_wrap_ciphertext: RootWrapCiphertext48,
    pub payload_ciphertext: IdentityPayloadCiphertext149,
}

impl IdentityFileV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, IdentityFormatError> {
        artifact::validate_json_input(bytes, MAX_IDENTITY_FILE_BYTES).map_err(map_json_error)?;
        let identity: Self = artifact::deserialize_json(bytes).map_err(map_json_error)?;
        identity.validate()?;
        if identity.to_json_bytes()? != bytes {
            return Err(IdentityFormatError::NonCanonicalJson);
        }
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), IdentityFormatError> {
        if self.magic != "jury-identity" {
            return Err(IdentityFormatError::UnknownMagic);
        }
        self.header.validate_for_active_release()
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, IdentityFormatError> {
        self.validate()?;
        artifact::pretty_json_bytes(self, MAX_IDENTITY_FILE_BYTES).map_err(map_json_error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityFormatError {
    ArtifactTooLarge,
    ConflictMarker,
    InvalidJson,
    NonCanonicalJson,
    UnknownMagic,
    UnsupportedProfile,
    DescriptorMismatch,
    CanonicalEncoding,
}

impl fmt::Display for IdentityFormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ArtifactTooLarge => "identity file exceeds its public size bound",
            Self::ConflictMarker => "identity file contains a conflict marker",
            Self::InvalidJson => "identity file JSON is invalid",
            Self::NonCanonicalJson => "identity file JSON is not canonical",
            Self::UnknownMagic => "identity file magic is unknown",
            Self::UnsupportedProfile => "identity protection profile is unsupported",
            Self::DescriptorMismatch => "identity public descriptor differs",
            Self::CanonicalEncoding => "identity canonical encoding is invalid",
        })
    }
}

impl std::error::Error for IdentityFormatError {}

const fn map_json_error(error: JsonError) -> IdentityFormatError {
    match error {
        JsonError::ArtifactTooLarge => IdentityFormatError::ArtifactTooLarge,
        JsonError::ConflictMarker => IdentityFormatError::ConflictMarker,
        JsonError::InvalidJson => IdentityFormatError::InvalidJson,
    }
}

impl From<crate::vault_v1::CanonicalError> for IdentityFormatError {
    fn from(_: crate::vault_v1::CanonicalError) -> Self {
        Self::CanonicalEncoding
    }
}

fn bytes_field(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), IdentityFormatError> {
    canonical::bytes_field(output, bytes).map_err(|_| IdentityFormatError::CanonicalEncoding)
}
