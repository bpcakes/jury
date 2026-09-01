//! Bounded authenticated Jury transfer envelope version 1.
//!
//! A transfer carries only the complete encrypted shared vault artifact and
//! the bounded public policy material required to validate it. Private
//! identities and installation-local state have no field in this format.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::artifact::{self, JsonError};
use crate::vault_v1::{
    BoundedBytes, Digest32, FixedBytes, MAX_VAULT_BYTES, PrincipalId, Signature64, VaultFileV1,
    VaultId,
};

/// Maximum encoded transfer file size accepted before JSON parsing.
pub const MAX_TRANSFER_BYTES: usize = 32 * 1024 * 1024;
/// Maximum canonical public policy catalog carried beside the vault.
pub const MAX_TRANSFER_CATALOG_BYTES: usize = 2 * 1024 * 1024;

pub type TransferVaultBytes = BoundedBytes<MAX_VAULT_BYTES>;
pub type TransferCatalogBytes = BoundedBytes<MAX_TRANSFER_CATALOG_BYTES>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferEnvelopeV1 {
    pub magic: String,
    pub version: u16,
    pub transfer_id: Digest32,
    pub created_at_ms: u64,
    pub source_vault_id: VaultId,
    pub source_genesis_fingerprint: Digest32,
    pub source_public_revision_hash: Digest32,
    pub vault_digest: Digest32,
    pub catalog_digest: Digest32,
    pub exporting_principal_id: PrincipalId,
    pub vault_json: TransferVaultBytes,
    pub public_catalog_json: TransferCatalogBytes,
    pub exporter_signature: Signature64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferFormatError {
    ArtifactTooLarge,
    ConflictMarker,
    InvalidJson,
    NonCanonicalJson,
    Invalid(&'static str),
}

impl fmt::Display for TransferFormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactTooLarge => formatter.write_str("transfer artifact exceeds 32 MiB"),
            Self::ConflictMarker => {
                formatter.write_str("transfer artifact contains a conflict marker")
            }
            Self::InvalidJson => formatter.write_str("invalid transfer JSON"),
            Self::NonCanonicalJson => formatter.write_str("transfer JSON is not canonical"),
            Self::Invalid(reason) => write!(formatter, "invalid transfer format: {reason}"),
        }
    }
}

impl std::error::Error for TransferFormatError {}

const fn map_json_error(error: JsonError) -> TransferFormatError {
    match error {
        JsonError::ArtifactTooLarge => TransferFormatError::ArtifactTooLarge,
        JsonError::ConflictMarker => TransferFormatError::ConflictMarker,
        JsonError::InvalidJson => TransferFormatError::InvalidJson,
    }
}

impl TransferEnvelopeV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, TransferFormatError> {
        artifact::validate_json_input(bytes, MAX_TRANSFER_BYTES).map_err(map_json_error)?;
        let envelope: Self = artifact::deserialize_json(bytes).map_err(map_json_error)?;
        envelope.validate_shape()?;
        if envelope.to_json_bytes()? != bytes {
            return Err(TransferFormatError::NonCanonicalJson);
        }
        Ok(envelope)
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, TransferFormatError> {
        self.validate_shape()?;
        artifact::pretty_json_bytes(self, MAX_TRANSFER_BYTES).map_err(map_json_error)
    }

    /// Typed signature input. JSON serialization is deliberately excluded.
    #[must_use]
    pub fn signature_preimage(&self) -> Vec<u8> {
        let mut output = b"jury-transfer-v1/envelope/signature\0\0\x01".to_vec();
        output.extend_from_slice(&self.version.to_be_bytes());
        output.extend_from_slice(self.transfer_id.as_bytes());
        output.extend_from_slice(&self.created_at_ms.to_be_bytes());
        output.extend_from_slice(self.source_vault_id.as_bytes());
        output.extend_from_slice(self.source_genesis_fingerprint.as_bytes());
        output.extend_from_slice(self.source_public_revision_hash.as_bytes());
        output.extend_from_slice(self.vault_digest.as_bytes());
        output.extend_from_slice(self.catalog_digest.as_bytes());
        output.extend_from_slice(self.exporting_principal_id.as_bytes());
        output
    }

    fn validate_shape(&self) -> Result<(), TransferFormatError> {
        if self.magic != "jury-transfer" || self.version != 1 {
            return Err(TransferFormatError::Invalid("unknown magic or version"));
        }
        if self.created_at_ms == 0
            || is_zero(&self.transfer_id)
            || is_zero(&self.source_genesis_fingerprint)
            || is_zero(&self.source_public_revision_hash)
            || is_zero(&self.vault_digest)
            || is_zero(&self.catalog_digest)
            || self.vault_json.is_empty()
            || self.public_catalog_json.is_empty()
        {
            return Err(TransferFormatError::Invalid("required field is empty"));
        }
        if sha256(self.vault_json.as_bytes()) != self.vault_digest
            || sha256(self.public_catalog_json.as_bytes()) != self.catalog_digest
        {
            return Err(TransferFormatError::Invalid("payload digest differs"));
        }
        let vault = VaultFileV1::parse(self.vault_json.as_bytes())
            .map_err(|_| TransferFormatError::Invalid("inner vault is invalid"))?;
        let terminal = vault
            .policy
            .revisions
            .last()
            .map(|revision| revision.recomputed_hash())
            .transpose()
            .map_err(|_| TransferFormatError::Invalid("inner revision is invalid"))?
            .unwrap_or_else(|| vault.header.genesis_fingerprint.clone());
        if vault.header.vault_id != self.source_vault_id
            || vault.header.genesis_fingerprint != self.source_genesis_fingerprint
            || terminal != self.source_public_revision_hash
        {
            return Err(TransferFormatError::Invalid("source metadata differs"));
        }
        Ok(())
    }
}

fn sha256(bytes: &[u8]) -> Digest32 {
    FixedBytes::new(Sha256::digest(bytes).into())
}

fn is_zero(digest: &Digest32) -> bool {
    digest.as_bytes().iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_truncation_conflict_markers_and_oversize_before_use() {
        assert_eq!(
            TransferEnvelopeV1::parse(br#"{"magic":"jury-transfer""#),
            Err(TransferFormatError::InvalidJson)
        );
        assert_eq!(
            TransferEnvelopeV1::parse(b"<<<<<<< current\n{}\n=======\n{}\n>>>>>>> incoming\n"),
            Err(TransferFormatError::ConflictMarker)
        );
        assert_eq!(
            TransferEnvelopeV1::parse(&vec![b' '; MAX_TRANSFER_BYTES + 1]),
            Err(TransferFormatError::ArtifactTooLarge)
        );
    }
}
