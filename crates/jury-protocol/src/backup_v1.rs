//! Bounded binary envelope for Jury owner-recovery backups.
//!
//! The public header is parsed and profile-checked before callers capture a
//! passphrase or allocate Argon2 memory. The encrypted body fills one exact
//! public size bucket; its authenticated plaintext carries its own logical
//! length followed only by zero padding.

use std::fmt;

use sha2::{Digest as _, Sha256};

use crate::{
    canonical::{self, jce_v1 as jce},
    identity_v1::KdfProfile,
    vault_v1::{Digest32, Nonce12, PrincipalId, RecoveryId, Salt16, VaultId},
};

pub const MAX_BACKUP_ENVELOPE_BYTES: usize = 64 * 1024 * 1024;
pub const BACKUP_BUCKET_BYTES: [usize; 5] = [
    4 * 1024 * 1024,
    8 * 1024 * 1024,
    16 * 1024 * 1024,
    32 * 1024 * 1024,
    MAX_BACKUP_ENVELOPE_BYTES,
];
pub const BACKUP_HEADER_BYTES: usize = 282;
pub const BACKUP_PREFIX_BYTES: usize = BACKUP_MAGIC.len() + BACKUP_HEADER_BYTES;
pub const AEAD_TAG_BYTES: usize = 16;

const BACKUP_MAGIC: &[u8; 16] = b"JURY-BACKUP-V1\0\0";
const ZERO_DIGEST: [u8; 32] = [0; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupHeaderV1 {
    pub backup_format: u16,
    pub backup_id: RecoveryId,
    pub created_at_ms: u64,
    pub vault_id: VaultId,
    pub genesis_fingerprint: Digest32,
    pub source_public_revision_hash: Digest32,
    pub owner_principal_id: PrincipalId,
    pub owner_descriptor_fingerprint: Digest32,
    pub kdf_profile: KdfProfile,
    pub argon2_version: u8,
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
    pub salt: Salt16,
    pub storage_algorithm: u8,
    pub nonce: Nonce12,
    pub target_bucket_id: u8,
    pub payload_ciphertext_length: u32,
    pub payload_digest: Digest32,
}

impl BackupHeaderV1 {
    pub fn validate(&self) -> Result<(), BackupFormatError> {
        let bucket = bucket_bytes(self.target_bucket_id)?;
        let expected_ciphertext = bucket
            .checked_sub(BACKUP_PREFIX_BYTES)
            .ok_or(BackupFormatError::InvalidBucket)?;
        if self.backup_format != 1
            || self.created_at_ms == 0
            || self.genesis_fingerprint.as_bytes() == &ZERO_DIGEST
            || self.source_public_revision_hash.as_bytes() == &ZERO_DIGEST
            || self.owner_descriptor_fingerprint.as_bytes() == &ZERO_DIGEST
            || self.payload_digest.as_bytes() == &ZERO_DIGEST
            || self.argon2_version != 0x13
            || self.memory_kib != self.kdf_profile.memory_kib()
            || self.passes != 3
            || self.lanes != 4
            || self.storage_algorithm != 1
            || usize::try_from(self.payload_ciphertext_length).ok() != Some(expected_ciphertext)
            || expected_ciphertext <= AEAD_TAG_BYTES
        {
            return Err(BackupFormatError::UnsupportedProfile);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<[u8; BACKUP_HEADER_BYTES], BackupFormatError> {
        self.validate()?;
        let mut output = [0_u8; BACKUP_HEADER_BYTES];
        let mut cursor = 0;
        put(&mut output, &mut cursor, &self.backup_format.to_be_bytes())?;
        put(&mut output, &mut cursor, self.backup_id.as_bytes())?;
        put(&mut output, &mut cursor, &self.created_at_ms.to_be_bytes())?;
        put(&mut output, &mut cursor, self.vault_id.as_bytes())?;
        put(
            &mut output,
            &mut cursor,
            self.genesis_fingerprint.as_bytes(),
        )?;
        put(
            &mut output,
            &mut cursor,
            self.source_public_revision_hash.as_bytes(),
        )?;
        put(&mut output, &mut cursor, self.owner_principal_id.as_bytes())?;
        put(
            &mut output,
            &mut cursor,
            self.owner_descriptor_fingerprint.as_bytes(),
        )?;
        put(&mut output, &mut cursor, &[self.kdf_profile.tag()])?;
        put(&mut output, &mut cursor, &[self.argon2_version])?;
        put(&mut output, &mut cursor, &self.memory_kib.to_be_bytes())?;
        put(&mut output, &mut cursor, &self.passes.to_be_bytes())?;
        put(&mut output, &mut cursor, &self.lanes.to_be_bytes())?;
        put(&mut output, &mut cursor, self.salt.as_bytes())?;
        put(&mut output, &mut cursor, &[self.storage_algorithm])?;
        put(&mut output, &mut cursor, self.nonce.as_bytes())?;
        put(&mut output, &mut cursor, &[self.target_bucket_id])?;
        put(
            &mut output,
            &mut cursor,
            &self.payload_ciphertext_length.to_be_bytes(),
        )?;
        put(&mut output, &mut cursor, self.payload_digest.as_bytes())?;
        if cursor != BACKUP_HEADER_BYTES {
            return Err(BackupFormatError::CanonicalEncoding);
        }
        Ok(output)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, BackupFormatError> {
        if bytes.len() != BACKUP_HEADER_BYTES {
            return Err(BackupFormatError::InvalidLength);
        }
        let mut cursor = 0;
        let backup_format = u16::from_be_bytes(take_array(bytes, &mut cursor)?);
        let backup_id = RecoveryId::from_bytes(take_array(bytes, &mut cursor)?)
            .map_err(|_| BackupFormatError::InvalidIdentifier)?;
        let created_at_ms = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
        let vault_id = VaultId::from_bytes(take_array(bytes, &mut cursor)?)
            .map_err(|_| BackupFormatError::InvalidIdentifier)?;
        let genesis_fingerprint = Digest32::new(take_array(bytes, &mut cursor)?);
        let source_public_revision_hash = Digest32::new(take_array(bytes, &mut cursor)?);
        let owner_principal_id = PrincipalId::from_bytes(take_array(bytes, &mut cursor)?)
            .map_err(|_| BackupFormatError::InvalidIdentifier)?;
        let owner_descriptor_fingerprint = Digest32::new(take_array(bytes, &mut cursor)?);
        let kdf_profile = match take_array::<1>(bytes, &mut cursor)?[0] {
            1 => KdfProfile::PortableV1,
            2 => KdfProfile::HardenedV1,
            _ => return Err(BackupFormatError::UnsupportedProfile),
        };
        let argon2_version = take_array::<1>(bytes, &mut cursor)?[0];
        let memory_kib = u32::from_be_bytes(take_array(bytes, &mut cursor)?);
        let passes = u32::from_be_bytes(take_array(bytes, &mut cursor)?);
        let lanes = u32::from_be_bytes(take_array(bytes, &mut cursor)?);
        let salt = Salt16::new(take_array(bytes, &mut cursor)?);
        let storage_algorithm = take_array::<1>(bytes, &mut cursor)?[0];
        let nonce = Nonce12::new(take_array(bytes, &mut cursor)?);
        let target_bucket_id = take_array::<1>(bytes, &mut cursor)?[0];
        let payload_ciphertext_length = u32::from_be_bytes(take_array(bytes, &mut cursor)?);
        let payload_digest = Digest32::new(take_array(bytes, &mut cursor)?);
        if cursor != BACKUP_HEADER_BYTES {
            return Err(BackupFormatError::CanonicalEncoding);
        }
        let header = Self {
            backup_format,
            backup_id,
            created_at_ms,
            vault_id,
            genesis_fingerprint,
            source_public_revision_hash,
            owner_principal_id,
            owner_descriptor_fingerprint,
            kdf_profile,
            argon2_version,
            memory_kib,
            passes,
            lanes,
            salt,
            storage_algorithm,
            nonce,
            target_bucket_id,
            payload_ciphertext_length,
            payload_digest,
        };
        header.validate()?;
        Ok(header)
    }

    pub fn recomputed_digest(&self) -> Result<Digest32, BackupFormatError> {
        let header = self.canonical_bytes()?;
        let mut preimage = jce("jury-v1/backup-header/hash");
        canonical::bytes_field(&mut preimage, &header)
            .map_err(|_| BackupFormatError::CanonicalEncoding)?;
        Ok(Digest32::new(Sha256::digest(preimage).into()))
    }

    #[must_use]
    pub fn kdf_info(&self) -> Vec<u8> {
        let mut output = jce("jury-v1/kdf/backup");
        output.extend_from_slice(&self.backup_format.to_be_bytes());
        output.extend_from_slice(self.vault_id.as_bytes());
        output.extend_from_slice(self.backup_id.as_bytes());
        output.push(self.target_bucket_id);
        output
    }

    pub fn aad(&self) -> Result<Vec<u8>, BackupFormatError> {
        let mut output = jce("jury-v1/backup/aad");
        output.extend_from_slice(&self.backup_format.to_be_bytes());
        output.extend_from_slice(self.recomputed_digest()?.as_bytes());
        output.push(self.target_bucket_id);
        Ok(output)
    }

    pub fn plaintext_capacity(&self) -> Result<usize, BackupFormatError> {
        usize::try_from(self.payload_ciphertext_length)
            .ok()
            .and_then(|length| length.checked_sub(AEAD_TAG_BYTES))
            .ok_or(BackupFormatError::InvalidLength)
    }
}

pub struct BackupEnvelopeV1 {
    pub header: BackupHeaderV1,
    ciphertext: Vec<u8>,
}

impl BackupEnvelopeV1 {
    pub fn new(header: BackupHeaderV1, ciphertext: Vec<u8>) -> Result<Self, BackupFormatError> {
        header.validate()?;
        if usize::try_from(header.payload_ciphertext_length).ok() != Some(ciphertext.len()) {
            return Err(BackupFormatError::InvalidLength);
        }
        Ok(Self { header, ciphertext })
    }

    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, BackupFormatError> {
        self.header.validate()?;
        let target = bucket_bytes(self.header.target_bucket_id)?;
        if self.ciphertext.len()
            != usize::try_from(self.header.payload_ciphertext_length)
                .map_err(|_| BackupFormatError::InvalidLength)?
        {
            return Err(BackupFormatError::InvalidLength);
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(target)
            .map_err(|_| BackupFormatError::ResourceUnavailable)?;
        output.extend_from_slice(BACKUP_MAGIC);
        output.extend_from_slice(&self.header.canonical_bytes()?);
        output.extend_from_slice(&self.ciphertext);
        if output.len() != target {
            return Err(BackupFormatError::InvalidBucket);
        }
        Ok(output)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, BackupFormatError> {
        if bytes.len() > MAX_BACKUP_ENVELOPE_BYTES {
            return Err(BackupFormatError::ArtifactTooLarge);
        }
        if bytes.len() < BACKUP_PREFIX_BYTES || &bytes[..BACKUP_MAGIC.len()] != BACKUP_MAGIC {
            return Err(BackupFormatError::UnknownMagic);
        }
        let header = BackupHeaderV1::parse(
            &bytes[BACKUP_MAGIC.len()..BACKUP_MAGIC.len() + BACKUP_HEADER_BYTES],
        )?;
        if bytes.len() != bucket_bytes(header.target_bucket_id)? {
            return Err(BackupFormatError::InvalidBucket);
        }
        let ciphertext_bytes = &bytes[BACKUP_PREFIX_BYTES..];
        let mut ciphertext = Vec::new();
        ciphertext
            .try_reserve_exact(ciphertext_bytes.len())
            .map_err(|_| BackupFormatError::ResourceUnavailable)?;
        ciphertext.extend_from_slice(ciphertext_bytes);
        Self::new(header, ciphertext)
    }
}

impl fmt::Debug for BackupEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupEnvelopeV1")
            .field("header", &self.header)
            .field("ciphertext_bytes", &self.ciphertext.len())
            .field("ciphertext", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupFormatError {
    ArtifactTooLarge,
    UnknownMagic,
    InvalidLength,
    InvalidBucket,
    InvalidIdentifier,
    UnsupportedProfile,
    CanonicalEncoding,
    ResourceUnavailable,
}

impl fmt::Display for BackupFormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ArtifactTooLarge => "backup exceeds its public size bound",
            Self::UnknownMagic => "backup file magic is unknown",
            Self::InvalidLength => "backup length is invalid",
            Self::InvalidBucket => "backup size bucket is invalid",
            Self::InvalidIdentifier => "backup identifier is invalid",
            Self::UnsupportedProfile => "backup protection profile is unsupported",
            Self::CanonicalEncoding => "backup canonical encoding is invalid",
            Self::ResourceUnavailable => "backup encoding resources are unavailable",
        })
    }
}

impl std::error::Error for BackupFormatError {}

pub const fn bucket_bytes(bucket_id: u8) -> Result<usize, BackupFormatError> {
    if bucket_id == 0 || bucket_id as usize > BACKUP_BUCKET_BYTES.len() {
        return Err(BackupFormatError::InvalidBucket);
    }
    Ok(BACKUP_BUCKET_BYTES[bucket_id as usize - 1])
}

pub fn smallest_bucket_id(logical_payload_bytes: usize) -> Result<u8, BackupFormatError> {
    let required = BACKUP_PREFIX_BYTES
        .checked_add(AEAD_TAG_BYTES)
        .and_then(|value| value.checked_add(logical_payload_bytes))
        .ok_or(BackupFormatError::ArtifactTooLarge)?;
    BACKUP_BUCKET_BYTES
        .iter()
        .position(|bucket| *bucket >= required)
        .and_then(|index| u8::try_from(index + 1).ok())
        .ok_or(BackupFormatError::ArtifactTooLarge)
}

fn put(output: &mut [u8], cursor: &mut usize, value: &[u8]) -> Result<(), BackupFormatError> {
    let end = cursor
        .checked_add(value.len())
        .ok_or(BackupFormatError::CanonicalEncoding)?;
    let destination = output
        .get_mut(*cursor..end)
        .ok_or(BackupFormatError::CanonicalEncoding)?;
    destination.copy_from_slice(value);
    *cursor = end;
    Ok(())
}

fn take_array<const N: usize>(
    input: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], BackupFormatError> {
    let end = cursor
        .checked_add(N)
        .ok_or(BackupFormatError::CanonicalEncoding)?;
    let value = input
        .get(*cursor..end)
        .ok_or(BackupFormatError::InvalidLength)?
        .try_into()
        .map_err(|_| BackupFormatError::InvalidLength)?;
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(bucket: u8) -> Result<BackupHeaderV1, Box<dyn std::error::Error>> {
        let target = bucket_bytes(bucket)?;
        Ok(BackupHeaderV1 {
            backup_format: 1,
            backup_id: RecoveryId::from_bytes([1; 32])?,
            created_at_ms: 7,
            vault_id: VaultId::from_bytes([2; 32])?,
            genesis_fingerprint: Digest32::new([3; 32]),
            source_public_revision_hash: Digest32::new([4; 32]),
            owner_principal_id: PrincipalId::from_bytes([5; 32])?,
            owner_descriptor_fingerprint: Digest32::new([6; 32]),
            kdf_profile: KdfProfile::PortableV1,
            argon2_version: 0x13,
            memory_kib: KdfProfile::PortableV1.memory_kib(),
            passes: 3,
            lanes: 4,
            salt: Salt16::new([7; 16]),
            storage_algorithm: 1,
            nonce: Nonce12::new([8; 12]),
            target_bucket_id: bucket,
            payload_ciphertext_length: u32::try_from(target - BACKUP_PREFIX_BYTES)?,
            payload_digest: Digest32::new([9; 32]),
        })
    }

    #[test]
    fn exact_bucket_envelope_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        for bucket in 1..=5 {
            let header = header(bucket)?;
            let ciphertext = vec![0x5a; usize::try_from(header.payload_ciphertext_length)?];
            let encoded = BackupEnvelopeV1::new(header.clone(), ciphertext)?.to_bytes()?;
            assert_eq!(encoded.len(), bucket_bytes(bucket)?);
            let parsed = BackupEnvelopeV1::parse(&encoded)?;
            assert_eq!(parsed.header, header);
            assert_eq!(parsed.to_bytes()?, encoded);
        }
        Ok(())
    }

    #[test]
    fn hostile_profile_bucket_and_type_confusion_reject() -> Result<(), Box<dyn std::error::Error>>
    {
        let header = header(1)?;
        let ciphertext = vec![0; usize::try_from(header.payload_ciphertext_length)?];
        let encoded = BackupEnvelopeV1::new(header, ciphertext)?.to_bytes()?;

        let mut hostile_kdf = encoded.clone();
        let memory_offset = BACKUP_MAGIC.len() + 204;
        hostile_kdf[memory_offset..memory_offset + 4].copy_from_slice(&1_u32.to_be_bytes());
        assert_eq!(
            BackupEnvelopeV1::parse(&hostile_kdf).map(|_| ()),
            Err(BackupFormatError::UnsupportedProfile)
        );

        let mut wrong_bucket = encoded.clone();
        wrong_bucket[BACKUP_MAGIC.len() + 245] = 2;
        assert_eq!(
            BackupEnvelopeV1::parse(&wrong_bucket).map(|_| ()),
            Err(BackupFormatError::UnsupportedProfile)
        );
        assert_eq!(
            BackupEnvelopeV1::parse(br#"{"magic":"jury-transfer"}"#).map(|_| ()),
            Err(BackupFormatError::UnknownMagic)
        );
        Ok(())
    }

    #[test]
    fn bucket_selection_accounts_for_all_framing() {
        let capacity = BACKUP_BUCKET_BYTES[0] - BACKUP_PREFIX_BYTES - AEAD_TAG_BYTES;
        assert_eq!(smallest_bucket_id(capacity), Ok(1));
        assert_eq!(smallest_bucket_id(capacity + 1), Ok(2));
        assert_eq!(
            smallest_bucket_id(MAX_BACKUP_ENVELOPE_BYTES),
            Err(BackupFormatError::ArtifactTooLarge)
        );
    }
}
