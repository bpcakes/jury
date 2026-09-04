//! Independently protected owner recovery archives.
//!
//! Private identity payload bytes never leave this crate. Adapters receive
//! typed recovered identities that can only be resealed or compared with an
//! already unlocked identity.

use std::fmt;

use jury_protected::{OsRandom, ProtectedMemory, ProtectionPolicy, RandomSource, SecretBytes};
use jury_protocol::{
    backup_v1::{
        AEAD_TAG_BYTES, BACKUP_PREFIX_BYTES, BackupEnvelopeV1, BackupHeaderV1,
        MAX_BACKUP_ENVELOPE_BYTES, smallest_bucket_id,
    },
    identity_v1::{IdentityHeaderV1, KdfProfile},
    vault_v1::{
        ContentRole, Digest32, ItemAccessMode, ItemId, Nonce12, PrincipalId, PrincipalKind,
        RecoveryId, Salt16, VaultFileV1,
    },
};

use crate::{
    crypto,
    identity::{
        ApproverIdentity, RecoveredIdentity, VaultPrincipalIdentity, WitnessIdentity,
        validate_passphrase,
    },
    local_state::{CheckpointCandidate, CheckpointRelation, PrincipalLocalState},
    policy::{PolicyState, replay_policy_with_witness_policies},
    transfer::TransferPublicCatalogV1,
};

mod codec;
mod error;

use codec::{
    ParsedPayload, PreparedIdentity, encode_payload, encoded_payload_len, parse_padded_payload,
};
pub use error::{BackupCapacityClass, BackupError, BackupErrorKind};
use error::{map_crypto_error, map_format_error, map_identity_error};

const RECOVERY_PAYLOAD_MAGIC: &[u8; 16] = b"JURY-RECOVERY-V1";
const RECOVERY_PAYLOAD_VERSION: u16 = 1;
const IDENTITY_PRIVATE_PAYLOAD_BYTES: usize = 133;
const MAX_BACKUP_ID_ATTEMPTS: usize = 16;
const MAX_IDENTITY_HEADER_BYTES: usize = 16 * 1024;
const MAX_CATALOG_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECOVERY_PAYLOAD_BYTES: usize =
    MAX_BACKUP_ENVELOPE_BYTES - BACKUP_PREFIX_BYTES - AEAD_TAG_BYTES - 4;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RecoveryRole {
    VaultPrincipal,
    Approver,
    WitnessClient,
}

impl RecoveryRole {
    const fn tag(self) -> u8 {
        match self {
            Self::VaultPrincipal => 1,
            Self::Approver => 2,
            Self::WitnessClient => 3,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, BackupError> {
        match tag {
            1 => Ok(Self::VaultPrincipal),
            2 => Ok(Self::Approver),
            3 => Ok(Self::WitnessClient),
            _ => Err(BackupError::new(BackupErrorKind::InvalidFormat)),
        }
    }
}

#[derive(Clone, Copy)]
pub struct LocalStateArchive<'a> {
    pub audit: &'a [u8],
    pub checkpoint: &'a [u8],
    pub receipts: &'a [u8],
}

impl fmt::Debug for LocalStateArchive<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalStateArchive")
            .field("audit_bytes", &self.audit.len())
            .field("checkpoint_bytes", &self.checkpoint.len())
            .field("receipt_bytes", &self.receipts.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

pub enum BackupIdentitySource<'a> {
    VaultPrincipal {
        identity: &'a VaultPrincipalIdentity,
        local_state: LocalStateArchive<'a>,
    },
    Approver {
        identity: &'a ApproverIdentity,
        local_state: LocalStateArchive<'a>,
    },
    WitnessClient {
        identity: &'a WitnessIdentity,
        local_state: LocalStateArchive<'a>,
    },
}

impl fmt::Debug for BackupIdentitySource<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupIdentitySource")
            .field("role", &self.role())
            .field("private", &"[REDACTED]")
            .finish()
    }
}

impl BackupIdentitySource<'_> {
    fn role(&self) -> RecoveryRole {
        match self {
            Self::VaultPrincipal { .. } => RecoveryRole::VaultPrincipal,
            Self::Approver { .. } => RecoveryRole::Approver,
            Self::WitnessClient { .. } => RecoveryRole::WitnessClient,
        }
    }

    fn principal_id(&self) -> PrincipalId {
        match self {
            Self::VaultPrincipal { identity, .. } => identity.principal_id(),
            Self::Approver { identity, .. } => identity.principal_id(),
            Self::WitnessClient { identity, .. } => identity.principal_id(),
        }
    }

    fn recovery_copy(&self) -> Result<RecoveredIdentity, BackupError> {
        match self {
            Self::VaultPrincipal { identity, .. } => identity.recovery_copy(),
            Self::Approver { identity, .. } => identity.recovery_copy(),
            Self::WitnessClient { identity, .. } => identity.recovery_copy(),
        }
        .map_err(map_identity_error)
    }

    fn local_state(&self) -> LocalStateArchive<'_> {
        match self {
            Self::VaultPrincipal { local_state, .. }
            | Self::Approver { local_state, .. }
            | Self::WitnessClient { local_state, .. } => *local_state,
        }
    }

    fn local_authenticator(&self, vault: &VaultFileV1) -> Result<PrincipalLocalState, BackupError> {
        match self {
            Self::VaultPrincipal { identity, .. } => PrincipalLocalState::for_vault_principal(
                identity,
                vault.header.vault_id,
                vault.header.genesis_fingerprint.clone(),
            ),
            Self::Approver { identity, .. } => PrincipalLocalState::for_approver(
                identity,
                vault.header.vault_id,
                vault.header.genesis_fingerprint.clone(),
            ),
            Self::WitnessClient { identity, .. } => PrincipalLocalState::for_witness(
                identity,
                vault.header.vault_id,
                vault.header.genesis_fingerprint.clone(),
            ),
        }
        .map_err(|_| BackupError::new(BackupErrorKind::InvalidLocalState))
    }
}

pub struct BackupCreateRequest<'a> {
    pub vault: &'a VaultFileV1,
    pub catalog: &'a TransferPublicCatalogV1,
    pub identities: &'a [BackupIdentitySource<'a>],
    pub profile: KdfProfile,
    pub created_at_ms: u64,
    pub backup_passphrase: &'a ProtectedMemory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCoverage {
    pub identity_roles: Vec<RecoveryRole>,
    pub direct_item_ids: Vec<ItemId>,
    pub witnessed_item_ids: Vec<ItemId>,
    pub unavailable_witnessed_item_ids: Vec<ItemId>,
    pub checkpoints_current: bool,
    pub external_witness_recovery_required: bool,
    pub recovers_juryd_replay_state: bool,
    pub recovers_external_anchors: bool,
    pub proves_witness_availability: bool,
    pub proves_quorum_availability: bool,
}

pub struct CreatedBackup {
    envelope: BackupEnvelopeV1,
    coverage: RecoveryCoverage,
}

impl CreatedBackup {
    #[must_use]
    pub const fn envelope(&self) -> &BackupEnvelopeV1 {
        &self.envelope
    }

    #[must_use]
    pub const fn coverage(&self) -> &RecoveryCoverage {
        &self.coverage
    }

    pub fn into_envelope(self) -> BackupEnvelopeV1 {
        self.envelope
    }
}

pub struct RecoveredLocalState {
    audit: Vec<u8>,
    checkpoint: Vec<u8>,
    receipts: Vec<u8>,
}

impl RecoveredLocalState {
    #[must_use]
    pub fn audit(&self) -> &[u8] {
        &self.audit
    }

    #[must_use]
    pub fn checkpoint(&self) -> &[u8] {
        &self.checkpoint
    }

    #[must_use]
    pub fn receipts(&self) -> &[u8] {
        &self.receipts
    }
}

impl fmt::Debug for RecoveredLocalState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveredLocalState")
            .field("audit_bytes", &self.audit.len())
            .field("checkpoint_bytes", &self.checkpoint.len())
            .field("receipts_bytes", &self.receipts.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

pub struct RecoveredRoleIdentity {
    role: RecoveryRole,
    identity: RecoveredIdentity,
    local_state: RecoveredLocalState,
}

impl RecoveredRoleIdentity {
    #[must_use]
    pub const fn role(&self) -> RecoveryRole {
        self.role
    }

    #[must_use]
    pub const fn identity(&self) -> &RecoveredIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn local_state(&self) -> &RecoveredLocalState {
        &self.local_state
    }
}

impl fmt::Debug for RecoveredRoleIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveredRoleIdentity")
            .field("role", &self.role)
            .field("identity", &self.identity)
            .field("local_state", &self.local_state)
            .finish()
    }
}

pub struct RecoveredBackup {
    header: BackupHeaderV1,
    vault: VaultFileV1,
    vault_bytes: Vec<u8>,
    catalog: TransferPublicCatalogV1,
    identities: Vec<RecoveredRoleIdentity>,
    coverage: RecoveryCoverage,
}

impl RecoveredBackup {
    #[must_use]
    pub const fn header(&self) -> &BackupHeaderV1 {
        &self.header
    }

    #[must_use]
    pub const fn vault(&self) -> &VaultFileV1 {
        &self.vault
    }

    #[must_use]
    pub fn vault_bytes(&self) -> &[u8] {
        &self.vault_bytes
    }

    #[must_use]
    pub const fn catalog(&self) -> &TransferPublicCatalogV1 {
        &self.catalog
    }

    #[must_use]
    pub fn identities(&self) -> &[RecoveredRoleIdentity] {
        &self.identities
    }

    #[must_use]
    pub const fn coverage(&self) -> &RecoveryCoverage {
        &self.coverage
    }

    #[must_use]
    pub fn identity(&self, role: RecoveryRole) -> Option<&RecoveredRoleIdentity> {
        self.identities
            .iter()
            .find(|identity| identity.role == role)
    }
}

impl fmt::Debug for RecoveredBackup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveredBackup")
            .field("header", &self.header)
            .field("vault_bytes", &self.vault_bytes.len())
            .field("identities", &self.identities)
            .field("coverage", &self.coverage)
            .field("private", &"[REDACTED]")
            .finish()
    }
}

pub struct BackupCreator<R = OsRandom> {
    source: R,
}

impl BackupCreator<OsRandom> {
    #[must_use]
    pub const fn new() -> Self {
        Self { source: OsRandom }
    }
}

impl Default for BackupCreator<OsRandom> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: RandomSource> BackupCreator<R> {
    #[cfg(test)]
    pub(crate) const fn from_source(source: R) -> Self {
        Self { source }
    }

    pub fn create(
        &mut self,
        request: BackupCreateRequest<'_>,
    ) -> Result<CreatedBackup, BackupError> {
        validate_passphrase(request.backup_passphrase).map_err(map_identity_error)?;
        if request.created_at_ms == 0
            || request.identities.is_empty()
            || request.identities.len() > 3
        {
            return Err(BackupError::new(BackupErrorKind::InvalidFormat));
        }
        let vault_bytes = request
            .vault
            .to_json_bytes()
            .map_err(|_| BackupError::new(BackupErrorKind::InvalidVault))?;
        let catalog_bytes = request
            .catalog
            .to_json_bytes()
            .map_err(|_| BackupError::new(BackupErrorKind::InvalidCatalog))?;
        if catalog_bytes.len() > MAX_CATALOG_BYTES {
            return Err(BackupError::capacity(BackupCapacityClass::Catalog));
        }
        let (policy, candidate) = validate_vault(request.vault, request.catalog)?;

        let mut prepared = Vec::with_capacity(request.identities.len());
        for source in request.identities {
            let role = source.role();
            if prepared
                .iter()
                .any(|entry: &PreparedIdentity<'_>| entry.role == role)
            {
                return Err(BackupError::new(BackupErrorKind::DuplicateRole));
            }
            validate_role_registration(&policy, source)?;
            let local = source.local_authenticator(request.vault)?;
            let local_files = source.local_state();
            validate_local_state(&local, &candidate, local_files)?;
            prepared.push(PreparedIdentity {
                role,
                identity: source.recovery_copy()?,
                local_state: local_files,
            });
        }
        prepared.sort_by_key(|entry| entry.role);
        let owner = prepared
            .iter()
            .find(|entry| entry.role == RecoveryRole::VaultPrincipal)
            .ok_or_else(|| BackupError::new(BackupErrorKind::OwnerRequired))?;
        let roles = prepared.iter().map(|entry| entry.role).collect::<Vec<_>>();
        let coverage = validate_recovery_coverage(&policy, &owner.identity, &roles)?;
        let logical_length = encoded_payload_len(&vault_bytes, &catalog_bytes, &prepared)?;
        let framed_length = logical_length
            .checked_add(4)
            .ok_or_else(|| BackupError::capacity(BackupCapacityClass::Envelope))?;
        let bucket_id = smallest_bucket_id(framed_length).map_err(map_format_error)?;

        let backup_id = self.draw_backup_id()?;
        let salt = Salt16::new(fill_public(&mut self.source)?);
        let nonce = Nonce12::new(fill_public(&mut self.source)?);
        let target = jury_protocol::backup_v1::bucket_bytes(bucket_id).map_err(map_format_error)?;
        let ciphertext_length = target
            .checked_sub(jury_protocol::backup_v1::BACKUP_PREFIX_BYTES)
            .ok_or_else(|| BackupError::capacity(BackupCapacityClass::Envelope))?;
        let plaintext_length = ciphertext_length
            .checked_sub(jury_protocol::backup_v1::AEAD_TAG_BYTES)
            .ok_or_else(|| BackupError::capacity(BackupCapacityClass::Envelope))?;
        let mut padded = SecretBytes::try_zeroed(plaintext_length)
            .map_err(|_| BackupError::new(BackupErrorKind::ResourceUnavailable))?;
        padded.as_mut_slice()[..4].copy_from_slice(
            &u32::try_from(logical_length)
                .map_err(|_| BackupError::capacity(BackupCapacityClass::Envelope))?
                .to_be_bytes(),
        );
        encode_payload(
            &mut padded.as_mut_slice()[4..4 + logical_length],
            &vault_bytes,
            &catalog_bytes,
            &prepared,
        )
        .map_err(|_| BackupError::new(BackupErrorKind::InvalidFormat))?;
        let payload_digest = crypto::sha256(&padded.as_slice()[4..4 + logical_length]);
        let header = BackupHeaderV1 {
            backup_format: 1,
            backup_id,
            created_at_ms: request.created_at_ms,
            vault_id: request.vault.header.vault_id,
            genesis_fingerprint: request.vault.header.genesis_fingerprint.clone(),
            source_public_revision_hash: policy.terminal_revision_hash().clone(),
            owner_principal_id: owner.identity.principal_id(),
            owner_descriptor_fingerprint: owner.identity.descriptor_fingerprint().clone(),
            kdf_profile: request.profile,
            argon2_version: 0x13,
            memory_kib: request.profile.memory_kib(),
            passes: 3,
            lanes: 4,
            salt,
            storage_algorithm: 1,
            nonce,
            target_bucket_id: bucket_id,
            payload_ciphertext_length: u32::try_from(ciphertext_length)
                .map_err(|_| BackupError::capacity(BackupCapacityClass::Envelope))?,
            payload_digest: Digest32::new(payload_digest),
        };
        let derived = crypto::derive_argon2_key(
            request.backup_passphrase,
            header.kdf_profile,
            header.salt.as_bytes(),
        )
        .map_err(map_crypto_error)?;
        let key =
            crypto::derive_hkdf_key(&derived, &header.kdf_info()).map_err(map_crypto_error)?;
        let ciphertext = crypto::seal_secret_bytes(
            &key,
            &header.nonce,
            &header.aad().map_err(map_format_error)?,
            &padded,
        )
        .map_err(map_crypto_error)?;
        let envelope = BackupEnvelopeV1::new(header, ciphertext).map_err(map_format_error)?;
        Ok(CreatedBackup { envelope, coverage })
    }

    fn draw_backup_id(&mut self) -> Result<RecoveryId, BackupError> {
        for _ in 0..MAX_BACKUP_ID_ATTEMPTS {
            let bytes = fill_public(&mut self.source)?;
            if let Ok(id) = RecoveryId::from_bytes(bytes) {
                return Ok(id);
            }
        }
        Err(BackupError::new(BackupErrorKind::EntropyUnavailable))
    }
}

pub fn open(
    envelope: &BackupEnvelopeV1,
    passphrase: &ProtectedMemory,
) -> Result<RecoveredBackup, BackupError> {
    envelope.header.validate().map_err(map_format_error)?;
    validate_passphrase(passphrase).map_err(map_identity_error)?;
    let derived = crypto::derive_argon2_key(
        passphrase,
        envelope.header.kdf_profile,
        envelope.header.salt.as_bytes(),
    )
    .map_err(map_crypto_error)?;
    let key =
        crypto::derive_hkdf_key(&derived, &envelope.header.kdf_info()).map_err(map_crypto_error)?;
    let plaintext = crypto::open_secret_bytes(
        &key,
        &envelope.header.nonce,
        &envelope.header.aad().map_err(map_format_error)?,
        envelope.ciphertext(),
        envelope
            .header
            .plaintext_capacity()
            .map_err(map_format_error)?,
        MAX_BACKUP_ENVELOPE_BYTES,
    )
    .map_err(map_crypto_error)?;
    let policy_memory = passphrase.status().policy();
    let parts = parse_padded_payload(plaintext.as_slice(), &envelope.header, policy_memory)?;
    validate_recovered(envelope.header.clone(), parts)
}

fn validate_vault(
    vault: &VaultFileV1,
    catalog: &TransferPublicCatalogV1,
) -> Result<(PolicyState, CheckpointCandidate), BackupError> {
    vault
        .validate()
        .map_err(|_| BackupError::new(BackupErrorKind::InvalidVault))?;
    let policy = replay_policy_with_witness_policies(&vault.policy, &catalog.witness_policies)
        .map_err(|_| BackupError::new(BackupErrorKind::InvalidVault))?;
    catalog
        .validate_for_policy(vault, &policy)
        .map_err(|_| BackupError::new(BackupErrorKind::InvalidCatalog))?;
    let candidate = CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items)
        .map_err(|_| BackupError::new(BackupErrorKind::InvalidVault))?;
    Ok((policy, candidate))
}

fn validate_role_registration(
    policy: &PolicyState,
    source: &BackupIdentitySource<'_>,
) -> Result<(), BackupError> {
    let principal = policy
        .principal(&source.principal_id())
        .ok_or_else(|| BackupError::new(BackupErrorKind::IdentityMismatch))?;
    let expected_kind = match source.role() {
        RecoveryRole::VaultPrincipal => {
            if !policy.is_owner(&source.principal_id()) {
                return Err(BackupError::new(BackupErrorKind::UnauthorizedOwner));
            }
            principal.descriptor.principal_kind
        }
        RecoveryRole::Approver => PrincipalKind::Approver,
        RecoveryRole::WitnessClient => PrincipalKind::Witness,
    };
    let descriptor = match source {
        BackupIdentitySource::VaultPrincipal { identity, .. } => identity.public_descriptor(),
        BackupIdentitySource::Approver { identity, .. } => identity.public_descriptor(),
        BackupIdentitySource::WitnessClient { identity, .. } => identity.public_descriptor(),
    }
    .map_err(map_identity_error)?;
    if descriptor.principal_kind != expected_kind || descriptor != principal.descriptor {
        return Err(BackupError::new(BackupErrorKind::IdentityMismatch));
    }
    Ok(())
}

fn validate_local_state(
    local: &PrincipalLocalState,
    candidate: &CheckpointCandidate,
    files: LocalStateArchive<'_>,
) -> Result<(), BackupError> {
    let verified = local
        .verify_files(
            Some(files.audit),
            Some(files.checkpoint),
            Some(files.receipts),
        )
        .map_err(|_| BackupError::new(BackupErrorKind::InvalidLocalState))?;
    if candidate
        .relation_to(verified.checkpoint())
        .map_err(|_| BackupError::new(BackupErrorKind::InvalidLocalState))?
        != CheckpointRelation::Equal
        || verified.audit_events_after_checkpoint() != 0
    {
        return Err(BackupError::new(BackupErrorKind::StaleCheckpoint));
    }
    Ok(())
}

fn validate_recovery_coverage(
    policy: &PolicyState,
    owner: &RecoveredIdentity,
    roles: &[RecoveryRole],
) -> Result<RecoveryCoverage, BackupError> {
    let mut direct_item_ids = Vec::new();
    let mut witnessed_item_ids = Vec::new();
    let mut unavailable_witnessed_item_ids = Vec::new();
    for (item_id, item) in policy.items() {
        let mode = item
            .access_mode()
            .ok_or_else(|| BackupError::new(BackupErrorKind::InvalidVault))?;
        if matches!(mode, ItemAccessMode::DirectOnly | ItemAccessMode::Mixed) {
            let owner_slots = item
                .direct_slots
                .iter()
                .filter(|slot| slot.recipient_principal_id == owner.principal_id())
                .collect::<Vec<_>>();
            if owner_slots.len() != 2
                || !owner_slots
                    .iter()
                    .any(|slot| slot.content_role == ContentRole::Descriptor)
                || !owner_slots
                    .iter()
                    .any(|slot| slot.content_role == ContentRole::Body)
            {
                return Err(BackupError::new(BackupErrorKind::DirectRecoveryUnavailable));
            }
            for slot in owner_slots {
                owner.verify_direct_slot(slot).map_err(map_identity_error)?;
            }
            direct_item_ids.push(*item_id);
        }
        if matches!(mode, ItemAccessMode::WitnessedOnly | ItemAccessMode::Mixed) {
            let authority = policy
                .witness_authority(item_id)
                .map_err(|_| BackupError::new(BackupErrorKind::InvalidVault))?
                .ok_or_else(|| BackupError::new(BackupErrorKind::InvalidVault))?;
            if mode == ItemAccessMode::WitnessedOnly
                && (!item.direct_slots.is_empty() || !authority.carries_quorum_claim)
            {
                return Err(BackupError::new(BackupErrorKind::InvalidVault));
            }
            witnessed_item_ids.push(*item_id);
            if !authority.reachable {
                unavailable_witnessed_item_ids.push(*item_id);
            }
        }
    }
    Ok(RecoveryCoverage {
        identity_roles: roles.to_vec(),
        direct_item_ids,
        witnessed_item_ids: witnessed_item_ids.clone(),
        unavailable_witnessed_item_ids,
        checkpoints_current: true,
        external_witness_recovery_required: !witnessed_item_ids.is_empty(),
        recovers_juryd_replay_state: false,
        recovers_external_anchors: false,
        proves_witness_availability: false,
        proves_quorum_availability: false,
    })
}

fn validate_recovered(
    header: BackupHeaderV1,
    parts: ParsedPayload,
) -> Result<RecoveredBackup, BackupError> {
    let vault = VaultFileV1::parse(&parts.vault_bytes)
        .map_err(|_| BackupError::new(BackupErrorKind::InvalidVault))?;
    let catalog = TransferPublicCatalogV1::parse(&parts.catalog_bytes)
        .map_err(|_| BackupError::new(BackupErrorKind::InvalidCatalog))?;
    let (policy, candidate) = validate_vault(&vault, &catalog)?;
    let owner = parts
        .identities
        .iter()
        .find(|entry| entry.role == RecoveryRole::VaultPrincipal)
        .ok_or_else(|| BackupError::new(BackupErrorKind::OwnerRequired))?;
    if header.vault_id != vault.header.vault_id
        || header.genesis_fingerprint != vault.header.genesis_fingerprint
        || &header.source_public_revision_hash != policy.terminal_revision_hash()
        || header.owner_principal_id != owner.identity.principal_id()
        || &header.owner_descriptor_fingerprint != owner.identity.descriptor_fingerprint()
    {
        return Err(BackupError::new(BackupErrorKind::IdentityMismatch));
    }
    for entry in &parts.identities {
        validate_recovered_registration(&policy, entry)?;
        let local = PrincipalLocalState::for_recovered_identity(
            &entry.identity,
            vault.header.vault_id,
            vault.header.genesis_fingerprint.clone(),
        )
        .map_err(|_| BackupError::new(BackupErrorKind::InvalidLocalState))?;
        validate_local_state(
            &local,
            &candidate,
            LocalStateArchive {
                audit: &entry.local_state.audit,
                checkpoint: &entry.local_state.checkpoint,
                receipts: &entry.local_state.receipts,
            },
        )?;
    }
    let roles = parts
        .identities
        .iter()
        .map(|entry| entry.role)
        .collect::<Vec<_>>();
    let coverage = validate_recovery_coverage(&policy, &owner.identity, &roles)?;
    Ok(RecoveredBackup {
        header,
        vault,
        vault_bytes: parts.vault_bytes,
        catalog,
        identities: parts.identities,
        coverage,
    })
}

fn validate_recovered_registration(
    policy: &PolicyState,
    entry: &RecoveredRoleIdentity,
) -> Result<(), BackupError> {
    let principal = policy
        .principal(&entry.identity.principal_id())
        .ok_or_else(|| BackupError::new(BackupErrorKind::IdentityMismatch))?;
    let descriptor = entry
        .identity
        .public_descriptor()
        .map_err(map_identity_error)?;
    if descriptor != principal.descriptor
        || role_for_kind(descriptor.principal_kind)? != entry.role
        || (entry.role == RecoveryRole::VaultPrincipal
            && !policy.is_owner(&entry.identity.principal_id()))
    {
        return Err(BackupError::new(BackupErrorKind::IdentityMismatch));
    }
    Ok(())
}

fn role_for_kind(kind: PrincipalKind) -> Result<RecoveryRole, BackupError> {
    match kind {
        PrincipalKind::Human | PrincipalKind::Machine => Ok(RecoveryRole::VaultPrincipal),
        PrincipalKind::Approver => Ok(RecoveryRole::Approver),
        PrincipalKind::Witness => Ok(RecoveryRole::WitnessClient),
    }
}

fn fill_public<const N: usize>(source: &mut impl RandomSource) -> Result<[u8; N], BackupError> {
    let mut output = [0_u8; N];
    source
        .fill(&mut output)
        .map_err(|_| BackupError::new(BackupErrorKind::EntropyUnavailable))?;
    Ok(output)
}

#[cfg(test)]
#[path = "backup_tests.rs"]
mod tests;
