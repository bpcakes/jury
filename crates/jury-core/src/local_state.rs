//! Principal-local authenticated audit, rollback checkpoints, and receipts.

mod audit;
mod checkpoint;
mod receipts;

use std::fmt;

use jury_protected::ProtectedMemory;
#[cfg(test)]
use jury_protected::ProtectionPolicy;
use jury_protocol::vault_v1::{Digest32, PrincipalId, VaultId};
use serde::{Serialize, de::DeserializeOwned};

pub use audit::{
    AuditAction, AuditEvent, AuditEventDraft, AuditEvidenceKind, AuditFailureStage, AuditItemScope,
    AuditOutcome, AuditVerification, WitnessAuditLink,
};
pub use checkpoint::{CheckpointCandidate, CheckpointRelation, LocalCheckpoint};
pub use receipts::{
    BackupReceipt, BackupVerificationReceipt, LocalReceipts, ReceiptUpdate, RestoreDrillReceipt,
    TransferReceipt,
};

use crate::canonical::jce_v1 as jce;
use crate::crypto;
use crate::identity::{ApproverIdentity, VaultPrincipalIdentity, WitnessIdentity};

pub const MAX_AUDIT_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_AUDIT_EVENT_BYTES: usize = 4 * 1024;
pub const MAX_AUDIT_EVENTS: usize = 524_288;
pub const MAX_CHECKPOINT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_RECEIPTS_BYTES: usize = 256 * 1024;

const ZERO_DIGEST: [u8; 32] = [0; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalStateErrorKind {
    InvalidFormat,
    ScopeMismatch,
    AuthenticationFailed,
    AuditTampered,
    CheckpointRollback,
    CheckpointDiverged,
    IncompleteState,
    CapacityExhausted,
    ProtectionUnavailable,
    ProviderFailure,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LocalStateError {
    kind: LocalStateErrorKind,
}

impl LocalStateError {
    pub(crate) const fn new(kind: LocalStateErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> LocalStateErrorKind {
        self.kind
    }
}

impl fmt::Debug for LocalStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalStateError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for LocalStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            LocalStateErrorKind::InvalidFormat => "local state format is invalid",
            LocalStateErrorKind::ScopeMismatch => "local state scope differs",
            LocalStateErrorKind::AuthenticationFailed => "local state authentication failed",
            LocalStateErrorKind::AuditTampered => "local audit chain is invalid",
            LocalStateErrorKind::CheckpointRollback => "vault state is behind the checkpoint",
            LocalStateErrorKind::CheckpointDiverged => "vault state diverges from the checkpoint",
            LocalStateErrorKind::IncompleteState => "principal local state is incomplete",
            LocalStateErrorKind::CapacityExhausted => "local state capacity is exhausted",
            LocalStateErrorKind::ProtectionUnavailable => {
                "local state key protection is unavailable"
            }
            LocalStateErrorKind::ProviderFailure => "local state provider failed",
        })
    }
}

impl std::error::Error for LocalStateError {}

fn parse_local_document<T>(bytes: &[u8], maximum_bytes: usize) -> Result<T, LocalStateError>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
    }
    let document = serde_json::from_slice(bytes)
        .map_err(|_| LocalStateError::new(LocalStateErrorKind::InvalidFormat))?;
    if serialize_local_document(&document, maximum_bytes)? != bytes {
        return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
    }
    Ok(document)
}

fn serialize_local_document(
    document: &impl Serialize,
    maximum_bytes: usize,
) -> Result<Vec<u8>, LocalStateError> {
    let mut bytes = serde_json::to_vec_pretty(document)
        .map_err(|_| LocalStateError::new(LocalStateErrorKind::ProviderFailure))?;
    bytes.push(b'\n');
    if bytes.len() > maximum_bytes {
        return Err(LocalStateError::new(LocalStateErrorKind::CapacityExhausted));
    }
    Ok(bytes)
}

fn authenticate_local_document(
    mac: &mut Digest32,
    key: &ProtectedMemory,
    preimage: &[u8],
) -> Result<(), LocalStateError> {
    *mac = Digest32::new(crypto::hmac_sha256(key, preimage).map_err(map_crypto_error)?);
    Ok(())
}

fn verify_local_document(
    mac: &Digest32,
    key: &ProtectedMemory,
    preimage: &[u8],
) -> Result<(), LocalStateError> {
    crypto::verify_hmac_sha256(key, preimage, mac.as_bytes()).map_err(map_crypto_error)
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalStateScope {
    pub(crate) vault_id: VaultId,
    pub(crate) genesis_fingerprint: Digest32,
    pub(crate) principal_id: PrincipalId,
}

impl LocalStateScope {
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    #[must_use]
    pub const fn genesis_fingerprint(&self) -> &Digest32 {
        &self.genesis_fingerprint
    }

    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal_id
    }
}

/// Three independent protected MAC keys scoped to one identity and vault.
pub struct PrincipalLocalState {
    scope: LocalStateScope,
    audit_key: ProtectedMemory,
    checkpoint_key: ProtectedMemory,
    receipts_key: ProtectedMemory,
}

impl PrincipalLocalState {
    pub fn for_vault_principal(
        identity: &VaultPrincipalIdentity,
        vault_id: VaultId,
        genesis_fingerprint: Digest32,
    ) -> Result<Self, LocalStateError> {
        Self::from_source(identity, vault_id, genesis_fingerprint)
    }

    pub fn for_approver(
        identity: &ApproverIdentity,
        vault_id: VaultId,
        genesis_fingerprint: Digest32,
    ) -> Result<Self, LocalStateError> {
        Self::from_source(identity, vault_id, genesis_fingerprint)
    }

    pub fn for_witness(
        identity: &WitnessIdentity,
        vault_id: VaultId,
        genesis_fingerprint: Digest32,
    ) -> Result<Self, LocalStateError> {
        Self::from_source(identity, vault_id, genesis_fingerprint)
    }

    fn from_source(
        source: &impl LocalKeySource,
        vault_id: VaultId,
        genesis_fingerprint: Digest32,
    ) -> Result<Self, LocalStateError> {
        let scope = LocalStateScope {
            vault_id,
            genesis_fingerprint,
            principal_id: source.principal_id(),
        };
        let audit_key = source.derive(&key_info("jury-v1/kdf/audit-mac", &scope))?;
        let checkpoint_key = source.derive(&key_info("jury-v1/kdf/checkpoint-mac", &scope))?;
        let receipts_key = source.derive(&key_info("jury-v1/kdf/receipt-mac", &scope))?;
        Ok(Self {
            scope,
            audit_key,
            checkpoint_key,
            receipts_key,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_test_seed(
        seed: &[u8; 32],
        scope: LocalStateScope,
    ) -> Result<Self, LocalStateError> {
        let seed = ProtectedMemory::initialize(
            32,
            ProtectionPolicy::EmergencyAllowDegraded,
            |destination| {
                destination.copy_from_slice(seed);
                Ok::<usize, ()>(destination.len())
            },
        )
        .map_err(|_| LocalStateError::new(LocalStateErrorKind::ProtectionUnavailable))?;
        let derive = |domain| {
            crypto::derive_hkdf_key(&seed, &key_info(domain, &scope)).map_err(map_crypto_error)
        };
        Ok(Self {
            audit_key: derive("jury-v1/kdf/audit-mac")?,
            checkpoint_key: derive("jury-v1/kdf/checkpoint-mac")?,
            receipts_key: derive("jury-v1/kdf/receipt-mac")?,
            scope,
        })
    }

    #[must_use]
    pub const fn scope(&self) -> &LocalStateScope {
        &self.scope
    }

    pub fn initialize(
        &self,
        candidate: &CheckpointCandidate,
        timestamp_ms: u64,
    ) -> Result<VerifiedLocalState, LocalStateError> {
        candidate.validate_scope(&self.scope)?;
        let (policy_sequence, _) = candidate.current_policy()?;
        let mut checkpoint = LocalCheckpoint::initial(candidate, &self.scope, timestamp_ms)?;
        let audit = audit::AuditLog::initialize(
            &self.scope,
            policy_sequence,
            checkpoint.audit_genesis_digest.clone(),
            &self.audit_key,
        )?;
        checkpoint.latest_audit_mac = audit.latest_mac().clone();
        checkpoint.authenticate(&self.checkpoint_key)?;
        let mut receipts = LocalReceipts::empty(&self.scope);
        receipts.authenticate(&self.receipts_key)?;
        Ok(VerifiedLocalState {
            audit,
            checkpoint,
            receipts,
            audit_events_after_checkpoint: 0,
        })
    }

    /// Verifies all three local files and their cross-links.
    ///
    /// A retained checkpoint detects audit tail deletion. Restoring both audit
    /// and checkpoint to an older valid pair is outside this local-only model;
    /// callers needing that property must retain an external anchor.
    pub fn verify_files(
        &self,
        audit_bytes: Option<&[u8]>,
        checkpoint_bytes: Option<&[u8]>,
        receipts_bytes: Option<&[u8]>,
    ) -> Result<VerifiedLocalState, LocalStateError> {
        let (Some(audit_bytes), Some(checkpoint_bytes), Some(receipts_bytes)) =
            (audit_bytes, checkpoint_bytes, receipts_bytes)
        else {
            return Err(LocalStateError::new(LocalStateErrorKind::IncompleteState));
        };
        let audit = audit::AuditLog::parse(audit_bytes, &self.scope, &self.audit_key)?;
        let checkpoint =
            LocalCheckpoint::parse(checkpoint_bytes, &self.scope, &self.checkpoint_key)?;
        let receipts = LocalReceipts::parse(receipts_bytes, &self.scope, &self.receipts_key)?;
        if audit.audit_genesis_digest() != &checkpoint.audit_genesis_digest {
            return Err(LocalStateError::new(LocalStateErrorKind::AuditTampered));
        }
        let checkpoint_index = audit
            .mac_index(&checkpoint.latest_audit_mac)
            .ok_or_else(|| LocalStateError::new(LocalStateErrorKind::AuditTampered))?;
        let audit_events_after_checkpoint = audit.len().saturating_sub(checkpoint_index + 1);
        Ok(VerifiedLocalState {
            audit,
            checkpoint,
            receipts,
            audit_events_after_checkpoint,
        })
    }

    pub fn append_event(
        &self,
        state: &mut VerifiedLocalState,
        draft: AuditEventDraft,
    ) -> Result<(), LocalStateError> {
        self.ensure_state_scope(state)?;
        let timestamp_ms = draft.timestamp_ms;
        state.audit.append(draft, &self.scope, &self.audit_key)?;
        state
            .checkpoint
            .record_audit(state.audit.latest_mac().clone(), timestamp_ms)?;
        state.checkpoint.authenticate(&self.checkpoint_key)?;
        state.audit_events_after_checkpoint = 0;
        Ok(())
    }

    /// Rebinds an authenticated audit tail left by an interrupted mutation to
    /// the checkpoint without appending a duplicate operation event.
    pub fn accept_audit_tail(
        &self,
        state: &mut VerifiedLocalState,
        timestamp_ms: u64,
    ) -> Result<(), LocalStateError> {
        self.ensure_state_scope(state)?;
        if state.audit_events_after_checkpoint == 0 {
            return Ok(());
        }
        state
            .checkpoint
            .record_audit(state.audit.latest_mac().clone(), timestamp_ms)?;
        state.checkpoint.authenticate(&self.checkpoint_key)?;
        state.audit_events_after_checkpoint = 0;
        Ok(())
    }

    /// Accepts equal or authenticated descendant public state and never lowers
    /// the retained checkpoint.
    pub fn accept_candidate(
        &self,
        state: &mut VerifiedLocalState,
        candidate: &CheckpointCandidate,
        timestamp_ms: u64,
    ) -> Result<CheckpointRelation, LocalStateError> {
        self.ensure_state_scope(state)?;
        candidate.validate_scope(&self.scope)?;
        let relation = candidate.relation_to(&state.checkpoint)?;
        match relation {
            CheckpointRelation::Equal => {}
            CheckpointRelation::StrictDescendant => {
                state.checkpoint.advance(candidate, timestamp_ms)?;
                state.checkpoint.authenticate(&self.checkpoint_key)?;
            }
            CheckpointRelation::Divergent => {
                return Err(LocalStateError::new(
                    LocalStateErrorKind::CheckpointDiverged,
                ));
            }
        }
        Ok(relation)
    }

    pub fn record_receipt(
        &self,
        state: &mut VerifiedLocalState,
        update: ReceiptUpdate,
    ) -> Result<(), LocalStateError> {
        self.ensure_state_scope(state)?;
        match &update {
            ReceiptUpdate::Transfer(receipt) => {
                if &receipt.captured_public_revision_hash
                    != state.checkpoint.accepted_public_revision_hash()
                {
                    return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
                }
            }
            ReceiptUpdate::Backup(receipt) => {
                if &receipt.captured_public_revision_hash
                    != state.checkpoint.accepted_public_revision_hash()
                {
                    return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
                }
            }
            ReceiptUpdate::BackupVerification(receipt) => {
                let Some(backup) = state.receipts.latest_backup() else {
                    return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
                };
                if receipt.backup_id != backup.backup_id
                    || receipt.captured_public_revision_hash != backup.captured_public_revision_hash
                    || receipt.payload_digest != backup.payload_digest
                {
                    return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
                }
            }
            ReceiptUpdate::RestoreDrill(receipt) => {
                let Some(backup) = state.receipts.latest_backup() else {
                    return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
                };
                if receipt.backup_id != backup.backup_id
                    || receipt.captured_public_revision_hash != backup.captured_public_revision_hash
                {
                    return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
                }
            }
        }
        state.receipts.update(update)?;
        state.receipts.authenticate(&self.receipts_key)?;
        Ok(())
    }

    pub fn serialize(
        &self,
        state: &VerifiedLocalState,
    ) -> Result<LocalStateFiles, LocalStateError> {
        self.ensure_state_scope(state)?;
        Ok(LocalStateFiles {
            audit: state.audit.to_bytes()?,
            checkpoint: state.checkpoint.to_bytes()?,
            receipts: state.receipts.to_bytes()?,
        })
    }

    fn ensure_state_scope(&self, state: &VerifiedLocalState) -> Result<(), LocalStateError> {
        if state.checkpoint.scope != self.scope
            || state.receipts.scope() != &self.scope
            || !state.audit.matches_scope(&self.scope)
        {
            Err(LocalStateError::new(LocalStateErrorKind::ScopeMismatch))
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for PrincipalLocalState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrincipalLocalState")
            .field("scope", &self.scope)
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

pub struct VerifiedLocalState {
    audit: audit::AuditLog,
    checkpoint: LocalCheckpoint,
    receipts: LocalReceipts,
    audit_events_after_checkpoint: usize,
}

impl VerifiedLocalState {
    #[must_use]
    pub fn audit(&self) -> AuditVerification {
        self.audit.verification()
    }

    #[must_use]
    pub const fn checkpoint(&self) -> &LocalCheckpoint {
        &self.checkpoint
    }

    #[must_use]
    pub const fn receipts(&self) -> &LocalReceipts {
        &self.receipts
    }

    #[must_use]
    pub const fn audit_events_after_checkpoint(&self) -> usize {
        self.audit_events_after_checkpoint
    }

    #[must_use]
    pub fn contains_operation(&self, operation_id: &Digest32) -> bool {
        self.audit.contains_operation(operation_id)
    }
}

impl fmt::Debug for VerifiedLocalState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedLocalState")
            .field("audit", &self.audit.verification())
            .field("checkpoint", &self.checkpoint)
            .field("receipts", &self.receipts)
            .field(
                "audit_events_after_checkpoint",
                &self.audit_events_after_checkpoint,
            )
            .finish()
    }
}

pub struct LocalStateFiles {
    audit: Vec<u8>,
    checkpoint: Vec<u8>,
    receipts: Vec<u8>,
}

impl LocalStateFiles {
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

impl fmt::Debug for LocalStateFiles {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalStateFiles")
            .field("audit_bytes", &self.audit.len())
            .field("checkpoint_bytes", &self.checkpoint.len())
            .field("receipts_bytes", &self.receipts.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

trait LocalKeySource {
    fn principal_id(&self) -> PrincipalId;
    fn derive(&self, info: &[u8]) -> Result<ProtectedMemory, LocalStateError>;
}

macro_rules! local_key_source {
    ($identity:ty) => {
        impl LocalKeySource for $identity {
            fn principal_id(&self) -> PrincipalId {
                <$identity>::principal_id(self)
            }

            fn derive(&self, info: &[u8]) -> Result<ProtectedMemory, LocalStateError> {
                self.derive_local_state_key(info).map_err(|error| {
                    use crate::identity::IdentityErrorKind;
                    LocalStateError::new(match error.kind() {
                        IdentityErrorKind::ProtectionUnavailable => {
                            LocalStateErrorKind::ProtectionUnavailable
                        }
                        _ => LocalStateErrorKind::ProviderFailure,
                    })
                })
            }
        }
    };
}

local_key_source!(VaultPrincipalIdentity);
local_key_source!(ApproverIdentity);
local_key_source!(WitnessIdentity);

fn key_info(domain: &str, scope: &LocalStateScope) -> Vec<u8> {
    let mut info = jce(domain);
    info.extend_from_slice(scope.vault_id.as_bytes());
    info.extend_from_slice(scope.genesis_fingerprint.as_bytes());
    info.extend_from_slice(scope.principal_id.as_bytes());
    info
}

pub(crate) fn append_digest(output: &mut Vec<u8>, digest: &Digest32) {
    output.extend_from_slice(digest.as_bytes());
}

pub(crate) fn append_optional_digest(output: &mut Vec<u8>, digest: Option<&Digest32>) {
    match digest {
        Some(digest) => {
            output.push(1);
            append_digest(output, digest);
        }
        None => output.push(0),
    }
}

pub(crate) fn digest_is_zero(digest: &Digest32) -> bool {
    digest.as_bytes() == &ZERO_DIGEST
}

pub(crate) fn map_crypto_error(error: crate::crypto::CryptoError) -> LocalStateError {
    LocalStateError::new(match error {
        crate::crypto::CryptoError::MemoryProtection => LocalStateErrorKind::ProtectionUnavailable,
        crate::crypto::CryptoError::AuthenticationFailed => {
            LocalStateErrorKind::AuthenticationFailed
        }
        _ => LocalStateErrorKind::ProviderFailure,
    })
}

#[cfg(test)]
#[path = "local_state_tests.rs"]
mod tests;
