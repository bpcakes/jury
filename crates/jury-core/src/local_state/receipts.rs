use jury_protected::ProtectedMemory;
use jury_protocol::vault_v1::Digest32;
use serde::{Deserialize, Serialize};

use super::{
    LocalStateError, LocalStateErrorKind, LocalStateScope, MAX_RECEIPTS_BYTES,
    authenticate_local_document, digest_is_zero, parse_local_document, serialize_local_document,
    verify_local_document,
};
use crate::canonical::jce_v1 as jce;

const ZERO_DIGEST: [u8; 32] = [0; 32];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferReceipt {
    pub transfer_id: Digest32,
    pub captured_public_revision_hash: Digest32,
    pub timestamp_ms: u64,
    pub output_digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupReceipt {
    pub backup_id: Digest32,
    pub captured_public_revision_hash: Digest32,
    pub timestamp_ms: u64,
    pub payload_digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupVerificationReceipt {
    pub backup_id: Digest32,
    pub captured_public_revision_hash: Digest32,
    pub timestamp_ms: u64,
    pub payload_digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreDrillReceipt {
    pub backup_id: Digest32,
    pub captured_public_revision_hash: Digest32,
    pub timestamp_ms: u64,
    pub output_digest: Digest32,
}

pub enum ReceiptUpdate {
    Transfer(TransferReceipt),
    Backup(BackupReceipt),
    BackupVerification(BackupVerificationReceipt),
    RestoreDrill(RestoreDrillReceipt),
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalReceipts {
    version: u16,
    scope: LocalStateScope,
    latest_transfer: Option<TransferReceipt>,
    latest_backup: Option<BackupReceipt>,
    latest_backup_verification: Option<BackupVerificationReceipt>,
    latest_restore_drill: Option<RestoreDrillReceipt>,
    mac: Digest32,
}

impl LocalReceipts {
    pub(super) fn empty(scope: &LocalStateScope) -> Self {
        Self {
            version: 1,
            scope: scope.clone(),
            latest_transfer: None,
            latest_backup: None,
            latest_backup_verification: None,
            latest_restore_drill: None,
            mac: Digest32::new(ZERO_DIGEST),
        }
    }

    pub(super) fn parse(
        bytes: &[u8],
        scope: &LocalStateScope,
        key: &ProtectedMemory,
    ) -> Result<Self, LocalStateError> {
        let receipts: Self = parse_local_document(bytes, MAX_RECEIPTS_BYTES)?;
        if receipts.validate_shape().is_err() {
            return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
        }
        if receipts.scope != *scope {
            return Err(LocalStateError::new(LocalStateErrorKind::ScopeMismatch));
        }
        receipts.verify(key)?;
        Ok(receipts)
    }

    pub(super) fn update(&mut self, update: ReceiptUpdate) -> Result<(), LocalStateError> {
        match update {
            ReceiptUpdate::Transfer(receipt) => {
                ensure_newer(
                    self.latest_transfer
                        .as_ref()
                        .map(|prior| prior.timestamp_ms),
                    receipt.timestamp_ms,
                )?;
                validate_transfer(&receipt)?;
                self.latest_transfer = Some(receipt);
            }
            ReceiptUpdate::Backup(receipt) => {
                ensure_newer(
                    self.latest_backup.as_ref().map(|prior| prior.timestamp_ms),
                    receipt.timestamp_ms,
                )?;
                validate_backup(&receipt)?;
                self.latest_backup = Some(receipt);
            }
            ReceiptUpdate::BackupVerification(receipt) => {
                ensure_newer(
                    self.latest_backup_verification
                        .as_ref()
                        .map(|prior| prior.timestamp_ms),
                    receipt.timestamp_ms,
                )?;
                validate_backup_verification(&receipt)?;
                self.latest_backup_verification = Some(receipt);
            }
            ReceiptUpdate::RestoreDrill(receipt) => {
                ensure_newer(
                    self.latest_restore_drill
                        .as_ref()
                        .map(|prior| prior.timestamp_ms),
                    receipt.timestamp_ms,
                )?;
                validate_restore_drill(&receipt)?;
                self.latest_restore_drill = Some(receipt);
            }
        }
        Ok(())
    }

    pub(super) fn authenticate(&mut self, key: &ProtectedMemory) -> Result<(), LocalStateError> {
        self.validate_shape()?;
        let preimage = self.mac_preimage();
        authenticate_local_document(&mut self.mac, key, &preimage)
    }

    fn verify(&self, key: &ProtectedMemory) -> Result<(), LocalStateError> {
        verify_local_document(&self.mac, key, &self.mac_preimage())
    }

    fn validate_shape(&self) -> Result<(), LocalStateError> {
        if self.version != 1 {
            return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
        }
        if let Some(receipt) = &self.latest_transfer {
            validate_transfer(receipt)?;
        }
        if let Some(receipt) = &self.latest_backup {
            validate_backup(receipt)?;
        }
        if let Some(receipt) = &self.latest_backup_verification {
            validate_backup_verification(receipt)?;
        }
        if let Some(receipt) = &self.latest_restore_drill {
            validate_restore_drill(receipt)?;
        }
        Ok(())
    }

    fn mac_preimage(&self) -> Vec<u8> {
        receipt_mac_preimage(
            self.version,
            &self.scope,
            [
                self.latest_transfer
                    .as_ref()
                    .map(ReceiptEntry::from_transfer),
                self.latest_backup.as_ref().map(ReceiptEntry::from_backup),
                self.latest_backup_verification
                    .as_ref()
                    .map(ReceiptEntry::from_backup_verification),
                self.latest_restore_drill
                    .as_ref()
                    .map(ReceiptEntry::from_restore_drill),
            ]
            .into_iter()
            .flatten()
            .collect(),
        )
    }

    pub(super) fn to_bytes(&self) -> Result<Vec<u8>, LocalStateError> {
        serialize_local_document(self, MAX_RECEIPTS_BYTES)
    }

    pub(super) const fn scope(&self) -> &LocalStateScope {
        &self.scope
    }

    #[must_use]
    pub const fn latest_transfer(&self) -> Option<&TransferReceipt> {
        self.latest_transfer.as_ref()
    }

    #[must_use]
    pub const fn latest_backup(&self) -> Option<&BackupReceipt> {
        self.latest_backup.as_ref()
    }

    #[must_use]
    pub const fn latest_backup_verification(&self) -> Option<&BackupVerificationReceipt> {
        self.latest_backup_verification.as_ref()
    }

    #[must_use]
    pub const fn latest_restore_drill(&self) -> Option<&RestoreDrillReceipt> {
        self.latest_restore_drill.as_ref()
    }
}

impl std::fmt::Debug for LocalReceipts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalReceipts")
            .field("scope", &self.scope)
            .field("has_transfer", &self.latest_transfer.is_some())
            .field("has_backup", &self.latest_backup.is_some())
            .field(
                "has_backup_verification",
                &self.latest_backup_verification.is_some(),
            )
            .field("has_restore_drill", &self.latest_restore_drill.is_some())
            .field("authentication", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub(super) struct ReceiptEntry {
    kind: u8,
    operation_id: Digest32,
    captured_public_revision_hash: Digest32,
    timestamp_ms: u64,
    output_digest: Digest32,
    verification_state: u8,
}

impl ReceiptEntry {
    pub(super) fn from_transfer(receipt: &TransferReceipt) -> Self {
        Self {
            kind: 1,
            operation_id: receipt.transfer_id.clone(),
            captured_public_revision_hash: receipt.captured_public_revision_hash.clone(),
            timestamp_ms: receipt.timestamp_ms,
            output_digest: receipt.output_digest.clone(),
            verification_state: 1,
        }
    }

    fn from_backup(receipt: &BackupReceipt) -> Self {
        Self {
            kind: 2,
            operation_id: receipt.backup_id.clone(),
            captured_public_revision_hash: receipt.captured_public_revision_hash.clone(),
            timestamp_ms: receipt.timestamp_ms,
            output_digest: receipt.payload_digest.clone(),
            verification_state: 1,
        }
    }

    fn from_backup_verification(receipt: &BackupVerificationReceipt) -> Self {
        Self {
            kind: 3,
            operation_id: receipt.backup_id.clone(),
            captured_public_revision_hash: receipt.captured_public_revision_hash.clone(),
            timestamp_ms: receipt.timestamp_ms,
            output_digest: receipt.payload_digest.clone(),
            verification_state: 2,
        }
    }

    fn from_restore_drill(receipt: &RestoreDrillReceipt) -> Self {
        Self {
            kind: 4,
            operation_id: receipt.backup_id.clone(),
            captured_public_revision_hash: receipt.captured_public_revision_hash.clone(),
            timestamp_ms: receipt.timestamp_ms,
            output_digest: receipt.output_digest.clone(),
            verification_state: 3,
        }
    }
}

fn ensure_newer(prior: Option<u64>, next: u64) -> Result<(), LocalStateError> {
    if next == 0 || prior.is_some_and(|prior| next < prior) {
        Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat))
    } else {
        Ok(())
    }
}

fn validate_common(
    operation_id: &Digest32,
    revision_hash: &Digest32,
    timestamp_ms: u64,
    output_digest: &Digest32,
) -> Result<(), LocalStateError> {
    if timestamp_ms == 0
        || digest_is_zero(operation_id)
        || digest_is_zero(revision_hash)
        || digest_is_zero(output_digest)
    {
        Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat))
    } else {
        Ok(())
    }
}

fn validate_transfer(receipt: &TransferReceipt) -> Result<(), LocalStateError> {
    validate_common(
        &receipt.transfer_id,
        &receipt.captured_public_revision_hash,
        receipt.timestamp_ms,
        &receipt.output_digest,
    )
}

fn validate_backup(receipt: &BackupReceipt) -> Result<(), LocalStateError> {
    validate_common(
        &receipt.backup_id,
        &receipt.captured_public_revision_hash,
        receipt.timestamp_ms,
        &receipt.payload_digest,
    )
}

fn validate_backup_verification(
    receipt: &BackupVerificationReceipt,
) -> Result<(), LocalStateError> {
    validate_common(
        &receipt.backup_id,
        &receipt.captured_public_revision_hash,
        receipt.timestamp_ms,
        &receipt.payload_digest,
    )
}

fn validate_restore_drill(receipt: &RestoreDrillReceipt) -> Result<(), LocalStateError> {
    validate_common(
        &receipt.backup_id,
        &receipt.captured_public_revision_hash,
        receipt.timestamp_ms,
        &receipt.output_digest,
    )
}

pub(super) fn receipt_mac_preimage(
    version: u16,
    scope: &LocalStateScope,
    mut entries: Vec<ReceiptEntry>,
) -> Vec<u8> {
    entries.sort_by(|left, right| {
        (left.kind, left.timestamp_ms, left.operation_id.as_bytes()).cmp(&(
            right.kind,
            right.timestamp_ms,
            right.operation_id.as_bytes(),
        ))
    });
    let mut output = jce("jury-v1/receipt/file-mac");
    output.extend_from_slice(&version.to_be_bytes());
    output.extend_from_slice(scope.principal_id.as_bytes());
    output.extend_from_slice(scope.vault_id.as_bytes());
    output.extend_from_slice(scope.genesis_fingerprint.as_bytes());
    output.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for entry in entries {
        output.push(entry.kind);
        output.extend_from_slice(entry.operation_id.as_bytes());
        output.extend_from_slice(entry.captured_public_revision_hash.as_bytes());
        output.extend_from_slice(&entry.timestamp_ms.to_be_bytes());
        output.extend_from_slice(entry.output_digest.as_bytes());
        output.push(entry.verification_state);
    }
    output
}
