use jury_protected::ProtectedMemory;
use jury_protocol::vault_v1::{Digest32, ItemId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupReceipt {
    backup_id: Digest32,
    captured_public_revision_hash: Digest32,
    timestamp_ms: u64,
    payload_digest: Digest32,
    coverage: BackupReceiptCoverage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupReceiptCoverage {
    pub owner_descriptor_fingerprint: Digest32,
    /// Bit 0 is vault-principal, bit 1 approver, and bit 2 witness-client.
    pub identity_role_mask: u8,
    pub direct_item_ids: Vec<ItemId>,
    pub witnessed_item_ids: Vec<ItemId>,
    pub unavailable_witnessed_item_ids: Vec<ItemId>,
    pub checkpoints_current: bool,
    pub external_witness_recovery_required: bool,
}

impl BackupReceipt {
    #[must_use]
    pub const fn with_coverage(
        backup_id: Digest32,
        captured_public_revision_hash: Digest32,
        timestamp_ms: u64,
        payload_digest: Digest32,
        coverage: BackupReceiptCoverage,
    ) -> Self {
        Self {
            backup_id,
            captured_public_revision_hash,
            timestamp_ms,
            payload_digest,
            coverage,
        }
    }

    #[must_use]
    pub const fn backup_id(&self) -> &Digest32 {
        &self.backup_id
    }

    #[must_use]
    pub const fn captured_public_revision_hash(&self) -> &Digest32 {
        &self.captured_public_revision_hash
    }

    #[must_use]
    pub const fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    #[must_use]
    pub const fn payload_digest(&self) -> &Digest32 {
        &self.payload_digest
    }

    #[must_use]
    pub const fn coverage(&self) -> &BackupReceiptCoverage {
        &self.coverage
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupReceiptWire {
    backup_id: Digest32,
    captured_public_revision_hash: Digest32,
    timestamp_ms: u64,
    payload_digest: Digest32,
    owner_descriptor_fingerprint: Digest32,
    identity_role_mask: u8,
    direct_item_ids: Vec<ItemId>,
    witnessed_item_ids: Vec<ItemId>,
    unavailable_witnessed_item_ids: Vec<ItemId>,
    checkpoints_current: bool,
    external_witness_recovery_required: bool,
}

impl Serialize for BackupReceipt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let coverage = self.coverage();
        BackupReceiptWire {
            backup_id: self.backup_id.clone(),
            captured_public_revision_hash: self.captured_public_revision_hash.clone(),
            timestamp_ms: self.timestamp_ms,
            payload_digest: self.payload_digest.clone(),
            owner_descriptor_fingerprint: coverage.owner_descriptor_fingerprint.clone(),
            identity_role_mask: coverage.identity_role_mask,
            direct_item_ids: coverage.direct_item_ids.clone(),
            witnessed_item_ids: coverage.witnessed_item_ids.clone(),
            unavailable_witnessed_item_ids: coverage.unavailable_witnessed_item_ids.clone(),
            checkpoints_current: coverage.checkpoints_current,
            external_witness_recovery_required: coverage.external_witness_recovery_required,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BackupReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = BackupReceiptWire::deserialize(deserializer)?;
        Ok(Self {
            backup_id: wire.backup_id,
            captured_public_revision_hash: wire.captured_public_revision_hash,
            timestamp_ms: wire.timestamp_ms,
            payload_digest: wire.payload_digest,
            coverage: BackupReceiptCoverage {
                owner_descriptor_fingerprint: wire.owner_descriptor_fingerprint,
                identity_role_mask: wire.identity_role_mask,
                direct_item_ids: wire.direct_item_ids,
                witnessed_item_ids: wire.witnessed_item_ids,
                unavailable_witnessed_item_ids: wire.unavailable_witnessed_item_ids,
                checkpoints_current: wire.checkpoints_current,
                external_witness_recovery_required: wire.external_witness_recovery_required,
            },
        })
    }
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
                    self.latest_backup.as_ref().map(BackupReceipt::timestamp_ms),
                    receipt.timestamp_ms(),
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
            operation_id: receipt.backup_id().clone(),
            captured_public_revision_hash: receipt.captured_public_revision_hash().clone(),
            timestamp_ms: receipt.timestamp_ms(),
            output_digest: backup_coverage_digest(receipt.payload_digest(), receipt.coverage()),
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

fn backup_coverage_digest(
    payload_digest: &Digest32,
    coverage_receipt: &BackupReceiptCoverage,
) -> Digest32 {
    let mut coverage = jce("jury-v1/receipt/backup-coverage");
    coverage.extend_from_slice(payload_digest.as_bytes());
    coverage.extend_from_slice(coverage_receipt.owner_descriptor_fingerprint.as_bytes());
    coverage.push(coverage_receipt.identity_role_mask);
    coverage.push(u8::from(coverage_receipt.checkpoints_current));
    coverage.push(u8::from(
        coverage_receipt.external_witness_recovery_required,
    ));
    append_item_ids(&mut coverage, &coverage_receipt.direct_item_ids);
    append_item_ids(&mut coverage, &coverage_receipt.witnessed_item_ids);
    append_item_ids(
        &mut coverage,
        &coverage_receipt.unavailable_witnessed_item_ids,
    );
    Digest32::new(Sha256::digest(coverage).into())
}

fn append_item_ids(output: &mut Vec<u8>, item_ids: &[ItemId]) {
    output.extend_from_slice(&(item_ids.len() as u32).to_be_bytes());
    for item_id in item_ids {
        output.extend_from_slice(item_id.as_bytes());
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
        receipt.backup_id(),
        receipt.captured_public_revision_hash(),
        receipt.timestamp_ms(),
        receipt.payload_digest(),
    )?;
    let coverage = receipt.coverage();
    if digest_is_zero(&coverage.owner_descriptor_fingerprint)
        || coverage.identity_role_mask & 1 == 0
        || coverage.identity_role_mask & !0b111 != 0
        || !coverage.checkpoints_current
        || !strictly_sorted_unique(&coverage.direct_item_ids)
        || !strictly_sorted_unique(&coverage.witnessed_item_ids)
        || !strictly_sorted_unique(&coverage.unavailable_witnessed_item_ids)
        || coverage.external_witness_recovery_required == coverage.witnessed_item_ids.is_empty()
        || coverage
            .unavailable_witnessed_item_ids
            .iter()
            .any(|item_id| !coverage.witnessed_item_ids.contains(item_id))
    {
        return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
    }
    Ok(())
}

fn strictly_sorted_unique(ids: &[ItemId]) -> bool {
    ids.windows(2).all(|pair| pair[0] < pair[1])
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_coverage_entry_matches_fixed_digest() -> Result<(), Box<dyn std::error::Error>> {
        let coverage = BackupReceiptCoverage {
            owner_descriptor_fingerprint: Digest32::new([0x22; 32]),
            identity_role_mask: 7,
            direct_item_ids: vec![
                ItemId::from_bytes([0x31; 32])?,
                ItemId::from_bytes([0x32; 32])?,
            ],
            witnessed_item_ids: vec![ItemId::from_bytes([0x41; 32])?],
            unavailable_witnessed_item_ids: vec![ItemId::from_bytes([0x41; 32])?],
            checkpoints_current: true,
            external_witness_recovery_required: true,
        };
        // Fixed independently using Python hashlib: the domain/version bytes,
        // payload, owner, three flags, then three big-endian u32-counted ID lists.
        let expected = Digest32::new([
            0xd1, 0x01, 0x37, 0x94, 0x9c, 0x1c, 0xb8, 0xd1, 0x38, 0xf0, 0xe1, 0x12, 0xd8, 0x53,
            0x59, 0x46, 0xb1, 0x42, 0x91, 0xc6, 0xe9, 0x75, 0x1d, 0xdd, 0x8a, 0xda, 0xb5, 0xd8,
            0x15, 0x34, 0xde, 0xc9,
        ]);
        let receipt = BackupReceipt::with_coverage(
            Digest32::new([0x01; 32]),
            Digest32::new([0x02; 32]),
            3,
            Digest32::new([0x11; 32]),
            coverage,
        );
        validate_backup(&receipt)?;
        assert_eq!(ReceiptEntry::from_backup(&receipt).output_digest, expected);
        let bytes = serde_json::to_vec(&receipt)?;
        let decoded: BackupReceipt = serde_json::from_slice(&bytes)?;
        assert_eq!(decoded, receipt);
        for field in [
            "owner_descriptor_fingerprint",
            "identity_role_mask",
            "direct_item_ids",
            "witnessed_item_ids",
            "unavailable_witnessed_item_ids",
            "checkpoints_current",
            "external_witness_recovery_required",
        ] {
            let mut missing = serde_json::to_value(&receipt)?;
            missing
                .as_object_mut()
                .ok_or("receipt was not an object")?
                .remove(field);
            assert!(serde_json::from_value::<BackupReceipt>(missing).is_err());
        }
        Ok(())
    }
}
