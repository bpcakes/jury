use std::fmt;

use sha2::{Digest as _, Sha256};

use crate::canonical::{self, jce_v1 as jce, optional_fixed, optional_u8};

use super::bytes::{Digest32, FixedBytes, RecipientPublicKey1216};
use super::types::{
    DescriptorMetadataV1, DirectSlotV1, PolicyGenesisV1, PolicyOperationV1, PrincipalDescriptorV1,
    SignedItemRevisionV1, SignedPolicyRevisionV1, SignedRolloverV1, SignedSuiteMigrationV1,
    SourceAttestationV1, WitnessShareCapsuleV1, WitnessedSlotV1, WitnessedStateV1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalError {
    LengthOverflow,
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("canonical field length exceeds u32")
    }
}

impl std::error::Error for CanonicalError {}

fn u16be(value: u16) -> [u8; 2] {
    value.to_be_bytes()
}

fn u64be(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn bytes_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), CanonicalError> {
    canonical::bytes_field(output, value).map_err(|_| CanonicalError::LengthOverflow)
}

fn list_bytes(output: &mut Vec<u8>, values: &[Vec<u8>]) -> Result<(), CanonicalError> {
    canonical::list_bytes(output, values).map_err(|_| CanonicalError::LengthOverflow)
}

fn list_fixed<T>(
    output: &mut Vec<u8>,
    values: &[T],
    append: impl FnMut(&mut Vec<u8>, &T),
) -> Result<(), CanonicalError> {
    canonical::list_fixed(output, values, append).map_err(|_| CanonicalError::LengthOverflow)
}

fn optional_bytes(output: &mut Vec<u8>, value: Option<&[u8]>) -> Result<(), CanonicalError> {
    canonical::optional_bytes(output, value).map_err(|_| CanonicalError::LengthOverflow)
}

fn sha256(value: &[u8]) -> Digest32 {
    FixedBytes::new(Sha256::digest(value).into())
}

/// Fingerprints one exact suite-1 recipient public bundle.
#[must_use]
pub fn recipient_public_key_fingerprint(key: &RecipientPublicKey1216) -> Digest32 {
    let mut output = jce("jury-v1/recipient-public-bundle/fingerprint");
    output.extend_from_slice(key.as_bytes());
    sha256(&output)
}

impl PrincipalDescriptorV1 {
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(1_283);
        output.extend_from_slice(&u16be(self.descriptor_version));
        output.extend_from_slice(self.principal_id.as_bytes());
        output.push(self.principal_kind.tag());
        output.extend_from_slice(self.recipient_public_key.as_bytes());
        output.extend_from_slice(self.verification_public_key.as_bytes());
        output
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = self.canonical_body();
        output.extend_from_slice(self.self_signature.as_bytes());
        output
    }

    pub fn fingerprint_preimage(&self) -> Result<Vec<u8>, CanonicalError> {
        let mut output = jce("jury-v1/principal-descriptor/fingerprint");
        output.extend_from_slice(&self.canonical_body());
        Ok(output)
    }

    pub fn self_signature_preimage(&self) -> Result<Vec<u8>, CanonicalError> {
        let mut output = jce("jury-v1/principal-descriptor/self-signature");
        output.extend_from_slice(&self.canonical_body());
        Ok(output)
    }
}

impl DescriptorMetadataV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(97);
        output.extend_from_slice(&u64be(self.revision));
        output.extend_from_slice(self.revision_seal_id.as_bytes());
        output.extend_from_slice(self.nonce.as_bytes());
        output.extend_from_slice(&self.ciphertext_length.to_be_bytes());
        output.extend_from_slice(self.ciphertext_digest.as_bytes());
        output.push(self.plaintext_schema);
        output.extend_from_slice(&u64be(self.key_epoch));
        output
    }
}

impl DirectSlotV1 {
    #[must_use]
    pub fn info_preimage(&self) -> Vec<u8> {
        let mut output = jce("jury-vault-v1-direct-revision-secret-slot");
        output.push(self.slot_schema);
        output.extend_from_slice(self.vault_id.as_bytes());
        output.extend_from_slice(self.item_id.as_bytes());
        output.extend_from_slice(&u64be(self.key_epoch));
        output.push(self.content_role.tag());
        output.extend_from_slice(&u64be(self.revision));
        output.extend_from_slice(self.revision_seal_id.as_bytes());
        output.extend_from_slice(self.recipient_principal_id.as_bytes());
        output
    }

    #[must_use]
    pub fn aad_preimage(&self) -> Vec<u8> {
        let mut output = jce("jury-vault-v1-direct-revision-secret-slot-aad");
        output.extend_from_slice(&u64be(self.policy_sequence));
        output.extend_from_slice(self.recipient_public_key_fingerprint.as_bytes());
        output.push(self.access_role.tag());
        output.push(self.slot_algorithm);
        output.push(self.item_access_mode.tag());
        output
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(1_365);
        output.push(self.slot_schema);
        output.push(self.slot_algorithm);
        output.extend_from_slice(&u16be(self.suite));
        output.extend_from_slice(&u16be(self.kem));
        output.extend_from_slice(&u16be(self.kdf));
        output.extend_from_slice(&u16be(self.aead));
        output.extend_from_slice(self.vault_id.as_bytes());
        output.extend_from_slice(self.item_id.as_bytes());
        output.extend_from_slice(&u64be(self.key_epoch));
        output.push(self.content_role.tag());
        output.extend_from_slice(&u64be(self.revision));
        output.extend_from_slice(self.revision_seal_id.as_bytes());
        output.extend_from_slice(self.recipient_principal_id.as_bytes());
        output.extend_from_slice(&u64be(self.policy_sequence));
        output.extend_from_slice(self.recipient_public_key_fingerprint.as_bytes());
        output.push(self.access_role.tag());
        output.push(self.item_access_mode.tag());
        output.extend_from_slice(self.encapsulation.as_bytes());
        output.extend_from_slice(self.ciphertext.as_bytes());
        output
    }
}

impl WitnessShareCapsuleV1 {
    fn append_context_fields(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&u16be(self.capsule_schema));
        output.extend_from_slice(&u16be(self.protocol));
        output.extend_from_slice(&u16be(self.construction));
        output.extend_from_slice(self.vault_id.as_bytes());
        output.extend_from_slice(self.genesis_fingerprint.as_bytes());
        output.extend_from_slice(self.item_id.as_bytes());
        output.extend_from_slice(&u64be(self.key_epoch));
        output.push(self.item_access_mode.tag());
        output.extend_from_slice(self.slot_id.as_bytes());
        output.push(self.content_role.tag());
        output.extend_from_slice(&u64be(self.revision));
        output.extend_from_slice(self.revision_seal_id.as_bytes());
        output.extend_from_slice(&u64be(self.vault_policy_sequence));
        output.extend_from_slice(self.witness_policy_id.as_bytes());
        output.extend_from_slice(&u64be(self.witness_policy_revision));
        output.extend_from_slice(self.witness_policy_digest.as_bytes());
        output.push(self.threshold);
        output.push(self.member_count);
        output.extend_from_slice(self.witness_id.as_bytes());
        output.extend_from_slice(self.contribution_key_fingerprint.as_bytes());
        output.push(self.share_index);
    }

    #[must_use]
    pub fn context_preimage(&self) -> Vec<u8> {
        let mut output = jce("jury-witness-v1/capsule/context");
        self.append_context_fields(&mut output);
        output
    }

    #[must_use]
    pub fn info_preimage(&self) -> Vec<u8> {
        let mut output = jce("jury-witness-v1/capsule/info");
        output.extend_from_slice(self.context_digest.as_bytes());
        output.extend_from_slice(self.witness_id.as_bytes());
        output.extend_from_slice(self.contribution_key_fingerprint.as_bytes());
        output.push(self.share_index);
        output
    }

    #[must_use]
    pub fn aad_preimage(&self) -> Vec<u8> {
        let mut output = jce("jury-witness-v1/capsule/aad");
        output.extend_from_slice(self.context_digest.as_bytes());
        output.extend_from_slice(self.share_commitment.as_bytes());
        output.extend_from_slice(self.witness_policy_digest.as_bytes());
        output.extend_from_slice(&u64be(self.vault_policy_sequence));
        output
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(1_461);
        self.append_context_fields(&mut output);
        output.extend_from_slice(self.context_digest.as_bytes());
        output.extend_from_slice(self.share_commitment.as_bytes());
        output.extend_from_slice(self.encapsulation.as_bytes());
        output.extend_from_slice(self.ciphertext.as_bytes());
        output
    }

    #[must_use]
    pub fn recomputed_context_digest(&self) -> Digest32 {
        sha256(&self.context_preimage())
    }
}

impl WitnessedSlotV1 {
    fn append_common_fields(&self, output: &mut Vec<u8>) {
        output.push(self.slot_schema);
        output.push(self.slot_algorithm);
        output.extend_from_slice(&u16be(self.suite));
        output.extend_from_slice(&u16be(self.protocol));
        output.extend_from_slice(&u16be(self.construction));
        output.extend_from_slice(self.vault_id.as_bytes());
        output.extend_from_slice(self.genesis_fingerprint.as_bytes());
        output.extend_from_slice(self.item_id.as_bytes());
        output.extend_from_slice(&u64be(self.key_epoch));
        output.push(self.item_access_mode.tag());
        output.extend_from_slice(self.slot_id.as_bytes());
        output.push(self.content_role.tag());
        output.extend_from_slice(&u64be(self.revision));
        output.extend_from_slice(self.revision_seal_id.as_bytes());
        output.extend_from_slice(&u64be(self.vault_policy_sequence));
        output.extend_from_slice(self.witness_policy_id.as_bytes());
        output.extend_from_slice(&u64be(self.witness_policy_revision));
        output.extend_from_slice(self.witness_policy_digest.as_bytes());
        output.push(self.threshold);
        output.push(self.member_count);
    }

    pub fn capsule_set_preimage(&self) -> Result<Vec<u8>, CanonicalError> {
        let capsules = self
            .capsules
            .iter()
            .map(WitnessShareCapsuleV1::canonical_bytes)
            .collect::<Vec<_>>();
        let mut output = jce("jury-witness-v1/capsule-set/hash");
        list_bytes(&mut output, &capsules)?;
        Ok(output)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        let capsules = self
            .capsules
            .iter()
            .map(WitnessShareCapsuleV1::canonical_bytes)
            .collect::<Vec<_>>();
        let mut output = Vec::new();
        self.append_common_fields(&mut output);
        list_bytes(&mut output, &capsules)?;
        output.extend_from_slice(self.capsule_set_digest.as_bytes());
        Ok(output)
    }

    pub fn digest_preimage(&self) -> Result<Vec<u8>, CanonicalError> {
        let slot = self.canonical_bytes()?;
        let mut output = jce("jury-witness-v1/slot/hash");
        bytes_field(&mut output, &slot)?;
        Ok(output)
    }

    pub fn recomputed_capsule_set_digest(&self) -> Result<Digest32, CanonicalError> {
        Ok(sha256(&self.capsule_set_preimage()?))
    }

    pub fn recomputed_digest(&self) -> Result<Digest32, CanonicalError> {
        Ok(sha256(&self.digest_preimage()?))
    }
}

impl WitnessedStateV1 {
    pub fn digest_preimage(&self) -> Result<Vec<u8>, CanonicalError> {
        witnessed_slot_set_digest_preimage(&self.slots)
    }

    pub fn recomputed_digest(&self) -> Result<Digest32, CanonicalError> {
        Ok(sha256(&self.digest_preimage()?))
    }
}

/// Builds the J19 slot-set digest preimage for an already canonical slot set.
///
/// This is also used by policy replay to bind the flattened current witnessed
/// state when more than one item has witnessed slots.
pub fn witnessed_slot_set_digest_preimage(
    slots: &[WitnessedSlotV1],
) -> Result<Vec<u8>, CanonicalError> {
    let slots = slots
        .iter()
        .map(WitnessedSlotV1::canonical_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    let mut output = jce("jury-witness-v1/slot-set/hash");
    list_bytes(&mut output, &slots)?;
    Ok(output)
}

/// Recomputes the J19 digest for an already canonical slot set.
pub fn witnessed_slot_set_digest(slots: &[WitnessedSlotV1]) -> Result<Digest32, CanonicalError> {
    Ok(sha256(&witnessed_slot_set_digest_preimage(slots)?))
}

impl SourceAttestationV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        let mut output = Vec::new();
        match self {
            Self::LegacyMigration {
                source_format,
                migration_id,
                final_legacy_audit_digest,
                terminal_legacy_audit_mac,
            } => {
                output.push(1);
                output.extend_from_slice(&u16be(*source_format));
                output.extend_from_slice(migration_id.as_bytes());
                output.extend_from_slice(final_legacy_audit_digest.as_bytes());
                output.extend_from_slice(terminal_legacy_audit_mac.as_bytes());
            }
            Self::Rollover { statement } => {
                output.push(2);
                bytes_field(&mut output, &statement.signature_preimage())?;
                output.extend_from_slice(statement.signature.as_bytes());
            }
        }
        Ok(output)
    }
}

impl SignedRolloverV1 {
    #[must_use]
    pub fn signature_preimage(&self) -> Vec<u8> {
        let mut output = jce("jury-v1/rollover/signature");
        output.extend_from_slice(&u16be(self.rollover_format));
        output.extend_from_slice(self.rollover_id.as_bytes());
        output.extend_from_slice(self.source_vault_id.as_bytes());
        output.extend_from_slice(self.source_genesis_fingerprint.as_bytes());
        output.extend_from_slice(self.terminal_source_revision_hash.as_bytes());
        output.extend_from_slice(self.destination_vault_id.as_bytes());
        output.extend_from_slice(&u16be(self.destination_suite));
        output.extend_from_slice(self.bootstrap_manifest_digest.as_bytes());
        output.extend_from_slice(self.acting_owner_principal_id.as_bytes());
        output
    }
}

impl SignedSuiteMigrationV1 {
    #[must_use]
    pub fn signature_preimage(&self) -> Vec<u8> {
        let mut output = jce("jury-v1/suite-migration/signature");
        output.extend_from_slice(&u16be(self.migration_format));
        output.extend_from_slice(self.migration_id.as_bytes());
        output.extend_from_slice(self.old_vault_id.as_bytes());
        output.extend_from_slice(self.old_genesis_fingerprint.as_bytes());
        output.extend_from_slice(self.old_terminal_revision_hash.as_bytes());
        output.extend_from_slice(&u16be(self.old_suite));
        output.extend_from_slice(self.new_vault_id.as_bytes());
        output.extend_from_slice(self.new_genesis_fingerprint.as_bytes());
        output.extend_from_slice(&u16be(self.new_suite));
        output.extend_from_slice(self.migrated_item_manifest_digest.as_bytes());
        output
    }
}

impl PolicyGenesisV1 {
    pub fn signature_preimage(&self) -> Result<Vec<u8>, CanonicalError> {
        let source = self
            .source_attestation
            .as_ref()
            .map(SourceAttestationV1::canonical_bytes)
            .transpose()?;
        let mut output = jce("jury-v1/policy-genesis/signature");
        output.extend_from_slice(self.vault_id.as_bytes());
        output.extend_from_slice(&u64be(self.policy_sequence));
        output.extend_from_slice(self.previous_policy_hash.as_bytes());
        output.extend_from_slice(&u64be(self.created_at_ms));
        bytes_field(&mut output, &self.owner.canonical_bytes())?;
        optional_bytes(&mut output, source.as_deref())?;
        output.extend_from_slice(&0_u32.to_be_bytes());
        output.extend_from_slice(&0_u32.to_be_bytes());
        Ok(output)
    }

    pub fn fingerprint_preimage(&self) -> Result<Vec<u8>, CanonicalError> {
        let signature_preimage = self.signature_preimage()?;
        let mut output = jce("jury-v1/policy-genesis/fingerprint");
        bytes_field(&mut output, &signature_preimage)?;
        output.extend_from_slice(self.owner_signature.as_bytes());
        Ok(output)
    }

    pub fn recomputed_fingerprint(&self) -> Result<Digest32, CanonicalError> {
        Ok(sha256(&self.fingerprint_preimage()?))
    }
}

impl PolicyOperationV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        let mut output = Vec::new();
        match self {
            Self::PrincipalAdd {
                descriptor,
                display_label,
                registration_proof_digest,
            } => {
                output.push(1);
                bytes_field(&mut output, &descriptor.canonical_bytes())?;
                bytes_field(&mut output, display_label.as_bytes())?;
                output.extend_from_slice(registration_proof_digest.as_bytes());
            }
            Self::PrincipalLabelChange {
                principal_id,
                prior_label,
                next_label,
            } => {
                output.push(2);
                output.extend_from_slice(principal_id.as_bytes());
                bytes_field(&mut output, prior_label.as_bytes())?;
                bytes_field(&mut output, next_label.as_bytes())?;
            }
            Self::PrincipalRemove {
                principal_id,
                removal_reason,
            } => {
                output.push(3);
                output.extend_from_slice(principal_id.as_bytes());
                output.push(removal_reason.tag());
            }
            Self::OwnerGrant { principal_id } => {
                output.push(4);
                output.extend_from_slice(principal_id.as_bytes());
            }
            Self::OwnerRevoke { principal_id } => {
                output.push(5);
                output.extend_from_slice(principal_id.as_bytes());
            }
            Self::ItemCreate {
                item_id,
                item_kind,
                key_epoch,
                descriptor,
                current_item_revision_hash,
                direct_slots,
                witnessed_state,
            } => {
                output.push(6);
                output.extend_from_slice(item_id.as_bytes());
                output.push(item_kind.tag());
                output.extend_from_slice(&u64be(*key_epoch));
                output.extend_from_slice(&descriptor.canonical_bytes());
                output.extend_from_slice(current_item_revision_hash.as_bytes());
                list_fixed(&mut output, direct_slots, |bytes, slot| {
                    bytes.extend_from_slice(&slot.canonical_bytes());
                })?;
                optional_fixed(
                    &mut output,
                    witnessed_state
                        .as_ref()
                        .map(|state| state.digest.as_bytes().as_slice()),
                );
            }
            Self::ItemRename {
                item_id,
                prior_descriptor_revision,
                next_descriptor,
            } => {
                output.push(7);
                output.extend_from_slice(item_id.as_bytes());
                output.extend_from_slice(&u64be(*prior_descriptor_revision));
                output.extend_from_slice(&next_descriptor.canonical_bytes());
            }
            Self::ItemDelete {
                item_id,
                final_descriptor_digest,
                final_item_revision_hash,
                deletion_policy_sequence,
            } => {
                output.push(8);
                output.extend_from_slice(item_id.as_bytes());
                output.extend_from_slice(final_descriptor_digest.as_bytes());
                output.extend_from_slice(final_item_revision_hash.as_bytes());
                output.extend_from_slice(&u64be(*deletion_policy_sequence));
            }
            Self::ItemRoleChange {
                item_id,
                principal_id,
                prior_role,
                next_role,
            } => {
                output.push(9);
                output.extend_from_slice(item_id.as_bytes());
                output.extend_from_slice(principal_id.as_bytes());
                optional_u8(&mut output, prior_role.map(|role| role.tag()));
                optional_u8(&mut output, next_role.map(|role| role.tag()));
            }
            Self::ItemReaderSetChange {
                item_id,
                prior_epoch,
                next_epoch,
                prior_reader_ids,
                next_reader_ids,
                replacement_descriptor,
                replacement_current_item_revision_hash,
            } => {
                output.push(10);
                output.extend_from_slice(item_id.as_bytes());
                output.extend_from_slice(&u64be(*prior_epoch));
                output.extend_from_slice(&u64be(*next_epoch));
                list_fixed(&mut output, prior_reader_ids, |bytes, id| {
                    bytes.extend_from_slice(id.as_bytes());
                })?;
                list_fixed(&mut output, next_reader_ids, |bytes, id| {
                    bytes.extend_from_slice(id.as_bytes());
                })?;
                output.extend_from_slice(&replacement_descriptor.canonical_bytes());
                output.extend_from_slice(replacement_current_item_revision_hash.as_bytes());
            }
            Self::ItemSlotsReplace {
                item_id,
                next_epoch,
                direct_slots,
                witnessed_state,
            } => {
                output.push(11);
                output.extend_from_slice(item_id.as_bytes());
                output.extend_from_slice(&u64be(*next_epoch));
                list_fixed(&mut output, direct_slots, |bytes, slot| {
                    bytes.extend_from_slice(&slot.canonical_bytes());
                })?;
                optional_fixed(
                    &mut output,
                    witnessed_state
                        .as_ref()
                        .map(|state| state.digest.as_bytes().as_slice()),
                );
            }
            Self::PrincipalReplace {
                prior_principal_id,
                next_descriptor,
                registration_proof_digest,
            } => {
                output.push(12);
                output.extend_from_slice(prior_principal_id.as_bytes());
                bytes_field(&mut output, &next_descriptor.canonical_bytes())?;
                output.extend_from_slice(registration_proof_digest.as_bytes());
            }
        }
        Ok(output)
    }
}

impl SignedPolicyRevisionV1 {
    pub fn signature_preimage(&self) -> Result<Vec<u8>, CanonicalError> {
        let operations = self
            .operations
            .iter()
            .map(PolicyOperationV1::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        let mut output = jce("jury-v1/policy-revision/signature");
        output.extend_from_slice(self.vault_id.as_bytes());
        output.extend_from_slice(&u64be(self.sequence));
        output.extend_from_slice(self.previous_revision_hash.as_bytes());
        output.extend_from_slice(&u64be(self.timestamp_ms));
        output.extend_from_slice(self.author_principal_id.as_bytes());
        list_bytes(&mut output, &operations)?;
        output.extend_from_slice(self.resulting_policy_state_hash.as_bytes());
        Ok(output)
    }

    pub fn hash_preimage(&self) -> Result<Vec<u8>, CanonicalError> {
        let signature_preimage = self.signature_preimage()?;
        let mut output = jce("jury-v1/policy-revision/hash");
        bytes_field(&mut output, &signature_preimage)?;
        output.extend_from_slice(self.signature.as_bytes());
        Ok(output)
    }

    pub fn recomputed_hash(&self) -> Result<Digest32, CanonicalError> {
        Ok(sha256(&self.hash_preimage()?))
    }
}

impl SignedItemRevisionV1 {
    #[must_use]
    pub fn signature_preimage(&self) -> Vec<u8> {
        let mut output = jce("jury-v1/item-revision/signature");
        output.extend_from_slice(self.vault_id.as_bytes());
        output.extend_from_slice(self.item_id.as_bytes());
        output.extend_from_slice(&u64be(self.item_revision));
        output.extend_from_slice(self.previous_item_revision_hash.as_bytes());
        output.extend_from_slice(&u64be(self.key_epoch));
        output.extend_from_slice(&u64be(self.policy_sequence));
        output.extend_from_slice(self.author_principal_id.as_bytes());
        output.extend_from_slice(&u64be(self.timestamp_ms));
        output.extend_from_slice(self.revision_seal_id.as_bytes());
        output.extend_from_slice(self.nonce.as_bytes());
        output.extend_from_slice(&self.ciphertext_length.to_be_bytes());
        output.extend_from_slice(self.ciphertext_digest.as_bytes());
        output.push(self.plaintext_schema);
        output.push(self.bucket_id);
        output
    }

    pub fn hash_preimage(&self) -> Result<Vec<u8>, CanonicalError> {
        let signature_preimage = self.signature_preimage();
        let mut output = jce("jury-v1/item-revision/hash");
        bytes_field(&mut output, &signature_preimage)?;
        output.extend_from_slice(self.signature.as_bytes());
        Ok(output)
    }

    pub fn recomputed_hash(&self) -> Result<Digest32, CanonicalError> {
        Ok(sha256(&self.hash_preimage()?))
    }
}

pub fn item_descriptor_aad(
    vault_id: &[u8; 32],
    item_id: &[u8; 32],
    key_epoch: u64,
    revision: u64,
    revision_seal_id: &[u8; 32],
) -> Vec<u8> {
    let mut output = jce("jury-vault-v1-item-descriptor");
    output.push(1);
    output.extend_from_slice(vault_id);
    output.extend_from_slice(item_id);
    output.extend_from_slice(&u64be(key_epoch));
    output.extend_from_slice(&u64be(revision));
    output.extend_from_slice(revision_seal_id);
    output
}

pub fn item_body_aad(
    vault_id: &[u8; 32],
    item_id: &[u8; 32],
    key_epoch: u64,
    revision: u64,
    revision_seal_id: &[u8; 32],
    bucket_id: u8,
) -> Vec<u8> {
    let mut output = jce("jury-vault-v1-item-body");
    output.push(1);
    output.extend_from_slice(vault_id);
    output.extend_from_slice(item_id);
    output.extend_from_slice(&u64be(key_epoch));
    output.extend_from_slice(&u64be(revision));
    output.extend_from_slice(revision_seal_id);
    output.push(bucket_id);
    output
}
