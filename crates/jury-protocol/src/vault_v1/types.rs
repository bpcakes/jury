use serde::{Deserialize, Serialize};

use super::bytes::{
    DescriptorCiphertext272, Digest32, DirectCiphertext48, Encapsulation1120, ItemCiphertext,
    ItemId, MigrationId, Nonce12, PrincipalId, RecipientPublicKey1216, RevisionSealId, RolloverId,
    ShareCiphertext49, Signature64, SlotId, VaultId, VerificationPublicKey32, WitnessPolicyId,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrincipalKind {
    Human,
    Machine,
    Approver,
    Witness,
}

impl PrincipalKind {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Human => 1,
            Self::Machine => 2,
            Self::Approver => 3,
            Self::Witness => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ItemKind {
    Canonical,
    Legacy,
}

impl ItemKind {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Canonical => 1,
            Self::Legacy => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContentRole {
    Descriptor,
    Body,
}

impl ContentRole {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Descriptor => 1,
            Self::Body => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessRole {
    Reader,
    Writer,
    Owner,
}

impl AccessRole {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Reader => 1,
            Self::Writer => 2,
            Self::Owner => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ItemAccessMode {
    DirectOnly,
    WitnessedOnly,
    Mixed,
}

impl ItemAccessMode {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::DirectOnly => 1,
            Self::WitnessedOnly => 2,
            Self::Mixed => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemovalReason {
    OperatorRemoval,
    Replacement,
    SuspectedCompromise,
    Retirement,
}

impl RemovalReason {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::OperatorRemoval => 1,
            Self::Replacement => 2,
            Self::SuspectedCompromise => 3,
            Self::Retirement => 4,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalDescriptorV1 {
    pub descriptor_version: u16,
    pub principal_id: PrincipalId,
    pub principal_kind: PrincipalKind,
    pub recipient_public_key: RecipientPublicKey1216,
    pub verification_public_key: VerificationPublicKey32,
    pub self_signature: Signature64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VaultHeaderV1 {
    pub magic: String,
    pub version: u16,
    pub vault_id: VaultId,
    pub created_at_ms: u64,
    pub suite: u16,
    pub policy_schema: u16,
    pub item_schema: u16,
    pub identity_schema: u16,
    pub genesis_fingerprint: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SourceAttestationV1 {
    LegacyMigration {
        source_format: u16,
        migration_id: MigrationId,
        final_legacy_audit_digest: Digest32,
        terminal_legacy_audit_mac: Digest32,
    },
    Rollover {
        statement: SignedRolloverV1,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRolloverV1 {
    pub rollover_format: u16,
    pub rollover_id: RolloverId,
    pub source_vault_id: VaultId,
    pub source_genesis_fingerprint: Digest32,
    pub terminal_source_revision_hash: Digest32,
    pub destination_vault_id: VaultId,
    pub destination_suite: u16,
    pub bootstrap_manifest_digest: Digest32,
    pub acting_owner_principal_id: PrincipalId,
    pub signature: Signature64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSuiteMigrationV1 {
    pub migration_format: u16,
    pub migration_id: MigrationId,
    pub old_vault_id: VaultId,
    pub old_genesis_fingerprint: Digest32,
    pub old_terminal_revision_hash: Digest32,
    pub old_suite: u16,
    pub new_vault_id: VaultId,
    pub new_genesis_fingerprint: Digest32,
    pub new_suite: u16,
    pub migrated_item_manifest_digest: Digest32,
    pub signature: Signature64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EmptyGenesisEntryV1 {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyGenesisV1 {
    pub vault_id: VaultId,
    pub policy_sequence: u64,
    pub previous_policy_hash: Digest32,
    pub created_at_ms: u64,
    pub suite: u16,
    pub owner: PrincipalDescriptorV1,
    pub source_attestation: Option<SourceAttestationV1>,
    pub item_inventory: Vec<EmptyGenesisEntryV1>,
    pub direct_grants: Vec<EmptyGenesisEntryV1>,
    pub owner_signature: Signature64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorMetadataV1 {
    pub revision: u64,
    pub revision_seal_id: RevisionSealId,
    pub nonce: Nonce12,
    pub ciphertext_length: u32,
    pub ciphertext_digest: Digest32,
    pub plaintext_schema: u8,
    pub key_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectSlotV1 {
    pub slot_schema: u8,
    pub slot_algorithm: u8,
    pub suite: u16,
    pub kem: u16,
    pub kdf: u16,
    pub aead: u16,
    pub vault_id: VaultId,
    pub item_id: ItemId,
    pub key_epoch: u64,
    pub content_role: ContentRole,
    pub revision: u64,
    pub revision_seal_id: RevisionSealId,
    pub recipient_principal_id: PrincipalId,
    pub policy_sequence: u64,
    pub recipient_public_key_fingerprint: Digest32,
    pub access_role: AccessRole,
    pub item_access_mode: ItemAccessMode,
    pub encapsulation: Encapsulation1120,
    pub ciphertext: DirectCiphertext48,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessShareCapsuleV1 {
    pub capsule_schema: u16,
    pub protocol: u16,
    pub construction: u16,
    pub vault_id: VaultId,
    pub genesis_fingerprint: Digest32,
    pub item_id: ItemId,
    pub key_epoch: u64,
    pub item_access_mode: ItemAccessMode,
    pub slot_id: SlotId,
    pub content_role: ContentRole,
    pub revision: u64,
    pub revision_seal_id: RevisionSealId,
    pub vault_policy_sequence: u64,
    pub witness_policy_id: WitnessPolicyId,
    pub witness_policy_revision: u64,
    pub witness_policy_digest: Digest32,
    pub threshold: u8,
    pub member_count: u8,
    pub witness_id: PrincipalId,
    pub contribution_key_fingerprint: Digest32,
    pub share_index: u8,
    pub context_digest: Digest32,
    pub share_commitment: Digest32,
    pub encapsulation: Encapsulation1120,
    pub ciphertext: ShareCiphertext49,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessedSlotV1 {
    pub slot_schema: u8,
    pub slot_algorithm: u8,
    pub suite: u16,
    pub protocol: u16,
    pub construction: u16,
    pub vault_id: VaultId,
    pub genesis_fingerprint: Digest32,
    pub item_id: ItemId,
    pub key_epoch: u64,
    pub item_access_mode: ItemAccessMode,
    pub slot_id: SlotId,
    pub content_role: ContentRole,
    pub revision: u64,
    pub revision_seal_id: RevisionSealId,
    pub vault_policy_sequence: u64,
    pub witness_policy_id: WitnessPolicyId,
    pub witness_policy_revision: u64,
    pub witness_policy_digest: Digest32,
    pub threshold: u8,
    pub member_count: u8,
    pub capsules: Vec<WitnessShareCapsuleV1>,
    pub capsule_set_digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessedStateV1 {
    pub slots: Vec<WitnessedSlotV1>,
    pub digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyOperationV1 {
    PrincipalAdd {
        descriptor: PrincipalDescriptorV1,
        display_label: String,
        registration_proof_digest: Digest32,
    },
    PrincipalLabelChange {
        principal_id: PrincipalId,
        prior_label: String,
        next_label: String,
    },
    PrincipalRemove {
        principal_id: PrincipalId,
        removal_reason: RemovalReason,
    },
    OwnerGrant {
        principal_id: PrincipalId,
    },
    OwnerRevoke {
        principal_id: PrincipalId,
    },
    ItemCreate {
        item_id: ItemId,
        item_kind: ItemKind,
        key_epoch: u64,
        descriptor: DescriptorMetadataV1,
        current_item_revision_hash: Digest32,
        direct_slots: Vec<DirectSlotV1>,
        witnessed_state: Option<WitnessedStateV1>,
    },
    ItemRename {
        item_id: ItemId,
        prior_descriptor_revision: u64,
        next_descriptor: DescriptorMetadataV1,
    },
    ItemDelete {
        item_id: ItemId,
        final_descriptor_digest: Digest32,
        final_item_revision_hash: Digest32,
        deletion_policy_sequence: u64,
    },
    ItemRoleChange {
        item_id: ItemId,
        principal_id: PrincipalId,
        prior_role: Option<AccessRole>,
        next_role: Option<AccessRole>,
    },
    ItemReaderSetChange {
        item_id: ItemId,
        prior_epoch: u64,
        next_epoch: u64,
        prior_reader_ids: Vec<PrincipalId>,
        next_reader_ids: Vec<PrincipalId>,
        replacement_descriptor: DescriptorMetadataV1,
        replacement_current_item_revision_hash: Digest32,
    },
    ItemSlotsReplace {
        item_id: ItemId,
        next_epoch: u64,
        direct_slots: Vec<DirectSlotV1>,
        witnessed_state: Option<WitnessedStateV1>,
    },
    PrincipalReplace {
        prior_principal_id: PrincipalId,
        next_descriptor: PrincipalDescriptorV1,
        registration_proof_digest: Digest32,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyRevisionV1 {
    pub vault_id: VaultId,
    pub sequence: u64,
    pub previous_revision_hash: Digest32,
    pub timestamp_ms: u64,
    pub author_principal_id: PrincipalId,
    pub operations: Vec<PolicyOperationV1>,
    pub resulting_policy_state_hash: Digest32,
    pub signature: Signature64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyJournalV1 {
    pub genesis: PolicyGenesisV1,
    pub revisions: Vec<SignedPolicyRevisionV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedItemRevisionV1 {
    pub vault_id: VaultId,
    pub item_id: ItemId,
    pub item_revision: u64,
    pub previous_item_revision_hash: Digest32,
    pub key_epoch: u64,
    pub policy_sequence: u64,
    pub author_principal_id: PrincipalId,
    pub timestamp_ms: u64,
    pub revision_seal_id: RevisionSealId,
    pub nonce: Nonce12,
    pub ciphertext_length: u32,
    pub ciphertext_digest: Digest32,
    pub plaintext_schema: u8,
    pub bucket_id: u8,
    pub signature: Signature64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ItemEnvelopeV1 {
    pub item_id: ItemId,
    pub descriptor: DescriptorMetadataV1,
    pub descriptor_ciphertext: DescriptorCiphertext272,
    pub prior_revisions: Vec<SignedItemRevisionV1>,
    pub current_revision: SignedItemRevisionV1,
    pub body_ciphertext: ItemCiphertext,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VaultFileV1 {
    pub header: VaultHeaderV1,
    pub policy: PolicyJournalV1,
    pub items: Vec<ItemEnvelopeV1>,
    pub suite_migration: Option<SignedSuiteMigrationV1>,
}
