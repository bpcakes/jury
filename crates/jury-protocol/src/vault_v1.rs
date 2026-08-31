//! Bounded `jury-vault` JSON format version 1.
//!
//! The JSON representation is public storage only. Cryptographic inputs are
//! produced by the typed JCE1 builders on the format types; JSON bytes are
//! never signed, hashed, or used as AEAD associated data.

mod bytes;
mod plaintext;
mod preimage;
mod types;
mod validate;

pub use bytes::{
    BoundedBytes, ByteStringError, DescriptorCiphertext272, Digest32, DirectCiphertext48,
    Encapsulation1120, FieldId, FixedBytes, ItemCiphertext, ItemId, MigrationId, Nonce12,
    PrincipalId, RecipientPublicKey1216, RevisionSealId, RolloverId, ShareCiphertext49,
    Signature64, SlotId, VaultId, VerificationPublicKey32, WitnessPolicyId,
};
pub use plaintext::{
    ITEM_DESCRIPTOR_PLAINTEXT_BYTES, ItemDescriptorV1, ItemFieldKind, ItemFieldV1, ItemFieldValue,
    ItemStateV1, MAX_FIELD_VALUE_BYTES, MAX_ITEM_FIELDS, MIN_CONCEALED_VALUE_BYTES, PlaintextError,
};
pub use preimage::{CanonicalError, item_body_aad, item_descriptor_aad};
pub use types::{
    AccessRole, ContentRole, DescriptorMetadataV1, DirectSlotV1, EmptyGenesisEntryV1,
    ItemAccessMode, ItemEnvelopeV1, ItemKind, PolicyGenesisV1, PolicyJournalV1, PolicyOperationV1,
    PrincipalDescriptorV1, PrincipalKind, RemovalReason, SignedItemRevisionV1,
    SignedPolicyRevisionV1, SignedRolloverV1, SignedSuiteMigrationV1, SourceAttestationV1,
    VaultFileV1, VaultHeaderV1, WitnessShareCapsuleV1, WitnessedSlotV1, WitnessedStateV1,
};
pub use validate::{
    FormatError, MAX_CURRENT_SLOTS, MAX_ITEM_REVISION_PROOFS, MAX_ITEMS, MAX_POLICY_REVISIONS,
    MAX_PUBLIC_LABEL_BYTES, MAX_VAULT_BYTES,
};

impl WitnessedStateV1 {
    /// Whether the state may carry a quorum claim at the item level.
    ///
    /// Callers must pass the direct slots authenticated by the same policy
    /// operation. A single direct slot makes access unilateral for its
    /// recipient and therefore suppresses the claim.
    #[must_use]
    pub const fn has_item_quorum_claim(&self, direct_slot_count: usize) -> bool {
        direct_slot_count == 0 && self.slots.len() == 2
    }
}
