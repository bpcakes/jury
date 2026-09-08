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
    ApprovalId, BoundedBytes, ByteStringError, CancellationId, DescriptorCiphertext272, Digest32,
    DirectCiphertext48, Encapsulation1120, FieldId, FixedBytes, IdentityPayloadCiphertext149,
    ItemCiphertext, ItemId, LabelId, MigrationId, Nonce12, PresentationNonce, PrincipalId,
    ReceiptId, RecipientPublicKey1216, RecoveryId, RegistrationId, RequestId, ResponseId,
    RevisionSealId, RolloverId, RootWrapCiphertext48, RotationId, Salt16, ShareCiphertext49,
    Signature64, SlotId, VaultId, VerificationPublicKey32, WitnessPolicyId,
};
pub use plaintext::{
    ITEM_DESCRIPTOR_PLAINTEXT_BYTES, ItemDescriptorV1, ItemFieldKind, ItemFieldV1, ItemFieldValue,
    ItemStateV1, MAX_FIELD_VALUE_BYTES, MAX_ITEM_FIELDS, MIN_CONCEALED_VALUE_BYTES, PlaintextError,
};
pub use preimage::{
    CanonicalError, item_body_aad, item_descriptor_aad, recipient_public_key_fingerprint,
    witnessed_slot_set_digest, witnessed_slot_set_digest_preimage,
};
pub use types::{
    AccessRole, ContentRole, DescriptorMetadataV1, DirectSlotV1, EmptyGenesisEntryV1,
    ItemAccessMode, ItemEnvelopeV1, ItemKind, PolicyGenesisV1, PolicyJournalV1, PolicyOperationV1,
    PrincipalDescriptorV1, PrincipalKind, RemovalReason, SignedItemRevisionV1,
    SignedPolicyRevisionV1, SignedRolloverV1, SignedSuiteMigrationV1, SourceAttestationV1,
    VaultFileV1, VaultHeaderV1, WitnessShareCapsuleV1, WitnessedSlotV1, WitnessedStateV1,
};
pub use validate::{
    FormatError, MAX_CURRENT_SLOTS, MAX_ITEM_REVISION_PROOFS, MAX_ITEMS, MAX_POLICY_REVISIONS,
    MAX_PUBLIC_LABEL_BYTES, MAX_VAULT_BYTES, validate_policy_operation_context,
};

impl PolicyGenesisV1 {
    /// The single defined empty bootstrap case. This is only a shape check;
    /// callers must still authenticate the bridge, manifest and revision.
    #[must_use]
    pub fn permits_empty_rollover_bootstrap(&self) -> bool {
        let Some(SourceAttestationV1::Rollover { statement }) = &self.source_attestation else {
            return false;
        };
        let Some(manifest) = &statement.bootstrap_manifest else {
            return false;
        };
        manifest.items.is_empty()
            && manifest.witness_policies.is_empty()
            && manifest.principals.len() == 1
            && manifest.principals[0].principal_id == self.owner.principal_id
            && manifest.principals[0].owner
            && manifest.principals[0].display_label == "owner"
            && manifest.destination_vault_id == self.vault_id
            && manifest.destination_suite == self.suite
            && manifest.created_at_ms == self.created_at_ms
            && manifest.acting_owner_principal_id == self.owner.principal_id
            && manifest.digest().as_ref() == Ok(&statement.bootstrap_manifest_digest)
            && self.owner.self_signature_preimage().is_ok_and(|preimage| {
                use sha2::{Digest as _, Sha256};
                manifest.principals[0].unsigned_descriptor_digest
                    == Digest32::new(Sha256::digest(preimage).into())
            })
    }
}

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
