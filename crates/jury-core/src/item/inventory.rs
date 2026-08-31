use std::collections::BTreeSet;

use jury_protocol::vault_v1::{
    DirectSlotV1, Nonce12, PolicyOperationV1, RevisionSealId, SlotId, VaultFileV1, WitnessedStateV1,
};

use super::{ItemError, ItemErrorKind};

/// Public artifact inventory used to reject seal, slot, and nonce reuse before
/// any replacement is returned.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ItemArtifactInventory {
    pub(super) revision_seal_ids: BTreeSet<RevisionSealId>,
    pub(super) slot_ids: BTreeSet<SlotId>,
    pub(super) nonces: BTreeSet<Nonce12>,
}

impl ItemArtifactInventory {
    pub fn from_vault(vault: &VaultFileV1) -> Result<Self, ItemError> {
        vault
            .validate()
            .map_err(|_| ItemError::new(ItemErrorKind::InvalidInput))?;
        let mut inventory = Self::default();
        for envelope in &vault.items {
            inventory
                .revision_seal_ids
                .insert(envelope.descriptor.revision_seal_id);
            inventory.nonces.insert(envelope.descriptor.nonce.clone());
            for revision in envelope
                .prior_revisions
                .iter()
                .chain(std::iter::once(&envelope.current_revision))
            {
                inventory
                    .revision_seal_ids
                    .insert(revision.revision_seal_id);
                inventory.nonces.insert(revision.nonce.clone());
            }
        }
        for revision in &vault.policy.revisions {
            for operation in &revision.operations {
                inventory.record_operation(operation);
            }
        }
        Ok(inventory)
    }

    fn record_operation(&mut self, operation: &PolicyOperationV1) {
        match operation {
            PolicyOperationV1::ItemCreate {
                descriptor,
                direct_slots,
                witnessed_state,
                ..
            } => {
                self.revision_seal_ids.insert(descriptor.revision_seal_id);
                self.nonces.insert(descriptor.nonce.clone());
                self.record_slots(direct_slots, witnessed_state.as_ref());
            }
            PolicyOperationV1::ItemRename {
                next_descriptor, ..
            }
            | PolicyOperationV1::ItemReaderSetChange {
                replacement_descriptor: next_descriptor,
                ..
            } => {
                self.revision_seal_ids
                    .insert(next_descriptor.revision_seal_id);
                self.nonces.insert(next_descriptor.nonce.clone());
            }
            PolicyOperationV1::ItemSlotsReplace {
                direct_slots,
                witnessed_state,
                ..
            } => self.record_slots(direct_slots, witnessed_state.as_ref()),
            _ => {}
        }
    }

    fn record_slots(
        &mut self,
        direct_slots: &[DirectSlotV1],
        witnessed_state: Option<&WitnessedStateV1>,
    ) {
        for slot in direct_slots {
            self.revision_seal_ids.insert(slot.revision_seal_id);
        }
        if let Some(state) = witnessed_state {
            for slot in &state.slots {
                self.revision_seal_ids.insert(slot.revision_seal_id);
                self.slot_ids.insert(slot.slot_id);
            }
        }
    }
}
