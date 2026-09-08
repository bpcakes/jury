mod retained;
use super::*;
use jury_protocol::{
    rollover_v1::BootstrapItemV1,
    vault_v1::{PolicyJournalV1, SignedRolloverV1},
};
pub(crate) use retained::validate_retained_bootstrap;

/// A complete current artifact and its authenticated retained bootstrap. Only
/// this constructor can pair the borrowed artifact with the validated state;
/// verification helpers cannot accept a caller-supplied replay result.
pub(super) struct ValidatedDestination<'a> {
    vault: &'a VaultFileV1,
    bootstrap: PolicyState,
}

impl<'a> ValidatedDestination<'a> {
    pub(super) fn validate(
        vault: &'a VaultFileV1,
        catalog: &crate::transfer::TransferPublicCatalogV1,
    ) -> Result<Self, RolloverError> {
        let current = RolloverSource::validate(vault, &catalog.witness_policies)?;
        catalog.to_json_bytes().map_err(|_| invalid())?;
        let bootstrap = catalog
            .validate_for_policy(vault, &current.policy)
            .map_err(|_| invalid())?
            .ok_or_else(invalid)?;
        Ok(Self { vault, bootstrap })
    }

    pub(super) fn vault(&self) -> &'a VaultFileV1 {
        self.vault
    }

    pub(super) fn bootstrap(&self) -> &PolicyState {
        &self.bootstrap
    }
}

pub(super) fn bootstrap_state(
    vault: &VaultFileV1,
    witness_policies: &[WitnessPolicy],
) -> Result<PolicyState, RolloverError> {
    let first = vault.policy.revisions.first().ok_or_else(invalid)?;
    replay_policy_with_witness_policies(
        &PolicyJournalV1 {
            genesis: vault.policy.genesis.clone(),
            revisions: vec![first.clone()],
        },
        witness_policies,
    )
    .map_err(|_| invalid())
}

pub(super) fn verify_fresh_envelope(
    vault: &VaultFileV1,
    entry: &BootstrapItemV1,
    statement: &SignedRolloverV1,
    created_at_ms: u64,
) -> Result<(), RolloverError> {
    let envelope = vault
        .items
        .iter()
        .find(|item| item.item_id == entry.destination_item_id)
        .ok_or_else(invalid)?;
    if !envelope.prior_revisions.is_empty()
        || envelope.current_revision.item_revision != 1
        || envelope.current_revision.key_epoch != 1
        || envelope.current_revision.policy_sequence != 1
        || envelope.current_revision.timestamp_ms != created_at_ms
        || envelope.current_revision.author_principal_id != statement.acting_owner_principal_id
    {
        return Err(invalid());
    }
    Ok(())
}

fn invalid() -> RolloverError {
    RolloverError::new(RolloverErrorKind::InvalidDestination)
}
