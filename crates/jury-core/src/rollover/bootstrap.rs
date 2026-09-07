mod retained;
use super::*;
use jury_protocol::{
    rollover_v1::BootstrapItemV1,
    vault_v1::{PolicyJournalV1, SignedRolloverV1},
};
pub(crate) use retained::validate_retained_bootstrap;

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
