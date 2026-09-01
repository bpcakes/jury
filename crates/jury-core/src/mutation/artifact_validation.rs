use super::*;

pub(super) fn validate_complete(
    vault: &VaultFileV1,
    witness_policies: &[WitnessPolicy],
    current: bool,
) -> Result<PolicyState, MutationError> {
    vault.validate().map_err(|error| {
        if current {
            map_current_format_error(error)
        } else {
            map_target_format_error(error)
        }
    })?;
    let policy = replay_policy_with_witness_policies(&vault.policy, witness_policies)
        .map_err(|error| map_replay_error(error.kind(), current))?;
    CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items).map_err(|_| {
        MutationError::new(if current {
            MutationErrorKind::InvalidCurrentState
        } else {
            MutationErrorKind::InvalidPlan
        })
    })?;
    Ok(policy)
}

pub(super) fn validate_envelope_delta(
    current: &VaultFileV1,
    target: &VaultFileV1,
    current_policy: &PolicyState,
    target_policy: &PolicyState,
) -> Result<(), MutationError> {
    let current_envelopes = current
        .items
        .iter()
        .map(|item| (item.item_id, item))
        .collect::<BTreeMap<_, _>>();
    let target_envelopes = target
        .items
        .iter()
        .map(|item| (item.item_id, item))
        .collect::<BTreeMap<_, _>>();
    for (item_id, target_item) in &target_policy.items {
        let target_envelope = target_envelopes
            .get(item_id)
            .ok_or_else(|| MutationError::new(MutationErrorKind::MissingItemEnvelope))?;
        let changed = current_policy.item(item_id).is_none_or(|current_item| {
            current_item.current_item_revision_hash != target_item.current_item_revision_hash
                || current_item.descriptor != target_item.descriptor
        });
        if changed
            && current_envelopes
                .get(item_id)
                .is_some_and(|current_envelope| *current_envelope == *target_envelope)
        {
            return Err(MutationError::new(MutationErrorKind::MissingItemEnvelope));
        }
        if !changed
            && current_envelopes
                .get(item_id)
                .is_some_and(|current_envelope| *current_envelope != *target_envelope)
        {
            return Err(MutationError::new(
                MutationErrorKind::UnexpectedItemEnvelope,
            ));
        }
    }
    if target_envelopes
        .keys()
        .any(|item_id| target_policy.item(item_id).is_none())
    {
        return Err(MutationError::new(
            MutationErrorKind::UnexpectedItemEnvelope,
        ));
    }
    Ok(())
}

pub(super) fn validate_privacy_cover(
    current: &VaultFileV1,
    target: &VaultFileV1,
    current_policy: &PolicyState,
    target_policy: &PolicyState,
) -> Result<(), MutationError> {
    let operations = &target
        .policy
        .revisions
        .last()
        .ok_or_else(|| MutationError::new(MutationErrorKind::InvalidPlan))?
        .operations;
    let touched = touched_item_ids(operations);
    if touched.is_empty()
        || operations.iter().any(|operation| {
            !matches!(
                operation,
                PolicyOperationV1::ItemReaderSetChange { .. }
                    | PolicyOperationV1::ItemSlotsReplace { .. }
            )
        })
    {
        return Err(MutationError::new(MutationErrorKind::InvalidPlan));
    }
    for item_id in touched {
        let prior_policy = current_policy
            .item(&item_id)
            .ok_or_else(|| MutationError::new(MutationErrorKind::InvalidPlan))?;
        let next_policy = target_policy
            .item(&item_id)
            .ok_or_else(|| MutationError::new(MutationErrorKind::InvalidPlan))?;
        let prior = current
            .items
            .binary_search_by_key(&item_id, |item| item.item_id)
            .ok()
            .and_then(|index| current.items.get(index))
            .ok_or_else(|| MutationError::new(MutationErrorKind::InvalidCurrentState))?;
        let next = target
            .items
            .binary_search_by_key(&item_id, |item| item.item_id)
            .ok()
            .and_then(|index| target.items.get(index))
            .ok_or_else(|| MutationError::new(MutationErrorKind::InvalidPlan))?;
        if prior_policy.grants != next_policy.grants
            || current_policy.effective_reader_ids(&item_id)
                != target_policy.effective_reader_ids(&item_id)
            || prior_policy.access_mode() != next_policy.access_mode()
            || prior.current_revision.bucket_id != next.current_revision.bucket_id
            || prior.current_revision.item_revision.checked_add(1)
                != Some(next.current_revision.item_revision)
        {
            return Err(MutationError::new(MutationErrorKind::InvalidPlan));
        }
    }
    Ok(())
}
