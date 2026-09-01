use super::*;

pub(super) fn transition_flags(
    current: &PolicyState,
    target: &PolicyState,
    touched: &BTreeSet<ItemId>,
    operations: &[PolicyOperationV1],
) -> Result<(bool, bool, bool), MutationError> {
    let mut direct_downgrade = false;
    let mut witness_changed = false;
    let mut witness_weakened = false;
    let replacements = operations
        .iter()
        .filter_map(|operation| match operation {
            PolicyOperationV1::PrincipalReplace {
                prior_principal_id,
                next_descriptor,
                ..
            } => Some((*prior_principal_id, next_descriptor.principal_id)),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    for item_id in touched {
        let Some(next) = target.item(item_id) else {
            continue;
        };
        let prior = current.item(item_id);
        let prior_direct_recipients = prior
            .into_iter()
            .flat_map(|item| &item.direct_slots)
            .map(|slot| {
                replacements
                    .get(&slot.recipient_principal_id)
                    .copied()
                    .unwrap_or(slot.recipient_principal_id)
            })
            .collect::<BTreeSet<_>>();
        let next_direct_recipients = next
            .direct_slots
            .iter()
            .map(|slot| slot.recipient_principal_id)
            .collect::<BTreeSet<_>>();
        if (!next_direct_recipients.is_empty()
            && !matches!(
                prior.and_then(crate::policy::ItemPolicyState::access_mode),
                Some(ItemAccessMode::DirectOnly | ItemAccessMode::Mixed)
            ))
            || next_direct_recipients
                .iter()
                .any(|principal| !prior_direct_recipients.contains(principal))
        {
            direct_downgrade = true;
        }
        let prior_digest = prior.and_then(witness_digest);
        let next_digest = witness_digest(next);
        if prior_digest != next_digest {
            witness_changed |= prior_digest.is_some() || next_digest.is_some();
            if let (Some(prior_digest), Some(next_digest)) = (prior_digest, next_digest) {
                let prior_policy = current
                    .witness_policy(prior_digest)
                    .ok_or_else(|| MutationError::new(MutationErrorKind::InvalidCurrentState))?;
                let next_policy = target
                    .witness_policy(next_digest)
                    .ok_or_else(|| MutationError::new(MutationErrorKind::InvalidPlan))?;
                witness_weakened |= witness_policy_is_weaker(prior_policy, next_policy);
            }
        }
    }
    Ok((direct_downgrade, witness_changed, witness_weakened))
}

fn witness_digest(item: &crate::policy::ItemPolicyState) -> Option<&Digest32> {
    item.witnessed_state
        .as_ref()
        .and_then(|state| state.slots.first())
        .map(|slot| &slot.witness_policy_digest)
}

fn witness_policy_is_weaker(prior: &WitnessPolicy, next: &WitnessPolicy) -> bool {
    if next.witness_threshold < prior.witness_threshold {
        return true;
    }
    prior.operation_rules.iter().any(|prior_rule| {
        next.operation_rules
            .iter()
            .find(|next_rule| next_rule.operation == prior_rule.operation)
            .is_none_or(|next_rule| {
                next_rule.approval_threshold < prior_rule.approval_threshold
                    || next_rule.allowed_request_lifetime_ms
                        > prior_rule.allowed_request_lifetime_ms
                    || next_rule.max_timeout_ms > prior_rule.max_timeout_ms
                    || next_rule.max_output_bytes > prior_rule.max_output_bytes
                    || next_rule.max_target_count > prior_rule.max_target_count
                    || assurance_is_weaker(
                        prior_rule.required_platform_assurance,
                        next_rule.required_platform_assurance,
                    )
                    || eligible_set_is_broader(
                        &prior_rule.eligible_approver_ids,
                        &next_rule.eligible_approver_ids,
                    )
            })
    })
}

fn assurance_is_weaker(
    prior: crate::policy::PlatformAssurance,
    next: crate::policy::PlatformAssurance,
) -> bool {
    matches!(
        (prior, next),
        (
            crate::policy::PlatformAssurance::StableExecutableIdentity,
            crate::policy::PlatformAssurance::NormalizedPathOnly
        )
    )
}

fn eligible_set_is_broader(
    prior: &[jury_protocol::vault_v1::PrincipalId],
    next: &[jury_protocol::vault_v1::PrincipalId],
) -> bool {
    next.iter().any(|id| !prior.contains(id))
}
