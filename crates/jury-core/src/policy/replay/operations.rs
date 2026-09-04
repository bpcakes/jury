fn add_principal(
    state: &mut PolicyState,
    descriptor: &PrincipalDescriptorV1,
    display_label: &str,
) -> Result<(), PolicyError> {
    validate_descriptor(descriptor)?;
    if display_label.is_empty() || display_label.len() > MAX_PUBLIC_LABEL_BYTES {
        return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
    }
    if state
        .historical_principal_ids
        .contains(&descriptor.principal_id)
        || state
            .historical_recipient_keys
            .contains(&descriptor.recipient_public_key)
        || state
            .historical_verification_keys
            .contains(&descriptor.verification_public_key)
    {
        return Err(PolicyError::new(PolicyErrorKind::IdentifierReused));
    }
    state
        .historical_principal_ids
        .insert(descriptor.principal_id);
    state
        .historical_principal_descriptors
        .insert(descriptor.principal_id, descriptor.clone());
    state
        .historical_recipient_keys
        .insert(descriptor.recipient_public_key.clone());
    state
        .historical_verification_keys
        .insert(descriptor.verification_public_key.clone());
    state.principals.insert(
        descriptor.principal_id,
        PrincipalPolicyState {
            descriptor: descriptor.clone(),
            display_label: display_label.to_owned(),
        },
    );
    Ok(())
}

fn remove_principal(
    state: &mut PolicyState,
    principal_id: &PrincipalId,
) -> Result<(), PolicyError> {
    if state.owners.contains(principal_id) {
        return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
    }
    if state
        .items
        .values()
        .any(|item| item.grants.contains_key(principal_id))
    {
        return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
    }
    state
        .principals
        .remove(principal_id)
        .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownPrincipal))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn create_item(
    state: &mut PolicyState,
    item_id: ItemId,
    item_kind: jury_protocol::vault_v1::ItemKind,
    key_epoch: u64,
    descriptor: &DescriptorMetadataV1,
    current_hash: &Digest32,
    direct_slots: &[DirectSlotV1],
    witnessed_state: Option<&WitnessedStateV1>,
) -> Result<(), PolicyError> {
    if state.historical_item_ids.contains(&item_id) {
        return Err(PolicyError::new(PolicyErrorKind::IdentifierReused));
    }
    let mut grants = BTreeMap::new();
    for slot in direct_slots {
        if slot.access_role != AccessRole::Owner
            && let Some(existing) = grants.insert(slot.recipient_principal_id, slot.access_role)
            && existing != slot.access_role
        {
            return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
        }
    }
    state.historical_item_ids.insert(item_id);
    state.items.insert(
        item_id,
        ItemPolicyState {
            item_kind,
            key_epoch,
            descriptor: descriptor.clone(),
            current_item_revision_hash: current_hash.clone(),
            grants,
            direct_slots: direct_slots.to_vec(),
            witnessed_state: witnessed_state.cloned(),
        },
    );
    Ok(())
}

fn delete_item(
    state: &mut PolicyState,
    item_id: &ItemId,
    descriptor_digest: &Digest32,
    revision_hash: &Digest32,
    sequence: u64,
) -> Result<(), PolicyError> {
    let item = state
        .items
        .remove(item_id)
        .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownItem))?;
    if item.descriptor.ciphertext_digest != *descriptor_digest
        || item.current_item_revision_hash != *revision_hash
    {
        return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
    }
    state.tombstones.insert(
        *item_id,
        TombstoneState {
            deletion_policy_sequence: sequence,
            final_descriptor_digest: descriptor_digest.clone(),
            final_item_revision_hash: revision_hash.clone(),
        },
    );
    Ok(())
}

fn change_role(
    state: &mut PolicyState,
    item_id: &ItemId,
    principal_id: &PrincipalId,
    prior_role: Option<AccessRole>,
    next_role: Option<AccessRole>,
) -> Result<(), PolicyError> {
    let principal = state
        .principals
        .get(principal_id)
        .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownPrincipal))?;
    if !matches!(
        principal.descriptor.principal_kind,
        PrincipalKind::Human | PrincipalKind::Machine
    ) || state.owners.contains(principal_id)
        || matches!(prior_role, Some(AccessRole::Owner))
        || matches!(next_role, Some(AccessRole::Owner))
    {
        return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
    }
    let item = state
        .items
        .get_mut(item_id)
        .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownItem))?;
    if item.grants.get(principal_id).copied() != prior_role {
        return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
    }
    match next_role {
        Some(role @ (AccessRole::Reader | AccessRole::Writer)) => {
            item.grants.insert(*principal_id, role);
        }
        None => {
            item.grants.remove(principal_id);
        }
        Some(AccessRole::Owner) => {
            return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
        }
    }
    Ok(())
}

fn replace_principal(
    state: &mut PolicyState,
    prior_id: &PrincipalId,
    next_descriptor: &PrincipalDescriptorV1,
) -> Result<(), PolicyError> {
    validate_descriptor(next_descriptor)?;
    let prior = state
        .principals
        .get(prior_id)
        .cloned()
        .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownPrincipal))?;
    if prior.descriptor.principal_kind != next_descriptor.principal_kind {
        return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
    }
    if state
        .historical_principal_ids
        .contains(&next_descriptor.principal_id)
        || state
            .historical_recipient_keys
            .contains(&next_descriptor.recipient_public_key)
        || state
            .historical_verification_keys
            .contains(&next_descriptor.verification_public_key)
    {
        return Err(PolicyError::new(PolicyErrorKind::IdentifierReused));
    }
    state.principals.remove(prior_id);
    state.principals.insert(
        next_descriptor.principal_id,
        PrincipalPolicyState {
            descriptor: next_descriptor.clone(),
            display_label: prior.display_label,
        },
    );
    state
        .historical_principal_ids
        .insert(next_descriptor.principal_id);
    state
        .historical_principal_descriptors
        .insert(next_descriptor.principal_id, next_descriptor.clone());
    state
        .historical_recipient_keys
        .insert(next_descriptor.recipient_public_key.clone());
    state
        .historical_verification_keys
        .insert(next_descriptor.verification_public_key.clone());
    if state.owners.remove(prior_id) {
        state.owners.insert(next_descriptor.principal_id);
    }
    for item in state.items.values_mut() {
        if let Some(role) = item.grants.remove(prior_id) {
            item.grants.insert(next_descriptor.principal_id, role);
        }
    }
    Ok(())
}

fn apply_rotations(
    prior: &PolicyState,
    next: &mut PolicyState,
    mut reader_rotations: BTreeMap<ItemId, ReaderRotation>,
    mut slot_rotations: BTreeMap<ItemId, SlotRotation>,
) -> Result<(), PolicyError> {
    let common_items = prior
        .items
        .keys()
        .filter(|item_id| next.items.contains_key(item_id))
        .copied()
        .collect::<Vec<_>>();
    for item_id in common_items {
        let prior_readers = prior.effective_reader_ids(&item_id);
        let next_readers = next.effective_reader_ids(&item_id);
        let readers_changed = prior_readers != next_readers;
        let reader_rotation = reader_rotations.remove(&item_id);
        let slot_rotation = slot_rotations.remove(&item_id);
        if readers_changed && (reader_rotation.is_none() || slot_rotation.is_none()) {
            return Err(PolicyError::new(PolicyErrorKind::IncompleteRotation));
        }
        if reader_rotation.is_some() && slot_rotation.is_none() {
            return Err(PolicyError::new(PolicyErrorKind::IncompleteRotation));
        }
        let current_epoch = prior
            .items
            .get(&item_id)
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownItem))?
            .key_epoch;
        let expected_epoch = current_epoch
            .checked_add(1)
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::CapacityExhausted))?;
        if let Some(rotation) = reader_rotation {
            if rotation.prior_epoch != current_epoch
                || rotation.next_epoch != expected_epoch
                || rotation.prior_reader_ids != prior_readers
                || rotation.next_reader_ids != next_readers
                || rotation.replacement_descriptor.key_epoch != expected_epoch
            {
                return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
            }
            let item = next
                .items
                .get_mut(&item_id)
                .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownItem))?;
            item.descriptor = rotation.replacement_descriptor;
            item.current_item_revision_hash = rotation.replacement_current_item_revision_hash;
        }
        if let Some(rotation) = slot_rotation {
            if rotation.next_epoch != expected_epoch {
                return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
            }
            let item = next
                .items
                .get_mut(&item_id)
                .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownItem))?;
            if !readers_changed
                && item.direct_slots == rotation.direct_slots
                && item.witnessed_state == rotation.witnessed_state
            {
                return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
            }
            item.key_epoch = expected_epoch;
            item.direct_slots = rotation.direct_slots;
            item.witnessed_state = rotation.witnessed_state;
            if item.descriptor.key_epoch != expected_epoch {
                return Err(PolicyError::new(PolicyErrorKind::IncompleteRotation));
            }
        }
    }
    if !reader_rotations.is_empty() || !slot_rotations.is_empty() {
        return Err(PolicyError::new(PolicyErrorKind::UnknownItem));
    }
    Ok(())
}

fn validate_complete_state(state: &PolicyState) -> Result<(), PolicyError> {
    if state.owners.is_empty()
        || state.owners.iter().any(|owner| {
            state
                .principals
                .get(owner)
                .is_none_or(|principal| principal.descriptor.principal_kind != PrincipalKind::Human)
        })
    {
        return Err(PolicyError::new(PolicyErrorKind::SoleOwner));
    }
    for (item_id, item) in &state.items {
        let mode = item
            .access_mode()
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::InvalidTransition))?;
        for (principal_id, role) in &item.grants {
            let principal = state
                .principals
                .get(principal_id)
                .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownPrincipal))?;
            if !matches!(
                principal.descriptor.principal_kind,
                PrincipalKind::Human | PrincipalKind::Machine
            ) || *role == AccessRole::Owner
            {
                return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
            }
        }
        for slot in &item.direct_slots {
            let principal = state
                .principals
                .get(&slot.recipient_principal_id)
                .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownPrincipal))?;
            let effective_role = state.effective_role(item_id, &slot.recipient_principal_id);
            let slot_role_is_current = effective_role == Some(slot.access_role)
                || matches!(
                    (effective_role, slot.access_role),
                    (
                        Some(AccessRole::Reader | AccessRole::Writer),
                        AccessRole::Reader | AccessRole::Writer
                    )
                );
            if !matches!(
                principal.descriptor.principal_kind,
                PrincipalKind::Human | PrincipalKind::Machine
            ) || !slot_role_is_current
                || slot.recipient_public_key_fingerprint
                    != jury_protocol::vault_v1::recipient_public_key_fingerprint(
                        &principal.descriptor.recipient_public_key,
                    )
                || slot.item_access_mode != mode
                || slot.key_epoch != item.key_epoch
                || slot.policy_sequence == 0
                || slot.policy_sequence > state.sequence
            {
                return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
            }
        }
        if let Some(witnessed) = &item.witnessed_state {
            let first = witnessed
                .slots
                .first()
                .ok_or_else(|| PolicyError::new(PolicyErrorKind::InvalidFormat))?;
            let first_members = first
                .capsules
                .iter()
                .map(|capsule| capsule.witness_id)
                .collect::<Vec<_>>();
            for slot in &witnessed.slots {
                let members = slot
                    .capsules
                    .iter()
                    .map(|capsule| capsule.witness_id)
                    .collect::<Vec<_>>();
                if slot.item_access_mode != mode
                    || slot.key_epoch != item.key_epoch
                    || slot.vault_policy_sequence == 0
                    || slot.vault_policy_sequence > state.sequence
                    || slot.threshold != first.threshold
                    || slot.witness_policy_id != first.witness_policy_id
                    || slot.witness_policy_revision != first.witness_policy_revision
                    || slot.witness_policy_digest != first.witness_policy_digest
                    || members != first_members
                {
                    return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
                }
            }
            for witness_id in first_members {
                if state.principals.get(&witness_id).is_none_or(|principal| {
                    principal.descriptor.principal_kind != PrincipalKind::Witness
                }) {
                    return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
                }
            }
            validate_item_policy_binding(state, item_id, witnessed)?;
        }
    }
    Ok(())
}

fn validate_complete_owner_slots(state: &PolicyState) -> Result<(), PolicyError> {
    for item in state.items.values() {
        let mode = item
            .access_mode()
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::InvalidTransition))?;
        if matches!(mode, ItemAccessMode::DirectOnly | ItemAccessMode::Mixed)
            && state.owners.iter().any(|owner_id| {
                let (count, has_descriptor, has_body) = item
                    .direct_slots
                    .iter()
                    .filter(|slot| slot.recipient_principal_id == *owner_id)
                    .fold((0_u8, false, false), |(count, descriptor, body), slot| {
                        (
                            count.saturating_add(1),
                            descriptor || slot.content_role == ContentRole::Descriptor,
                            body || slot.content_role == ContentRole::Body,
                        )
                    });
                count != 2 || !has_descriptor || !has_body
            })
        {
            return Err(PolicyError::new(PolicyErrorKind::IncompleteRotation));
        }
    }
    Ok(())
}

fn validate_descriptor(descriptor: &PrincipalDescriptorV1) -> Result<(), PolicyError> {
    if descriptor.descriptor_version != 1 {
        return Err(PolicyError::new(PolicyErrorKind::InvalidFormat));
    }
    let preimage = descriptor
        .self_signature_preimage()
        .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidFormat))?;
    crypto::verify_bytes(
        &descriptor.verification_public_key,
        &preimage,
        &descriptor.self_signature,
    )
    .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidSignature))
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum OperationKey {
    Principal(u8, PrincipalId),
    Item(u8, ItemId),
    ItemPrincipal(u8, ItemId, PrincipalId),
}

fn operation_key(operation: &PolicyOperationV1) -> OperationKey {
    match operation {
        PolicyOperationV1::PrincipalAdd { descriptor, .. } => {
            OperationKey::Principal(1, descriptor.principal_id)
        }
        PolicyOperationV1::PrincipalLabelChange { principal_id, .. } => {
            OperationKey::Principal(2, *principal_id)
        }
        PolicyOperationV1::PrincipalRemove { principal_id, .. } => {
            OperationKey::Principal(3, *principal_id)
        }
        PolicyOperationV1::OwnerGrant { principal_id } => OperationKey::Principal(4, *principal_id),
        PolicyOperationV1::OwnerRevoke { principal_id } => {
            OperationKey::Principal(5, *principal_id)
        }
        PolicyOperationV1::ItemCreate { item_id, .. } => OperationKey::Item(6, *item_id),
        PolicyOperationV1::ItemRename { item_id, .. } => OperationKey::Item(7, *item_id),
        PolicyOperationV1::ItemDelete { item_id, .. } => OperationKey::Item(8, *item_id),
        PolicyOperationV1::ItemRoleChange {
            item_id,
            principal_id,
            ..
        } => OperationKey::ItemPrincipal(9, *item_id, *principal_id),
        PolicyOperationV1::ItemReaderSetChange { item_id, .. } => OperationKey::Item(10, *item_id),
        PolicyOperationV1::ItemSlotsReplace { item_id, .. } => OperationKey::Item(11, *item_id),
        PolicyOperationV1::PrincipalReplace {
            prior_principal_id, ..
        } => OperationKey::Principal(12, *prior_principal_id),
    }
}

fn map_identifier_error(error: IdentifierGenerationError) -> PolicyError {
    PolicyError::new(match error {
        IdentifierGenerationError::EntropyUnavailable => PolicyErrorKind::EntropyUnavailable,
        IdentifierGenerationError::RetryExhausted => PolicyErrorKind::RetryExhausted,
    })
}
