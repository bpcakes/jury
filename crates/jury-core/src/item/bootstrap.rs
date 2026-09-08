use super::sealing::{ResolvedAccess, ResolvedDirect, build_witnessed_slot_with_id};
use super::*;
use jury_protocol::vault_v1::SlotId;

/// Protected item content awaiting the final genesis-bound witness capsules.
/// This is not a publishable item or policy mutation. Consuming it once prevents
/// reusing its reserved witness slot identifiers for another completion.
pub(crate) struct StagedItemCreation {
    envelope: ItemEnvelopeV1,
    kind: ItemKind,
    access: ItemAccessPlan,
    direct: Vec<DirectSlotV1>,
    direct_recipients: Vec<ResolvedDirect>,
    witness_slot_ids: Option<[SlotId; 2]>,
    mode: ItemAccessMode,
    descriptor: SealedContent,
    body: SealedContent,
}

impl StagedItemCreation {
    pub(crate) fn envelope(&self) -> &ItemEnvelopeV1 {
        &self.envelope
    }
    pub(crate) fn direct_slots(&self) -> &[DirectSlotV1] {
        &self.direct
    }
    pub(crate) const fn witness_slot_ids(&self) -> Option<[SlotId; 2]> {
        self.witness_slot_ids
    }
}

impl<R: RandomSource> ItemCreator<R> {
    pub(crate) fn stage_create(
        &mut self,
        policy: &PolicyState,
        author: &VaultPrincipalIdentity,
        timestamp_ms: u64,
        input: NewItem,
        reserved: &mut ItemArtifactInventory,
    ) -> Result<StagedItemCreation, ItemError> {
        let mut generator = NativeIdGenerator::from_source(&mut self.source);
        let generated = generator
            .generate_item_id(|id| {
                ItemId::from_bytes(*id.as_bytes()).map_or(true, |id| policy.item_id_was_used(&id))
            })
            .map_err(map_identifier_error)?;
        let item_id = ItemId::from_bytes(*generated.as_bytes())
            .map_err(|_| ItemError::new(ItemErrorKind::InvalidInput))?;
        let sequence = next(policy.sequence())?;
        let resolved = resolve_access(policy, sequence, &input.access, None, None, None)?;
        let descriptor = self.seal_content(
            policy,
            item_id,
            1,
            ContentRole::Descriptor,
            1,
            input.bucket_id,
            &input.descriptor,
            &input.state,
            reserved,
        )?;
        let body = self.seal_content(
            policy,
            item_id,
            1,
            ContentRole::Body,
            1,
            input.bucket_id,
            &input.descriptor,
            &input.state,
            reserved,
        )?;
        // Direct slots depend on the access mode but not genesis. Delay only
        // the witnessed capsules, retaining their required final access mode.
        let direct_access = ResolvedAccess {
            direct: resolved.direct.clone(),
            direct_roles: resolved.direct_roles.clone(),
            witness_policy: None,
            mode: resolved.mode,
        };
        let direct = self
            .build_slots(
                policy,
                item_id,
                1,
                sequence,
                &direct_access,
                &descriptor,
                &body,
                reserved,
            )?
            .direct;
        let witness_slot_ids = if resolved.witness_policy.is_some() {
            Some([
                draw_slot_id(&mut self.source, &mut reserved.slot_ids)?,
                draw_slot_id(&mut self.source, &mut reserved.slot_ids)?,
            ])
        } else {
            None
        };
        let current_revision = sign_item_revision(
            author,
            policy,
            item_id,
            1,
            FixedBytes::new(ZERO_DIGEST),
            1,
            sequence,
            timestamp_ms,
            input.bucket_id,
            &body,
        )?;
        let envelope = ItemEnvelopeV1 {
            item_id,
            descriptor: descriptor_metadata(1, 1, &descriptor)?,
            descriptor_ciphertext: DescriptorCiphertext272::from_slice(&descriptor.ciphertext)
                .map_err(|_| ItemError::new(ItemErrorKind::ProviderFailure))?,
            prior_revisions: Vec::new(),
            current_revision,
            body_ciphertext: jury_protocol::vault_v1::ItemCiphertext::new(body.ciphertext.clone())
                .map_err(|_| ItemError::new(ItemErrorKind::CapacityExhausted))?,
        };
        Ok(StagedItemCreation {
            envelope,
            kind: input.kind,
            access: input.access.clone(),
            direct,
            direct_recipients: resolved.direct,
            witness_slot_ids,
            mode: resolved.mode,
            descriptor,
            body,
        })
    }

    pub(crate) fn finish_create(
        &mut self,
        policy: &PolicyState,
        staged: StagedItemCreation,
        access: ItemAccessPlan,
    ) -> Result<PreparedItemBatchComponent, ItemError> {
        let invalid = || ItemError::new(ItemErrorKind::InvalidInput);
        let sequence = next(policy.sequence())?;
        let resolved = resolve_access(policy, sequence, &access, None, None, None)?;
        let envelope = &staged.envelope;
        if policy.vault_id() != envelope.current_revision.vault_id
            || sequence != envelope.current_revision.policy_sequence
            || resolved.mode != staged.mode
            || resolved.direct != staged.direct_recipients
            || access.grants != staged.access.grants
            || access.direct_recipient_ids != staged.access.direct_recipient_ids
            || resolved.witness_policy.is_some() != staged.witness_slot_ids.is_some()
        {
            return Err(invalid());
        }
        let witnessed = match (resolved.witness_policy, staged.witness_slot_ids) {
            (Some(witness_policy), Some(ids)) => {
                let mut slots = Vec::with_capacity(2);
                for (role, content, id) in [
                    (ContentRole::Descriptor, &staged.descriptor, ids[0]),
                    (ContentRole::Body, &staged.body, ids[1]),
                ] {
                    slots.push(build_witnessed_slot_with_id(
                        &mut self.source,
                        self.protection,
                        policy,
                        witness_policy,
                        envelope.item_id,
                        1,
                        sequence,
                        staged.mode,
                        role,
                        content,
                        id,
                    )?);
                }
                let mut state = WitnessedStateV1 {
                    slots,
                    digest: FixedBytes::new(ZERO_DIGEST),
                };
                state.digest = state.recomputed_digest().map_err(|_| invalid())?;
                Some(state)
            }
            (None, None) => None,
            _ => return Err(invalid()),
        };
        let mut operations = vec![PolicyOperationV1::ItemCreate {
            item_id: envelope.item_id,
            item_kind: staged.kind,
            key_epoch: 1,
            descriptor: envelope.descriptor.clone(),
            current_item_revision_hash: envelope
                .current_revision
                .recomputed_hash()
                .map_err(|_| invalid())?,
            direct_slots: staged.direct,
            witnessed_state: witnessed,
        }];
        append_creation_grants(
            &mut operations,
            &access,
            &resolved.direct_roles,
            envelope.item_id,
        );
        Ok(PreparedItemBatchComponent {
            operations,
            envelope: staged.envelope,
        })
    }
}
