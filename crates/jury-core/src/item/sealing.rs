use super::*;

impl<R: RandomSource> ItemCreator<R> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn seal_content(
        &mut self,
        policy: &PolicyState,
        item_id: ItemId,
        epoch: u64,
        role: ContentRole,
        revision: u64,
        bucket_id: u8,
        descriptor: &ItemDescriptorV1,
        state: &ItemStateV1,
        reserved: &mut ItemArtifactInventory,
    ) -> Result<SealedContent, ItemError> {
        let secret = ProtectedRevisionSecret {
            bytes: crypto::random_secret(32, self.protection, &mut self.source)
                .map_err(map_crypto_error)?,
        };
        let seal_id = draw_seal_id(&mut self.source, &mut reserved.revision_seal_ids)?;
        let nonce = draw_nonce(&mut self.source, &mut reserved.nonces)?;
        let aad = match role {
            ContentRole::Descriptor => item_descriptor_aad(
                policy.vault_id().as_bytes(),
                item_id.as_bytes(),
                epoch,
                revision,
                seal_id.as_bytes(),
            ),
            ContentRole::Body => item_body_aad(
                policy.vault_id().as_bytes(),
                item_id.as_bytes(),
                epoch,
                revision,
                seal_id.as_bytes(),
                bucket_id,
            ),
        };
        let plaintext_bytes = match role {
            ContentRole::Descriptor => Zeroizing::new(descriptor.encode().to_vec()),
            ContentRole::Body => Zeroizing::new(
                state
                    .frame(bucket_id)
                    .map_err(|_| ItemError::new(ItemErrorKind::InvalidInput))?,
            ),
        };
        let plaintext = protect(&plaintext_bytes, self.protection)?;
        let ciphertext =
            crypto::seal(secret.memory(), &nonce, &aad, &plaintext).map_err(map_crypto_error)?;
        Ok(SealedContent {
            secret,
            seal_id,
            nonce,
            revision,
            ciphertext,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_slots(
        &mut self,
        policy: &PolicyState,
        item_id: ItemId,
        epoch: u64,
        sequence: u64,
        access: &ResolvedAccess<'_>,
        descriptor: &SealedContent,
        body: &SealedContent,
        reserved: &mut ItemArtifactInventory,
    ) -> Result<BuiltSlots, ItemError> {
        let mut direct = Vec::new();
        for content in [
            (ContentRole::Descriptor, descriptor),
            (ContentRole::Body, body),
        ] {
            for recipient in &access.direct {
                direct.push(build_direct_slot(
                    &mut self.source,
                    policy,
                    item_id,
                    epoch,
                    sequence,
                    access.mode,
                    content.0,
                    content.1,
                    recipient,
                )?);
            }
        }
        direct.sort_by(|left, right| {
            (
                left.content_role,
                left.recipient_principal_id,
                left.canonical_bytes(),
            )
                .cmp(&(
                    right.content_role,
                    right.recipient_principal_id,
                    right.canonical_bytes(),
                ))
        });
        let witnessed = access
            .witness_policy
            .map(|witness_policy| {
                let mut slots = Vec::new();
                for (role, content) in [
                    (ContentRole::Descriptor, descriptor),
                    (ContentRole::Body, body),
                ] {
                    slots.push(build_witnessed_slot(
                        &mut self.source,
                        self.protection,
                        policy,
                        witness_policy,
                        item_id,
                        epoch,
                        sequence,
                        access.mode,
                        role,
                        content,
                        reserved,
                    )?);
                }
                let mut state = WitnessedStateV1 {
                    slots,
                    digest: FixedBytes::new(ZERO_DIGEST),
                };
                state.digest = state
                    .recomputed_digest()
                    .map_err(|_| ItemError::new(ItemErrorKind::InvalidInput))?;
                Ok(state)
            })
            .transpose()?;
        Ok(BuiltSlots { direct, witnessed })
    }
}

pub(super) struct SealedContent {
    pub(super) secret: ProtectedRevisionSecret,
    pub(super) seal_id: RevisionSealId,
    pub(super) nonce: Nonce12,
    pub(super) revision: u64,
    pub(super) ciphertext: Vec<u8>,
}

struct ResolvedDirect {
    principal_id: PrincipalId,
    public_key: RecipientPublicKey1216,
    role: AccessRole,
}

pub(super) struct ResolvedAccess<'a> {
    direct: Vec<ResolvedDirect>,
    pub(super) direct_roles: BTreeMap<PrincipalId, AccessRole>,
    witness_policy: Option<&'a WitnessPolicy>,
    mode: ItemAccessMode,
}

pub(super) struct BuiltSlots {
    pub(super) direct: Vec<DirectSlotV1>,
    pub(super) witnessed: Option<WitnessedStateV1>,
}

pub(super) fn resolve_access<'a>(
    policy: &'a PolicyState,
    sequence: u64,
    plan: &ItemAccessPlan,
    replacement: Option<&PrincipalReplacement>,
    registration: Option<&PrincipalRegistration>,
    owner_change: Option<OwnerChange>,
) -> Result<ResolvedAccess<'a>, ItemError> {
    if replacement.is_some_and(|replacement| {
        replacement.prior_principal_id == replacement.next_descriptor.principal_id
            || plan
                .grants
                .iter()
                .any(|grant| grant.principal_id == replacement.prior_principal_id)
            || plan
                .direct_recipient_ids
                .contains(&replacement.prior_principal_id)
    }) {
        return Err(ItemError::new(ItemErrorKind::InvalidInput));
    }
    if registration.is_some_and(|registration| {
        policy.principal_id_was_used(&registration.descriptor.principal_id) || replacement.is_some()
    }) {
        return Err(ItemError::new(ItemErrorKind::InvalidInput));
    }
    if owner_change.is_some_and(|change| match change {
        OwnerChange::Grant(principal_id) => policy.is_owner(&principal_id),
        OwnerChange::Revoke(principal_id) => !policy.is_owner(&principal_id),
    }) {
        return Err(ItemError::new(ItemErrorKind::InvalidInput));
    }
    let mut grants = BTreeMap::new();
    for grant in &plan.grants {
        let is_replacement_owner = replacement.is_some_and(|replacement| {
            replacement.next_descriptor.principal_id == grant.principal_id
                && policy.is_owner(&replacement.prior_principal_id)
        });
        if !matches!(grant.role, AccessRole::Reader | AccessRole::Writer)
            || grants.insert(grant.principal_id, grant.role).is_some()
            || policy.is_owner(&grant.principal_id)
            || is_replacement_owner
        {
            return Err(ItemError::new(ItemErrorKind::InvalidInput));
        }
        let principal_kind = replacement
            .filter(|replacement| replacement.next_descriptor.principal_id == grant.principal_id)
            .map(|replacement| replacement.next_descriptor.principal_kind)
            .or_else(|| {
                registration
                    .filter(|registration| {
                        registration.descriptor.principal_id == grant.principal_id
                    })
                    .map(|registration| registration.descriptor.principal_kind)
            })
            .or_else(|| {
                policy
                    .principal(&grant.principal_id)
                    .map(|principal| principal.descriptor.principal_kind)
            })
            .ok_or_else(|| ItemError::new(ItemErrorKind::InvalidInput))?;
        if !matches!(
            principal_kind,
            PrincipalKind::Human | PrincipalKind::Machine
        ) {
            return Err(ItemError::new(ItemErrorKind::InvalidInput));
        }
    }
    if plan
        .direct_recipient_ids
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(ItemError::new(ItemErrorKind::InvalidInput));
    }
    let mut direct_recipient_ids = plan.direct_recipient_ids.clone();
    if !direct_recipient_ids.is_empty() {
        direct_recipient_ids.extend(next_owner_ids(policy, replacement, owner_change));
        direct_recipient_ids.sort_unstable();
        direct_recipient_ids.dedup();
    }
    let mut direct = Vec::new();
    let mut direct_roles = BTreeMap::new();
    for principal_id in &direct_recipient_ids {
        let replaced = replacement
            .filter(|replacement| replacement.next_descriptor.principal_id == *principal_id);
        let registered = registration
            .filter(|registration| registration.descriptor.principal_id == *principal_id);
        let descriptor = replaced
            .map(|replacement| &replacement.next_descriptor)
            .or_else(|| registered.map(|registration| &registration.descriptor))
            .or_else(|| {
                policy
                    .principal(principal_id)
                    .map(|principal| &principal.descriptor)
            });
        let descriptor = descriptor.ok_or_else(|| ItemError::new(ItemErrorKind::InvalidInput))?;
        if !matches!(
            descriptor.principal_kind,
            PrincipalKind::Human | PrincipalKind::Machine
        ) {
            return Err(ItemError::new(ItemErrorKind::InvalidInput));
        }
        let is_replacement_owner =
            replaced.is_some_and(|replacement| policy.is_owner(&replacement.prior_principal_id));
        let will_be_owner = match owner_change {
            Some(OwnerChange::Grant(candidate)) if candidate == *principal_id => true,
            Some(OwnerChange::Revoke(candidate)) if candidate == *principal_id => false,
            _ => policy.is_owner(principal_id),
        };
        let role = if will_be_owner || is_replacement_owner {
            AccessRole::Owner
        } else {
            grants
                .get(principal_id)
                .copied()
                .ok_or_else(|| ItemError::new(ItemErrorKind::Unauthorized))?
        };
        direct_roles.insert(*principal_id, role);
        direct.push(ResolvedDirect {
            principal_id: *principal_id,
            public_key: descriptor.recipient_public_key.clone(),
            role,
        });
    }
    let witness_policy = plan
        .witness_policy_digest
        .as_ref()
        .map(|digest| {
            let witness = policy
                .witness_policy(digest)
                .ok_or_else(|| ItemError::new(ItemErrorKind::InvalidInput))?;
            witness
                .validate()
                .map_err(|_| ItemError::new(ItemErrorKind::InvalidInput))?;
            if witness.vault_id != policy.vault_id()
                || witness.genesis_fingerprint != *policy.genesis_fingerprint()
                || witness.vault_policy_sequence != sequence
                || witness.digest().ok().as_ref() != Some(digest)
            {
                return Err(ItemError::new(ItemErrorKind::InvalidInput));
            }
            Ok(witness)
        })
        .transpose()?;
    let mode = match (direct.is_empty(), witness_policy.is_none()) {
        (false, true) => ItemAccessMode::DirectOnly,
        (true, false) => ItemAccessMode::WitnessedOnly,
        (false, false) => ItemAccessMode::Mixed,
        (true, true) => return Err(ItemError::new(ItemErrorKind::InvalidInput)),
    };
    Ok(ResolvedAccess {
        direct,
        direct_roles,
        witness_policy,
        mode,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_direct_slot(
    source: &mut impl RandomSource,
    policy: &PolicyState,
    item_id: ItemId,
    epoch: u64,
    sequence: u64,
    mode: ItemAccessMode,
    role: ContentRole,
    content: &SealedContent,
    recipient: &ResolvedDirect,
) -> Result<DirectSlotV1, ItemError> {
    let fingerprint = recipient_public_key_fingerprint(&recipient.public_key);
    let mut slot = DirectSlotV1 {
        slot_schema: 1,
        slot_algorithm: 1,
        suite: SUITE,
        kem: 0x647a,
        kdf: 1,
        aead: 3,
        vault_id: policy.vault_id(),
        item_id,
        key_epoch: epoch,
        content_role: role,
        revision: content.revision,
        revision_seal_id: content.seal_id,
        recipient_principal_id: recipient.principal_id,
        policy_sequence: sequence,
        recipient_public_key_fingerprint: fingerprint,
        access_role: recipient.role,
        item_access_mode: mode,
        encapsulation: Encapsulation1120::new([0; 1_120]),
        ciphertext: DirectCiphertext48::new([0; 48]),
    };
    let (encapsulation, ciphertext) = crypto::seal_hpke(
        &recipient.public_key,
        content.secret.memory(),
        &slot.info_preimage(),
        &slot.aad_preimage(),
        source,
    )
    .map_err(map_crypto_error)?;
    slot.encapsulation = encapsulation;
    slot.ciphertext = DirectCiphertext48::from_slice(&ciphertext)
        .map_err(|_| ItemError::new(ItemErrorKind::ProviderFailure))?;
    Ok(slot)
}

#[allow(clippy::too_many_arguments)]
fn build_witnessed_slot(
    source: &mut impl RandomSource,
    protection: ProtectionPolicy,
    policy: &PolicyState,
    witness_policy: &WitnessPolicy,
    item_id: ItemId,
    epoch: u64,
    sequence: u64,
    mode: ItemAccessMode,
    role: ContentRole,
    content: &SealedContent,
    reserved: &mut ItemArtifactInventory,
) -> Result<WitnessedSlotV1, ItemError> {
    let members = witness_policy
        .witness_descriptors
        .iter()
        .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
        .collect::<Vec<_>>();
    let share_indexes = members
        .iter()
        .map(|descriptor| descriptor.share_index)
        .collect::<BTreeSet<_>>();
    if members.len() > 32 || share_indexes.len() != members.len() {
        return Err(ItemError::new(ItemErrorKind::InvalidInput));
    }
    let member_count = u8::try_from(members.len())
        .map_err(|_| ItemError::new(ItemErrorKind::CapacityExhausted))?;
    let slot_id = draw_slot_id(source, &mut reserved.slot_ids)?;
    let policy_digest = witness_policy
        .digest()
        .map_err(|_| ItemError::new(ItemErrorKind::InvalidInput))?;
    let share_seed = crypto::random_secret(32, protection, source).map_err(map_crypto_error)?;
    let shares = share_seed
        .expose(|seed| {
            content.secret.memory().expose(|secret| {
                let seed: &[u8; 32] = seed
                    .try_into()
                    .map_err(|_| ItemError::new(ItemErrorKind::ProviderFailure))?;
                let mut rng = ChaCha20Rng::from_seed(*seed);
                Gf256::split_bytes_with_participant_ids_iter(
                    usize::from(witness_policy.witness_threshold),
                    members.len(),
                    secret,
                    &mut rng,
                    members
                        .iter()
                        .map(|descriptor| IdentifierGf256(Gf256(descriptor.share_index))),
                )
                .map_err(|_| ItemError::new(ItemErrorKind::ProviderFailure))
            })
        })
        .map_err(|_| ItemError::new(ItemErrorKind::ProtectionUnavailable))?
        .map_err(|_| ItemError::new(ItemErrorKind::ProtectionUnavailable))??;
    let shares = Zeroizing::new(shares);
    let mut capsules = Vec::with_capacity(members.len());
    for (descriptor, bytes) in members.into_iter().zip(shares.iter()) {
        if bytes.first().copied() != Some(descriptor.share_index) {
            return Err(ItemError::new(ItemErrorKind::ProviderFailure));
        }
        let share = protect(bytes, protection)?;
        let mut capsule = WitnessShareCapsuleV1 {
            capsule_schema: 1,
            protocol: 1,
            construction: 1,
            vault_id: policy.vault_id(),
            genesis_fingerprint: policy.genesis_fingerprint().clone(),
            item_id,
            key_epoch: epoch,
            item_access_mode: mode,
            slot_id,
            content_role: role,
            revision: content.revision,
            revision_seal_id: content.seal_id,
            vault_policy_sequence: sequence,
            witness_policy_id: witness_policy.witness_policy_id,
            witness_policy_revision: witness_policy.revision,
            witness_policy_digest: policy_digest.clone(),
            threshold: witness_policy.witness_threshold,
            member_count,
            witness_id: descriptor.witness_id,
            contribution_key_fingerprint: descriptor.contribution_key_fingerprint.clone(),
            share_index: descriptor.share_index,
            context_digest: FixedBytes::new(ZERO_DIGEST),
            share_commitment: FixedBytes::new(ZERO_DIGEST),
            encapsulation: Encapsulation1120::new([0; 1_120]),
            ciphertext: ShareCiphertext49::new([0; 49]),
        };
        capsule.context_digest = capsule.recomputed_context_digest();
        capsule.share_commitment = share_commitment(&capsule.context_digest, &share)?;
        let (encapsulation, ciphertext) = crypto::seal_hpke(
            &descriptor.contribution_public_key,
            &share,
            &capsule.info_preimage(),
            &capsule.aad_preimage(),
            source,
        )
        .map_err(map_crypto_error)?;
        capsule.encapsulation = encapsulation;
        capsule.ciphertext = ShareCiphertext49::from_slice(&ciphertext)
            .map_err(|_| ItemError::new(ItemErrorKind::ProviderFailure))?;
        capsules.push(capsule);
    }
    capsules.sort_by_key(|capsule| capsule.share_index);
    let mut slot = WitnessedSlotV1 {
        slot_schema: 1,
        slot_algorithm: 2,
        suite: SUITE,
        protocol: 1,
        construction: 1,
        vault_id: policy.vault_id(),
        genesis_fingerprint: policy.genesis_fingerprint().clone(),
        item_id,
        key_epoch: epoch,
        item_access_mode: mode,
        slot_id,
        content_role: role,
        revision: content.revision,
        revision_seal_id: content.seal_id,
        vault_policy_sequence: sequence,
        witness_policy_id: witness_policy.witness_policy_id,
        witness_policy_revision: witness_policy.revision,
        witness_policy_digest: policy_digest,
        threshold: witness_policy.witness_threshold,
        member_count,
        capsules,
        capsule_set_digest: FixedBytes::new(ZERO_DIGEST),
    };
    slot.capsule_set_digest = slot
        .recomputed_capsule_set_digest()
        .map_err(|_| ItemError::new(ItemErrorKind::InvalidInput))?;
    Ok(slot)
}

fn share_commitment(
    context_digest: &Digest32,
    share: &ProtectedMemory,
) -> Result<Digest32, ItemError> {
    let mut digest = Sha256::new();
    digest.update(jce("jury-witness-v1/share/commitment"));
    digest.update(context_digest.as_bytes());
    share
        .expose(|bytes| digest.update(bytes))
        .map_err(|_| ItemError::new(ItemErrorKind::ProtectionUnavailable))?;
    Ok(FixedBytes::new(digest.finalize().into()))
}
