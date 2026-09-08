use super::*;

pub(in crate::rollover) fn validate_source_catalog(
    source: &RolloverSource<'_>,
    catalog: &TransferPublicCatalogV1,
) -> Result<(), RolloverError> {
    catalog.to_json_bytes().map_err(|_| source_invalid())?;
    catalog
        .validate_for_policy(source.vault, &source.policy)
        .map_err(|_| source_invalid())?;
    let replayed =
        replay_policy_with_witness_policies(&source.vault.policy, &catalog.witness_policies)
            .map_err(|_| source_invalid())?;
    if replayed != source.policy {
        return Err(source_invalid());
    }
    Ok(())
}

pub(super) fn fresh_challenges(
    initial: &PolicyState,
    owner: &VaultPrincipalIdentity,
    catalog: &TransferPublicCatalogV1,
    source: &PolicyState,
    timestamp_ms: u64,
    lifetime_ms: u64,
    protection: ProtectionPolicy,
) -> Result<
    (
        Vec<RegistrationChallengeV1>,
        Vec<RegistrationRoleDescriptorV1>,
    ),
    RolloverError,
> {
    let mut creator = RegistrationCreator::new(protection);
    let mut challenges = Vec::new();
    let mut prior_roles = Vec::new();
    for prior in active_proofs(catalog, source) {
        let share_index = match &prior.role_descriptor {
            RegistrationRoleDescriptorV1::Witness { descriptor } => Some(descriptor.share_index),
            RegistrationRoleDescriptorV1::Approver { .. } => None,
            RegistrationRoleDescriptorV1::VaultPrincipal => return Err(source_invalid()),
        };
        challenges.push(
            creator
                .create_challenge(
                    initial,
                    owner,
                    prior.challenge.candidate_descriptor.clone(),
                    timestamp_ms,
                    lifetime_ms,
                    share_index,
                )
                .map_err(|_| failed())?,
        );
        prior_roles.push(prior.role_descriptor.clone());
    }
    Ok((challenges, prior_roles))
}

pub(super) fn verify_fresh_roles(
    initial: &PolicyState,
    challenges: &[RegistrationChallengeV1],
    prior_roles: &[RegistrationRoleDescriptorV1],
    proofs: &[RegistrationProofV1],
    now_ms: u64,
) -> Result<(), RolloverError> {
    if challenges.len() != prior_roles.len() || challenges.len() != proofs.len() {
        return Err(invalid());
    }
    for ((challenge, prior), proof) in challenges.iter().zip(prior_roles).zip(proofs) {
        verify_proof_signatures(initial, challenge, proof, now_ms).map_err(|_| invalid())?;
        if prior.principal_id() != Some(proof.candidate_principal_id)
            || !same_fresh_role(prior, &proof.role_descriptor, challenge.issued_at_ms)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn same_fresh_role(
    prior: &RegistrationRoleDescriptorV1,
    next: &RegistrationRoleDescriptorV1,
    timestamp_ms: u64,
) -> bool {
    let mut expected = prior.clone();
    match (&mut expected, next) {
        (
            RegistrationRoleDescriptorV1::Approver { descriptor },
            RegistrationRoleDescriptorV1::Approver { descriptor: next },
        ) => {
            if descriptor.created_at_ms > timestamp_ms {
                return false;
            }
            descriptor.created_at_ms = timestamp_ms;
            descriptor.self_signature = next.self_signature.clone();
        }
        (
            RegistrationRoleDescriptorV1::Witness { descriptor },
            RegistrationRoleDescriptorV1::Witness { descriptor: next },
        ) => {
            if descriptor.created_at_ms > timestamp_ms {
                return false;
            }
            descriptor.created_at_ms = timestamp_ms;
            descriptor.self_signature = next.self_signature.clone();
        }
        _ => return false,
    }
    &expected == next
}

pub(super) fn principal_operations(
    source: &PolicyState,
    statement: &SignedRolloverV1,
    proofs: &[RegistrationProofV1],
) -> Result<Vec<PolicyOperationV1>, RolloverError> {
    let mut operations = super::principal_operations(source, statement)?;
    for operation in &mut operations {
        if let PolicyOperationV1::PrincipalAdd {
            descriptor,
            registration_proof_digest,
            ..
        } = operation
            && matches!(
                descriptor.principal_kind,
                PrincipalKind::Approver | PrincipalKind::Witness
            )
        {
            let proof = proofs
                .iter()
                .find(|proof| proof.candidate_principal_id == descriptor.principal_id)
                .ok_or_else(invalid)?;
            *registration_proof_digest = proof.digest().map_err(|_| invalid())?;
        }
    }
    Ok(operations)
}

pub(in crate::rollover) fn active_proofs<'a>(
    catalog: &'a TransferPublicCatalogV1,
    source: &PolicyState,
) -> Vec<&'a RegistrationProofV1> {
    catalog
        .registration_proofs
        .iter()
        .filter(|proof| source.principal(&proof.candidate_principal_id).is_some())
        .collect()
}
