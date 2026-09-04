pub(super) fn policy_catalog_json_bytes(catalog: &PolicyCatalogV1) -> Result<Vec<u8>, CliError> {
    catalog.validate()?;
    serde_json::to_vec(catalog).map_err(|_| invalid_policy_catalog())
}
pub(super) fn add_catalog_registration_proof(
    catalog: &mut PolicyCatalogV1,
    proof: &RegistrationProofV1,
) -> Result<(), CliError> {
    let role = &proof.role_descriptor;
    let id = role.principal_id().ok_or_else(invalid_policy_catalog)?;
    if let Some(existing) = catalog
        .role_descriptors
        .iter()
        .find(|existing| existing.principal_id() == Some(id))
    {
        if existing != role {
            return Err(CliError::new(
                CliErrorKind::Conflict,
                "role-descriptor-conflict",
                "a different role descriptor already exists for this principal",
            ));
        }
    } else {
        catalog.role_descriptors.push(role.clone());
    }
    if let Some(existing) = catalog
        .registration_proofs
        .iter()
        .find(|existing| existing.candidate_principal_id == id)
    {
        if existing == proof {
            return Ok(());
        }
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "registration-proof-conflict",
            "a different registration proof already exists for this principal",
        ));
    }
    catalog.registration_proofs.push(proof.clone());
    catalog
        .role_descriptors
        .sort_by_key(RegistrationRoleDescriptorV1::principal_id);
    catalog
        .registration_proofs
        .sort_by_key(|proof| proof.candidate_principal_id);
    policy_catalog_json_bytes(catalog).map(|_| ())
}

pub(super) fn add_catalog_witness_policy(
    catalog: &mut PolicyCatalogV1,
    current_policy: &PolicyState,
    policy: &WitnessPolicy,
) -> Result<(), CliError> {
    let digest = policy.digest().map_err(|_| invalid_policy_catalog())?;
    if let Some(existing) = catalog
        .witness_policies
        .iter()
        .find(|existing| existing.digest().ok().as_ref() == Some(&digest))
    {
        if existing == policy {
            return Ok(());
        }
        return Err(invalid_policy_catalog());
    }
    catalog.witness_policies.push(policy.clone());
    let mut retained = current_policy
        .items()
        .filter_map(|(_, item)| {
            item.witnessed_state
                .as_ref()
                .and_then(|state| state.slots.first())
                .map(|slot| slot.witness_policy_digest.clone())
        })
        .collect::<BTreeSet<_>>();
    retained.insert(digest);
    let mut pending = retained.iter().cloned().collect::<Vec<_>>();
    while let Some(current) = pending.pop() {
        let entry = catalog
            .witness_policies
            .iter()
            .find(|entry| entry.digest().ok().as_ref() == Some(&current))
            .ok_or_else(invalid_policy_catalog)?;
        if entry.revision > 1 && retained.insert(entry.predecessor_policy_digest.clone()) {
            pending.push(entry.predecessor_policy_digest.clone());
        }
    }
    catalog.witness_policies.retain(|entry| {
        entry
            .digest()
            .is_ok_and(|entry_digest| retained.contains(&entry_digest))
    });
    catalog.witness_policies.sort_by_key(|entry| {
        entry
            .digest()
            .map(|digest| *digest.as_bytes())
            .unwrap_or([0; 32])
    });
    let retained_label_digests = catalog
        .witness_policies
        .iter()
        .map(|policy| policy.review_label_set_digest.clone())
        .collect::<BTreeSet<_>>();
    catalog
        .review_label_sets
        .retain(|set| retained_label_digests.contains(&set.digest));
    catalog
        .review_label_sets
        .sort_by_key(|set| set.digest.clone());
    policy_catalog_json_bytes(catalog).map(|_| ())
}

pub(super) fn add_catalog_review_label_set(
    catalog: &mut PolicyCatalogV1,
    set: jury_core::transfer::ReviewLabelSetV1,
) -> Result<(), CliError> {
    if let Some(existing) = catalog
        .review_label_sets
        .iter()
        .find(|existing| existing.digest == set.digest)
    {
        if existing != &set {
            return Err(invalid_policy_catalog());
        }
        return Ok(());
    }
    catalog.review_label_sets.push(set);
    catalog
        .review_label_sets
        .sort_by_key(|entry| entry.digest.clone());
    policy_catalog_json_bytes(catalog).map(|_| ())
}

pub(super) struct VaultPrincipalContext {
    pub(super) home: VaultHomeLocation,
    pub(super) vault: VaultFileV1,
    pub(super) policy: PolicyState,
    pub(super) catalog_before: PolicyCatalogV1,
    pub(super) catalog_before_bytes: Option<Vec<u8>>,
    pub(super) catalog: PolicyCatalogV1,
    pub(super) identity: VaultPrincipalIdentity,
    pub(super) state: VaultStateDirectory,
    pub(super) local: PrincipalLocalState,
    pub(super) protection_degraded: bool,
}

pub(super) struct AccessibleItem {
    pub(super) envelope_index: usize,
    pub(super) descriptor: ItemDescriptorV1,
}
