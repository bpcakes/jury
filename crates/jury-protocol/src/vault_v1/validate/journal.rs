use super::*;

pub(super) fn validate_header(vault: &VaultFileV1) -> Result<(), FormatError> {
    validate_header_discriminants(&HeaderProbeFields {
        magic: vault.header.magic.clone(),
        version: vault.header.version,
        suite: vault.header.suite,
        policy_schema: vault.header.policy_schema,
        item_schema: vault.header.item_schema,
        identity_schema: vault.header.identity_schema,
    })?;
    if vault.header.vault_id != vault.policy.genesis.vault_id {
        return Err(FormatError::Invalid("header and genesis vault differ"));
    }
    if vault.header.created_at_ms != vault.policy.genesis.created_at_ms {
        return Err(FormatError::Invalid("header and genesis time differ"));
    }
    if vault.policy.genesis.suite != vault.header.suite {
        return Err(FormatError::Invalid("genesis suite differs"));
    }
    if vault.policy.genesis.recomputed_fingerprint()? != vault.header.genesis_fingerprint {
        return Err(FormatError::Invalid("genesis fingerprint differs"));
    }
    Ok(())
}

pub(super) fn validate_policy(vault: &VaultFileV1) -> Result<(), FormatError> {
    let genesis = &vault.policy.genesis;
    if genesis.policy_sequence != 0 || genesis.previous_policy_hash.as_bytes() != &ZERO_DIGEST {
        return Err(FormatError::Invalid("genesis sequence is not zero"));
    }
    if genesis.owner.descriptor_version != 1
        || genesis.owner.principal_kind != crate::vault_v1::PrincipalKind::Human
    {
        return Err(FormatError::Invalid("genesis owner is not one v1 human"));
    }
    if !genesis.item_inventory.is_empty() || !genesis.direct_grants.is_empty() {
        return Err(FormatError::Invalid("genesis state is not empty"));
    }
    validate_source_attestation(vault)?;
    if vault.policy.revisions.len() > MAX_POLICY_REVISIONS {
        return Err(FormatError::CapacityExhausted("policy revisions"));
    }

    let mut previous_hash = vault.header.genesis_fingerprint.clone();
    for (index, revision) in vault.policy.revisions.iter().enumerate() {
        let expected_sequence = u64::try_from(index)
            .map_err(|_| FormatError::CapacityExhausted("policy revisions"))?
            + 1;
        if revision.vault_id != vault.header.vault_id
            || revision.sequence != expected_sequence
            || revision.previous_revision_hash != previous_hash
        {
            return Err(FormatError::Invalid("policy ancestry differs"));
        }
        if revision.operations.is_empty()
            && !(index == 0 && genesis.permits_empty_rollover_bootstrap())
        {
            return Err(FormatError::Invalid("policy revision has no operation"));
        }
        for operation in &revision.operations {
            validate_operation(
                operation,
                revision.sequence,
                &vault.header.vault_id,
                &vault.header.genesis_fingerprint,
            )?;
        }
        previous_hash = revision.recomputed_hash()?;
    }
    Ok(())
}

fn validate_source_attestation(vault: &VaultFileV1) -> Result<(), FormatError> {
    let Some(attestation) = &vault.policy.genesis.source_attestation else {
        return Ok(());
    };
    match attestation {
        SourceAttestationV1::LegacyMigration { source_format, .. } => {
            if !matches!(source_format, 1 | 2) {
                return Err(FormatError::Invalid("legacy source version differs"));
            }
        }
        SourceAttestationV1::Rollover { statement } => {
            if statement.rollover_format != 1
                || statement.destination_vault_id != vault.header.vault_id
                || statement.destination_suite != vault.header.suite
                || statement.source_vault_id == statement.destination_vault_id
                || statement.source_genesis_fingerprint == vault.header.genesis_fingerprint
            {
                return Err(FormatError::Invalid(
                    "rollover does not create one new lineage",
                ));
            }
            if let Some(manifest) = &statement.bootstrap_manifest
                && (manifest.destination_vault_id != vault.header.vault_id
                    || manifest.destination_suite != vault.header.suite
                    || manifest.created_at_ms != vault.header.created_at_ms
                    || manifest.acting_owner_principal_id != statement.acting_owner_principal_id
                    || manifest.acting_owner_principal_id
                        != vault.policy.genesis.owner.principal_id
                    || manifest.digest()? != statement.bootstrap_manifest_digest)
            {
                return Err(FormatError::Invalid("rollover manifest commitment differs"));
            }
        }
    }
    Ok(())
}
